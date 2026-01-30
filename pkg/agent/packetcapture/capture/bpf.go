// Copyright 2024 Antrea Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package capture

import (
	"encoding/binary"
	"net"
	"strings"

	"golang.org/x/net/bpf"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"

	crdv1alpha1 "antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
)

const (
	lengthByte    int    = 1
	lengthHalf    int    = 2
	lengthWord    int    = 4
	etherTypeIPv4 uint32 = 0x0800
	etherTypeIPv6 uint32 = 0x86DD

	jumpMask                 uint32 = 0x1fff
	ip4SourceAddrOffset      uint32 = 26
	ip4DestinationAddrOffset uint32 = 30
	ip4SourcePort            uint32 = 14
	ip4DestinationPort       uint32 = 16
	ip4HeaderSize            uint32 = 14
	ip4HeaderFlags           uint32 = 20

	ip6HeaderOffset          uint32 = 14
	ip6HeaderSize            uint32 = 40
	ip6NextHeaderOffset      uint32 = ip6HeaderOffset + 6             // 20
	ip6SourceAddrOffset      uint32 = ip6HeaderOffset + 8             // 22
	ip6DestinationAddrOffset uint32 = ip6HeaderOffset + 24            // 38
	ip6L4HeaderOffset        uint32 = ip6HeaderOffset + ip6HeaderSize // 54
	ip6SourcePort            uint32 = 0
	ip6DestinationPort       uint32 = 2
	ip6TCPFlags              uint32 = 13
	ip6ICMPv6Type            uint32 = 0
	ip6ICMPv6Code            uint32 = 1
)

var (
	returnDrop              = bpf.RetConstant{Val: 0}
	returnKeep              = bpf.RetConstant{Val: 0x40000}
	loadIPv4SourcePort      = bpf.LoadIndirect{Off: ip4SourcePort, Size: lengthHalf}
	loadIPv4DestinationPort = bpf.LoadIndirect{Off: ip4DestinationPort, Size: lengthHalf}
	loadEtherKind           = bpf.LoadAbsolute{Off: 12, Size: lengthHalf}
	loadIPv4Protocol        = bpf.LoadAbsolute{Off: 23, Size: lengthByte}
	loadIPv4TCPFlags        = bpf.LoadIndirect{Off: 27, Size: lengthByte}
	loadIPv4ICMPType        = bpf.LoadIndirect{Off: 14, Size: lengthByte}
	loadIPv4ICMPCode        = bpf.LoadIndirect{Off: 15, Size: lengthByte}

	loadIPv6NextHeader      = bpf.LoadAbsolute{Off: ip6NextHeaderOffset, Size: lengthByte}
	loadIPv6SourcePort      = bpf.LoadAbsolute{Off: ip6L4HeaderOffset + ip6SourcePort, Size: lengthHalf}
	loadIPv6DestinationPort = bpf.LoadAbsolute{Off: ip6L4HeaderOffset + ip6DestinationPort, Size: lengthHalf}
	loadIPv6TCPFlags        = bpf.LoadAbsolute{Off: ip6L4HeaderOffset + ip6TCPFlags, Size: lengthByte}
	loadIPv6ICMPv6Type      = bpf.LoadAbsolute{Off: ip6L4HeaderOffset + ip6ICMPv6Type, Size: lengthByte}
	loadIPv6ICMPv6Code      = bpf.LoadAbsolute{Off: ip6L4HeaderOffset + ip6ICMPv6Code, Size: lengthByte}
)

// Supported protocol strings (must be uppercase, since validation uses strings.ToUpper).
// These values are matched against user input in the controller.
var ProtocolMap = map[string]uint32{
	"UDP":    17,
	"TCP":    6,
	"ICMP":   1,
	"ICMPV6": 58,
}

var ICMPMsgTypeMap = map[crdv1alpha1.ICMPMsgType]uint32{
	crdv1alpha1.ICMPMsgTypeEcho:       8,
	crdv1alpha1.ICMPMsgTypeEchoReply:  0,
	crdv1alpha1.ICMPMsgTypeDstUnreach: 3,
	crdv1alpha1.ICMPMsgTypeTimexceed:  11,
}

var ICMPv6MsgTypeMap = map[crdv1alpha1.ICMPv6MsgType]uint32{
	crdv1alpha1.ICMPv6MsgTypeEcho:         128,
	crdv1alpha1.ICMPv6MsgTypeEchoReply:    129,
	crdv1alpha1.ICMPv6MsgTypeDstUnreach:   1,
	crdv1alpha1.ICMPv6MsgTypeTimexceed:    3,
	crdv1alpha1.ICMPv6MsgTypePacketTooBig: 2,
	crdv1alpha1.ICMPv6MsgTypeParamProblem: 4,
}

type tcpFlagsFilter struct {
	flag uint32
	mask uint32
}

// handles both icmp & icmpv6 msgs
type icmpFilter struct {
	icmpType uint32
	icmpCode *uint32
}

type transportFilters struct {
	srcPort  uint16
	dstPort  uint16
	tcpFlags []tcpFlagsFilter
	icmp     []icmpFilter
}

// ipFamilyHandler encapsulates protocol-specific constants and filter compilation logic
// to allow for a unified, protocol-agnostic packet filter generation function.
type ipFamilyHandler struct {
	etherType             uint32
	addressChunks         int // IPv4: 1, IPv6: 4
	sourceAddrOffset      uint32
	destinationAddrOffset uint32

	loadProtocol        bpf.Instruction
	loadSourcePort      bpf.Instruction
	loadDestinationPort bpf.Instruction
	loadTCPFlags        bpf.Instruction
	loadICMPType        bpf.Instruction
	loadICMPCode        bpf.Instruction
}

// ipv4Handler provides the IPv4-specific implementations for the ipFamilyHandler.
var ipv4Handler = &ipFamilyHandler{
	etherType:             etherTypeIPv4,
	addressChunks:         1,
	sourceAddrOffset:      ip4SourceAddrOffset,
	destinationAddrOffset: ip4DestinationAddrOffset,

	loadProtocol:        loadIPv4Protocol,
	loadSourcePort:      loadIPv4SourcePort,
	loadDestinationPort: loadIPv4DestinationPort,
	loadTCPFlags:        loadIPv4TCPFlags,
	loadICMPType:        loadIPv4ICMPType,
	loadICMPCode:        loadIPv4ICMPCode,
}

// ipv6Handler provides the IPv6-specific implementations for the ipFamilyHandler.
var ipv6Handler = &ipFamilyHandler{
	etherType:             etherTypeIPv6,
	addressChunks:         4,
	sourceAddrOffset:      ip6SourceAddrOffset,
	destinationAddrOffset: ip6DestinationAddrOffset,

	loadProtocol:        loadIPv6NextHeader,
	loadSourcePort:      loadIPv6SourcePort,
	loadDestinationPort: loadIPv6DestinationPort,
	loadTCPFlags:        loadIPv6TCPFlags,
	loadICMPType:        loadIPv6ICMPv6Type,
	loadICMPCode:        loadIPv6ICMPv6Code,
}

func loadIPv4HeaderOffset(skipTrue uint8) []bpf.Instruction {
	return []bpf.Instruction{
		bpf.LoadAbsolute{Off: ip4HeaderFlags, Size: lengthHalf},              // flags+fragment offset, since we need to calc where the src/dst port is
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: jumpMask, SkipTrue: skipTrue}, // check if there is a L4 header
		bpf.LoadMemShift{Off: ip4HeaderSize},                                 // calculate the size of IP header
	}
}

func compareProtocolIP(etherType uint32, skipTrue, skipFalse uint8) bpf.Instruction {
	return bpf.JumpIf{Cond: bpf.JumpEqual, Val: etherType, SkipTrue: skipTrue, SkipFalse: skipFalse}
}

func compareProtocol(protocol uint32, skipTrue, skipFalse uint8) bpf.Instruction {
	return bpf.JumpIf{Cond: bpf.JumpEqual, Val: protocol, SkipTrue: skipTrue, SkipFalse: skipFalse}
}

// getAddressChunk abstracts the process of extracting a 4-byte chunk from an IP address,
// handling the structural differences between IPv4 (one chunk) and IPv6 (four chunks).
func (h *ipFamilyHandler) getAddressChunk(ip net.IP, chunkIndex int) uint32 {
	if h.etherType == etherTypeIPv4 {
		return binary.BigEndian.Uint32(ip[len(ip)-4:])
	}
	return binary.BigEndian.Uint32(ip[chunkIndex*4 : (chunkIndex+1)*4])
}

// calculateSkipOffset determines the correct 'SkipFalse' jump offset for an IP address chunk
// comparison. When checking bidirectional traffic ('Both' direction), a failed check for the first
// direction should not jump to the end (drop), but rather to the start of the check for the other
// direction. jumpToReturnTraffic: If true, calculate the offset to jump to the return traffic block.
// chunkIndex: The current 4-byte chunk index of the IP being checked (0-3 for IPv6).
func (h *ipFamilyHandler) calculateSkipOffset(chunkIndex int, skipFalse, skipToEnd uint8, jumpToReturnTraffic bool) uint8 {
	if jumpToReturnTraffic {
		// calculate the relative jump offsets (SkipFalse) that decrease by 2 per chunk
		// for the srcIP and dstIP cases.
		return skipFalse - uint8((chunkIndex+1)*2)
	}
	return skipToEnd
}

func (h *ipFamilyHandler) countAddrForSkipFalse(srcIP, dstIP net.IP) uint8 {
	var count uint8
	// We keep track of this count so we can correctly calculate the
	// relative jump offsets (SkipFalse) that decrease by 2 per chunk
	// for the srcIP and dstIP cases.
	if srcIP != nil {
		count += uint8(h.addressChunks * 2)
	}
	if dstIP != nil {
		count += uint8(h.addressChunks * 2)
	}
	return count
}

func calculateSkipFalse(handler *ipFamilyHandler, srcIP, dstIP net.IP, transport *transportFilters) uint8 {
	var count uint8

	count += handler.countAddrForSkipFalse(srcIP, dstIP)

	if transport.srcPort > 0 || transport.dstPort > 0 || len(transport.tcpFlags) > 0 || len(transport.icmp) > 0 {
		if handler.etherType == etherTypeIPv4 {
			// load fragment offset
			count += 3
		}

		if transport.srcPort > 0 {
			count += 2
		}
		if transport.dstPort > 0 {
			count += 2
		}
		if len(transport.tcpFlags) > 0 {
			count += uint8(len(transport.tcpFlags) * 3)
		}
		if len(transport.icmp) > 0 { // handles both icmp & icmpv6 msgs
			count += 1
			for _, m := range transport.icmp {
				count += 1
				if m.icmpCode != nil {
					count += 2
				}
			}
		}
	}
	// ret keep
	count += 1

	return count
}

// compileIPFilters generates the BPF instructions for matching source and/or destination
// IP addresses. It is protocol-agnostic, using the handler to abstract the differences
// between IPv4 (1 chunk) and IPv6 (4 chunks). It also manages the complex jump logic
// required for bidirectional traffic matching.
func compileIPFilters(handler *ipFamilyHandler, srcIP, dstIP net.IP, size, curLen, skipFalse uint8, needsOtherTrafficDirectionCheck bool) []bpf.Instruction {
	inst := []bpf.Instruction{}

	// calculate skip size to jump to the final instruction (NO MATCH)
	skipToEnd := func() uint8 {
		return size - curLen - uint8(len(inst)) - 2
	}

	if srcIP != nil {
		for i := range handler.addressChunks {
			offset := uint32(i * 4)
			addrVal := handler.getAddressChunk(srcIP, i)
			inst = append(inst, bpf.LoadAbsolute{Off: handler.sourceAddrOffset + offset, Size: lengthWord})

			// needsOtherTrafficDirectionCheck indicates if we need to check whether the packet belongs to the
			// return traffic flow when source IP from the packet spec and packet header don't match and we are
			// capturing packets in both direction. If true, we calculate skipFalse to jump to the instruction
			// that compares the destination IP from the packet spec with the loaded source IP from the packet
			// header.
			currentSkipFalse := handler.calculateSkipOffset(i, skipFalse, skipToEnd(), needsOtherTrafficDirectionCheck)
			inst = append(inst, bpf.JumpIf{Cond: bpf.JumpEqual, Val: addrVal, SkipTrue: 0, SkipFalse: currentSkipFalse})
		}
	}

	if dstIP != nil {
		for i := range handler.addressChunks {
			offset := uint32(i * 4)
			addrVal := handler.getAddressChunk(dstIP, i)
			inst = append(inst, bpf.LoadAbsolute{Off: handler.destinationAddrOffset + offset, Size: lengthWord})

			// If the dstIP doesn't match, skip to the end (no match), unless a srcIP was not provided and
			// we need to check the other direction of traffic (reply). If we don't need to check the other
			// direction of traffic, we can already say the packet is not a match. If a srcIP was provided
			// and get to that stage in the filter (dstIP check), then it means the srcIP was a match: if
			// the srcIP matches but not the dstIP, we don't need to check the other direction of traffic
			// (guaranteed no match).
			checkReturnTraffic := srcIP == nil && needsOtherTrafficDirectionCheck
			currentSkipFalse := handler.calculateSkipOffset(i, skipFalse, skipToEnd(), checkReturnTraffic)
			inst = append(inst, bpf.JumpIf{Cond: bpf.JumpEqual, Val: addrVal, SkipTrue: 0, SkipFalse: currentSkipFalse})
		}
	}
	return inst
}

// Generates BPF instructions for filtering transport-layer traffic based on ports, TCP flags,
// ICMP and ICMPv6 messages.
func compileTransportFilters(handler *ipFamilyHandler, size, curLen uint8, transport *transportFilters) []bpf.Instruction {
	inst := []bpf.Instruction{}

	// calculate skip size to jump to the final instruction (NO MATCH)
	skipToEnd := func() uint8 {
		return size - curLen - uint8(len(inst)) - 2
	}

	if transport.srcPort > 0 || transport.dstPort > 0 || len(transport.tcpFlags) > 0 || len(transport.icmp) > 0 {
		// For fragment checks and IP header length calculation to find the L4 header offset,
		// as the IP header can have variable options.
		if handler.etherType == etherTypeIPv4 {
			skipTrue := skipToEnd() - 1
			inst = append(inst, loadIPv4HeaderOffset(skipTrue)...)
		}
		if transport.srcPort > 0 {
			inst = append(inst, handler.loadSourcePort)
			inst = append(inst, bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(transport.srcPort), SkipTrue: 0, SkipFalse: skipToEnd()})
		}
		if transport.dstPort > 0 {
			inst = append(inst, handler.loadDestinationPort)
			inst = append(inst, bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(transport.dstPort), SkipTrue: 0, SkipFalse: skipToEnd()})
		}

		// tcp flags
		if len(transport.tcpFlags) > 0 {
			for i, f := range transport.tcpFlags {
				inst = append(inst, handler.loadTCPFlags)
				inst = append(inst, bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: f.mask})
				if i == len(transport.tcpFlags)-1 { // last flag match condition
					inst = append(inst, bpf.JumpIf{Cond: bpf.JumpEqual, Val: f.flag, SkipTrue: 0, SkipFalse: skipToEnd()})
				} else {
					inst = append(inst, bpf.JumpIf{Cond: bpf.JumpEqual, Val: f.flag, SkipTrue: skipToEnd() - 1, SkipFalse: 0})
				}
			}
		}

		// handles both icmp & icmpv6 msgs
		if len(transport.icmp) > 0 {
			inst = append(inst, handler.loadICMPType)
			for i, f := range transport.icmp {
				var skipTrue, skipFalse uint8
				if f.icmpCode != nil {
					if i != len(transport.icmp)-1 {
						skipFalse = 2
					} else {
						skipFalse = skipToEnd()
					}
				} else {
					if i != len(transport.icmp)-1 {
						skipTrue, skipFalse = skipToEnd()-1, 0
					} else {
						skipTrue, skipFalse = 0, skipToEnd()
					}
				}
				inst = append(inst, bpf.JumpIf{Cond: bpf.JumpEqual, Val: f.icmpType, SkipTrue: skipTrue, SkipFalse: skipFalse})
				if f.icmpCode != nil {
					inst = append(inst, handler.loadICMPCode)
					inst = append(inst, bpf.JumpIf{Cond: bpf.JumpEqual, Val: *f.icmpCode, SkipTrue: skipToEnd() - 1, SkipFalse: skipToEnd()})
				}
			}
		}
	}

	// return (accept)
	inst = append(inst, returnKeep)

	return inst
}

// compilePacketFilter acts as the main entry point for BPF filter generation.
// It inspects the IP family specified in the CRD and dispatches the request
// to the unified compiler with the appropriate protocol-specific handler
// (ipv4Handler for IPv4, ipv6Handler for IPv6).
func compilePacketFilter(packetSpec *crdv1alpha1.Packet, srcIP, dstIP net.IP, direction crdv1alpha1.CaptureDirection) []bpf.Instruction {
	if packetSpec != nil && packetSpec.IPFamily == v1.IPv6Protocol {
		return compileGenericPacketFilter(ipv6Handler, packetSpec, srcIP, dstIP, direction)
	}
	return compileGenericPacketFilter(ipv4Handler, packetSpec, srcIP, dstIP, direction)
}

// compileGenericPacketFilter compiles the CRD spec to BPF instructions using a
// protocol-specific handler to manage differences between IPv4 and IPv6.
func compileGenericPacketFilter(handler *ipFamilyHandler, packetSpec *crdv1alpha1.Packet, srcIP, dstIP net.IP, direction crdv1alpha1.CaptureDirection) []bpf.Instruction {
	size := uint8(calculateInstructionsSize(handler, packetSpec, srcIP, dstIP, direction))

	// Start with checking the EtherType.
	inst := []bpf.Instruction{loadEtherKind}
	// skip means how many instructions we need to skip if the compare fails.
	// for example, for now we have 2 instructions, and the total size is 17, if ipv4
	// check failed, we need to jump to the end (ret #0), skip 17-3=14 instructions.
	// if check succeed, skipTrue means we jump to the next instruction. Here 3 means we
	// have 3 instructions so far.
	inst = append(inst, compareProtocolIP(handler.etherType, 0, size-3))

	if packetSpec != nil && packetSpec.Protocol != nil {
		var proto uint32
		if packetSpec.Protocol.Type == intstr.Int {
			proto = uint32(packetSpec.Protocol.IntVal)
		} else {
			proto = ProtocolMap[strings.ToUpper(packetSpec.Protocol.StrVal)]
		}
		inst = append(inst, handler.loadProtocol)
		inst = append(inst, compareProtocol(proto, 0, size-5))
	}

	// ports, TCP flags, ICMP and ICMPv6 messages
	var transport transportFilters
	if packetSpec.TransportHeader.TCP != nil {
		if packetSpec.TransportHeader.TCP.SrcPort != nil {
			transport.srcPort = uint16(*packetSpec.TransportHeader.TCP.SrcPort)
		}
		if packetSpec.TransportHeader.TCP.DstPort != nil {
			transport.dstPort = uint16(*packetSpec.TransportHeader.TCP.DstPort)
		}
		if packetSpec.TransportHeader.TCP.Flags != nil {
			for _, f := range packetSpec.TransportHeader.TCP.Flags {
				m := f.Value // default to flag if not specified
				if f.Mask != nil {
					m = *f.Mask
				}
				transport.tcpFlags = append(transport.tcpFlags, tcpFlagsFilter{
					flag: uint32(f.Value),
					mask: uint32(m),
				})
			}
		}
	} else if packetSpec.TransportHeader.UDP != nil {
		if packetSpec.TransportHeader.UDP.SrcPort != nil {
			transport.srcPort = uint16(*packetSpec.TransportHeader.UDP.SrcPort)
		}
		if packetSpec.TransportHeader.UDP.DstPort != nil {
			transport.dstPort = uint16(*packetSpec.TransportHeader.UDP.DstPort)
		}
	} else if packetSpec.TransportHeader.ICMP != nil {
		for _, f := range packetSpec.TransportHeader.ICMP.Messages {
			var typeValue uint32
			var codeValue *uint32
			if f.Type.Type == intstr.Int {
				typeValue = uint32(f.Type.IntVal)
			} else {
				typeValue = ICMPMsgTypeMap[crdv1alpha1.ICMPMsgType(strings.ToLower(f.Type.StrVal))]
			}
			if f.Code != nil {
				codeValue = ptr.To(uint32(*f.Code))
			}

			transport.icmp = append(transport.icmp, icmpFilter{
				icmpType: typeValue,
				icmpCode: codeValue,
			})
		}
	} else if packetSpec.TransportHeader.ICMPv6 != nil {
		for _, f := range packetSpec.TransportHeader.ICMPv6.Messages {
			var typeValue uint32
			var codeValue *uint32
			if f.Type.Type == intstr.Int {
				typeValue = uint32(f.Type.IntVal)
			} else {
				typeValue = ICMPv6MsgTypeMap[crdv1alpha1.ICMPv6MsgType(strings.ToLower(f.Type.StrVal))]
			}
			if f.Code != nil {
				codeValue = ptr.To(uint32(*f.Code))
			}

			transport.icmp = append(transport.icmp, icmpFilter{
				icmpType: typeValue,
				icmpCode: codeValue,
			})
		}
	}

	switch direction {
	case crdv1alpha1.CaptureDirectionSourceToDestination:
		inst = append(inst, compileIPFilters(handler, srcIP, dstIP, size, uint8(len(inst)), 0, false)...)
	case crdv1alpha1.CaptureDirectionDestinationToSource:
		transport.srcPort, transport.dstPort = transport.dstPort, transport.srcPort
		inst = append(inst, compileIPFilters(handler, dstIP, srcIP, size, uint8(len(inst)), 0, false)...)
	default:
		skipFalse := calculateSkipFalse(handler, srcIP, dstIP, &transport)
		inst = append(inst, compileIPFilters(handler, srcIP, dstIP, size, uint8(len(inst)), skipFalse, true)...)
		inst = append(inst, compileTransportFilters(handler, size, uint8(len(inst)), &transport)...)
		transport.srcPort, transport.dstPort = transport.dstPort, transport.srcPort
		inst = append(inst, compileIPFilters(handler, dstIP, srcIP, size, uint8(len(inst)), 0, false)...)
	}
	inst = append(inst, compileTransportFilters(handler, size, uint8(len(inst)), &transport)...)

	// return (drop)
	inst = append(inst, returnDrop)

	return inst
}

// We need to figure out how long the instruction list will be first. It will be used in the instructions' jump case.
// For example, If you provide all the filters supported by `PacketCapture`, it will end with the following BPF filter string:
// 'ip proto 6 and src host 127.0.0.1 and dst host 127.0.0.1 and src port 123 and dst port 124'
// And using `tcpdump -i <device> '<filter>' -d` will generate the following BPF instructions:
// (000) ldh      [12]                                     # Load 2B at 12 (Ethertype)
// (001) jeq      #0x800           jt 2	jf 16              # Ethertype: If IPv4, goto #2, else #16
// (002) ldb      [23]                                     # Load 1B at 23 (IPv4 Protocol)
// (003) jeq      #0x6             jt 4	jf 16              # IPv4 Protocol: If TCP, goto #4, #16
// (004) ld       [26]                                     # Load 4B at 26 (source address)
// (005) jeq      #0x7f000001      jt 6	jf 16              # If bytes match(127.0.0.1), goto #6, else #16
// (006) ld       [30]                                     # Load 4B at 30 (dest address)
// (007) jeq      #0x7f000001      jt 8	jf 16              # If bytes match(127.0.0.1), goto #8, else #16
// (008) ldh      [20]                                     # Load 2B at 20 (13b Fragment Offset)
// (009) jset     #0x1fff          jt 16	jf 10          # Use 0x1fff as a mask for fragment offset; If fragment offset != 0, #10, else #16
// (010) ldxb     4*([14]&0xf)                             # x = IP header length
// (011) ldh      [x + 14]                                 # Load 2B at x+14 (TCP Source Port)
// (012) jeq      #0x7b            jt 13	jf 16		   # TCP Source Port: If 123, goto #13, else #16
// (013) ldh      [x + 16]                                 # Load 2B at x+16 (TCP dst port)
// (014) jeq      #0x7c            jt 15	jf 16		   # TCP dst port: If 123, goto #15, else #16
// (015) ret      #262144                                  # MATCH
// (016) ret      #0                                       # NOMATCH

// When capturing return traffic also (i.e., both src -> dst and dst -> src), the filter might look like this:
// 'ip proto 6 and ((src host 10.244.1.2 and dst host 10.244.1.3 and src port 123 and dst port 124) or (src host 10.244.1.3 and dst host 10.244.1.2 and src port 124 and dst port 123))'
// And using `tcpdump -i <device> '<filter>' -d` will generate the following BPF instructions:
// Ethertype, IPv4 protocol...
// (004) ld       [26]									   # Load 4B at 26 (source address)
// (005) jeq      #0xaf40102       jt 6	jf 15			   # If bytes match(10.244.1.2), goto #6, else #15
// (006) ld       [30]									   # Load 4B at 30 (dest address)
// (007) jeq      #0xaf40103       jt 8	jf 26			   # If bytes match(10.244.1.3), goto #8, else #26
// Check fragment offset and calculate IP header length...
// (011) ldh      [x + 14]								   # Load 2B at x+14 (TCP Source Port)
// (012) jeq      #0x7b            jt 13	jf 26		   # TCP Source Port: If 123, goto #13, else #26
// (013) ldh      [x + 16]								   # Load 2B at x+16 (TCP dst port)
// (014) jeq      #0x7c            jt 25	jf 26		   # TCP dst port: If 123, goto #25, else #26
// (015) jeq      #0xaf40103       jt 16	jf 26		   # If bytes match(10.244.1.3), goto #16, else #26
// (016) ld       [30]									   # Load 4B at 30 (return traffic dest address)
// (017) jeq      #0xaf40102       jt 18	jf 26		   # If bytes match(10.244.1.2), goto #18, else #26
// Check fragment offset and calculate IP header length...
// (021) ldh      [x + 14]								   # Load 2B at x+14 (TCP Source Port)
// (022) jeq      #0x7c            jt 23	jf 26		   # TCP Source Port: If 124, goto #23, else #26
// (023) ldh      [x + 16]								   # Load 2B at x+16 (TCP dst port)
// (024) jeq      #0x7b            jt 25	jf 26		   # TCP dst port: If 123, goto #25, else #26
// (025) ret      #262144								   # MATCH
// (026) ret      #0									   # NOMATCH

// For simpler code generation in 'Both' direction, an extra instruction to accept the packet is added after instruction 014.
// The final instruction set looks like this:
// Ethertype, IPv4 protocol...
// Source IP, Destination IP, Source port, Destination port...
// (015) ret      #262144								   # MATCH
// Source IP, Destination IP, Source port, Destination port for return traffic...
// (026) ret      #262144								   # MATCH
// (027) ret      #0									   # NOMATCH

// To capture all TCP packets from 10.0.0.4 to 10.0.0.5 with either SYN or ACK flags set, the filter would be:
// 'ip proto 6 and src host 10.0.0.4 and dst host 10.0.0.5 and ((tcp[tcpflags] & tcp-syn) == tcp-syn) or ((tcp[tcpflags] & tcp-ack) == tcp-ack))'
// And using `tcpdump -i <device> '<filter>' -d` will generate the following BPF instructions:
// Ethertype, IPv4 protocol...
// Source and Destination IP...
// Check fragment offset and calculate IP header length...
// (011) ldh      [x + 27]                                 # Load 1B at x+27 (TCP Flags)
// (012) and	  0x2			            			   # Apply a bitwise AND with 0x2 (SYN flag)
// (013) jeq      #0x2             jt 17    jf 14          # If SYN is set, goto #17, else #14
// (014) ldh      [x + 27]                                 # Again load 1B at x+27 (TCP Flags)
// (015) and	  0x10			            			   # Apply a bitwise AND with 0x10 (ACK flag)
// (016) jeq      #0x10            jt 17    jf 18          # If ACK is set, goto #17, else #18
// (017) ret      #262144                                  # MATCH
// (018) ret      #0                                       # NOMATCH

// To capture ICMP destination unreachable (host unreachable) packets from 10.0.0.1 to 10.0.0.2, the tcpdump filter would be:
// 'ip proto 1 and src host 10.0.0.1 and dst host 10.0.0.2 and icmp[0]=3 and icmp[1]=1'
// And using `tcpdump -i <device> '<filter>' -d` will generate the following BPF instructions:
// Ethertype, IPv4 protocol...
// Source and Destination IP...
// Check fragment offset and calculate IP header length...
// (011) ldb      [x + 14]								   # Load 1B at x+14 (ICMP Type)
// (012) jeq      #0x3             jt 13   jf 16		   # ICMP Type: If 3, goto #13, else #16
// (013) ldb      [x + 15]								   # Load 1B at x+15 (ICMP Code)
// (014) jeq      #0x1             jt 15   jf 16		   # ICMP Code: If 1, goto #15, else #16
// (015) ret      #262144								   # MATCH
// (016) ret      #0									   # NOMATCH

// For IPv6, the filter is similar but accounts for the 16-byte addresses, which are
// loaded and compared in 4-byte chunks. There is also no need for the fragment
// offset calculation to find the L4 header.
// 'ip6 proto 6 and src host fd00::1 and dst host fd00::2 and src port 123 and dst port 124'
// And using `tcpdump -i <device> '<filter>' -d` will generate the following BPF instructions:
// (000) ldh      [12]                                     # Load 2B at 12 (Ethertype)
// (001) jeq      #0x86dd          jt 2	jf 25              # Ethertype: If IPv6, goto #2, else #25
// (002) ldb      [20]                                     # Load 1B at 20 (Next Header)
// (003) jeq      #0x6             jt 4	jf 25              # Next Header: If TCP, goto #4, else #25
// (004) ld       [22]                                     # Load 4B at 22 (Src Addr chunk 1)
// (005) jeq      #0xfd000000      jt 6	jf 25              # If chunk 1 matches, goto #6, else #25
// (006) ld       [26]                                     # Load 4B at 26 (Src Addr chunk 2)
// (007) jeq      #0x0             jt 8	jf 25              # If chunk 2 matches, goto #8, else #25
// (008) ld       [30]                                     # Load 4B at 30 (Src Addr chunk 3)
// (009) jeq      #0x0             jt 10	jf 25          # If chunk 3 matches, goto #10, else #25
// (010) ld       [34]                                     # Load 4B at 34 (Src Addr chunk 4)
// (011) jeq      #0x1             jt 12	jf 25          # If chunk 4 matches (fd00::1), goto #12, else #25
// (012) ld       [38]                                     # Load 4B at 38 (Dst Addr chunk 1)
// (013) jeq      #0xfd000000      jt 14	jf 25          # If chunk 1 matches, goto #14, else #25
// (014) ld       [42]                                     # Load 4B at 42 (Dst Addr chunk 2)
// (015) jeq      #0x0             jt 16	jf 25          # If chunk 2 matches, goto #16, else #25
// (016) ld       [46]                                     # Load 4B at 46 (Dst Addr chunk 3)
// (017) jeq      #0x0             jt 18	jf 25          # If chunk 3 matches, goto #18, else #25
// (018) ld       [50]                                     # Load 4B at 50 (Dst Addr chunk 4)
// (019) jeq      #0x2             jt 20	jf 25          # If chunk 4 matches (fd00::2), goto #20, else #25
// (020) ldh      [54]                                     # Load 2B at 54 (TCP Src Port)
// (021) jeq      #0x7b            jt 22	jf 25		   # TCP Src Port: If 123, goto #22, else #25
// (022) ldh      [56]                                     # Load 2B at 56 (TCP Dst port)
// (023) jeq      #0x7c            jt 24	jf 25		   # TCP Dst port: If 124, goto #24, else #25
// (024) ret      #262144                                # MATCH
// (025) ret      #0                                       # NOMATCH

func calculateInstructionsSize(handler *ipFamilyHandler, packet *crdv1alpha1.Packet, srcIP, dstIP net.IP, direction crdv1alpha1.CaptureDirection) int {
	count := 0
	// load ethertype
	count++
	// ip check
	count++

	if srcIP != nil {
		count += handler.addressChunks * 2 // load + compare for each chunk
	}
	if dstIP != nil {
		count += handler.addressChunks * 2 // load + compare for each chunk
	}

	if packet != nil {
		// protocol check
		if packet.Protocol != nil {
			count += 2
		}
		transport := packet.TransportHeader
		portFiltersSize := func() int {
			count := 0
			if transport.TCP != nil {
				// load Fragment Offset
				if handler.etherType == etherTypeIPv4 {
					count += 3
				}
				if transport.TCP.SrcPort != nil {
					count += 2
				}
				if transport.TCP.DstPort != nil {
					count += 2
				}
				if transport.TCP.Flags != nil {
					// every TCP Flag match condition will have 3 instructions - load, bitwise AND, compare
					count += len(transport.TCP.Flags) * 3
				}
			} else if transport.UDP != nil {
				// load Fragment Offset
				if handler.etherType == etherTypeIPv4 {
					count += 3
				}
				if transport.UDP.SrcPort != nil {
					count += 2
				}
				if transport.UDP.DstPort != nil {
					count += 2
				}
			} else if transport.ICMP != nil {
				// load Fragment Offset
				if handler.etherType == etherTypeIPv4 {
					count += 3
				}
				count += 1 // load icmp type
				for _, m := range transport.ICMP.Messages {
					count += 1 // compare icmp type
					if m.Code != nil {
						count += 2 // load + compare icmp code
					}
				}
			} else if transport.ICMPv6 != nil {
				count += 1 // load icmpv6 type
				for _, m := range transport.ICMPv6.Messages {
					count += 1 // compare icmpv6 type
					if m.Code != nil {
						count += 2 // load + compare icmpv6 code
					}
				}
			}
			return count
		}()

		count += portFiltersSize

		if direction == crdv1alpha1.CaptureDirectionBoth {

			// extra returnKeep
			count++

			// src and dst ip (return traffic)
			if srcIP != nil {
				count += handler.addressChunks * 2
			}
			if dstIP != nil {
				count += handler.addressChunks * 2
			}

			count += portFiltersSize
		}
	}

	// ret command
	count += 2
	return count
}
