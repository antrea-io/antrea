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
	"k8s.io/apimachinery/pkg/util/intstr"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

const (
	lengthByte    int    = 1
	lengthHalf    int    = 2
	lengthWord    int    = 4
	bitsPerWord   int    = 32
	etherTypeIPv4 uint32 = 0x0800

	jumpMask           uint32 = 0x1fff
	ip4SourcePort      uint32 = 14
	ip4DestinationPort uint32 = 16
	ip4HeaderSize      uint32 = 14
	ip4HeaderFlags     uint32 = 20
)

var (
	returnDrop                 = bpf.RetConstant{Val: 0}
	returnKeep                 = bpf.RetConstant{Val: 0x40000}
	loadIPv4SourcePort         = bpf.LoadIndirect{Off: ip4SourcePort, Size: lengthHalf}
	loadIPv4DestinationPort    = bpf.LoadIndirect{Off: ip4DestinationPort, Size: lengthHalf}
	loadEtherKind              = bpf.LoadAbsolute{Off: 12, Size: lengthHalf}
	loadIPv4SourceAddress      = bpf.LoadAbsolute{Off: 26, Size: lengthWord}
	loadIPv4DestinationAddress = bpf.LoadAbsolute{Off: 30, Size: lengthWord}
	loadIPv4Protocol           = bpf.LoadAbsolute{Off: 23, Size: lengthByte}
)

var ProtocolMap = map[string]uint32{
	"UDP":  17,
	"TCP":  6,
	"ICMP": 1,
}

func loadIPv4HeaderOffset(skipTrue uint8) []bpf.Instruction {
	return []bpf.Instruction{
		bpf.LoadAbsolute{Off: ip4HeaderFlags, Size: lengthHalf},              // flags+fragment offset, since we need to calc where the src/dst port is
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: jumpMask, SkipTrue: skipTrue}, // check if there is a L4 header
		bpf.LoadMemShift{Off: ip4HeaderSize},                                 // calculate the size of IP header
	}
}

func compareProtocolIP4(skipTrue, skipFalse uint8) bpf.Instruction {
	return bpf.JumpIf{Cond: bpf.JumpEqual, Val: etherTypeIPv4, SkipTrue: skipTrue, SkipFalse: skipFalse}
}

func compareProtocol(protocol uint32, skipTrue, skipFalse uint8) bpf.Instruction {
	return bpf.JumpIf{Cond: bpf.JumpEqual, Val: protocol, SkipTrue: skipTrue, SkipFalse: skipFalse}
}

// compilePacketFilter compiles the CRD spec to bpf instructions. For now, we only focus on
// ipv4 traffic. Compared to the raw BPF filter supported by libpcap, we only need to support
// limited use cases, so an expression parser is not needed.
func compilePacketFilter(packetSpec *crdv1alpha1.Packet, srcIP, dstIP net.IP, bidirection bool) []bpf.Instruction {
	size := uint8(calculateInstructionsSize(packetSpec, bidirection))

	// ipv4 check
	inst := []bpf.Instruction{loadEtherKind} //(000)
	// skip means how many instructions we need to skip if the compare fails.
	// for example, for now we have 2 instructions, and the total size is 17, if ipv4
	// check failed, we need to jump to the end (ret #0), skip 17-3=14 instructions.
	// if check succeed, skipTrue means we jump to the next instruction. Here 3 means we
	// have 3 instructions so far.
	inst = append(inst, compareProtocolIP4(0, size-3)) //(001)

	if packetSpec != nil {
		if packetSpec.Protocol != nil {
			var proto uint32
			if packetSpec.Protocol.Type == intstr.Int {
				proto = uint32(packetSpec.Protocol.IntVal)
			} else {
				proto = ProtocolMap[strings.ToUpper(packetSpec.Protocol.StrVal)]
			}

			inst = append(inst, loadIPv4Protocol)                  //(002)
			inst = append(inst, compareProtocol(proto, 0, size-5)) //(003) 27-5=22
		}
	}

	// source ip
	if srcIP != nil {
		inst = append(inst, loadIPv4SourceAddress) //(004)
		addrVal := binary.BigEndian.Uint32(srcIP[len(srcIP)-4:])
		// from here we need to check the inst length to calculate skipFalse. If no protocol is set, there will be no related bpf instructions.
		if bidirection {
			inst = append(inst, bpf.JumpIf{Cond: bpf.JumpEqual, Val: addrVal, SkipTrue: 0, SkipFalse: size - uint8(len(inst)) - 13}) //(005) 27-5-13=9
		} else {
			inst = append(inst, bpf.JumpIf{Cond: bpf.JumpEqual, Val: addrVal, SkipTrue: 0, SkipFalse: size - uint8(len(inst)) - 2}) //(005) 17-5-2=10
		}
	}
	// dst ip
	if dstIP != nil {
		inst = append(inst, loadIPv4DestinationAddress) //(006)
		addrVal := binary.BigEndian.Uint32(dstIP[len(dstIP)-4:])
		inst = append(inst, bpf.JumpIf{Cond: bpf.JumpEqual, Val: addrVal, SkipTrue: 0, SkipFalse: size - uint8(len(inst)) - 2}) //(007) 18, 8
	}

	// ports
	var srcPort, dstPort uint16
	if packetSpec.TransportHeader.TCP != nil {
		if packetSpec.TransportHeader.TCP.SrcPort != nil {
			srcPort = uint16(*packetSpec.TransportHeader.TCP.SrcPort)
		}
		if packetSpec.TransportHeader.TCP.DstPort != nil {
			dstPort = uint16(*packetSpec.TransportHeader.TCP.DstPort)
		}
	} else if packetSpec.TransportHeader.UDP != nil {
		if packetSpec.TransportHeader.UDP.SrcPort != nil {
			srcPort = uint16(*packetSpec.TransportHeader.UDP.SrcPort)
		}
		if packetSpec.TransportHeader.UDP.DstPort != nil {
			dstPort = uint16(*packetSpec.TransportHeader.UDP.DstPort)
		}
	}

	if srcPort > 0 || dstPort > 0 {
		skipTrue := size - uint8(len(inst)) - 3
		inst = append(inst, loadIPv4HeaderOffset(skipTrue)...) //(008), (009), (010)
		if srcPort > 0 {
			inst = append(inst, loadIPv4SourcePort)                                                                                         //(011)
			inst = append(inst, bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(srcPort), SkipTrue: 0, SkipFalse: size - uint8(len(inst)) - 2}) //(012)
		}
		if dstPort > 0 {
			inst = append(inst, loadIPv4DestinationPort)                                                                                    //(013)
			inst = append(inst, bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(dstPort), SkipTrue: 0, SkipFalse: size - uint8(len(inst)) - 2}) //(014)
		}
	}

	if bidirection {
		// src ip (return traffic)
		if dstIP != nil {
			addrVal := binary.BigEndian.Uint32(dstIP[len(dstIP)-4:])
			inst = append(inst, bpf.JumpIf{Cond: bpf.JumpEqual, Val: addrVal, SkipTrue: 0, SkipFalse: size - uint8(len(inst)) - 2}) //(015)
		}

		// dst ip (return traffic)
		if srcIP != nil {
			inst = append(inst, loadIPv4SourceAddress) //(016)
			addrVal := binary.BigEndian.Uint32(srcIP[len(srcIP)-4:])
			inst = append(inst, bpf.JumpIf{Cond: bpf.JumpEqual, Val: addrVal, SkipTrue: 0, SkipFalse: size - uint8(len(inst)) - 2}) //(017)
		}

		if srcPort > 0 || dstPort > 0 {
			skipTrue := size - uint8(len(inst)) - 3
			inst = append(inst, loadIPv4HeaderOffset(skipTrue)...) //(018), (019), (020)
			if dstPort > 0 {
				inst = append(inst, loadIPv4SourcePort)                                                                                         //(021)
				inst = append(inst, bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(dstPort), SkipTrue: 0, SkipFalse: size - uint8(len(inst)) - 2}) //(022)
			}
			if srcPort > 0 {
				inst = append(inst, loadIPv4DestinationPort)                                                                                    //(023)
				inst = append(inst, bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(srcPort), SkipTrue: 0, SkipFalse: size - uint8(len(inst)) - 2}) //(024)
			}
		}
	}

	// return
	inst = append(inst, returnKeep) //(015), (025)
	inst = append(inst, returnDrop) //(016), (026)

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
// (009) jset     #0x1fff          jt 16	jf 10      # Use 0x1fff as a mask for fragment offset; If fragment offset != 0, #10, else #16
// (010) ldxb     4*([14]&0xf)                             # x = IP header length
// (011) ldh      [x + 14]                                 # Load 2B at x+14 (TCP Source Port)
// (012) jeq      #0x7b            jt 13	jf 16      # TCP Source Port: If 123, goto #13, else #16
// (013) ldh      [x + 16]                                 # Load 2B at x+16 (TCP dst port)
// (014) jeq      #0x7c            jt 15	jf 16      # TCP dst port: If 123, goto $15, else #16
// (015) ret      #262144                                  # MATCH
// (016) ret      #0                                       # NOMATCH

// When capturing return traffic also (i.e., both src -> dst and dst -> src), the filter might look like this:
// 'ip proto 6 and ((src host 10.244.1.2 and dst host 10.244.1.3 and src port 123 and dst port 124) or (src host 10.244.1.3 and dst host 10.244.1.2 and src port 124 and dst port 123))'
// And using `tcpdump -i <device> '<filter>' -d` will generate the following BPF instructions:
// (000) ldh      [12]									   # Load 2B at 12 (Ethertype)
// (001) jeq      #0x800           jt 2	jf 26			   # Ethertype: If IPv4, goto #2, else #26
// (002) ldb      [23]									   # Load 1B at 23 (IPv4 Protocol)
// (003) jeq      #0x6             jt 4	jf 26			   # IPv4 Protocol: If TCP, goto #4, #26
// (004) ld       [26]									   # Load 4B at 26 (source address)
// (005) jeq      #0xaf40102       jt 6	jf 15			   # If bytes match(10.244.0.2), goto #6, else #15
// (006) ld       [30]									   # Load 4B at 30 (dest address)
// (007) jeq      #0xaf40103       jt 8	jf 26			   # If bytes match(10.244.0.3), goto #8, else #26
// (008) ldh      [20]									   # Load 2B at 20 (13b Fragment Offset)
// (009) jset     #0x1fff          jt 26	jf 10	   # Use 0x1fff as a mask for fragment offset; If fragment offset != 0, #10, else #26
// (010) ldxb     4*([14]&0xf)							   # x = IP header length
// (011) ldh      [x + 14]								   # Load 2B at x+14 (TCP Source Port)
// (012) jeq      #0x7b            jt 13	jf 26	   # TCP Source Port: If 123, goto #13, else #26
// (013) ldh      [x + 16]								   # Load 2B at x+16 (TCP dst port)
// (014) jeq      #0x7c            jt 25	jf 26	   # TCP dst port: If 123, goto #25, else #26
// (015) jeq      #0xaf40103       jt 16	jf 26		   # If bytes match(10.244.0.3), goto #16, else #26
// (016) ld       [30]									   # Load 4B at 30 (return traffic dest address)
// (017) jeq      #0xaf40102       jt 18	jf 26		   # If bytes match(10.244.0.2), goto #18, else #26
// (018) ldh      [20]									   # Load 2B at 20 (13b Fragment Offset)
// (019) jset     #0x1fff          jt 26	jf 20	   # Use 0x1fff as a mask for fragment offset; If fragment offset != 0, #20, else #26
// (020) ldxb     4*([14]&0xf)							   # x = IP header length
// (021) ldh      [x + 14]								   # Load 2B at x+14 (TCP Source Port)
// (022) jeq      #0x7c            jt 23	jf 26	   # TCP Source Port: If 124, goto #23, else #26
// (023) ldh      [x + 16]								   # Load 2B at x+16 (TCP dst port)
// (024) jeq      #0x7b            jt 25	jf 26	   # TCP dst port: If 123, goto #25, else #26
// (025) ret      #262144								   # MATCH
// (026) ret      #0									   # NOMATCH

func calculateInstructionsSize(packet *crdv1alpha1.Packet, bidirection bool) int {
	count := 0
	// load ethertype
	count++
	// ip check
	count++

	if packet != nil {
		// protocol check
		if packet.Protocol != nil {
			count += 2
		}
		transPort := packet.TransportHeader
		if transPort.TCP != nil {
			// load Fragment Offset
			count += 3
			if transPort.TCP.SrcPort != nil {
				count += 2
			}
			if transPort.TCP.DstPort != nil {
				count += 2
			}

		} else if transPort.UDP != nil {
			count += 3
			if transPort.UDP.SrcPort != nil {
				count += 2
			}
			if transPort.UDP.DstPort != nil {
				count += 2
			}
		}
	}
	// src and dst ip
	count += 4

	if bidirection {
		count += 10
	}

	// ret command
	count += 2
	return count

}
