// Copyright 2020 Antrea Authors
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

package openflow

import (
	"encoding/binary"
	"math/rand"
	"net"

	"antrea.io/libOpenflow/protocol"
	"antrea.io/ofnet/ofctrl"
	"k8s.io/klog/v2"
)

type ofPacketOutBuilder struct {
	pktOut  *ofctrl.PacketOut
	icmpID  *uint16
	icmpSeq *uint16
}

// SetSrcMAC sets the packet's source MAC with the provided value.
func (b *ofPacketOutBuilder) SetSrcMAC(mac net.HardwareAddr) PacketOutBuilder {
	b.pktOut.SrcMAC = mac
	return b
}

// SetDstMAC sets the packet's destination MAC with the provided value.
func (b *ofPacketOutBuilder) SetDstMAC(mac net.HardwareAddr) PacketOutBuilder {
	b.pktOut.DstMAC = mac
	return b
}

// SetSrcIP sets the packet's source IP with the provided value.
func (b *ofPacketOutBuilder) SetSrcIP(ip net.IP) PacketOutBuilder {
	if ip.To4() != nil {
		if b.pktOut.IPHeader == nil {
			b.pktOut.IPHeader = new(protocol.IPv4)
		}
		b.pktOut.IPHeader.NWSrc = ip
	} else {
		if b.pktOut.IPv6Header == nil {
			b.pktOut.IPv6Header = new(protocol.IPv6)
		}
		b.pktOut.IPv6Header.NWSrc = ip
	}
	return b
}

// SetDstIP sets the packet's destination IP with the provided value.
func (b *ofPacketOutBuilder) SetDstIP(ip net.IP) PacketOutBuilder {
	if ip.To4() != nil {
		if b.pktOut.IPHeader == nil {
			b.pktOut.IPHeader = new(protocol.IPv4)
		}
		b.pktOut.IPHeader.NWDst = ip
	} else {
		if b.pktOut.IPv6Header == nil {
			b.pktOut.IPv6Header = new(protocol.IPv6)
		}
		b.pktOut.IPv6Header.NWDst = ip
	}
	return b
}

// SetIPProtocol sets IP protocol in the packet's IP header.
func (b *ofPacketOutBuilder) SetIPProtocol(proto Protocol) PacketOutBuilder {
	switch proto {
	case ProtocolTCPv6, ProtocolUDPv6, ProtocolSCTPv6, ProtocolICMPv6:
		if b.pktOut.IPv6Header == nil {
			b.pktOut.IPv6Header = new(protocol.IPv6)
		}
	default:
		if b.pktOut.IPHeader == nil {
			b.pktOut.IPHeader = new(protocol.IPv4)
		}
	}
	switch proto {
	case ProtocolTCPv6:
		b.pktOut.IPv6Header.NextHeader = protocol.Type_TCP
	case ProtocolUDPv6:
		b.pktOut.IPv6Header.NextHeader = protocol.Type_UDP
	case ProtocolSCTPv6:
		b.pktOut.IPv6Header.NextHeader = 0x84
	case ProtocolICMPv6:
		b.pktOut.IPv6Header.NextHeader = protocol.Type_IPv6ICMP
	case ProtocolTCP:
		b.pktOut.IPHeader.Protocol = protocol.Type_TCP
	case ProtocolUDP:
		b.pktOut.IPHeader.Protocol = protocol.Type_UDP
	case ProtocolSCTP:
		b.pktOut.IPHeader.Protocol = 0x84
	case ProtocolICMP:
		b.pktOut.IPHeader.Protocol = protocol.Type_ICMP
	default:
		b.pktOut.IPHeader.Protocol = 0xff
	}
	return b
}

// ofPacketOutBuilder sets IP protocol in the packet's IP header with the
// intetger protocol value.
func (b *ofPacketOutBuilder) SetIPProtocolValue(isIPv6 bool, protoValue uint8) PacketOutBuilder {
	if isIPv6 {
		if b.pktOut.IPv6Header == nil {
			b.pktOut.IPv6Header = new(protocol.IPv6)
		}
		b.pktOut.IPv6Header.NextHeader = protoValue
	} else {
		if b.pktOut.IPHeader == nil {
			b.pktOut.IPHeader = new(protocol.IPv4)
		}
		b.pktOut.IPHeader.Protocol = protoValue
	}
	return b
}

// SetTTL sets TTL in the packet's IP header.
func (b *ofPacketOutBuilder) SetTTL(ttl uint8) PacketOutBuilder {
	if b.pktOut.IPv6Header == nil {
		if b.pktOut.IPHeader == nil {
			b.pktOut.IPHeader = new(protocol.IPv4)
		}
		b.pktOut.IPHeader.TTL = ttl
	} else {
		b.pktOut.IPv6Header.HopLimit = ttl
	}
	return b
}

// SetIPFlags sets flags in the packet's IP header. IPv4 only.
func (b *ofPacketOutBuilder) SetIPFlags(flags uint16) PacketOutBuilder {
	if b.pktOut.IPv6Header == nil {
		if b.pktOut.IPHeader == nil {
			b.pktOut.IPHeader = new(protocol.IPv4)
		}
		b.pktOut.IPHeader.Flags = flags
	}
	return b
}

// SetTCPSrcPort sets the source port in the packet's TCP header.
func (b *ofPacketOutBuilder) SetTCPSrcPort(port uint16) PacketOutBuilder {
	if b.pktOut.TCPHeader == nil {
		b.pktOut.TCPHeader = new(protocol.TCP)
	}
	b.pktOut.TCPHeader.PortSrc = port
	return b
}

// SetTCPDstPort sets the destination port in the packet's TCP header.
func (b *ofPacketOutBuilder) SetTCPDstPort(port uint16) PacketOutBuilder {
	if b.pktOut.TCPHeader == nil {
		b.pktOut.TCPHeader = new(protocol.TCP)
	}
	b.pktOut.TCPHeader.PortDst = port
	return b
}

// SetTCPFlags sets the flags in the packet's TCP header.
func (b *ofPacketOutBuilder) SetTCPFlags(flags uint8) PacketOutBuilder {
	if b.pktOut.TCPHeader == nil {
		b.pktOut.TCPHeader = new(protocol.TCP)
	}
	b.pktOut.TCPHeader.Code = flags
	return b
}
func (b *ofPacketOutBuilder) SetTCPSeqNum(seqNum uint32) PacketOutBuilder {
	if b.pktOut.TCPHeader == nil {
		b.pktOut.TCPHeader = new(protocol.TCP)
	}
	b.pktOut.TCPHeader.SeqNum = seqNum
	return b
}

func (b *ofPacketOutBuilder) SetTCPAckNum(ackNum uint32) PacketOutBuilder {
	if b.pktOut.TCPHeader == nil {
		b.pktOut.TCPHeader = new(protocol.TCP)
	}
	b.pktOut.TCPHeader.AckNum = ackNum
	return b
}

// SetUDPSrcPort sets the source port in the packet's UDP header.
func (b *ofPacketOutBuilder) SetUDPSrcPort(port uint16) PacketOutBuilder {
	if b.pktOut.UDPHeader == nil {
		b.pktOut.UDPHeader = new(protocol.UDP)
	}
	b.pktOut.UDPHeader.PortSrc = port
	return b
}

// SetUDPDstPort sets the destination port in the packet's UDP header.
func (b *ofPacketOutBuilder) SetUDPDstPort(port uint16) PacketOutBuilder {
	if b.pktOut.UDPHeader == nil {
		b.pktOut.UDPHeader = new(protocol.UDP)
	}
	b.pktOut.UDPHeader.PortDst = port
	return b
}

// SetICMPType sets the type in the packet's ICMP header.
func (b *ofPacketOutBuilder) SetICMPType(icmpType uint8) PacketOutBuilder {
	if b.pktOut.ICMPHeader == nil {
		b.pktOut.ICMPHeader = new(protocol.ICMP)
	}
	b.pktOut.ICMPHeader.Type = icmpType
	return b
}

// SetICMPCode sets the code in the packet's ICMP header.
func (b *ofPacketOutBuilder) SetICMPCode(icmpCode uint8) PacketOutBuilder {
	if b.pktOut.ICMPHeader == nil {
		b.pktOut.ICMPHeader = new(protocol.ICMP)
	}
	b.pktOut.ICMPHeader.Code = icmpCode
	return b
}

// SetICMs sets the identifier in the packet's ICMP header.
func (b *ofPacketOutBuilder) SetICMPID(id uint16) PacketOutBuilder {
	if b.pktOut.ICMPHeader == nil {
		b.pktOut.ICMPHeader = new(protocol.ICMP)
	}
	b.icmpID = &id
	return b
}

//SetICMPSequence sets the sequence number in the packet's ICMP header.
func (b *ofPacketOutBuilder) SetICMPSequence(seq uint16) PacketOutBuilder {
	if b.pktOut.ICMPHeader == nil {
		b.pktOut.ICMPHeader = new(protocol.ICMP)
	}
	b.icmpSeq = &seq
	return b
}

func (b *ofPacketOutBuilder) SetICMPData(data []byte) PacketOutBuilder {
	if b.pktOut.ICMPHeader == nil {
		b.pktOut.ICMPHeader = new(protocol.ICMP)
	}
	b.pktOut.ICMPHeader.Data = data
	return b
}

// SetInport sets the in_port field of the packetOut message.
func (b *ofPacketOutBuilder) SetInport(inPort uint32) PacketOutBuilder {
	b.pktOut.InPort = inPort
	return b
}

// SetOutport sets the output port of the packetOut message. If the message is expected to go through OVS pipeline
// from table0, use openflow13.P_TABLE, which is also the default value.
func (b *ofPacketOutBuilder) SetOutport(outport uint32) PacketOutBuilder {
	b.pktOut.OutPort = outport
	return b
}

// AddLoadAction loads the data to the target field at specified range when the packet is received by OVS Switch.
func (b *ofPacketOutBuilder) AddLoadAction(name string, data uint64, rng *Range) PacketOutBuilder {
	act, _ := ofctrl.NewNXLoadAction(name, data, rng.ToNXRange())
	b.pktOut.Actions = append(b.pktOut.Actions, act)
	return b
}

func (b *ofPacketOutBuilder) AddLoadRegMark(mark *RegMark) PacketOutBuilder {
	name := mark.field.GetNXFieldName()
	return b.AddLoadAction(name, uint64(mark.value), mark.field.rng)
}

func (b *ofPacketOutBuilder) Done() *ofctrl.PacketOut {
	if b.pktOut.IPHeader != nil && b.pktOut.IPv6Header != nil {
		klog.Errorf("Invalid PacketOutBuilder: IP header and IPv6 header are not allowed to exist at the same time")
		return nil
	}
	if b.pktOut.IPv6Header == nil {
		if b.pktOut.ICMPHeader != nil {
			if len(b.pktOut.ICMPHeader.Data) == 0 {
				b.setICMPData()
			}
			b.pktOut.ICMPHeader.Checksum = b.icmpHeaderChecksum()
			b.pktOut.IPHeader.Length = 20 + b.pktOut.ICMPHeader.Len()
		} else if b.pktOut.TCPHeader != nil {
			b.pktOut.TCPHeader.HdrLen = 5
			// #nosec G404: random number generator not used for security purposes
			b.pktOut.TCPHeader.SeqNum = rand.Uint32()
			if b.pktOut.TCPHeader.AckNum == 0 {
				// #nosec G404: random number generator not used for security purposes
				b.pktOut.TCPHeader.AckNum = rand.Uint32()
			}
			b.pktOut.TCPHeader.Checksum = b.tcpHeaderChecksum()
			b.pktOut.IPHeader.Length = 20 + b.pktOut.TCPHeader.Len()
		} else if b.pktOut.UDPHeader != nil {
			b.pktOut.UDPHeader.Length = b.pktOut.UDPHeader.Len()
			b.pktOut.UDPHeader.Checksum = b.udpHeaderChecksum()
			b.pktOut.IPHeader.Length = 20 + b.pktOut.UDPHeader.Len()
		}
		// #nosec G404: random number generator not used for security purposes
		b.pktOut.IPHeader.Id = uint16(rand.Uint32())
		// Set IP version in the IP Header.
		b.pktOut.IPHeader.Version = 0x4
		b.pktOut.IPHeader.Checksum = b.ipHeaderChecksum()
	} else {
		if b.pktOut.ICMPHeader != nil {
			if len(b.pktOut.ICMPHeader.Data) == 0 {
				b.setICMPData()
			}
			b.pktOut.ICMPHeader.Checksum = b.icmpHeaderChecksum()
			b.pktOut.IPv6Header.Length = b.pktOut.ICMPHeader.Len()
		} else if b.pktOut.TCPHeader != nil {
			b.pktOut.TCPHeader.HdrLen = 5
			// #nosec G404: random number generator not used for security purposes
			b.pktOut.TCPHeader.SeqNum = rand.Uint32()
			if b.pktOut.TCPHeader.AckNum == 0 {
				// #nosec G404: random number generator not used for security purposes
				b.pktOut.TCPHeader.AckNum = rand.Uint32()
			}
			b.pktOut.TCPHeader.Checksum = b.tcpHeaderChecksum()
			b.pktOut.IPv6Header.Length = b.pktOut.TCPHeader.Len()
		} else if b.pktOut.UDPHeader != nil {
			b.pktOut.UDPHeader.Length = b.pktOut.UDPHeader.Len()
			b.pktOut.UDPHeader.Checksum = b.udpHeaderChecksum()
			b.pktOut.IPv6Header.Length = b.pktOut.UDPHeader.Len()
		}
		// Set IPv6 version in the IP Header.
		b.pktOut.IPv6Header.Version = 0x6
	}
	return b.pktOut
}

func (b *ofPacketOutBuilder) setICMPData() {
	data := make([]byte, 4)
	if b.icmpID != nil {
		binary.BigEndian.PutUint16(data, *b.icmpID)
	}
	if b.icmpSeq != nil {
		binary.BigEndian.PutUint16(data[2:], *b.icmpSeq)
	}
	b.pktOut.ICMPHeader.Data = data
}

func (b *ofPacketOutBuilder) ipHeaderChecksum() uint16 {
	ipHeader := *b.pktOut.IPHeader
	ipHeader.Checksum = 0
	ipHeader.Data = nil
	data, _ := ipHeader.MarshalBinary()
	return checksum(data)
}

func (b *ofPacketOutBuilder) icmpHeaderChecksum() uint16 {
	icmpHeader := *b.pktOut.ICMPHeader
	icmpHeader.Checksum = 0
	data, _ := icmpHeader.MarshalBinary()
	checksumData := data
	if b.pktOut.IPv6Header != nil {
		checksumData = append(b.generatePseudoHeader(uint16(len(data))), data...)
	}
	return checksum(checksumData)
}

func (b *ofPacketOutBuilder) tcpHeaderChecksum() uint16 {
	tcpHeader := *b.pktOut.TCPHeader
	tcpHeader.Checksum = 0
	data, _ := tcpHeader.MarshalBinary()
	checksumData := append(b.generatePseudoHeader(uint16(len(data))), data...)
	return checksum(checksumData)
}

func (b *ofPacketOutBuilder) udpHeaderChecksum() uint16 {
	udpHeader := *b.pktOut.UDPHeader
	udpHeader.Checksum = 0
	data, _ := udpHeader.MarshalBinary()
	checksumData := append(b.generatePseudoHeader(uint16(len(data))), data...)
	checksum := checksum(checksumData)
	// From RFC 768:
	// If the computed checksum is zero, it is transmitted as all ones (the
	// equivalent in one's complement arithmetic). An all zero transmitted
	// checksum value means that the transmitter generated no checksum (for
	// debugging or for higher level protocols that don't care).
	if checksum == 0 {
		checksum = 0xffff
	}
	return checksum
}

func (b *ofPacketOutBuilder) generatePseudoHeader(length uint16) []byte {
	var pseudoHeader []byte
	if b.pktOut.IPv6Header == nil {
		pseudoHeader = make([]byte, 12)
		copy(pseudoHeader[0:4], b.pktOut.IPHeader.NWSrc.To4())
		copy(pseudoHeader[4:8], b.pktOut.IPHeader.NWDst.To4())
		pseudoHeader[8] = 0x0
		pseudoHeader[9] = b.pktOut.IPHeader.Protocol
		binary.BigEndian.PutUint16(pseudoHeader[10:12], length)
	} else {
		pseudoHeader = make([]byte, 40)
		copy(pseudoHeader[0:16], b.pktOut.IPv6Header.NWSrc.To16())
		copy(pseudoHeader[16:32], b.pktOut.IPv6Header.NWDst.To16())
		binary.BigEndian.PutUint32(pseudoHeader[32:36], uint32(length))
		pseudoHeader[36] = 0x0
		pseudoHeader[37] = 0x0
		pseudoHeader[38] = 0x0
		pseudoHeader[39] = b.pktOut.IPv6Header.NextHeader
	}
	return pseudoHeader
}

func checksum(data []byte) uint16 {
	sum := uint32(0)
	for ; len(data) >= 2; data = data[2:] {
		sum += uint32(data[0])<<8 | uint32(data[1])
	}
	if len(data) > 0 {
		sum += uint32(data[0]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}
