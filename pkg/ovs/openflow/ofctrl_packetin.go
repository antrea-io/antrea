// Copyright 2021 Antrea Authors
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
	"errors"
	"fmt"

	"antrea.io/libOpenflow/protocol"
	"antrea.io/libOpenflow/util"
	"antrea.io/ofnet/ofctrl"
)

const (
	icmpEchoRequestType  uint8 = 8
	icmp6EchoRequestType uint8 = 128
	// tcpStandardHdrLen is the TCP header length without options.
	tcpStandardHdrLen uint8 = 5
)

func GetTCPHeaderData(ipPkt util.Message) (tcpSrcPort, tcpDstPort uint16, tcpSeqNum, tcpAckNum uint32, tcpHdrLen uint8, tcpFlags uint8, tcpWinSize uint16, err error) {
	tcpIn, err := GetTCPPacketFromIPMessage(ipPkt)
	if err != nil {
		return 0, 0, 0, 0, 0, 0, 0, err
	}
	return tcpIn.PortSrc, tcpIn.PortDst, tcpIn.SeqNum, tcpIn.AckNum, tcpIn.HdrLen, tcpIn.Code, tcpIn.WinSize, nil
}

// GetTCPPacketFromIPMessage gets a TCP struct from an IP message.
func GetTCPPacketFromIPMessage(ipPkt util.Message) (tcpPkt *protocol.TCP, err error) {
	var tcpBytes []byte

	// Transfer Buffer to TCP
	switch typedIPPkt := ipPkt.(type) {
	case *protocol.IPv4:
		tcpBytes, err = typedIPPkt.Data.(*util.Buffer).MarshalBinary()
	case *protocol.IPv6:
		tcpBytes, err = typedIPPkt.Data.(*util.Buffer).MarshalBinary()
	}
	if err != nil {
		return nil, err
	}
	tcpPkt = new(protocol.TCP)
	err = tcpPkt.UnmarshalBinary(tcpBytes)
	if err != nil {
		return nil, err
	}

	return tcpPkt, nil
}

func GetTCPDNSData(tcpPkt *protocol.TCP) (data []byte, length int, err error) {
	// TCP.HdrLen is 4-octet unit indicating the length of TCP header including options.
	tcpOptionsLen := (tcpPkt.HdrLen - tcpStandardHdrLen) * 4
	// Move two more octet.
	// From RFC 7766:
	// DNS clients and servers SHOULD pass the two-octet length field, and
	// the message described by that length field, to the TCP layer at the
	// same time (e.g., in a single "write" system call) to make it more
	// likely that all the data will be transmitted in a single TCP segment.
	if int(tcpOptionsLen+2) > len(tcpPkt.Data) {
		return nil, 0, fmt.Errorf("no DNS data in TCP data")
	}
	dnsDataLen := binary.BigEndian.Uint16(tcpPkt.Data[tcpOptionsLen : tcpOptionsLen+2])
	dnsData := tcpPkt.Data[tcpOptionsLen+2:]
	return dnsData, int(dnsDataLen), nil
}

func GetUDPHeaderData(ipPkt util.Message) (udpSrcPort, udpDstPort uint16, err error) {
	var udpIn *protocol.UDP
	switch typedIPPkt := ipPkt.(type) {
	case *protocol.IPv4:
		udpIn = typedIPPkt.Data.(*protocol.UDP)
	case *protocol.IPv6:
		udpIn = typedIPPkt.Data.(*protocol.UDP)
	}
	return udpIn.PortSrc, udpIn.PortDst, nil
}

func getICMPHeaderData(ipPkt util.Message) (icmpType, icmpCode uint8, icmpEchoID, icmpEchoSeq uint16, err error) {
	switch typedIPPkt := ipPkt.(type) {
	case *protocol.IPv4:
		icmpIn := typedIPPkt.Data.(*protocol.ICMP)
		if icmpIn.Type == icmpEchoRequestType {
			if len(icmpIn.Data) < 4 {
				return 0, 0, 0, 0, errors.New("ICMP payload is too short to unmarshal an ICMP echo message")
			}
			icmpEchoID = binary.BigEndian.Uint16(icmpIn.Data[:2])
			icmpEchoSeq = binary.BigEndian.Uint16(icmpIn.Data[2:4])
		}
		icmpType = icmpIn.Type
		icmpCode = icmpIn.Code
	case *protocol.IPv6:
		icmpIn := typedIPPkt.Data.(*protocol.ICMPv6EchoReqRpl)
		if icmpIn.Type == icmp6EchoRequestType {
			icmpEchoID = icmpIn.Identifier
			icmpEchoSeq = icmpIn.SeqNum
		}
		icmpType = icmpIn.Type
		icmpCode = icmpIn.Code
	}

	return icmpType, icmpCode, icmpEchoID, icmpEchoSeq, nil
}

func ParsePacketIn(pktIn *ofctrl.PacketIn) (*Packet, error) {
	packet := Packet{}
	ethernetData := new(protocol.Ethernet)
	if err := ethernetData.UnmarshalBinary(pktIn.Data.(*util.Buffer).Bytes()); err != nil {
		return nil, err
	}
	packet.DestinationMAC = ethernetData.HWDst
	packet.SourceMAC = ethernetData.HWSrc

	if ethernetData.Ethertype == protocol.IPv4_MSG {
		ipPkt := ethernetData.Data.(*protocol.IPv4)
		packet.DestinationIP = ipPkt.NWDst
		packet.SourceIP = ipPkt.NWSrc
		packet.TTL = ipPkt.TTL
		packet.IPProto = ipPkt.Protocol
		packet.IPFlags = ipPkt.Flags
		packet.IPLength = ipPkt.Length
	} else if ethernetData.Ethertype == protocol.IPv6_MSG {
		ipPkt := ethernetData.Data.(*protocol.IPv6)
		packet.DestinationIP = ipPkt.NWDst
		packet.SourceIP = ipPkt.NWSrc
		packet.TTL = ipPkt.HopLimit
		packet.IPProto = ipPkt.NextHeader
		// IPv6 header includes only playload length. Add 40 to count in
		// the IPv6 header length.
		packet.IPLength = ipPkt.Length + 40
		packet.IsIPv6 = true
	} else {
		// Not an IP packet.
		return &packet, nil
	}

	var err error
	if packet.IPProto == protocol.Type_TCP {
		packet.SourcePort, packet.DestinationPort, _, _, _, packet.TCPFlags, _, err = GetTCPHeaderData(ethernetData.Data)
	} else if packet.IPProto == protocol.Type_UDP {
		packet.SourcePort, packet.DestinationPort, err = GetUDPHeaderData(ethernetData.Data)
	} else if packet.IPProto == protocol.Type_ICMP || packet.IPProto == protocol.Type_IPv6ICMP {
		_, _, packet.ICMPEchoID, packet.ICMPEchoSeq, err = getICMPHeaderData(ethernetData.Data)
	}
	if err != nil {
		return nil, err
	}
	return &packet, nil
}
