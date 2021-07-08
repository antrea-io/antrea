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

	"antrea.io/libOpenflow/protocol"
	"antrea.io/libOpenflow/util"
	"antrea.io/ofnet/ofctrl"
)

const (
	icmpEchoRequestType  uint8 = 8
	icmp6EchoRequestType uint8 = 128
)

// GetTCPHeaderData gets TCP header data from IP packet.
func GetTCPHeaderData(ipPkt util.Message) (tcpSrcPort, tcpDstPort uint16, tcpSeqNum, tcpAckNum uint32, tcpFlags uint8, err error) {
	var tcpBytes []byte

	// Transfer Buffer to TCP
	switch typedIPPkt := ipPkt.(type) {
	case *protocol.IPv4:
		tcpBytes, err = typedIPPkt.Data.(*util.Buffer).MarshalBinary()
	case *protocol.IPv6:
		tcpBytes, err = typedIPPkt.Data.(*util.Buffer).MarshalBinary()
	}
	if err != nil {
		return 0, 0, 0, 0, 0, err
	}
	tcpIn := new(protocol.TCP)
	err = tcpIn.UnmarshalBinary(tcpBytes)
	if err != nil {
		return 0, 0, 0, 0, 0, err
	}

	return tcpIn.PortSrc, tcpIn.PortDst, tcpIn.SeqNum, tcpIn.AckNum, tcpIn.Code, nil
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
	var icmpIn *protocol.ICMP
	switch typedIPPkt := ipPkt.(type) {
	case *protocol.IPv4:
		icmpIn = typedIPPkt.Data.(*protocol.ICMP)
	case *protocol.IPv6:
		icmpIn = typedIPPkt.Data.(*protocol.ICMP)
	}

	if icmpIn.Type == icmpEchoRequestType || icmpIn.Type == icmp6EchoRequestType {
		if len(icmpIn.Data) < 4 {
			return 0, 0, 0, 0, errors.New("ICMP payload is too short to unmarshal an ICMP echo message")
		}
		icmpEchoID = binary.BigEndian.Uint16(icmpIn.Data[:2])
		icmpEchoSeq = binary.BigEndian.Uint16(icmpIn.Data[2:4])
	}
	return icmpIn.Type, icmpIn.Code, icmpEchoID, icmpEchoSeq, nil
}

func ParsePacketIn(pktIn *ofctrl.PacketIn) (*Packet, error) {
	packet := Packet{}
	packet.DestinationMAC = pktIn.Data.HWDst
	packet.SourceMAC = pktIn.Data.HWSrc

	if pktIn.Data.Ethertype == protocol.IPv4_MSG {
		ipPkt := pktIn.Data.Data.(*protocol.IPv4)
		packet.DestinationIP = ipPkt.NWDst
		packet.SourceIP = ipPkt.NWSrc
		packet.TTL = ipPkt.TTL
		packet.IPProto = ipPkt.Protocol
		packet.IPFlags = ipPkt.Flags
		packet.IPLength = ipPkt.Length
	} else if pktIn.Data.Ethertype == protocol.IPv6_MSG {
		ipPkt := pktIn.Data.Data.(*protocol.IPv6)
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
		packet.SourcePort, packet.DestinationPort, _, _, packet.TCPFlags, err = GetTCPHeaderData(pktIn.Data.Data)
	} else if packet.IPProto == protocol.Type_UDP {
		packet.SourcePort, packet.DestinationPort, err = GetUDPHeaderData(pktIn.Data.Data)
	} else if packet.IPProto == protocol.Type_ICMP || packet.IPProto == protocol.Type_IPv6ICMP {
		_, _, packet.ICMPEchoID, packet.ICMPEchoSeq, err = getICMPHeaderData(pktIn.Data.Data)
	}
	if err != nil {
		return nil, err
	}
	return &packet, nil
}
