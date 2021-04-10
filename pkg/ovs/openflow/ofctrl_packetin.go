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
	"github.com/contiv/libOpenflow/protocol"
	"github.com/contiv/libOpenflow/util"
	"github.com/contiv/ofnet/ofctrl"
)

// GetTCPHeaderData gets TCP header data from IP packet.
func GetTCPHeaderData(ipPkt util.Message) (tcpSrcPort uint16, tcpDstPort uint16, tcpSeqNum uint32, tcpAckNum uint32, tcpFlags uint8, err error) {
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

func getUDPHeaderData(ipPkt util.Message) (udpSrcPort uint16, udpDstPort uint16, err error) {
	var udpBytes []byte

	switch typedIPPkt := ipPkt.(type) {
	case *protocol.IPv4:
		udpBytes, err = typedIPPkt.Data.(*util.Buffer).MarshalBinary()
	case *protocol.IPv6:
		udpBytes, err = typedIPPkt.Data.(*util.Buffer).MarshalBinary()
	}
	if err != nil {
		return 0, 0, err
	}
	udpIn := new(protocol.UDP)
	err = udpIn.UnmarshalBinary(udpBytes)
	if err != nil {
		return 0, 0, err
	}

	return udpIn.PortSrc, udpIn.PortDst, nil
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
		if err != nil {
			return nil, err
		}
	} else if packet.IPProto == protocol.Type_UDP {
		packet.SourcePort, packet.DestinationPort, err = getUDPHeaderData(pktIn.Data.Data)
		if err != nil {
			return nil, err
		}
	}
	return &packet, nil
}
