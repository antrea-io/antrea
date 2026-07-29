// Copyright 2023 Antrea Authors
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

	"antrea.io/libOpenflow/protocol"

	binding "antrea.io/antrea/v2/pkg/ovs/openflow"
)

const (
	ipv4HdrLen uint16 = 20
	ipv6HdrLen uint16 = 40

	icmpUnusedHdrLen uint16 = 4

	tcpAck uint8 = 0b010000
	tcpRst uint8 = 0b000100

	icmpDstUnreachableType         uint8 = 3
	icmpDstHostAdminProhibitedCode uint8 = 10

	icmpv6DstUnreachableType     uint8 = 1
	icmpv6DstAdminProhibitedCode uint8 = 1
)

func SendRejectPacketOut(ofClient Client,
	srcMAC string,
	dstMAC string,
	srcIP string,
	dstIP string,
	inPort uint32,
	outPort uint32,
	isIPv6 bool,
	ethernetPkt *protocol.Ethernet,
	proto uint8,
	mutateFunc func(binding.PacketOutBuilder) binding.PacketOutBuilder) error {
	if proto == protocol.Type_TCP {
		// Get TCP data.
		oriTCPSrcPort, oriTCPDstPort, oriTCPSeqNum, _, _, _, _, err := binding.GetTCPHeaderData(ethernetPkt.Data)
		if err != nil {
			return err
		}
		// While sending TCP reject packet-out, switch original src/dst port,
		// set the ackNum as original seqNum+1 and set the flag as ack+rst.
		return ofClient.SendTCPPacketOut(
			srcMAC,
			dstMAC,
			srcIP,
			dstIP,
			inPort,
			outPort,
			isIPv6,
			oriTCPDstPort,
			oriTCPSrcPort,
			0,
			oriTCPSeqNum+1,
			0,
			tcpAck|tcpRst,
			0,
			nil,
			mutateFunc)
	}
	// Use ICMP host administratively prohibited for ICMP, UDP, SCTP reject.
	icmpType := icmpDstUnreachableType
	icmpCode := icmpDstHostAdminProhibitedCode
	ipHdrLen := ipv4HdrLen
	if isIPv6 {
		icmpType = icmpv6DstUnreachableType
		icmpCode = icmpv6DstAdminProhibitedCode
		ipHdrLen = ipv6HdrLen
	}
	ipHdr, err := ethernetPkt.Data.MarshalBinary()
	if err != nil {
		return err
	}
	// As per RFC 792, an ICMP Destination Unreachable message includes a copy of the IP header
	// of the original datagram, plus its first 64 bits (8 bytes), which is enough for the
	// receiver to identify the transport ports and match the error to a connection. The length
	// is bounded by the marshaled packet length, so that a short non-TCP packet (e.g. IPv6
	// NextHeader=59 with no payload) cannot trigger a slice-bounds panic.
	origPacketCopyLen := min(int(ipHdrLen)+8, len(ipHdr))
	icmpData := make([]byte, int(icmpUnusedHdrLen)+origPacketCopyLen)
	// Put ICMP unused header in Data prop and set it to zero.
	binary.BigEndian.PutUint32(icmpData[:icmpUnusedHdrLen], 0)
	copy(icmpData[icmpUnusedHdrLen:], ipHdr[:origPacketCopyLen])
	return ofClient.SendICMPPacketOut(
		srcMAC,
		dstMAC,
		srcIP,
		dstIP,
		inPort,
		outPort,
		isIPv6,
		icmpType,
		icmpCode,
		icmpData,
		mutateFunc)
}
