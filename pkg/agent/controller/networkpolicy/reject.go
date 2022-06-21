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

package networkpolicy

import (
	"encoding/binary"
	"fmt"

	"antrea.io/libOpenflow/protocol"
	"antrea.io/ofnet/ofctrl"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/openflow"
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

const (
	IPv4HdrLen uint16 = 20
	IPv6HdrLen uint16 = 40

	ICMPUnusedHdrLen uint16 = 4

	TCPAck uint8 = 0b010000
	TCPRst uint8 = 0b000100

	ICMPDstUnreachableType         uint8 = 3
	ICMPDstHostAdminProhibitedCode uint8 = 10

	ICMPv6DstUnreachableType     uint8 = 1
	ICMPv6DstAdminProhibitedCode uint8 = 1
)

type RejectType int

const (
	// RejectPodLocal represents this packetOut is used to reject Pod-to-Pod traffic
	// and for this response, the srcPod and the dstPod are on the same Node.
	RejectPodLocal RejectType = iota
	// RejectPodRemoteToLocal represents this packetOut is used to reject Pod-to-Pod
	// traffic and for this response, the srcPod is on a remote Node and the dstPod is
	// on the local Node.
	RejectPodRemoteToLocal
	// RejectLocalToRemote represents this packetOut is used to reject traffic and for
	// this response, the srcPod is on the local Node and the dstPod is on a remote Node.
	// While generating rejection from local to remote, there is no difference between
	// Service traffic and Pod traffic.
	RejectLocalToRemote
	// RejectServiceLocal represents this packetOut is used to reject Service traffic,
	// when AntreaProxy is enabled. The EndpointPod and the dstPod of the reject
	// response are on the same Node.
	RejectServiceLocal
	// RejectServiceRemoteToLocal represents this packetOut is used to reject Service
	// traffic, when AntreaProxy is enabled. The EndpointPod is on a remote Node and
	// the dstPod of the reject response is on the local Node.
	RejectServiceRemoteToLocal
	// RejectNoAPServiceLocal represents this packetOut is used to reject Service
	// traffic, when AntreaProxy is disabled. The EndpointPod and the dstPod of the
	// reject response are on the same Node.
	RejectNoAPServiceLocal
	// RejectNoAPServiceRemoteToLocal represents this packetOut is used to reject
	// Service traffic, when AntreaProxy is disabled. The EndpointPod is on a remote
	// Node and the dstPod of the reject response is on the local Node.
	RejectNoAPServiceRemoteToLocal
	// Unsupported indicates that Antrea couldn't generate packetOut for current
	// packetIn.
	Unsupported
)

// rejectRequest sends reject response to the requesting client, based on the
// packet-in message.
func (c *Controller) rejectRequest(pktIn *ofctrl.PacketIn) error {
	// Get ethernet data.
	srcMAC := pktIn.Data.HWDst.String()
	dstMAC := pktIn.Data.HWSrc.String()

	var (
		srcIP  string
		dstIP  string
		proto  uint8
		isIPv6 bool
	)
	switch ipPkt := pktIn.Data.Data.(type) {
	case *protocol.IPv4:
		// Get IP data.
		srcIP = ipPkt.NWDst.String()
		dstIP = ipPkt.NWSrc.String()
		proto = ipPkt.Protocol
		isIPv6 = false
	case *protocol.IPv6:
		// Get IP data.
		srcIP = ipPkt.NWDst.String()
		dstIP = ipPkt.NWSrc.String()
		proto = ipPkt.NextHeader
		isIPv6 = true
	}

	sIface, srcFound := c.ifaceStore.GetInterfaceByIP(srcIP)
	dIface, dstFound := c.ifaceStore.GetInterfaceByIP(dstIP)
	// isServiceTraffic checks if it's a Service traffic when the destination of the
	// reject response is on local Node. When the destination of the reject response is
	// remote, isServiceTraffic will always return false. Because there is no
	// difference between Service traffic and Pod-to-Pod traffic in this case. They all
	// belong to RejectLocalToRemote type and use the same logic to handle.
	// There are two situations in which it can be determined that this is a service
	// traffic:
	// 1. When AntreaProxy is enabled, EpSelectedRegMark is set in ServiceEPStateField.
	// 2. When AntreaProxy is disabled, dstIP of reject response is on the local Node
	//    and dstMAC of reject response is antrea-gw's MAC. In this case, the reject
	//    response is being generated for locally-originated traffic that went through
	//    kube-proxy and was re-injected into the bridge through antrea-gw.
	isServiceTraffic := func() bool {
		if c.antreaProxyEnabled {
			matches := pktIn.GetMatches()
			if match := getMatchRegField(matches, openflow.ServiceEPStateField); match != nil {
				svcEpstate, err := getInfoInReg(match, openflow.ServiceEPStateField.GetRange().ToNXRange())
				if err != nil {
					return false
				}
				return svcEpstate&openflow.EpSelectedRegMark.GetValue() == openflow.EpSelectedRegMark.GetValue()
			}
			return false
		}
		gwIfaces := c.ifaceStore.GetInterfacesByType(interfacestore.GatewayInterface)
		return dstFound && dstMAC == gwIfaces[0].MAC.String()
	}
	packetOutType := getRejectType(isServiceTraffic(), c.antreaProxyEnabled, srcFound, dstFound)
	if packetOutType == Unsupported {
		return fmt.Errorf("error when generating reject response for the packet from: %s to %s: neither source nor destination are on this Node", dstIP, srcIP)
	}
	// When in AntreaIPAM mode, even though srcPod and dstPod are on the same Node, MAC
	// will still be re-written in L3ForwardingTable. During rejection, the reject
	// response will be directly sent to the dst OF port without go through
	// L3ForwardingTable. So we need to re-write MAC here. There is no need to check
	// whether AntreaIPAM mode is enabled. Because if AntreaIPAM mode is disabled,
	// this re-write doesn't change anything.
	if packetOutType == RejectPodLocal {
		srcMAC = sIface.MAC.String()
		dstMAC = dIface.MAC.String()
	}
	inPort, outPort := getRejectOFPorts(packetOutType, sIface, dIface)
	mutateFunc := getRejectPacketOutMutateFunc(packetOutType)

	if proto == protocol.Type_TCP {
		// Get TCP data.
		oriTCPSrcPort, oriTCPDstPort, oriTCPSeqNum, _, _, err := binding.GetTCPHeaderData(pktIn.Data.Data)
		if err != nil {
			return err
		}
		// While sending TCP reject packet-out, switch original src/dst port,
		// set the ackNum as original seqNum+1 and set the flag as ack+rst.
		return c.ofClient.SendTCPPacketOut(
			srcMAC,
			dstMAC,
			srcIP,
			dstIP,
			inPort,
			outPort,
			isIPv6,
			oriTCPDstPort,
			oriTCPSrcPort,
			oriTCPSeqNum+1,
			TCPAck|TCPRst,
			mutateFunc)
	}
	// Use ICMP host administratively prohibited for ICMP, UDP, SCTP reject.
	icmpType := ICMPDstUnreachableType
	icmpCode := ICMPDstHostAdminProhibitedCode
	ipHdrLen := IPv4HdrLen
	if isIPv6 {
		icmpType = ICMPv6DstUnreachableType
		icmpCode = ICMPv6DstAdminProhibitedCode
		ipHdrLen = IPv6HdrLen
	}
	ipHdr, _ := pktIn.Data.Data.MarshalBinary()
	icmpData := make([]byte, int(ICMPUnusedHdrLen+ipHdrLen+8))
	// Put ICMP unused header in Data prop and set it to zero.
	binary.BigEndian.PutUint32(icmpData[:ICMPUnusedHdrLen], 0)
	copy(icmpData[ICMPUnusedHdrLen:], ipHdr[:ipHdrLen+8])
	return c.ofClient.SendICMPPacketOut(
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

// getRejectType returns RejectType of a rejection.
func getRejectType(isServiceTraffic, antreaProxyEnabled, srcIsLocal, dstIsLocal bool) RejectType {
	if !isServiceTraffic {
		if srcIsLocal {
			if dstIsLocal {
				return RejectPodLocal
			}
			return RejectLocalToRemote
		}
		if dstIsLocal {
			return RejectPodRemoteToLocal
		}
		return Unsupported
	}
	if !antreaProxyEnabled {
		if srcIsLocal {
			return RejectNoAPServiceLocal
		}
		if dstIsLocal {
			return RejectNoAPServiceRemoteToLocal
		}
		return Unsupported
	}
	if srcIsLocal {
		if dstIsLocal {
			return RejectServiceLocal
		}
		return RejectLocalToRemote
	}
	if dstIsLocal {
		return RejectServiceRemoteToLocal
	}
	return Unsupported
}

// getRejectOFPorts returns the inPort and outPort of a packetOut based on the RejectType.
func getRejectOFPorts(rejectType RejectType, sIface, dIface *interfacestore.InterfaceConfig) (uint32, uint32) {
	inPort := uint32(config.HostGatewayOFPort)
	outPort := uint32(0)
	switch rejectType {
	case RejectPodLocal:
		inPort = uint32(sIface.OFPort)
		outPort = uint32(dIface.OFPort)
	case RejectServiceLocal:
		inPort = uint32(sIface.OFPort)
	case RejectPodRemoteToLocal:
		inPort = config.HostGatewayOFPort
		outPort = uint32(dIface.OFPort)
	case RejectServiceRemoteToLocal:
		inPort = config.HostGatewayOFPort
	case RejectLocalToRemote:
		inPort = uint32(sIface.OFPort)
	case RejectNoAPServiceLocal:
		inPort = uint32(sIface.OFPort)
		outPort = config.HostGatewayOFPort
	case RejectNoAPServiceRemoteToLocal:
		inPort = config.DefaultTunOFPort
		outPort = config.HostGatewayOFPort
	}
	return inPort, outPort
}

// getRejectPacketOutMutateFunc returns the mutate func of a packetOut based on the RejectType.
func getRejectPacketOutMutateFunc(rejectType RejectType) func(binding.PacketOutBuilder) binding.PacketOutBuilder {
	var mutatePacketOut func(binding.PacketOutBuilder) binding.PacketOutBuilder
	switch rejectType {
	case RejectServiceLocal:
		tableID := openflow.ConntrackTable.GetID()
		mutatePacketOut = func(packetOutBuilder binding.PacketOutBuilder) binding.PacketOutBuilder {
			return packetOutBuilder.AddResubmitAction(nil, &tableID)
		}
	case RejectLocalToRemote:
		tableID := openflow.L3ForwardingTable.GetID()
		mutatePacketOut = func(packetOutBuilder binding.PacketOutBuilder) binding.PacketOutBuilder {
			return packetOutBuilder.AddResubmitAction(nil, &tableID)
		}
	}
	return mutatePacketOut
}
