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
	"fmt"
	"net"

	"antrea.io/libOpenflow/protocol"
	"antrea.io/ofnet/ofctrl"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/openflow"
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

type rejectType int

const (
	// rejectPodLocal represents this packetOut is used to reject Pod-to-Pod traffic
	// and for this response, the srcPod and the dstPod are on the same Node.
	rejectPodLocal rejectType = iota
	// rejectPodRemoteToLocal represents this packetOut is used to reject Pod-to-Pod
	// traffic and for this response, the srcPod is on a remote Node and the dstPod is
	// on the local Node.
	rejectPodRemoteToLocal
	// rejectPodLocalToRemote represents this packetOut is used to reject Pod-to-Pod
	// traffic and for this response, the srcPod is on the local Node and the dstPod is
	// on a remote Node.
	rejectPodLocalToRemote
	// rejectServiceLocal represents this packetOut is used to reject Service traffic,
	// when AntreaProxy is enabled. The EndpointPod and the dstPod of the reject
	// response are on the same Node.
	rejectServiceLocal
	// rejectServiceRemoteToLocal represents this packetOut is used to reject Service
	// traffic, when AntreaProxy is enabled. The EndpointPod is on a remote Node and
	// the dstPod of the reject response is on the local Node.
	rejectServiceRemoteToLocal
	// rejectServiceLocalToRemote represents this packetOut is used to reject Service
	// traffic, when AntreaProxy is enabled. The EndpointPod is on the local Node and
	// the dstPod of the reject response is on a remote Node.
	rejectServiceLocalToRemote
	// rejectNoAPServiceLocal represents this packetOut is used to reject Service
	// traffic, when AntreaProxy is disabled. The EndpointPod and the dstPod of the
	// reject response are on the same Node.
	rejectNoAPServiceLocal
	// rejectNoAPServiceRemoteToLocal represents this packetOut is used to reject
	// Service traffic, when AntreaProxy is disabled. The EndpointPod is on a remote
	// Node and the dstPod of the reject response is on the local Node.
	rejectNoAPServiceRemoteToLocal
	// rejectServiceRemoteToExternal represents this packetOut is used to reject
	// Service traffic, when AntreaProxy is enabled. The EndpointPod is on a remote
	// Node and the destination of the reject response is an external client.
	rejectServiceRemoteToExternal
	// unsupported indicates that Antrea couldn't generate packetOut for current
	// packetIn.
	unsupported
)

// rejectRequest sends reject response to the requesting client, based on the
// packet-in message.
func (c *Controller) rejectRequest(pktIn *ofctrl.PacketIn) error {
	// All src/dst mean the source/destination of the reject packet, which are destination/source of the incoming packet.
	// Get ethernet data.
	ethernetPkt, err := openflow.GetEthernetPacket(pktIn)
	if err != nil {
		return err
	}
	srcMAC := ethernetPkt.HWDst.String()
	dstMAC := ethernetPkt.HWSrc.String()

	var (
		srcIP  string
		dstIP  string
		proto  uint8
		isIPv6 bool
	)
	switch ipPkt := ethernetPkt.Data.(type) {
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

	sIface, srcIsLocal := c.ifaceStore.GetInterfaceByIP(srcIP)
	dIface, dstIsLocal := c.ifaceStore.GetInterfaceByIP(dstIP)
	// dstIsDirect means that the reject packet destination is on the same Node and the reject packet can be forwarded
	// without leaving the OVS bridge.
	dstIsDirect := dstIsLocal
	matches := pktIn.GetMatches()
	if c.antreaProxyEnabled && dstIsLocal {
		// Check if OVS InPort matches dIface.
		// If port doesn't match, set dstIsDirect to false since the reject packet destination should not be sent to
		// local Pod directly.
		if match := matches.GetMatchByName(binding.OxmFieldInPort); match != nil {
			dstIsDirect = match.GetValue().(uint32) == uint32(dIface.OFPort)
		}
	}
	isFlexibleIPAMSrc, isFlexibleIPAMDst, ctZone, err := parseFlexibleIPAMStatus(pktIn, c.nodeConfig, srcIP, srcIsLocal, dstIP, dstIsLocal)
	if err != nil {
		return err
	}

	// isServiceTraffic checks if it's a Service traffic when the destination of the
	// reject response is on local Node. When the destination of the reject response is
	// remote, isServiceTraffic will always return false. Because there is no
	// difference between Service traffic and Pod-to-Pod traffic in this case. They all
	// belong to RejectLocalToRemote type and use the same logic to handle.
	// There are two situations in which it can be determined that this is a service
	// traffic:
	// 1. When AntreaProxy is enabled, EpSelectedRegMark is set in ServiceEPStateField.
	//    AntreaProxy is required for FlexibleIPAM feature.
	// 2. When AntreaProxy is disabled, dstIP of reject response is on the local Node
	//    and dstMAC of reject response is antrea-gw's MAC. In this case, the reject
	//    response is being generated for locally-originated traffic that went through
	//    kube-proxy and was re-injected into the bridge through antrea-gw.
	isServiceTraffic := func() bool {
		if c.nodeType == config.ExternalNode {
			return false
		}
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
		return dstIsLocal && dstMAC == gwIfaces[0].MAC.String()
	}
	packetOutType := getRejectType(isServiceTraffic(), c.antreaProxyEnabled, srcIsLocal, dstIsDirect)
	if packetOutType == unsupported {
		return fmt.Errorf("error when generating reject response for the packet from: %s to %s: neither source nor destination are on this Node", dstIP, srcIP)
	}
	if packetOutType == rejectServiceRemoteToExternal {
		dstMAC = openflow.GlobalVirtualMAC.String()
	}
	// When in AntreaIPAM mode, even though srcPod and dstPod are on the same Node, MAC
	// will still be re-written in L3ForwardingTable. During rejection, the reject
	// response will be directly sent to the dst OF port without go through
	// L3ForwardingTable. So we need to re-write MAC here. There is no need to check
	// whether AntreaIPAM mode is enabled. Because if AntreaIPAM mode is disabled,
	// this re-write doesn't change anything.
	if packetOutType == rejectPodLocal {
		srcMAC = sIface.MAC.String()
		dstMAC = dIface.MAC.String()
	}

	inPort, outPort := getRejectOFPorts(packetOutType, sIface, dIface, c.gwPort, c.tunPort)
	mutateFunc := getRejectPacketOutMutateFunc(packetOutType, c.nodeType, isFlexibleIPAMSrc, isFlexibleIPAMDst, ctZone)

	return openflow.SendRejectPacketOut(c.ofClient,
		srcMAC,
		dstMAC,
		srcIP,
		dstIP,
		inPort,
		outPort,
		isIPv6,
		ethernetPkt,
		proto,
		mutateFunc)
}

// getRejectType returns rejectType of a rejection.
func getRejectType(isServiceTraffic, antreaProxyEnabled, srcIsLocal, dstIsLocal bool) rejectType {
	if !isServiceTraffic {
		if srcIsLocal {
			if dstIsLocal {
				return rejectPodLocal
			}
			return rejectPodLocalToRemote
		}
		if dstIsLocal {
			return rejectPodRemoteToLocal
		}
		return unsupported
	}
	if !antreaProxyEnabled {
		if srcIsLocal {
			return rejectNoAPServiceLocal
		}
		if dstIsLocal {
			return rejectNoAPServiceRemoteToLocal
		}
		return unsupported
	}
	if srcIsLocal {
		if dstIsLocal {
			return rejectServiceLocal
		}
		return rejectServiceLocalToRemote
	}
	if dstIsLocal {
		return rejectServiceRemoteToLocal
	}
	return rejectServiceRemoteToExternal
}

// getRejectOFPorts returns the inPort and outPort of a packetOut based on the rejectType.
func getRejectOFPorts(rejectType rejectType, sIface, dIface *interfacestore.InterfaceConfig, gwOFPort, tunOFPort uint32) (uint32, uint32) {
	inPort := gwOFPort
	outPort := uint32(0)
	switch rejectType {
	case rejectPodLocal:
		inPort = uint32(sIface.OFPort)
		outPort = uint32(dIface.OFPort)
	case rejectServiceLocal:
		fallthrough
	case rejectServiceLocalToRemote:
		// For rejectServiceLocal and rejectServiceLocalToRemote, we set inPort as the
		// OFPort of the srcPod to simulate its rejection. And we don't set outPort, since
		// it's Service traffic load-balanced by AntreaProxy. The reject response packet
		// needs to be UnDNATed by the pipeline, instead of directly sending it out
		// through outPort.
		inPort = uint32(sIface.OFPort)
	case rejectPodRemoteToLocal:
		if dIface.Type == interfacestore.ExternalEntityInterface {
			inPort = uint32(dIface.EntityInterfaceConfig.UplinkPort.OFPort)
		} else {
			inPort = gwOFPort
		}
		outPort = uint32(dIface.OFPort)
	case rejectServiceRemoteToLocal:
		inPort = gwOFPort
	case rejectPodLocalToRemote:
		inPort = uint32(sIface.OFPort)
		if sIface.Type == interfacestore.ExternalEntityInterface {
			outPort = uint32(sIface.EntityInterfaceConfig.UplinkPort.OFPort)
		}
	case rejectNoAPServiceLocal:
		inPort = uint32(sIface.OFPort)
		outPort = gwOFPort
	case rejectNoAPServiceRemoteToLocal:
		inPort = tunOFPort
		if inPort == 0 {
			// If tunnel interface is not found, which means we are in noEncap mode, then use
			// gateway port as inPort.
			inPort = gwOFPort
		}
		outPort = gwOFPort
	case rejectServiceRemoteToExternal:
		inPort = tunOFPort
		if inPort == 0 {
			// If tunnel interface is not found, which means we are in noEncap mode, then use
			// gateway port as inPort.
			inPort = gwOFPort
		}
	}
	return inPort, outPort
}

// getRejectPacketOutMutateFunc returns the mutate func of a packetOut based on the rejectType.
func getRejectPacketOutMutateFunc(rejectType rejectType, nodeType config.NodeType, isFlexibleIPAMSrc, isFlexibleIPAMDst bool, ctZone uint32) func(binding.PacketOutBuilder) binding.PacketOutBuilder {
	var mutatePacketOut func(binding.PacketOutBuilder) binding.PacketOutBuilder
	mutatePacketOut = func(packetOutBuilder binding.PacketOutBuilder) binding.PacketOutBuilder {
		return packetOutBuilder.AddLoadRegMark(openflow.GeneratedRejectPacketOutRegMark)
	}
	switch rejectType {
	case rejectServiceLocal:
		tableID := openflow.ConntrackTable.GetID()
		if isFlexibleIPAMSrc {
			mutatePacketOut = func(packetOutBuilder binding.PacketOutBuilder) binding.PacketOutBuilder {
				return packetOutBuilder.AddLoadRegMark(openflow.GeneratedRejectPacketOutRegMark).
					AddLoadRegMark(openflow.AntreaFlexibleIPAMRegMark).AddLoadRegMark(binding.NewRegMark(openflow.CtZoneField, ctZone)).
					AddResubmitAction(nil, &tableID)
			}
		} else {
			mutatePacketOut = func(packetOutBuilder binding.PacketOutBuilder) binding.PacketOutBuilder {
				return packetOutBuilder.AddLoadRegMark(openflow.GeneratedRejectPacketOutRegMark).
					AddLoadRegMark(binding.NewRegMark(openflow.CtZoneField, ctZone)).
					AddResubmitAction(nil, &tableID)
			}
		}
	case rejectPodLocalToRemote:
		tableID := openflow.L3ForwardingTable.GetID()
		// L3ForwardingTable is not initialized for ExternalNode case since layer 3 is not needed.
		if nodeType == config.ExternalNode {
			tableID = openflow.L2ForwardingCalcTable.GetID()
		}
		if isFlexibleIPAMSrc {
			mutatePacketOut = func(packetOutBuilder binding.PacketOutBuilder) binding.PacketOutBuilder {
				return packetOutBuilder.AddLoadRegMark(openflow.GeneratedRejectPacketOutRegMark).
					AddLoadRegMark(openflow.AntreaFlexibleIPAMRegMark).AddLoadRegMark(binding.NewRegMark(openflow.CtZoneField, ctZone)).
					AddResubmitAction(nil, &tableID)
			}
		} else {
			mutatePacketOut = func(packetOutBuilder binding.PacketOutBuilder) binding.PacketOutBuilder {
				return packetOutBuilder.AddLoadRegMark(openflow.GeneratedRejectPacketOutRegMark).
					AddLoadRegMark(binding.NewRegMark(openflow.CtZoneField, ctZone)).
					AddResubmitAction(nil, &tableID)
			}
		}
	case rejectServiceRemoteToLocal:
		if isFlexibleIPAMDst {
			tableID := openflow.ConntrackTable.GetID()
			mutatePacketOut = func(packetOutBuilder binding.PacketOutBuilder) binding.PacketOutBuilder {
				return packetOutBuilder.AddLoadRegMark(openflow.GeneratedRejectPacketOutRegMark).
					AddLoadRegMark(binding.NewRegMark(openflow.CtZoneField, ctZone)).
					AddResubmitAction(nil, &tableID)
			}
		}
	}
	return mutatePacketOut
}

func parseFlexibleIPAMStatus(pktIn *ofctrl.PacketIn, nodeConfig *config.NodeConfig, srcIP string, srcIsLocal bool, dstIP string, dstIsLocal bool) (isFlexibleIPAMSrc bool, isFlexibleIPAMDst bool, ctZone uint32, err error) {
	// isFlexibleIPAMSrc is true if srcIP belongs to a local FlexibleIPAM Pod.
	// isFlexibleIPAMDst is true if dstIP belongs to a local FlexibleIPAM Pod.
	// ctZone is not zero if FlexibleIPAM is enabled.
	if srcIsLocal && nodeConfig.PodIPv4CIDR != nil && !nodeConfig.PodIPv4CIDR.Contains(net.ParseIP(srcIP)) {
		isFlexibleIPAMSrc = true
	}
	if dstIsLocal && nodeConfig.PodIPv4CIDR != nil && !nodeConfig.PodIPv4CIDR.Contains(net.ParseIP(dstIP)) {
		isFlexibleIPAMDst = true
	}
	// ctZone is read from the incoming packet.
	// The generated reject packet should have same ctZone with the incoming packet, otherwise the conntrack cannot work properly.
	matches := pktIn.GetMatches()
	if match := getMatchRegField(matches, openflow.CtZoneField); match != nil {
		ctZone, err = getInfoInReg(match, openflow.CtZoneField.GetRange().ToNXRange())
		if err != nil {
			return false, false, 0, err
		}
	}
	return
}
