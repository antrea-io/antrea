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
	"net"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/openflow/cookie"
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

type featurePodConnectivity struct {
	cookieAllocator cookie.Allocator
	ipProtocols     []binding.Protocol

	nodeFlowCache       *flowCategoryCache
	podFlowCache        *flowCategoryCache
	gatewayFlows        []binding.Flow
	defaultTunnelFlows  []binding.Flow
	hostNetworkingFlows []binding.Flow

	gatewayIPs    map[binding.Protocol]net.IP
	ctZones       map[binding.Protocol]int
	nodeConfig    *config.NodeConfig
	networkConfig *config.NetworkConfig

	connectUplinkToBridge bool
}

func (c *featurePodConnectivity) getFeatureID() featureID {
	return PodConnectivity
}

func newFeaturePodConnectivity(
	cookieAllocator cookie.Allocator,
	ipProtocols []binding.Protocol,
	nodeConfig *config.NodeConfig,
	networkConfig *config.NetworkConfig,
	connectUplinkToBridge bool) feature {
	ctZones := make(map[binding.Protocol]int)
	gatewayIPs := make(map[binding.Protocol]net.IP)
	for _, ipProtocol := range ipProtocols {
		if ipProtocol == binding.ProtocolIP {
			ctZones[ipProtocol] = CtZone
			gatewayIPs[ipProtocol] = nodeConfig.GatewayConfig.IPv4
		} else if ipProtocol == binding.ProtocolIPv6 {
			ctZones[ipProtocol] = CtZoneV6
			gatewayIPs[ipProtocol] = nodeConfig.GatewayConfig.IPv6
		}
	}

	return &featurePodConnectivity{
		cookieAllocator:       cookieAllocator,
		ipProtocols:           ipProtocols,
		nodeFlowCache:         newFlowCategoryCache(),
		podFlowCache:          newFlowCategoryCache(),
		gatewayIPs:            gatewayIPs,
		ctZones:               ctZones,
		nodeConfig:            nodeConfig,
		networkConfig:         networkConfig,
		connectUplinkToBridge: connectUplinkToBridge,
	}
}

// Stage: OutputStage
// Tables: ARPResponderTable
// Refactored from:
//   - `func (c *client) arpNormalFlow(category cookie.Category) binding.Flow`
// arpNormalFlow generates the flow to response arp in normal way if no flow in ARPResponderTable is matched.
func (c *featurePodConnectivity) arpNormalFlow(category cookie.Category) binding.Flow {
	return ARPResponderTable.ofTable.BuildFlow(priorityLow).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		MatchProtocol(binding.ProtocolARP).
		Action().Normal().
		Done()
}

// Stage: OutputStage
// Tables: ARPResponderTable
// Refactored from:
//   - `func (c *client) arpResponderFlow(peerGatewayIP net.IP, category cookie.Category) binding.Flow`
// Modification:
//  - Response arp request with specific MAC address.
// arpResponderFlow generates the flow to response arp request with specific MAC address for specific IP address.
func (c *featurePodConnectivity) arpResponderFlow(category cookie.Category, ipAddr net.IP, macAddr net.HardwareAddr) binding.Flow {
	return ARPResponderTable.ofTable.BuildFlow(priorityNormal).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		MatchProtocol(binding.ProtocolARP).
		MatchARPOp(arpOpRequest).
		MatchARPTpa(ipAddr).
		Action().Move(binding.NxmFieldSrcMAC, binding.NxmFieldDstMAC).
		Action().SetSrcMAC(macAddr).
		Action().LoadARPOperation(arpOpReply).
		Action().Move(binding.NxmFieldARPSha, binding.NxmFieldARPTha).
		Action().SetARPSha(macAddr).
		Action().Move(binding.NxmFieldARPSpa, binding.NxmFieldARPTpa).
		Action().SetARPSpa(ipAddr).
		Action().OutputInPort().
		Done()
}

// Stage: ClassifierStage
// Tables: ClassifierTable
// Refactored from:
//   - `func (c *client) tunnelClassifierFlow(tunnelOFPort uint32, category cookie.Category) binding.Flow`
// tunnelClassifierFlow generates the flow to mark traffic comes from the tunnelOFPort.
func (c *featurePodConnectivity) tunnelClassifierFlow(category cookie.Category, tunnelOFPort uint32) binding.Flow {
	return ClassifierTable.ofTable.BuildFlow(priorityNormal).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		MatchInPort(tunnelOFPort).
		Action().LoadRegMark(FromTunnelRegMark).
		Action().LoadRegMark(RewriteMACRegMark).
		Action().GotoStage(binding.ConntrackStateStage).
		Done()
}

// Stage: ClassifierStage
// Tables: ClassifierTable
// Refactored from:
//   - `func (c *client) tunnelClassifierFlow(tunnelOFPort uint32, category cookie.Category) binding.Flow`
// gatewayClassifierFlow generates the flow to mark traffic comes from the gatewayOFPort.
func (c *featurePodConnectivity) gatewayClassifierFlow(category cookie.Category) binding.Flow {
	return ClassifierTable.ofTable.BuildFlow(priorityNormal).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		MatchInPort(config.HostGatewayOFPort).
		Action().LoadRegMark(FromGatewayRegMark).
		Action().NextTable().
		Done()
}

// Stage: ClassifierStage
// Tables: ClassifierTable
// Refactored from:
//   - `func (c *client) podClassifierFlow(podOFPort uint32, category cookie.Category, isAntreaFlexibleIPAM bool) binding.Flow`
// podClassifierFlow generates the flow to mark traffic comes from the podOFPort.
func (c *featurePodConnectivity) podClassifierFlow(category cookie.Category, podOFPort uint32, isAntreaFlexibleIPAM bool) binding.Flow {
	flowBuilder := ClassifierTable.ofTable.BuildFlow(priorityLow).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		MatchInPort(podOFPort).
		Action().LoadRegMark(FromLocalRegMark).
		Action().NextTable()
	if isAntreaFlexibleIPAM {
		// mark traffic from local AntreaFlexibleIPAM Pod
		flowBuilder = flowBuilder.Action().LoadRegMark(AntreaFlexibleIPAMRegMark)
	}
	return flowBuilder.Done()
}

// Stage: ClassifierStage
// Tables: ClassifierTable
// Refactored from:
//   - `func (c *client) podUplinkClassifierFlows(dstMAC net.HardwareAddr, category cookie.Category) (flows []binding.Flow)`
// podUplinkClassifierFlows generates the flows to mark traffic from uplink and bridge ports, which are needed when
// uplink is connected to OVS bridge when AntreaFlexibleIPAM is configured.
func (c *featurePodConnectivity) podUplinkClassifierFlows(dstMAC net.HardwareAddr, category cookie.Category) []binding.Flow {
	return []binding.Flow{
		ClassifierTable.ofTable.BuildFlow(priorityHigh).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			MatchInPort(config.UplinkOFPort).
			MatchDstMAC(dstMAC).
			Action().LoadRegMark(FromUplinkRegMark).
			Action().GotoStage(binding.ConntrackStateStage).
			Done(),
		ClassifierTable.ofTable.BuildFlow(priorityHigh).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			MatchInPort(config.BridgeOFPort).
			MatchDstMAC(dstMAC).
			Action().LoadRegMark(FromBridgeRegMark).
			Action().GotoStage(binding.ConntrackStateStage).
			Done(),
	}
}

// Stage: ValidationStage
// Tables: ARPSpoofGuardTable
// Refactored from:
//  - `func (c *client) arpSpoofGuardFlow(ifIP net.IP, ifMAC net.HardwareAddr, ifOFPort uint32, category cookie.Category) binding.Flow`
//  - `func (c *client) gatewayARPSpoofGuardFlows(gatewayIP net.IP, gatewayMAC net.HardwareAddr, category cookie.Category) (flows []binding.Flow)`
// Modification:
// - Removed function `gatewayARPSpoofGuardFlows`.
// arpSpoofGuardFlow generates the flow to check ARP traffic sent out from local pods interfaces or Antrea gateway.
func (c *featurePodConnectivity) arpSpoofGuardFlow(category cookie.Category, ifIP net.IP, ifMAC net.HardwareAddr, ifOFPort uint32) binding.Flow {
	return ARPSpoofGuardTable.ofTable.BuildFlow(priorityNormal).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		MatchProtocol(binding.ProtocolARP).
		MatchInPort(ifOFPort).
		MatchARPSha(ifMAC).
		MatchARPSpa(ifIP).
		Action().NextTable().
		Done()
}

// Stage: ValidationStage
// Tables: SpoofGuardTable
// Refactored from:
//   - `func (c *client) gatewayIPSpoofGuardFlows(category cookie.Category) []binding.Flow`
// gatewayIPSpoofGuardFlows generates the flow to skip spoof guard checking for traffic sent from gateway interface.
func (c *featurePodConnectivity) gatewayIPSpoofGuardFlows(category cookie.Category) []binding.Flow {
	var flows []binding.Flow
	for _, ipProtocol := range c.ipProtocols {
		nextTable := SpoofGuardTable.ofTable.GetNext()
		if ipProtocol == binding.ProtocolIPv6 {
			nextTable = IPv6Table.ofTable.GetID()
		}
		flows = append(flows,
			SpoofGuardTable.ofTable.BuildFlow(priorityNormal).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchProtocol(ipProtocol).
				MatchInPort(config.HostGatewayOFPort).
				Action().ResubmitToTables(nextTable).
				Done(),
		)
	}
	return flows
}

// Stage: ValidationStage
// Tables: SpoofGuardTable
// Refactored from:
//   - `func (c *client) podIPSpoofGuardFlow(ifIPs []net.IP, ifMAC net.HardwareAddr, ifOFPort uint32,
//     category cookie.Category) []binding.Flow`
// podIPSpoofGuardFlow generates the flow to check IP traffic sent out from local pod. Traffic from host gateway
// interface will not be checked, since it might be pod to service traffic or host namespace traffic.
func (c *featurePodConnectivity) podIPSpoofGuardFlow(category cookie.Category, ifIPs []net.IP, ifMAC net.HardwareAddr, ifOFPort uint32) []binding.Flow {
	var flows []binding.Flow
	for _, ifIP := range ifIPs {
		ipProtocol := getIPProtocol(ifIP)
		nextTable := SpoofGuardTable.ofTable.GetNext()
		if ipProtocol == binding.ProtocolIPv6 {
			nextTable = IPv6Table.ofTable.GetID()
		}
		flows = append(flows,
			SpoofGuardTable.ofTable.BuildFlow(priorityNormal).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchProtocol(ipProtocol).
				MatchInPort(ifOFPort).
				MatchSrcMAC(ifMAC).
				MatchSrcIP(ifIP).
				Action().ResubmitToTables(nextTable).
				Done())
	}
	return flows
}

// Stage: ValidationStage
// Tables: SpoofGuardTable, IPv6Table
// Refactored from:
//   - `func (c *client) ipv6Flows(category cookie.Category) []binding.Flow`
// ipv6Flows generates the flows to allow IPv6 packets from link-local addresses and handle multicast packets, Neighbor
// Solicitation and ND Advertisement packets properly.
func (c *featurePodConnectivity) ipv6Flows(category cookie.Category) []binding.Flow {
	var flows []binding.Flow

	_, ipv6LinkLocalIpnet, _ := net.ParseCIDR(ipv6LinkLocalAddr)
	_, ipv6MulticastIpnet, _ := net.ParseCIDR(ipv6MulticastAddr)
	flows = append(flows,
		// Allow IPv6 packets (e.g. Multicast Listener Report Message V2) which are sent from link-local addresses in
		// SpoofGuardTable, so that these packets will not be dropped.
		SpoofGuardTable.ofTable.BuildFlow(priorityNormal).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			MatchProtocol(binding.ProtocolIPv6).
			MatchSrcIPNet(*ipv6LinkLocalIpnet).
			Action().ResubmitToTables(IPv6Table.ofTable.GetID()).
			Done(),
		// Handle IPv6 Neighbor Solicitation and Neighbor Advertisement as a regular L2 learning Switch by using normal.
		IPv6Table.ofTable.BuildFlow(priorityNormal).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			MatchProtocol(binding.ProtocolICMPv6).
			MatchICMPv6Type(135).
			MatchICMPv6Code(0).
			Action().Normal().
			Done(),
		IPv6Table.ofTable.BuildFlow(priorityNormal).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			MatchProtocol(binding.ProtocolICMPv6).
			MatchICMPv6Type(136).
			MatchICMPv6Code(0).
			Action().Normal().
			Done(),
		// Handle IPv6 multicast packets as a regular L2 learning Switch by using normal.
		// It is used to ensure that all kinds of IPv6 multicast packets are properly handled (e.g. Multicast Listener
		// Report Message V2).
		IPv6Table.ofTable.BuildFlow(priorityNormal).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			MatchProtocol(binding.ProtocolIPv6).
			MatchDstIPNet(*ipv6MulticastIpnet).
			Action().Normal().
			Done(),
	)
	return flows
}

// Stage: ValidationStage
// Tables: SpoofGuardTable
// New added
// spoofGuardDefaultDropFlow generates the flow to drop the packet which is not matched by any other flows.
func (c *featurePodConnectivity) spoofGuardDefaultDropFlow(category cookie.Category) binding.Flow {
	return SpoofGuardTable.ofTable.BuildFlow(priorityMiss).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Action().Drop().
		Done()
}

// Stage: RoutingStage
// Tables: L3ForwardingTable
// Refactored from:
//   - `func (c *client) l3FwdFlowToGateway(localGatewayIPs []net.IP, localGatewayMAC net.HardwareAddr,
//      category cookie.Category) []binding.Flow`
// l3FwdFlowToGateway generates the L3 forward flows to rewrite the destination MAC of the packets to the gateway
// interface MAC if the destination IP is the gateway IP or the connection was initiated through the gateway interface.
func (c *featurePodConnectivity) l3FwdFlowToGateway(category cookie.Category) []binding.Flow {
	var flows []binding.Flow
	for ipProtocol, gatewayIP := range c.gatewayIPs {
		flows = append(flows, L3ForwardingTable.ofTable.BuildFlow(priorityNormal).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			MatchProtocol(ipProtocol).
			MatchRegMark(RewriteMACRegMark).
			MatchDstIP(gatewayIP).
			Action().SetDstMAC(c.nodeConfig.GatewayConfig.MAC).
			Action().LoadRegMark(ToGatewayRegMark).
			Action().GotoStage(binding.SwitchingStage).
			Done())
	}

	// Rewrite the destination MAC address with the local host gateway MAC if the packet is in the reply direction and
	// is marked with FromGatewayCTMark. This is for connections which were initiated through the gateway, to ensure that
	// this reply traffic gets forwarded correctly (back to the host network namespace, through the gateway). In
	// particular, it is necessary in the following 2 cases:
	//  1) reply traffic for connections from a local Pod to a ClusterIP Service (when AntreaProxy is disabled and
	//  kube-proxy is used). In this case the destination IP address of the reply traffic is the Pod which initiated the
	//  connection to the Service (no SNAT). We need to make sure that these packets are sent back through the gateway
	//  so that the source IP can be rewritten (Service backend IP -> Service ClusterIP).
	//  2) when hair-pinning is involved, i.e. connections between 2 local Pods, for which NAT is performed. This
	//  applies regardless of whether AntreaProxy is enabled or not, and thus also applies to Windows Nodes (for which
	//  AntreaProxy is enabled by default). One example is a Pod accessing a NodePort Service for which
	//  externalTrafficPolicy is set to Local, using the local Node's IP address.
	for _, ipProtocol := range c.ipProtocols {
		flows = append(flows, L3ForwardingTable.ofTable.BuildFlow(priorityHigh).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			MatchProtocol(ipProtocol).
			MatchCTMark(FromGatewayCTMark).
			MatchCTStateRpl(true).
			MatchCTStateTrk(true).
			Action().SetDstMAC(c.nodeConfig.GatewayConfig.MAC).
			Action().LoadRegMark(ToGatewayRegMark).
			Action().GotoStage(binding.SwitchingStage).
			Done())

		if c.networkConfig.TrafficEncapMode.SupportsEncap() {
			flows = append(flows, L3ForwardingTable.ofTable.BuildFlow(priorityHigh).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchProtocol(ipProtocol).
				MatchRegMark(FromTunnelRegMark).
				MatchCTMark(FromGatewayCTMark).
				MatchCTStateRpl(true).MatchCTStateTrk(true).
				Action().SetDstMAC(c.nodeConfig.GatewayConfig.MAC).
				Action().LoadRegMark(ToGatewayRegMark).
				Action().GotoStage(binding.SwitchingStage).
				Done())
		}

		if c.connectUplinkToBridge {
			flows = append(flows, L3ForwardingTable.ofTable.BuildFlow(priorityHigh).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchProtocol(ipProtocol).
				MatchCTMark(FromBridgeCTMark).
				MatchCTStateRpl(true).
				MatchCTStateTrk(true).
				Action().SetDstMAC(c.nodeConfig.UplinkNetConfig.MAC).
				Action().LoadRegMark(ToUplinkRegMark).
				Action().GotoStage(binding.SwitchingStage).
				Done())
		}
	}
	return flows
}

// Stage: RoutingStage
// Tables: L3ForwardingTable
// Refactored from:
//   - `func (c *client) l3FwdFlowToRemote(localGatewayMAC net.HardwareAddr, peerSubnet net.IPNet, tunnelPeer net.IP,
//      category cookie.Category) binding.Flow`
// l3FwdFlowToRemote generates the L3 forward flow for traffic to a remote Node (Pods or gateway) through the tunnel.
func (c *featurePodConnectivity) l3FwdFlowToRemote(category cookie.Category,
	localGatewayMAC net.HardwareAddr,
	peerSubnet net.IPNet,
	tunnelPeer net.IP) binding.Flow {
	ipProtocol := getIPProtocol(peerSubnet.IP)
	return L3ForwardingTable.ofTable.BuildFlow(priorityNormal).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		MatchProtocol(ipProtocol).
		MatchDstIPNet(peerSubnet).
		Action().SetSrcMAC(localGatewayMAC).  // Rewrite src MAC to local gateway MAC.
		Action().SetDstMAC(GlobalVirtualMAC). // Rewrite dst MAC to virtual MAC.
		Action().SetTunnelDst(tunnelPeer).    // Flow based tunnel. Set tunnel destination.
		Action().LoadRegMark(ToTunnelRegMark).
		Action().NextTable().
		Done()
}

// Stage: RoutingStage
// Tables: L3ForwardingTable
// Refactored from:
//   - `func (c *client) l3FwdFlowToPod(localGatewayMAC net.HardwareAddr, podInterfaceIPs []net.IP,
//      podInterfaceMAC net.HardwareAddr, category cookie.Category) []binding.Flow`
// l3FwdFlowToPod generates the L3 forward flows for traffic from tunnel to a local Pod. It rewrites the destination MAC
// (should be GlobalVirtualMAC) to the Pod interface MAC, and rewrites the source MAC to the gateway interface MAC.
func (c *featurePodConnectivity) l3FwdFlowToPod(category cookie.Category,
	localGatewayMAC net.HardwareAddr,
	podInterfaceIPs []net.IP,
	podInterfaceMAC net.HardwareAddr) []binding.Flow {
	var flows []binding.Flow
	for _, ip := range podInterfaceIPs {
		ipProtocol := getIPProtocol(ip)
		flowBuilder := L3ForwardingTable.ofTable.BuildFlow(priorityNormal).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			MatchProtocol(ipProtocol)
		if !c.connectUplinkToBridge {
			// dstMAC will always be overwritten for AntreaFlexibleIPAM
			flowBuilder = flowBuilder.MatchRegMark(RewriteMACRegMark)
		}
		flows = append(flows, flowBuilder.
			MatchDstIP(ip).
			Action().SetSrcMAC(localGatewayMAC). // Rewrite src MAC to local gateway MAC.
			Action().SetDstMAC(podInterfaceMAC). // Rewrite dst MAC to pod MAC.
			Action().LoadRegMark(ToLocalRegMark).
			Action().NextTable().
			Done())
	}
	return flows
}

// Stage: RoutingStage
// Tables: L3ForwardingTable
// Requirements: noEncap, networkPolicyOnly, traffic encryption with WireGuard or hybrid mode
// Refactored from:
//   - `func (c *client) l3FwdFlowToRemoteViaGW(localGatewayMAC net.HardwareAddr, peerSubnet net.IPNet, category cookie.Category,
//      isAntreaFlexibleIPAM bool) binding.Flow`
// l3FwdFlowToRemoteViaGW generates the L3 forward flow to support traffic to remote via gateway. It is used when the
// cross-Node traffic does not require encapsulation (in noEncap, networkPolicyOnly, or hybrid mode).
func (c *featurePodConnectivity) l3FwdFlowToRemoteViaGW(category cookie.Category,
	localGatewayMAC net.HardwareAddr,
	peerSubnet net.IPNet,
	isAntreaFlexibleIPAM bool) binding.Flow {
	ipProtocol := getIPProtocol(peerSubnet.IP)
	priority := priorityNormal
	// AntreaFlexibleIPAM Pod -> Per-Node IPAM Pod traffic will be sent to remote Gw directly.
	if isAntreaFlexibleIPAM {
		priority = priorityHigh
	}
	flowBuilder := L3ForwardingTable.ofTable.BuildFlow(priority).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		MatchProtocol(ipProtocol).
		MatchDstIPNet(peerSubnet)
	if isAntreaFlexibleIPAM {
		flowBuilder = flowBuilder.MatchRegMark(AntreaFlexibleIPAMRegMark)
	}
	return flowBuilder.
		Action().SetDstMAC(localGatewayMAC).
		Action().LoadRegMark(ToGatewayRegMark).
		Action().NextTable().
		Done()
}

// Stage: RoutingStage
// Tables: L3ForwardingTable
// Requirements: networkPolicyOnly mode
// Refactored from:
//   - `func (c *client) l3FwdFlowRouteToPod(podInterfaceIPs []net.IP, podInterfaceMAC net.HardwareAddr,
//      category cookie.Category) []binding.Flow`
// l3FwdFlowRouteToPod generates the flows to route the traffic to a Pod based on the destination IP. It rewrites the
// destination MAC of the packets to the Pod interface MAC. The flow is used in the networkPolicyOnly mode for the
// traffic from the gateway to a local Pod.
func (c *featurePodConnectivity) l3FwdFlowRouteToPod(category cookie.Category,
	podInterfaceIPs []net.IP,
	podInterfaceMAC net.HardwareAddr) []binding.Flow {
	var flows []binding.Flow
	for _, ip := range podInterfaceIPs {
		ipProtocol := getIPProtocol(ip)
		flows = append(flows, L3ForwardingTable.ofTable.BuildFlow(priorityNormal).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			MatchProtocol(ipProtocol).
			MatchDstIP(ip).
			Action().SetDstMAC(podInterfaceMAC).
			Action().LoadRegMark(ToLocalRegMark).
			Action().NextTable().
			Done())
	}
	return flows
}

// Stage: RoutingStage
// Tables: L3ForwardingTable
// New added
func (c *featurePodConnectivity) l3DefaultFlowToPod(category cookie.Category) binding.Flow {
	return L3ForwardingTable.ofTable.BuildFlow(priorityMiss).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		Action().GotoStage(binding.SwitchingStage).
		Done()
}

// Stage: RoutingStage
// Tables: L3ForwardingTable
// Refactored from:
//   - `func (c *client) decTTLFlows(category cookie.Category) []binding.Flow`
// decTTLFlows decrements TTL by one for the packets forwarded across Nodes. The TTL decrement should be skipped for the
// packets which enter OVS pipeline from the gateway interface, as the host IP stack should have decremented the TTL
// already for such packets.
func (c *featurePodConnectivity) decTTLFlows(category cookie.Category) []binding.Flow {
	var flows []binding.Flow
	for _, ipProtocol := range c.ipProtocols {
		flows = append(flows,
			// Skip packets from the gateway interface.
			L3DecTTLTable.ofTable.BuildFlow(priorityHigh).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchProtocol(ipProtocol).
				MatchRegMark(FromGatewayRegMark).
				Action().NextTable().
				Done(),
			L3DecTTLTable.ofTable.BuildFlow(priorityNormal).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchProtocol(ipProtocol).
				Action().DecTTL().
				Action().NextTable().
				Done(),
		)
	}
	return flows
}

// Stage: ValidationStage
// Tables: ConntrackTable, ConntrackStateTable
// Stage: ConntrackStage
// Tables: ConntrackCommitTable
// Refactored from:
//   - `func (c *client) connectionTrackFlows(category cookie.Category) []binding.Flow`
// Modifications:
//   - Remove the flows related with Service since they are for feature Service.
// conntrackFlows generates the flows that are related to conntrack.
func (c *featurePodConnectivity) conntrackFlows(category cookie.Category) []binding.Flow {
	var flows []binding.Flow
	for _, ipProtocol := range c.ipProtocols {
		flows = append(flows,
			// This flow is used to maintain conntrack.
			ConntrackTable.ofTable.BuildFlow(priorityNormal).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchProtocol(ipProtocol).
				Action().CT(false, ConntrackTable.ofTable.GetNext(), c.ctZones[ipProtocol]).
				NAT().
				CTDone().
				Done(),
			// Add flow which is used to drop invalid packet.
			ConntrackStateTable.ofTable.BuildFlow(priorityLow).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchProtocol(ipProtocol).
				MatchCTStateInv(true).
				MatchCTStateTrk(true).
				Action().Drop().
				Done(),
			ConntrackCommitTable.ofTable.BuildFlow(priorityLow).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchProtocol(ipProtocol).
				MatchCTStateNew(true).
				MatchCTStateTrk(true).
				MatchCTStateDNAT(false).
				MatchCTStateSNAT(false).
				Action().CT(true, ConntrackCommitTable.ofTable.GetNext(), c.ctZones[ipProtocol]).
				CTDone().
				Done(),
			// Connections initiated through the gateway are marked with FromGatewayCTMark.
			ConntrackCommitTable.ofTable.BuildFlow(priorityNormal).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchProtocol(ipProtocol).
				MatchRegMark(FromGatewayRegMark).
				MatchCTStateNew(true).
				MatchCTStateTrk(true).
				MatchCTStateDNAT(false).
				MatchCTStateSNAT(false).
				Action().CT(true, ConntrackCommitTable.ofTable.GetNext(), c.ctZones[ipProtocol]).
				LoadToCtMark(FromGatewayCTMark).
				CTDone().
				Done(),
			// Connections initiated through the bridge port are marked with FromBridgeCTMark.
			ConntrackCommitTable.ofTable.BuildFlow(priorityNormal).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				MatchProtocol(ipProtocol).
				MatchRegMark(FromBridgeRegMark).
				MatchCTStateNew(true).
				MatchCTStateTrk(true).
				Action().CT(true, ConntrackCommitTable.ofTable.GetNext(), c.ctZones[ipProtocol]).
				LoadToCtMark(FromBridgeCTMark).CTDone().
				Done(),
		)
	}

	return flows
}

// Stage: SwitchingStage
// Tables: L2ForwardingCalcTable
// Refactored from:
//   - func (c *client) l2ForwardCalcFlow(dstMAC net.HardwareAddr, ofPort uint32, skipIngressRules bool, category cookie.Category) binding.Flow
// l2ForwardCalcFlow generates the flow that matches dst MAC and loads ofPort to reg.
func (c *featurePodConnectivity) l2ForwardCalcFlow(category cookie.Category,
	dstMAC net.HardwareAddr,
	ofPort uint32,
	skipIngressRules bool) binding.Flow {
	flowBuilder := L2ForwardingCalcTable.ofTable.BuildFlow(priorityNormal).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		MatchDstMAC(dstMAC).
		Action().LoadToRegField(TargetOFPortField, ofPort).
		Action().LoadRegMark(OFPortFoundRegMark)

	if skipIngressRules {
		return flowBuilder.Action().GotoStage(binding.ConntrackStage).Done()
	} else {
		return flowBuilder.Action().NextTable().Done()
	}
}

// Stage: OutputStage
// Tables: l2ForwardOutputFlow
// Refactored from:
//   - `func (c *client) l2ForwardOutputFlows(category cookie.Category) []binding.Flow`
// Modifications:
//   - Removed hairpin related flow since it is for feature Service.
// l2ForwardOutputFlow generates the flow that output packets to OVS port after L2 forwarding calculation.
func (c *featurePodConnectivity) l2ForwardOutputFlow(category cookie.Category) binding.Flow {
	return L2ForwardingOutTable.ofTable.BuildFlow(priorityNormal).
		Cookie(c.cookieAllocator.Request(category).Raw()).
		MatchRegMark(OFPortFoundRegMark).
		Action().OutputToRegField(TargetOFPortField).
		Done()
}

func (c *featurePodConnectivity) initialize(category cookie.Category) []binding.Flow {
	var flows []binding.Flow

	for _, ipProtocol := range c.ipProtocols {
		if ipProtocol == binding.ProtocolIPv6 {
			flows = append(flows, c.ipv6Flows(category)...)
			break
		}
	}
	flows = append(flows, c.arpNormalFlow(category))
	flows = append(flows, c.arpResponderFlow(category, c.nodeConfig.GatewayConfig.IPv4, c.nodeConfig.GatewayConfig.MAC))
	flows = append(flows, c.spoofGuardDefaultDropFlow(category))
	flows = append(flows, c.l3DefaultFlowToPod(category))
	flows = append(flows, c.decTTLFlows(category)...)
	flows = append(flows, c.conntrackFlows(category)...)
	flows = append(flows, c.l2ForwardOutputFlow(category))
	return flows
}
