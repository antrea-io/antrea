// Copyright 2022 Antrea Authors
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
	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/antrea/pkg/util/runtime"
)

type featurePodConnectivity struct {
	cookieAllocator cookie.Allocator
	ipProtocols     []binding.Protocol

	nodeCachedFlows *flowCategoryCache
	podCachedFlows  *flowCategoryCache
	tcCachedFlows   *flowCategoryCache

	gatewayIPs    map[binding.Protocol]net.IP
	ctZones       map[binding.Protocol]int
	localCIDRs    map[binding.Protocol]net.IPNet
	nodeIPs       map[binding.Protocol]net.IP
	nodeConfig    *config.NodeConfig
	networkConfig *config.NetworkConfig

	connectUplinkToBridge bool
	ctZoneSrcField        *binding.RegField
	ipCtZoneTypeRegMarks  map[binding.Protocol]*binding.RegMark
	enableMulticast       bool
	proxyAll              bool
	enableTrafficControl  bool

	category cookie.Category
}

func (f *featurePodConnectivity) getFeatureName() string {
	return "PodConnectivity"
}

func newFeaturePodConnectivity(
	cookieAllocator cookie.Allocator,
	ipProtocols []binding.Protocol,
	nodeConfig *config.NodeConfig,
	networkConfig *config.NetworkConfig,
	connectUplinkToBridge bool,
	enableMulticast bool,
	proxyAll bool,
	enableTrafficControl bool) *featurePodConnectivity {
	ctZones := make(map[binding.Protocol]int)
	gatewayIPs := make(map[binding.Protocol]net.IP)
	localCIDRs := make(map[binding.Protocol]net.IPNet)
	nodeIPs := make(map[binding.Protocol]net.IP)
	ipCtZoneTypeRegMarks := make(map[binding.Protocol]*binding.RegMark)
	for _, ipProtocol := range ipProtocols {
		if ipProtocol == binding.ProtocolIP {
			ctZones[ipProtocol] = CtZone
			gatewayIPs[ipProtocol] = nodeConfig.GatewayConfig.IPv4
			nodeIPs[ipProtocol] = nodeConfig.NodeIPv4Addr.IP
			if nodeConfig.PodIPv4CIDR != nil {
				localCIDRs[ipProtocol] = *nodeConfig.PodIPv4CIDR
			}
			ipCtZoneTypeRegMarks[ipProtocol] = IPCtZoneTypeRegMark
		} else if ipProtocol == binding.ProtocolIPv6 {
			ctZones[ipProtocol] = CtZoneV6
			gatewayIPs[ipProtocol] = nodeConfig.GatewayConfig.IPv6
			nodeIPs[ipProtocol] = nodeConfig.NodeIPv6Addr.IP
			if nodeConfig.PodIPv6CIDR != nil {
				localCIDRs[ipProtocol] = *nodeConfig.PodIPv6CIDR
			}
			ipCtZoneTypeRegMarks[ipProtocol] = IPv6CtZoneTypeRegMark
		}
	}

	return &featurePodConnectivity{
		cookieAllocator:       cookieAllocator,
		ipProtocols:           ipProtocols,
		nodeCachedFlows:       newFlowCategoryCache(),
		podCachedFlows:        newFlowCategoryCache(),
		tcCachedFlows:         newFlowCategoryCache(),
		gatewayIPs:            gatewayIPs,
		ctZones:               ctZones,
		localCIDRs:            localCIDRs,
		nodeIPs:               nodeIPs,
		nodeConfig:            nodeConfig,
		networkConfig:         networkConfig,
		connectUplinkToBridge: connectUplinkToBridge,
		enableTrafficControl:  enableTrafficControl,
		ipCtZoneTypeRegMarks:  ipCtZoneTypeRegMarks,
		ctZoneSrcField:        getZoneSrcField(connectUplinkToBridge),
		enableMulticast:       enableMulticast,
		proxyAll:              proxyAll,
		category:              cookie.PodConnectivity,
	}
}

func (f *featurePodConnectivity) initFlows() []binding.Flow {
	var flows []binding.Flow
	gatewayMAC := f.nodeConfig.GatewayConfig.MAC

	for _, ipProtocol := range f.ipProtocols {
		if ipProtocol == binding.ProtocolIPv6 {
			flows = append(flows, f.ipv6Flows()...)
		} else if ipProtocol == binding.ProtocolIP {
			flows = append(flows, f.arpNormalFlow())
			flows = append(flows, f.arpSpoofGuardFlow(f.gatewayIPs[ipProtocol], gatewayMAC, config.HostGatewayOFPort))
			if f.connectUplinkToBridge {
				flows = append(flows, f.arpResponderFlow(f.gatewayIPs[ipProtocol], gatewayMAC))
				flows = append(flows, f.arpSpoofGuardFlow(f.nodeConfig.NodeIPv4Addr.IP, gatewayMAC, config.HostGatewayOFPort))
				flows = append(flows, f.hostBridgeUplinkVLANFlows()...)
			}
			if runtime.IsWindowsPlatform() || f.connectUplinkToBridge {
				// This installs the flows between bridge local port and uplink port to support host networking.
				// TODO: support IPv6
				podCIDRMap := map[binding.Protocol]net.IPNet{binding.ProtocolIP: *f.nodeConfig.PodIPv4CIDR}
				flows = append(flows, f.hostBridgeUplinkFlows(podCIDRMap)...)
			}
		}
	}
	if f.connectUplinkToBridge {
		flows = append(flows, f.l3FwdFlowToNode()...)
	}
	flows = append(flows, f.l3FwdFlowToExternal())
	flows = append(flows, f.decTTLFlows()...)
	flows = append(flows, f.conntrackFlows()...)
	flows = append(flows, f.l2ForwardOutputFlow())
	flows = append(flows, f.gatewayClassifierFlow())
	flows = append(flows, f.l2ForwardCalcFlow(gatewayMAC, config.HostGatewayOFPort))
	flows = append(flows, f.gatewayIPSpoofGuardFlows()...)
	flows = append(flows, f.l3FwdFlowToGateway()...)
	// Add flow to ensure the liveliness check packet could be forwarded correctly.
	flows = append(flows, f.localProbeFlows()...)

	if f.networkConfig.TrafficEncapMode.SupportsEncap() {
		flows = append(flows, f.tunnelClassifierFlow(config.DefaultTunOFPort))
		flows = append(flows, f.l2ForwardCalcFlow(GlobalVirtualMAC, config.DefaultTunOFPort))
	}

	if f.networkConfig.TrafficEncapMode.IsNetworkPolicyOnly() {
		flows = append(flows, f.l3FwdFlowRouteToGW()...)
		// If IPv6 is enabled, this flow will never get hit. Replies any ARP request with the same global virtual MAC.
		flows = append(flows, f.arpResponderStaticFlow())
	} else {
		// If NetworkPolicyOnly mode is enabled, IPAM is implemented by the primary CNI, which may not use the Pod CIDR
		// of the Node. Therefore, it doesn't make sense to install flows for the Pod CIDR. Individual flow for each local
		// Pod IP will take care of routing the traffic to destination Pod.
		flows = append(flows, f.l3FwdFlowToLocalPodCIDR()...)
	}
	if f.enableTrafficControl {
		flows = append(flows, f.trafficControlCommonFlows()...)
	}
	return flows
}

func (f *featurePodConnectivity) replayFlows() []binding.Flow {
	var flows []binding.Flow

	// Get cached flows.
	for _, cachedFlows := range []*flowCategoryCache{f.nodeCachedFlows, f.podCachedFlows, f.tcCachedFlows} {
		flows = append(flows, getCachedFlows(cachedFlows)...)
	}

	return flows
}

// trafficControlMarkFlows generates the flows to mark the packets that need to be redirected or mirrored.
func (f *featurePodConnectivity) trafficControlMarkFlows(sourceOFPorts []uint32, targetOFPort uint32, direction v1alpha2.Direction, action v1alpha2.TrafficControlAction) []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var actionRegMark *binding.RegMark
	if action == v1alpha2.ActionRedirect {
		actionRegMark = TrafficControlRedirectRegMark
	} else if action == v1alpha2.ActionMirror {
		actionRegMark = TrafficControlMirrorRegMark
	}
	var flows []binding.Flow
	for _, port := range sourceOFPorts {
		if direction == v1alpha2.DirectionIngress || direction == v1alpha2.DirectionBoth {
			// This generates the flow to mark the packets destined for a provided port.
			flows = append(flows, TrafficControlTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchRegFieldWithValue(TargetOFPortField, port).
				Action().LoadToRegField(TrafficControlTargetOFPortField, targetOFPort).
				Action().LoadRegMark(actionRegMark).
				Action().NextTable().
				Done())
		}
		// This generates the flow to mark the packets sourced from a provided port.
		if direction == v1alpha2.DirectionEgress || direction == v1alpha2.DirectionBoth {
			flows = append(flows, TrafficControlTable.ofTable.BuildFlow(priorityNormal).
				Cookie(cookieID).
				MatchInPort(port).
				Action().LoadToRegField(TrafficControlTargetOFPortField, targetOFPort).
				Action().LoadRegMark(actionRegMark).
				Action().NextTable().
				Done())
		}
	}
	return flows
}

// trafficControlReturnClassifierFlow generates the flow to mark the packets from traffic control return port and forward
// the packets to stageRouting directly. Note that, for the packets which are originally to be output to a tunnel port,
// value of NXM_NX_TUN_IPV4_DST for the returned packets needs to be loaded in stageRouting.
func (f *featurePodConnectivity) trafficControlReturnClassifierFlow(returnOFPort uint32) binding.Flow {
	return ClassifierTable.ofTable.BuildFlow(priorityNormal).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchInPort(returnOFPort).
		Action().LoadRegMark(FromTCReturnRegMark).
		Action().GotoStage(stageRouting).
		Done()
}

// trafficControlCommonFlows generates the common flows for traffic control.
func (f *featurePodConnectivity) trafficControlCommonFlows() []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	return []binding.Flow{
		// This generates the flow to output packets to the original target port as well as mirror the packets to the target
		// traffic control port.
		L2ForwardingOutTable.ofTable.BuildFlow(priorityHigh+1).
			Cookie(cookieID).
			MatchRegMark(OFPortFoundRegMark, TrafficControlMirrorRegMark).
			Action().OutputToRegField(TargetOFPortField).
			Action().OutputToRegField(TrafficControlTargetOFPortField).
			Done(),
		// This generates the flow to output the packets to be redirected to the target traffic control port.
		L2ForwardingOutTable.ofTable.BuildFlow(priorityHigh+1).
			Cookie(cookieID).
			MatchRegMark(OFPortFoundRegMark, TrafficControlRedirectRegMark).
			Action().OutputToRegField(TrafficControlTargetOFPortField).
			Done(),
		// This generates the flow to forward the returned packets (with FromTCReturnRegMark) to stageOutput directly
		// after loading output port number to reg1 in L2ForwardingCalcTable.
		TrafficControlTable.ofTable.BuildFlow(priorityHigh).
			Cookie(cookieID).
			MatchRegMark(OFPortFoundRegMark, FromTCReturnRegMark).
			Action().GotoStage(stageOutput).
			Done(),
	}
}
