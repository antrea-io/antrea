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
	binding "antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/util/runtime"
)

type featurePodConnectivity struct {
	cookieAllocator cookie.Allocator
	ipProtocols     []binding.Protocol

	nodeCachedFlows *flowCategoryCache
	podCachedFlows  *flowCategoryCache

	gatewayIPs    map[binding.Protocol]net.IP
	ctZones       map[binding.Protocol]int
	localCIDRs    map[binding.Protocol]net.IPNet
	nodeIPs       map[binding.Protocol]net.IP
	nodeConfig    *config.NodeConfig
	networkConfig *config.NetworkConfig
	// ovsDatapathType is the type of the datapath used by the bridge.
	ovsDatapathType ovsconfig.OVSDatapathType

	connectUplinkToBridge bool
	ctZoneSrcField        *binding.RegField
	ipCtZoneTypeRegMarks  map[binding.Protocol]*binding.RegMark
	enableMulticast       bool

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
	ovsDatapathType ovsconfig.OVSDatapathType,
	connectUplinkToBridge bool,
	enableMulticast bool) *featurePodConnectivity {
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
		gatewayIPs:            gatewayIPs,
		ctZones:               ctZones,
		localCIDRs:            localCIDRs,
		nodeIPs:               nodeIPs,
		nodeConfig:            nodeConfig,
		networkConfig:         networkConfig,
		ovsDatapathType:       ovsDatapathType,
		connectUplinkToBridge: connectUplinkToBridge,
		ipCtZoneTypeRegMarks:  ipCtZoneTypeRegMarks,
		ctZoneSrcField:        getZoneSrcField(connectUplinkToBridge),
		enableMulticast:       enableMulticast,
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
	flows = append(flows, f.localProbeFlow()...)

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
	return flows
}

func (f *featurePodConnectivity) replayFlows() []binding.Flow {
	var flows []binding.Flow

	// Get cached flows.
	for _, cachedFlows := range []*flowCategoryCache{f.nodeCachedFlows, f.podCachedFlows} {
		flows = append(flows, getCachedFlows(cachedFlows)...)
	}

	return flows
}
