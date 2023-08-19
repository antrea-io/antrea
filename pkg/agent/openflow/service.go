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
	"sync"

	"antrea.io/libOpenflow/openflow15"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/nodeip"
	"antrea.io/antrea/pkg/agent/openflow/cookie"
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

type featureService struct {
	cookieAllocator cookie.Allocator
	nodeIPChecker   nodeip.Checker
	ipProtocols     []binding.Protocol
	bridge          binding.Bridge

	cachedFlows *flowCategoryCache
	groupCache  sync.Map

	gatewayIPs             map[binding.Protocol]net.IP
	virtualIPs             map[binding.Protocol]net.IP
	virtualNodePortDNATIPs map[binding.Protocol]net.IP
	dnatCtZones            map[binding.Protocol]int
	snatCtZones            map[binding.Protocol]int
	gatewayMAC             net.HardwareAddr
	nodePortAddresses      map[binding.Protocol][]net.IP
	serviceCIDRs           map[binding.Protocol]net.IPNet
	localCIDRs             map[binding.Protocol]net.IPNet
	networkConfig          *config.NetworkConfig
	gatewayPort            uint32

	enableAntreaPolicy    bool
	enableProxy           bool
	proxyAll              bool
	enableDSR             bool
	connectUplinkToBridge bool
	ctZoneSrcField        *binding.RegField

	category cookie.Category
}

func (f *featureService) getFeatureName() string {
	return "Service"
}

func newFeatureService(
	cookieAllocator cookie.Allocator,
	nodeIPChecker nodeip.Checker,
	ipProtocols []binding.Protocol,
	nodeConfig *config.NodeConfig,
	networkConfig *config.NetworkConfig,
	serviceConfig *config.ServiceConfig,
	bridge binding.Bridge,
	enableAntreaPolicy,
	enableProxy,
	proxyAll,
	enableDSR,
	connectUplinkToBridge bool) *featureService {
	gatewayIPs := make(map[binding.Protocol]net.IP)
	virtualIPs := make(map[binding.Protocol]net.IP)
	virtualNodePortDNATIPs := make(map[binding.Protocol]net.IP)
	dnatCtZones := make(map[binding.Protocol]int)
	snatCtZones := make(map[binding.Protocol]int)
	nodePortAddresses := make(map[binding.Protocol][]net.IP)
	serviceCIDRs := make(map[binding.Protocol]net.IPNet)
	localCIDRs := make(map[binding.Protocol]net.IPNet)
	for _, ipProtocol := range ipProtocols {
		if ipProtocol == binding.ProtocolIP {
			gatewayIPs[ipProtocol] = nodeConfig.GatewayConfig.IPv4
			virtualIPs[ipProtocol] = config.VirtualServiceIPv4
			virtualNodePortDNATIPs[ipProtocol] = config.VirtualNodePortDNATIPv4
			dnatCtZones[ipProtocol] = CtZone
			snatCtZones[ipProtocol] = SNATCtZone
			nodePortAddresses[ipProtocol] = serviceConfig.NodePortAddressesIPv4
			if serviceConfig.ServiceCIDR != nil {
				serviceCIDRs[ipProtocol] = *serviceConfig.ServiceCIDR
			}
			if nodeConfig.PodIPv4CIDR != nil {
				localCIDRs[ipProtocol] = *nodeConfig.PodIPv4CIDR
			}
		} else if ipProtocol == binding.ProtocolIPv6 {
			gatewayIPs[ipProtocol] = nodeConfig.GatewayConfig.IPv6
			virtualIPs[ipProtocol] = config.VirtualServiceIPv6
			virtualNodePortDNATIPs[ipProtocol] = config.VirtualNodePortDNATIPv6
			dnatCtZones[ipProtocol] = CtZoneV6
			snatCtZones[ipProtocol] = SNATCtZoneV6
			nodePortAddresses[ipProtocol] = serviceConfig.NodePortAddressesIPv6
			if serviceConfig.ServiceCIDRv6 != nil {
				serviceCIDRs[ipProtocol] = *serviceConfig.ServiceCIDRv6
			}
			if nodeConfig.PodIPv6CIDR != nil {
				localCIDRs[ipProtocol] = *nodeConfig.PodIPv6CIDR
			}
		}
	}

	return &featureService{
		cookieAllocator:        cookieAllocator,
		nodeIPChecker:          nodeIPChecker,
		ipProtocols:            ipProtocols,
		bridge:                 bridge,
		cachedFlows:            newFlowCategoryCache(),
		groupCache:             sync.Map{},
		gatewayIPs:             gatewayIPs,
		virtualIPs:             virtualIPs,
		virtualNodePortDNATIPs: virtualNodePortDNATIPs,
		dnatCtZones:            dnatCtZones,
		snatCtZones:            snatCtZones,
		nodePortAddresses:      nodePortAddresses,
		serviceCIDRs:           serviceCIDRs,
		localCIDRs:             localCIDRs,
		gatewayMAC:             nodeConfig.GatewayConfig.MAC,
		gatewayPort:            nodeConfig.GatewayConfig.OFPort,
		networkConfig:          networkConfig,
		enableAntreaPolicy:     enableAntreaPolicy,
		enableProxy:            enableProxy,
		proxyAll:               proxyAll,
		enableDSR:              enableDSR,
		connectUplinkToBridge:  connectUplinkToBridge,
		ctZoneSrcField:         getZoneSrcField(connectUplinkToBridge),
		category:               cookie.Service,
	}
}

// serviceNoEndpointFlow generates the flow to match the packets to Service without Endpoint and send them to controller.
func (f *featureService) serviceNoEndpointFlow() binding.Flow {
	return EndpointDNATTable.ofTable.BuildFlow(priorityNormal).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchRegMark(SvcNoEpRegMark).
		Action().SendToController([]byte{uint8(PacketInCategorySvcReject)}, false).
		Done()
}

func (f *featureService) initFlows() []*openflow15.FlowMod {
	var flows []binding.Flow
	if f.enableProxy {
		flows = append(flows, f.conntrackFlows()...)
		flows = append(flows, f.preRoutingClassifierFlows()...)
		flows = append(flows, f.l3FwdFlowToExternalEndpoint())
		flows = append(flows, f.gatewaySNATFlows()...)
		flows = append(flows, f.snatConntrackFlows()...)
		flows = append(flows, f.serviceNeedLBFlow())
		flows = append(flows, f.sessionAffinityReselectFlow())
		flows = append(flows, f.serviceNoEndpointFlow())
		flows = append(flows, f.l2ForwardOutputHairpinServiceFlow())
		if f.proxyAll {
			// This installs the flows to match the first packet of NodePort connection. The flows set a bit of a register
			// to mark the Service type of the packet as NodePort, and the mark is consumed in table serviceLBTable.
			flows = append(flows, f.nodePortMarkFlows()...)
		}
		if f.enableDSR {
			flows = append(flows, f.dsrServiceNoDNATFlows()...)
		}
	} else {
		// This installs the flows to enable Service connectivity. Upstream kube-proxy is leveraged to provide load-balancing,
		// and the flows installed by this method ensure that traffic sent from local Pods to any Service address can be
		// forwarded to the host gateway interface correctly, otherwise packets might be dropped by egress rules before
		// they are DNATed to backend Pods.
		flows = append(flows, f.serviceCIDRDNATFlows()...)
	}
	return GetFlowModMessages(flows, binding.AddMessage)
}

func (f *featureService) replayFlows() []*openflow15.FlowMod {
	return getCachedFlowMessages(f.cachedFlows)
}

func (f *featureService) replayGroups() []binding.OFEntry {
	var groups []binding.OFEntry
	f.groupCache.Range(func(id, value interface{}) bool {
		group := value.(binding.Group)
		group.Reset()
		groups = append(groups, group)
		return true
	})
	return groups
}

func (f *featureService) initGroups() []binding.OFEntry {
	return nil
}

func (f *featureService) replayMeters() []binding.OFEntry {
	return nil
}
