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
	"antrea.io/antrea/pkg/agent/openflow/cookie"
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

type featureEgress struct {
	cookieAllocator cookie.Allocator
	ipProtocols     []binding.Protocol

	cachedFlows *flowCategoryCache
	cachedMeter sync.Map

	exceptCIDRs map[binding.Protocol][]net.IPNet
	nodeIPs     map[binding.Protocol]net.IP
	gatewayMAC  net.HardwareAddr

	category                   cookie.Category
	enableEgressTrafficShaping bool

	trafficEncapMode config.TrafficEncapModeType

	virtualIPs  map[binding.Protocol]net.IP
	snatCtZones map[binding.Protocol]int
}

func (f *featureEgress) getFeatureName() string {
	return "Egress"
}

func newFeatureEgress(cookieAllocator cookie.Allocator,
	ipProtocols []binding.Protocol,
	nodeConfig *config.NodeConfig,
	egressConfig *config.EgressConfig,
	enableEgressTrafficShaping bool,
	trafficEncapMode config.TrafficEncapModeType) *featureEgress {
	exceptCIDRs := make(map[binding.Protocol][]net.IPNet)
	for _, cidr := range egressConfig.ExceptCIDRs {
		if cidr.IP.To4() == nil {
			exceptCIDRs[binding.ProtocolIPv6] = append(exceptCIDRs[binding.ProtocolIPv6], cidr)
		} else {
			exceptCIDRs[binding.ProtocolIP] = append(exceptCIDRs[binding.ProtocolIP], cidr)
		}
	}

	nodeIPs := make(map[binding.Protocol]net.IP)
	virtualIPs := make(map[binding.Protocol]net.IP)
	snatCtZones := make(map[binding.Protocol]int)
	for _, ipProtocol := range ipProtocols {
		switch ipProtocol {
		case binding.ProtocolIP:
			nodeIPs[ipProtocol] = nodeConfig.NodeIPv4Addr.IP
			virtualIPs[ipProtocol] = config.VirtualEgressSNATIPv4
			snatCtZones[ipProtocol] = SNATCtZone
		case binding.ProtocolIPv6:
			nodeIPs[ipProtocol] = nodeConfig.NodeIPv6Addr.IP
			virtualIPs[ipProtocol] = config.VirtualEgressSNATIPv6
			snatCtZones[ipProtocol] = SNATCtZoneV6
		}
	}

	return &featureEgress{
		cachedFlows:                newFlowCategoryCache(),
		cachedMeter:                sync.Map{},
		cookieAllocator:            cookieAllocator,
		exceptCIDRs:                exceptCIDRs,
		ipProtocols:                ipProtocols,
		nodeIPs:                    nodeIPs,
		gatewayMAC:                 nodeConfig.GatewayConfig.MAC,
		category:                   cookie.Egress,
		enableEgressTrafficShaping: enableEgressTrafficShaping,
		trafficEncapMode:           trafficEncapMode,
		virtualIPs:                 virtualIPs,
		snatCtZones:                snatCtZones,
	}
}

func (f *featureEgress) initFlows() []*openflow15.FlowMod {
	// This installs the flows to enable Pods to communicate to the external IP addresses. The flows identify the packets
	// from local Pods to the external IP address, and mark the packets to be SNAT'd with the configured SNAT IPs.
	initialFlows := f.externalFlows()
	if f.enableEgressTrafficShaping {
		initialFlows = append(initialFlows, f.egressQoSDefaultFlow())
	}
	if f.trafficEncapMode.IsHybrid() {
		initialFlows = append(initialFlows, f.unSNATConntrackFlows()...)
	}
	return GetFlowModMessages(initialFlows, binding.AddMessage)
}

func (f *featureEgress) replayFlows() []*openflow15.FlowMod {
	return getCachedFlowMessages(f.cachedFlows)
}

func (f *featureEgress) initGroups() []binding.OFEntry {
	return nil
}

func (f *featureEgress) replayGroups() []binding.OFEntry {
	return nil
}

func (f *featureEgress) replayMeters() []binding.OFEntry {
	var meters []binding.OFEntry
	f.cachedMeter.Range(func(id, value interface{}) bool {
		meter := value.(binding.Meter)
		meter.Reset()
		meters = append(meters, meter)
		return true
	})
	return meters
}

func (f *featureEgress) unSNATConntrackFlows() []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	var flows []binding.Flow
	for _, ipProtocol := range f.ipProtocols {
		flows = append(flows, UnSNATTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchProtocol(ipProtocol).
			MatchDstIP(f.virtualIPs[ipProtocol]).
			Action().CT(false, ConntrackStateTable.GetID(), f.snatCtZones[ipProtocol], nil).
			NAT().
			CTDone().
			Done())
	}
	return flows
}

// l3FwdFlowsFromGWToRemoteViaTun generates the flows to match the packets sourced from gateway and destined for remote
// Pods via tunnel in hybrid mode.
func (f *featureEgress) l3FwdFlowsFromGWToRemoteViaTun(localGatewayMAC net.HardwareAddr, peerSubnet net.IPNet, tunnelPeer net.IP) []binding.Flow {
	ipProtocol := getIPProtocol(peerSubnet.IP)
	flow := L3ForwardingTable.ofTable.BuildFlow(priorityNormal + 1).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchProtocol(ipProtocol).
		MatchRegMark(FromGatewayRegMark).
		MatchDstIPNet(peerSubnet).
		Action().SetSrcMAC(localGatewayMAC).  // Rewrite src MAC to local gateway MAC.
		Action().SetDstMAC(GlobalVirtualMAC). // Rewrite dst MAC to virtual MAC.
		Action().SetTunnelDst(tunnelPeer).    // Flow based tunnel. Set tunnel destination.
		Action().LoadRegMark(ToTunnelRegMark).
		Action().GotoTable(L3DecTTLTable.GetID()).
		Done()
	return []binding.Flow{flow}
}

func (f *featureEgress) snatConntrackFlowFromTun(peerSubnet net.IPNet) binding.Flow {
	ipProtocol := getIPProtocol(peerSubnet.IP)
	return UnSNATTable.ofTable.BuildFlow(priorityNormal).
		Cookie(f.cookieAllocator.Request(f.category).Raw()).
		MatchProtocol(ipProtocol).
		MatchRegMark(FromTunnelRegMark).
		MatchSrcIPNet(peerSubnet).
		Action().CT(false, ConntrackStateTable.GetID(), f.snatCtZones[ipProtocol], nil).
		NAT().
		CTDone().
		Done()
}
