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
	"fmt"
	"net"
	"sync"

	"antrea.io/libOpenflow/openflow15"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/openflow/cookie"
	"antrea.io/antrea/pkg/agent/types"
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

type featureMulticast struct {
	cookieAllocator cookie.Allocator
	ipProtocols     []binding.Protocol
	bridge          binding.Bridge
	gatewayPort     uint32
	encapEnabled    bool
	tunnelPort      uint32

	cachedFlows        *flowCategoryCache
	groupCache         sync.Map
	enableAntreaPolicy bool

	category cookie.Category
}

func (f *featureMulticast) getFeatureName() string {
	return "Multicast"
}

func newFeatureMulticast(cookieAllocator cookie.Allocator, ipProtocols []binding.Protocol, bridge binding.Bridge, anpEnabled bool, gwPort uint32, encapEnabled bool, tunnelPort uint32) *featureMulticast {
	return &featureMulticast{
		cookieAllocator:    cookieAllocator,
		ipProtocols:        ipProtocols,
		cachedFlows:        newFlowCategoryCache(),
		bridge:             bridge,
		category:           cookie.Multicast,
		groupCache:         sync.Map{},
		enableAntreaPolicy: anpEnabled,
		gatewayPort:        gwPort,
		encapEnabled:       encapEnabled,
		tunnelPort:         tunnelPort,
	}
}

func multicastPipelineClassifyFlow(cookieID uint64, pipeline binding.Pipeline) binding.Flow {
	targetTable := pipeline.GetFirstTable()
	return PipelineIPClassifierTable.ofTable.BuildFlow(priorityHigh).
		Cookie(cookieID).
		MatchProtocol(binding.ProtocolIP).
		MatchDstIPNet(*types.McastCIDR).
		Action().ResubmitToTables(targetTable.GetID()).
		Done()
}

func (f *featureMulticast) initFlows() []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	return f.multicastOutputFlows(cookieID)
}

func (f *featureMulticast) replayFlows() []binding.Flow {
	// Get cached flows.
	return getCachedFlows(f.cachedFlows)
}

func (f *featureMulticast) multicastReceiversGroup(groupID binding.GroupIDType, tableID uint8, ports []uint32, remoteIPs []net.IP) error {
	group := f.bridge.CreateGroupTypeAll(groupID).ResetBuckets()
	for i := range ports {
		group = group.Bucket().
			LoadToRegField(OFPortFoundRegMark.GetField(), OFPortFoundRegMark.GetValue()).
			LoadToRegField(TargetOFPortField, ports[i]).
			ResubmitToTable(tableID).
			Done()
	}
	for _, ip := range remoteIPs {
		group = group.Bucket().
			LoadToRegField(OFPortFoundRegMark.GetField(), OFPortFoundRegMark.GetValue()).
			LoadToRegField(TargetOFPortField, f.tunnelPort).
			SetTunnelDst(ip).
			ResubmitToTable(MulticastOutputTable.GetID()).
			Done()
	}

	_, installed := f.groupCache.Load(groupID)
	if !installed {
		if err := group.Add(); err != nil {
			return fmt.Errorf("error when installing Multicast receiver Group %d: %w", groupID, err)
		}
	} else {
		if err := group.Modify(); err != nil {
			return fmt.Errorf("error when modifying Multicast receiver Group %d: %w", groupID, err)
		}
	}
	f.groupCache.Store(groupID, group)
	return nil
}

func (f *featureMulticast) multicastOutputFlows(cookieID uint64) []binding.Flow {
	flows := []binding.Flow{
		MulticastOutputTable.ofTable.BuildFlow(priorityNormal).
			Cookie(cookieID).
			MatchRegMark(OFPortFoundRegMark).
			Action().OutputToRegField(TargetOFPortField).
			Done(),
	}
	if f.encapEnabled {
		// When running with encap mode, drop the multicast packets if it is received from tunnel port and expected to
		// output to antrea-gw0, or received from antrea-gw0 and expected to output to tunnel. These flows are used to
		// avoid duplication on packet forwarding. For example, if the packet is received on tunnel port, it means
		// the sender is a Pod on other Node, then the packet is already sent to external via antrea-gw0 on the source
		// Node. On the reverse, if the packet is received on antrea-gw0, it means the sender is from external, then
		// the Pod receivers on other Nodes should also receive the packets from the underlay network.
		flows = append(flows, MulticastOutputTable.ofTable.BuildFlow(priorityHigh).
			Cookie(cookieID).
			MatchRegMark(FromTunnelRegMark).
			MatchRegMark(OFPortFoundRegMark).
			MatchRegFieldWithValue(TargetOFPortField, config.HostGatewayOFPort).
			Action().Drop().
			Done(),
			MulticastOutputTable.ofTable.BuildFlow(priorityHigh).
				Cookie(cookieID).
				MatchRegMark(FromGatewayRegMark).
				MatchRegMark(OFPortFoundRegMark).
				MatchRegFieldWithValue(TargetOFPortField, config.DefaultTunOFPort).
				Action().Drop().
				Done(),
		)
	}
	return flows
}

func (f *featureMulticast) multicastSkipIGMPMetricFlows() []binding.Flow {
	cookieID := f.cookieAllocator.Request(f.category).Raw()
	flows := make([]binding.Flow, 0, 2)
	for _, t := range []*Table{MulticastIngressPodMetricTable, MulticastEgressPodMetricTable} {
		flows = append(flows, t.ofTable.BuildFlow(priorityHigh).
			Cookie(cookieID).
			MatchProtocol(binding.ProtocolIGMP).
			Action().NextTable().
			Done())
	}
	return flows
}

func (f *featureMulticast) multicastPodMetricFlows(podIP net.IP, podOFPort uint32) []binding.Flow {
	ipProtocol := getIPProtocol(podIP)
	return []binding.Flow{
		// Generates the flows to forward multicast egress packets before outputting to MulticastOutputTable.
		// It matches source IP with IP of the local sender Pod.
		MulticastEgressPodMetricTable.ofTable.BuildFlow(priorityNormal).
			Cookie(f.cookieAllocator.Request(f.category).Raw()).
			MatchProtocol(ipProtocol).
			MatchSrcIP(podIP).
			Action().NextTable().
			Done(),
		// Generates the flows to collect multicast ingress packets metrics before outputting to MulticastOutputTable.
		// It matches TargetOFPortField with the OFPort of a multicast receiver Pod.
		MulticastIngressPodMetricTable.ofTable.BuildFlow(priorityNormal).
			Cookie(f.cookieAllocator.Request(f.category).Raw()).
			MatchProtocol(binding.ProtocolIP).
			MatchRegFieldWithValue(TargetOFPortField, podOFPort).
			Action().NextTable().
			Done(),
	}
}

func (f *featureMulticast) replayGroups() {
	var groups []binding.OFEntry
	f.groupCache.Range(func(id, value interface{}) bool {
		group := value.(binding.Group)
		group.Reset()
		groups = append(groups, group)
		return true
	})
	if err := f.bridge.AddOFEntriesInBundle(groups, nil, nil); err != nil {
		klog.ErrorS(err, "error when replaying cached groups for Multicast")
	}
}

func (f *featureMulticast) multicastRemoteReportFlows(groupID binding.GroupIDType, firstMulticastTable binding.Table) []binding.Flow {
	return []binding.Flow{
		// This flow outputs the IGMP report message sent from Antrea Agent to an OpenFlow group which is expected to
		// broadcast to all the other Nodes in the cluster. The multicast groups in side the IGMP report message
		// include the ones local Pods have joined in.
		MulticastRoutingTable.ofTable.BuildFlow(priorityHigh).
			Cookie(f.cookieAllocator.Request(f.category).Raw()).
			MatchProtocol(binding.ProtocolIGMP).
			MatchInPort(openflow15.P_CONTROLLER).
			Action().LoadRegMark(CustomReasonIGMPRegMark).
			Action().Group(groupID).
			Done(),
		// This flow ensures the IGMP report message sent from Antrea Agent to bypass the check in SpoofGuardTable.
		ClassifierTable.ofTable.BuildFlow(priorityNormal).
			Cookie(f.cookieAllocator.Request(f.category).Raw()).
			MatchInPort(openflow15.P_CONTROLLER).
			Action().GotoTable(SpoofGuardTable.GetNext()).
			Done(),
		// This flow ensures the multicast packet sent from a different Node via the tunnel port to enter Multicast
		// pipeline.
		ClassifierTable.ofTable.BuildFlow(priorityHigh).
			Cookie(f.cookieAllocator.Request(f.category).Raw()).
			MatchInPort(f.tunnelPort).
			MatchProtocol(binding.ProtocolIP).
			MatchDstIPNet(*types.McastCIDR).
			Action().LoadRegMark(FromTunnelRegMark).
			Action().GotoTable(firstMulticastTable.GetID()).
			Done(),
	}
}
