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

	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/openflow/cookie"
	"antrea.io/antrea/pkg/agent/types"
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

type featureMulticast struct {
	cookieAllocator cookie.Allocator
	ipProtocols     []binding.Protocol
	bridge          binding.Bridge

	cachedFlows        *flowCategoryCache
	groupCache         sync.Map
	enableAntreaPolicy bool

	category cookie.Category
}

func (f *featureMulticast) getFeatureName() string {
	return "Multicast"
}

func newFeatureMulticast(cookieAllocator cookie.Allocator, ipProtocols []binding.Protocol, bridge binding.Bridge, anpEnabled bool) *featureMulticast {
	return &featureMulticast{
		cookieAllocator:    cookieAllocator,
		ipProtocols:        ipProtocols,
		cachedFlows:        newFlowCategoryCache(),
		bridge:             bridge,
		category:           cookie.Multicast,
		groupCache:         sync.Map{},
		enableAntreaPolicy: anpEnabled,
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
	return []binding.Flow{
		f.multicastOutputFlow(cookieID),
	}
}

func (f *featureMulticast) replayFlows() []binding.Flow {
	// Get cached flows.
	return getCachedFlows(f.cachedFlows)
}

func (f *featureMulticast) multicastReceiversGroup(groupID binding.GroupIDType, tableID uint8, ports ...uint32) error {
	group := f.bridge.CreateGroupTypeAll(groupID).ResetBuckets()
	for i := range ports {
		group = group.Bucket().
			LoadToRegField(OFPortFoundRegMark.GetField(), OFPortFoundRegMark.GetValue()).
			LoadToRegField(TargetOFPortField, ports[i]).
			ResubmitToTable(tableID).
			Done()
	}
	if err := group.Add(); err != nil {
		return fmt.Errorf("error when installing Multicast receiver Group: %w", err)
	}
	f.groupCache.Store(groupID, group)
	return nil
}

func (f *featureMulticast) multicastOutputFlow(cookieID uint64) binding.Flow {
	return MulticastOutputTable.ofTable.BuildFlow(priorityNormal).
		Cookie(cookieID).
		MatchRegMark(OFPortFoundRegMark).
		Action().OutputToRegField(TargetOFPortField).
		Done()
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
	f.groupCache.Range(func(id, value interface{}) bool {
		group := value.(binding.Group)
		group.Reset()
		if err := group.Add(); err != nil {
			klog.ErrorS(err, "Error when replaying cached group", "group", id)
		}
		return true
	})
}
