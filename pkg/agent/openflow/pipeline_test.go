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
	"testing"

	"github.com/stretchr/testify/require"

	binding "antrea.io/antrea/pkg/ovs/openflow"
)

type ipStack int

const (
	ipv4Only ipStack = iota
	ipv6Only
	dualStack
)

func TestBuildPipeline(t *testing.T) {
	ipStackMap := map[ipStack][]binding.Protocol{
		ipv4Only:  {binding.ProtocolIP},
		ipv6Only:  {binding.ProtocolIPv6},
		dualStack: {binding.ProtocolIP, binding.ProtocolIPv6},
	}
	for _, tc := range []struct {
		ipStack        ipStack
		features       []feature
		expectedTables map[binding.PipelineID][]*Table
	}{
		{
			ipStack: dualStack,
			features: []feature{
				&featurePodConnectivity{ipProtocols: ipStackMap[dualStack]},
				&featureNetworkPolicy{enableAntreaPolicy: true},
				&featureService{enableProxy: true, proxyAll: true},
				&featureEgress{},
			},
			expectedTables: map[binding.PipelineID][]*Table{
				pipelineRoot: {
					PipelineRootClassifierTable,
				},
				pipelineIP: {
					ClassifierTable,
					SpoofGuardTable,
					IPv6Table,
					SNATConntrackTable,
					ConntrackTable,
					ConntrackStateTable,
					PreRoutingClassifierTable,
					NodePortMarkTable,
					SessionAffinityTable,
					ServiceLBTable,
					EndpointDNATTable,
					AntreaPolicyEgressRuleTable,
					EgressRuleTable,
					EgressDefaultTable,
					EgressMetricTable,
					L3ForwardingTable,
					EgressMarkTable,
					L3DecTTLTable,
					ServiceMarkTable,
					SNATConntrackCommitTable,
					L2ForwardingCalcTable,
					AntreaPolicyIngressRuleTable,
					IngressRuleTable,
					IngressDefaultTable,
					IngressMetricTable,
					ConntrackCommitTable,
					L2ForwardingOutTable,
				},
				pipelineARP: {
					ARPSpoofGuardTable,
					ARPResponderTable,
				},
			},
		},
		{
			ipStack: ipv6Only,
			features: []feature{
				&featurePodConnectivity{ipProtocols: ipStackMap[ipv6Only]},
				&featureNetworkPolicy{enableAntreaPolicy: true},
				&featureService{enableProxy: true, proxyAll: true},
				&featureEgress{},
			},
			expectedTables: map[binding.PipelineID][]*Table{
				pipelineRoot: {
					PipelineRootClassifierTable,
				},
				pipelineIP: {
					ClassifierTable,
					SpoofGuardTable,
					IPv6Table,
					SNATConntrackTable,
					ConntrackTable,
					ConntrackStateTable,
					PreRoutingClassifierTable,
					NodePortMarkTable,
					SessionAffinityTable,
					ServiceLBTable,
					EndpointDNATTable,
					AntreaPolicyEgressRuleTable,
					EgressRuleTable,
					EgressDefaultTable,
					EgressMetricTable,
					L3ForwardingTable,
					EgressMarkTable,
					L3DecTTLTable,
					ServiceMarkTable,
					SNATConntrackCommitTable,
					L2ForwardingCalcTable,
					AntreaPolicyIngressRuleTable,
					IngressRuleTable,
					IngressDefaultTable,
					IngressMetricTable,
					ConntrackCommitTable,
					L2ForwardingOutTable,
				},
			},
		},
		{
			ipStack: ipv4Only,
			features: []feature{
				&featurePodConnectivity{ipProtocols: ipStackMap[ipv4Only]},
				&featureNetworkPolicy{enableAntreaPolicy: true},
				&featureService{enableProxy: false},
				&featureEgress{},
			},
			expectedTables: map[binding.PipelineID][]*Table{
				pipelineRoot: {
					PipelineRootClassifierTable,
				},
				pipelineIP: {
					ClassifierTable,
					SpoofGuardTable,
					ConntrackTable,
					ConntrackStateTable,
					DNATTable,
					AntreaPolicyEgressRuleTable,
					EgressRuleTable,
					EgressDefaultTable,
					EgressMetricTable,
					L3ForwardingTable,
					L3DecTTLTable,
					L2ForwardingCalcTable,
					AntreaPolicyIngressRuleTable,
					IngressRuleTable,
					IngressDefaultTable,
					IngressMetricTable,
					ConntrackCommitTable,
					L2ForwardingOutTable,
				},
				pipelineARP: {
					ARPSpoofGuardTable,
					ARPResponderTable,
				},
			},
		},
		{
			ipStack: ipv4Only,
			features: []feature{
				&featurePodConnectivity{ipProtocols: ipStackMap[ipv4Only]},
				&featureNetworkPolicy{enableAntreaPolicy: true},
				&featureService{enableProxy: true, proxyAll: false},
				&featureEgress{},
			},
			expectedTables: map[binding.PipelineID][]*Table{
				pipelineRoot: {
					PipelineRootClassifierTable,
				},
				pipelineIP: {
					ClassifierTable,
					SpoofGuardTable,
					SNATConntrackTable,
					ConntrackTable,
					ConntrackStateTable,
					PreRoutingClassifierTable,
					SessionAffinityTable,
					ServiceLBTable,
					EndpointDNATTable,
					AntreaPolicyEgressRuleTable,
					EgressRuleTable,
					EgressDefaultTable,
					EgressMetricTable,
					L3ForwardingTable,
					EgressMarkTable,
					L3DecTTLTable,
					ServiceMarkTable,
					SNATConntrackCommitTable,
					L2ForwardingCalcTable,
					AntreaPolicyIngressRuleTable,
					IngressRuleTable,
					IngressDefaultTable,
					IngressMetricTable,
					ConntrackCommitTable,
					L2ForwardingOutTable,
				},
				pipelineARP: {
					ARPSpoofGuardTable,
					ARPResponderTable,
				},
			},
		},
	} {
		pipelineIDs := []binding.PipelineID{pipelineRoot, pipelineIP}
		if tc.ipStack != ipv6Only {
			pipelineIDs = append(pipelineIDs, pipelineARP)
		}
		pipelineRequiredTablesMap := make(map[binding.PipelineID]map[*Table]struct{})
		for _, pipelineID := range pipelineIDs {
			pipelineRequiredTablesMap[pipelineID] = make(map[*Table]struct{})
		}
		pipelineRequiredTablesMap[pipelineRoot][PipelineRootClassifierTable] = struct{}{}
		for _, f := range tc.features {
			for _, table := range f.getRequiredTables() {
				if _, ok := pipelineRequiredTablesMap[table.pipeline]; ok {
					pipelineRequiredTablesMap[table.pipeline][table] = struct{}{}
				}
			}
		}

		for pipelineID := firstPipeline; pipelineID <= lastPipeline; pipelineID++ {
			if _, ok := pipelineRequiredTablesMap[pipelineID]; !ok {
				continue
			}
			var requiredTables []*Table
			for _, table := range tableOrderCache[pipelineID] {
				if _, ok := pipelineRequiredTablesMap[pipelineID][table]; ok {
					requiredTables = append(requiredTables, table)
				}
			}
			generatePipeline(pipelineID, requiredTables)

			tables := tc.expectedTables[pipelineID]
			for i := 0; i < len(tables)-1; i++ {
				require.NotNil(t, tables[i].ofTable, "table %q should be initialized", tables[i].name)
				require.Less(t, tables[i].GetID(), tables[i+1].GetID(), fmt.Sprintf("id of table %q should less than that of table %q", tables[i].GetName(), tables[i+1].GetName()))
			}
			require.NotNil(t, tables[len(tables)-1].ofTable, "table %q should be initialized", tables[len(tables)-1].name)
		}
		reset()
	}
}

func reset() {
	objs := tableCache.List()
	for i := 0; i < len(objs); i++ {
		tableCache.Delete(objs[i])
	}
	binding.ResetTableID()
}
