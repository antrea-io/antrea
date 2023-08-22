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

	"antrea.io/antrea/pkg/agent/config"
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

type ipStack int

const (
	ipv4Only ipStack = iota
	ipv6Only
	dualStack
)

var (
	defaultOptions = clientOptions{
		enableProxy:           true,
		enableAntreaPolicy:    true,
		proxyAll:              false,
		connectUplinkToBridge: false,
		enableMulticast:       false,
		enableTrafficControl:  false,
		enableMulticluster:    false,
		enableL7NetworkPolicy: false,
	}
)

func newTestFeaturePodConnectivity(ipProtocols []binding.Protocol, options ...clientOptionsFn) *featurePodConnectivity {
	o := defaultOptions
	for _, fn := range options {
		fn(&o)
	}
	return &featurePodConnectivity{
		ipProtocols:           ipProtocols,
		connectUplinkToBridge: o.connectUplinkToBridge,
		enableMulticast:       o.enableMulticast,
		enableTrafficControl:  o.enableTrafficControl,
		proxyAll:              o.proxyAll,
	}
}

func newTestFeatureNetworkPolicy(nodeType config.NodeType, options ...clientOptionsFn) *featureNetworkPolicy {
	o := defaultOptions
	for _, fn := range options {
		fn(&o)
	}
	return &featureNetworkPolicy{
		nodeType:              nodeType,
		enableMulticast:       o.enableMulticast,
		enableAntreaPolicy:    o.enableAntreaPolicy,
		enableL7NetworkPolicy: o.enableL7NetworkPolicy,
	}
}

func newTestFeatureService(options ...clientOptionsFn) *featureService {
	o := defaultOptions
	for _, fn := range options {
		fn(&o)
	}
	return &featureService{
		enableAntreaPolicy: o.enableAntreaPolicy,
		enableProxy:        o.enableProxy,
		proxyAll:           o.proxyAll,
	}
}

func newTestFeatureEgress() *featureEgress {
	return &featureEgress{}
}

func newTestFeatureMulticast() *featureMulticast {
	return &featureMulticast{}
}

func newTestFeatureExternalNodeConnectivity() *featureExternalNodeConnectivity {
	return &featureExternalNodeConnectivity{}
}

func TestBuildPipeline(t *testing.T) {
	ipStackMap := map[ipStack][]binding.Protocol{
		ipv4Only:  {binding.ProtocolIP},
		ipv6Only:  {binding.ProtocolIPv6},
		dualStack: {binding.ProtocolIP, binding.ProtocolIPv6},
	}
	for _, tc := range []struct {
		name           string
		ipStack        ipStack
		features       []feature
		expectedTables map[binding.PipelineID][]*Table
	}{
		{
			name:    "K8s Node, dual stack, with default options",
			ipStack: dualStack,
			features: []feature{
				newTestFeaturePodConnectivity(ipStackMap[dualStack]),
				newTestFeatureNetworkPolicy(config.K8sNode),
				newTestFeatureService(),
				newTestFeatureEgress(),
			},
			expectedTables: map[binding.PipelineID][]*Table{
				pipelineRoot: {
					PipelineRootClassifierTable,
				},
				pipelineIP: {
					ClassifierTable,
					SpoofGuardTable,
					IPv6Table,
					UnSNATTable,
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
					SNATMarkTable,
					SNATTable,
					L2ForwardingCalcTable,
					AntreaPolicyIngressRuleTable,
					IngressRuleTable,
					IngressDefaultTable,
					IngressMetricTable,
					ConntrackCommitTable,
					OutputTable,
				},
				pipelineARP: {
					ARPSpoofGuardTable,
					ARPResponderTable,
				},
			},
		},
		{
			name:    "K8s Node, IPv6 only, with default options",
			ipStack: ipv6Only,
			features: []feature{
				newTestFeaturePodConnectivity(ipStackMap[ipv6Only]),
				newTestFeatureNetworkPolicy(config.K8sNode),
				newTestFeatureService(),
				newTestFeatureEgress(),
			},
			expectedTables: map[binding.PipelineID][]*Table{
				pipelineRoot: {
					PipelineRootClassifierTable,
				},
				pipelineIP: {
					ClassifierTable,
					SpoofGuardTable,
					IPv6Table,
					UnSNATTable,
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
					SNATMarkTable,
					SNATTable,
					L2ForwardingCalcTable,
					AntreaPolicyIngressRuleTable,
					IngressRuleTable,
					IngressDefaultTable,
					IngressMetricTable,
					ConntrackCommitTable,
					OutputTable,
				},
			},
		},
		{
			name:    "K8s Node, IPv4 only, with default options",
			ipStack: ipv6Only,
			features: []feature{
				newTestFeaturePodConnectivity(ipStackMap[ipv4Only]),
				newTestFeatureNetworkPolicy(config.K8sNode),
				newTestFeatureService(),
				newTestFeatureEgress(),
			},
			expectedTables: map[binding.PipelineID][]*Table{
				pipelineRoot: {
					PipelineRootClassifierTable,
				},
				pipelineIP: {
					ClassifierTable,
					SpoofGuardTable,
					UnSNATTable,
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
					SNATMarkTable,
					SNATTable,
					L2ForwardingCalcTable,
					AntreaPolicyIngressRuleTable,
					IngressRuleTable,
					IngressDefaultTable,
					IngressMetricTable,
					ConntrackCommitTable,
					OutputTable,
				},
			},
		},
		{
			name:    "K8s Node, IPv4 only, with TrafficControl and connectUplinkToBridge enabled",
			ipStack: ipv6Only,
			features: []feature{
				newTestFeaturePodConnectivity(ipStackMap[ipv4Only], enableTrafficControl, enableConnectUplinkToBridge),
				newTestFeatureNetworkPolicy(config.K8sNode),
				newTestFeatureService(),
				newTestFeatureEgress(),
			},
			expectedTables: map[binding.PipelineID][]*Table{
				pipelineRoot: {
					PipelineRootClassifierTable,
				},
				pipelineIP: {
					ClassifierTable,
					SpoofGuardTable,
					UnSNATTable,
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
					SNATMarkTable,
					SNATTable,
					L2ForwardingCalcTable,
					TrafficControlTable,
					AntreaPolicyIngressRuleTable,
					IngressRuleTable,
					IngressDefaultTable,
					IngressMetricTable,
					ConntrackCommitTable,
					VLANTable,
					OutputTable,
				},
			},
		},
		{
			name:    "K8s Node, IPv4 only, with L7NetworkPolicy enabled",
			ipStack: ipv6Only,
			features: []feature{
				newTestFeaturePodConnectivity(ipStackMap[ipv4Only]),
				newTestFeatureNetworkPolicy(config.K8sNode, enableL7NetworkPolicy),
				newTestFeatureService(),
				newTestFeatureEgress(),
			},
			expectedTables: map[binding.PipelineID][]*Table{
				pipelineRoot: {
					PipelineRootClassifierTable,
				},
				pipelineIP: {
					ClassifierTable,
					SpoofGuardTable,
					UnSNATTable,
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
					SNATMarkTable,
					SNATTable,
					L2ForwardingCalcTable,
					TrafficControlTable,
					AntreaPolicyIngressRuleTable,
					IngressRuleTable,
					IngressDefaultTable,
					IngressMetricTable,
					ConntrackCommitTable,
					OutputTable,
				},
			},
		},
		{
			name:    "K8s Node, IPv4 only, with AntreaPolicy disabled",
			ipStack: ipv6Only,
			features: []feature{
				newTestFeaturePodConnectivity(ipStackMap[ipv4Only]),
				newTestFeatureNetworkPolicy(config.K8sNode, disableAntreaPolicy),
				newTestFeatureService(),
				newTestFeatureEgress(),
			},
			expectedTables: map[binding.PipelineID][]*Table{
				pipelineRoot: {
					PipelineRootClassifierTable,
				},
				pipelineIP: {
					ClassifierTable,
					SpoofGuardTable,
					UnSNATTable,
					ConntrackTable,
					ConntrackStateTable,
					PreRoutingClassifierTable,
					SessionAffinityTable,
					ServiceLBTable,
					EndpointDNATTable,
					EgressRuleTable,
					EgressDefaultTable,
					EgressMetricTable,
					L3ForwardingTable,
					EgressMarkTable,
					L3DecTTLTable,
					SNATMarkTable,
					SNATTable,
					L2ForwardingCalcTable,
					IngressRuleTable,
					IngressDefaultTable,
					IngressMetricTable,
					ConntrackCommitTable,
					OutputTable,
				},
			},
		},
		{
			name:    "K8s Node, IPv4 only, with AntreaProxy disabled",
			ipStack: ipv4Only,
			features: []feature{
				newTestFeaturePodConnectivity(ipStackMap[ipv4Only]),
				newTestFeatureNetworkPolicy(config.K8sNode),
				newTestFeatureService(disableProxy),
				newTestFeatureEgress(),
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
					OutputTable,
				},
				pipelineARP: {
					ARPSpoofGuardTable,
					ARPResponderTable,
				},
			},
		},
		{
			name:    "K8s Node, IPv4 only, with proxyAll enabled",
			ipStack: ipv4Only,
			features: []feature{
				newTestFeaturePodConnectivity(ipStackMap[ipv4Only]),
				newTestFeatureNetworkPolicy(config.K8sNode),
				newTestFeatureService(enableProxyAll),
				newTestFeatureEgress(),
			},
			expectedTables: map[binding.PipelineID][]*Table{
				pipelineRoot: {
					PipelineRootClassifierTable,
				},
				pipelineIP: {
					ClassifierTable,
					SpoofGuardTable,
					UnSNATTable,
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
					SNATMarkTable,
					SNATTable,
					L2ForwardingCalcTable,
					AntreaPolicyIngressRuleTable,
					IngressRuleTable,
					IngressDefaultTable,
					IngressMetricTable,
					ConntrackCommitTable,
					OutputTable,
				},
				pipelineARP: {
					ARPSpoofGuardTable,
					ARPResponderTable,
				},
			},
		},
		{
			name:    "K8s Node, IPv4 only, with multicast enabled",
			ipStack: ipv4Only,
			features: []feature{
				newTestFeaturePodConnectivity(ipStackMap[ipv4Only], enableMulticast),
				newTestFeatureNetworkPolicy(config.K8sNode, enableMulticast),
				newTestFeatureService(),
				newTestFeatureMulticast(),
			},
			expectedTables: map[binding.PipelineID][]*Table{
				pipelineRoot: {
					PipelineRootClassifierTable,
				},
				pipelineIP: {
					ClassifierTable,
					SpoofGuardTable,
					PipelineIPClassifierTable,
					UnSNATTable,
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
					L3DecTTLTable,
					SNATMarkTable,
					SNATTable,
					L2ForwardingCalcTable,
					AntreaPolicyIngressRuleTable,
					IngressRuleTable,
					IngressDefaultTable,
					IngressMetricTable,
					ConntrackCommitTable,
					OutputTable,
				},
				pipelineARP: {
					ARPSpoofGuardTable,
					ARPResponderTable,
				},
				pipelineMulticast: {
					MulticastEgressRuleTable,
					MulticastEgressMetricTable,
					MulticastEgressPodMetricTable,

					MulticastRoutingTable,

					MulticastIngressRuleTable,
					MulticastIngressMetricTable,
					MulticastIngressPodMetricTable,

					MulticastOutputTable,
				},
			},
		},
		{
			name: "External Node, IPv4 only",
			features: []feature{
				newTestFeatureExternalNodeConnectivity(),
				newTestFeatureNetworkPolicy(config.ExternalNode),
			},
			expectedTables: map[binding.PipelineID][]*Table{
				pipelineRoot: {
					PipelineRootClassifierTable,
				},
				pipelineIP: {
					ConntrackTable,
					ConntrackStateTable,
					EgressSecurityClassifierTable,
					AntreaPolicyEgressRuleTable,
					EgressRuleTable,
					EgressDefaultTable,
					EgressMetricTable,
					L2ForwardingCalcTable,
					IngressSecurityClassifierTable,
					AntreaPolicyIngressRuleTable,
					IngressRuleTable,
					IngressDefaultTable,
					IngressMetricTable,
					ConntrackCommitTable,
					OutputTable,
				},
				pipelineNonIP: {
					NonIPTable,
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pipelineRequiredTablesMap := make(map[binding.PipelineID]map[*Table]struct{})
			for pipelineID := range tc.expectedTables {
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
			resetPipelines()
		})
	}
}

func resetPipelines() {
	objs := tableCache.List()
	for i := 0; i < len(objs); i++ {
		tableCache.Delete(objs[i])
	}
	binding.ResetTableID()
}
