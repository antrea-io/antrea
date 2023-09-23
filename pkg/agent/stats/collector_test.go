// Copyright 2020 Antrea Authors
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

package stats

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"k8s.io/apimachinery/pkg/types"

	oftest "antrea.io/antrea/pkg/agent/openflow/testing"
	agenttypes "antrea.io/antrea/pkg/agent/types"
	cpv1beta "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	statsv1alpha1 "antrea.io/antrea/pkg/apis/stats/v1alpha1"
	queriertest "antrea.io/antrea/pkg/querier/testing"
)

var (
	np1 = cpv1beta.NetworkPolicyReference{
		Type:      cpv1beta.K8sNetworkPolicy,
		Namespace: "foo",
		Name:      "bar",
		UID:       "uid1",
	}
	np2 = cpv1beta.NetworkPolicyReference{
		Type:      cpv1beta.K8sNetworkPolicy,
		Namespace: "foo",
		Name:      "baz",
		UID:       "uid2",
	}
	acnp1 = cpv1beta.NetworkPolicyReference{
		Type:      cpv1beta.AntreaClusterNetworkPolicy,
		Namespace: "",
		Name:      "baz",
		UID:       "uid3",
	}
	annp1 = cpv1beta.NetworkPolicyReference{
		Type:      cpv1beta.AntreaNetworkPolicy,
		Namespace: "foo",
		Name:      "bar",
		UID:       "uid4",
	}
)

func TestCollect(t *testing.T) {
	ctrl := gomock.NewController(t)
	tests := []struct {
		name                    string
		ruleStats               map[uint32]*agenttypes.RuleMetric
		ofIDToPolicyMap         map[uint32]*agenttypes.PolicyRule
		expectedStatsCollection *statsCollection
	}{
		{
			name: "one or multiple rules per policy",
			ruleStats: map[uint32]*agenttypes.RuleMetric{
				1: {
					Bytes:    10,
					Packets:  1,
					Sessions: 1,
				},
				2: {
					Bytes:    15,
					Packets:  2,
					Sessions: 1,
				},
				3: {
					Bytes:    30,
					Packets:  5,
					Sessions: 3,
				},
			},
			ofIDToPolicyMap: map[uint32]*agenttypes.PolicyRule{
				1: {PolicyRef: &np1},
				2: {PolicyRef: &np1},
				3: {PolicyRef: &np2},
			},
			expectedStatsCollection: &statsCollection{
				networkPolicyStats: map[types.UID]*statsv1alpha1.TrafficStats{
					np1.UID: {
						Bytes:    25,
						Packets:  3,
						Sessions: 2,
					},
					np2.UID: {
						Bytes:    30,
						Packets:  5,
						Sessions: 3,
					},
				},
				antreaClusterNetworkPolicyStats: map[types.UID]map[string]*statsv1alpha1.TrafficStats{},
				antreaNetworkPolicyStats:        map[types.UID]map[string]*statsv1alpha1.TrafficStats{},
			},
		},
		{
			name: "blended policies",
			ruleStats: map[uint32]*agenttypes.RuleMetric{
				1: {
					Bytes:    10,
					Packets:  1,
					Sessions: 1,
				},
				2: {
					Bytes:    15,
					Packets:  2,
					Sessions: 1,
				},
				3: {
					Bytes:    30,
					Packets:  5,
					Sessions: 3,
				},
			},
			ofIDToPolicyMap: map[uint32]*agenttypes.PolicyRule{
				1: {PolicyRef: &np1},
				2: {Name: "rule1", PolicyRef: &acnp1},
				3: {Name: "rule2", PolicyRef: &annp1},
			},
			expectedStatsCollection: &statsCollection{
				networkPolicyStats: map[types.UID]*statsv1alpha1.TrafficStats{
					np1.UID: {
						Bytes:    10,
						Packets:  1,
						Sessions: 1,
					},
				},
				antreaClusterNetworkPolicyStats: map[types.UID]map[string]*statsv1alpha1.TrafficStats{
					acnp1.UID: {
						"rule1": {
							Bytes:    15,
							Packets:  2,
							Sessions: 1,
						},
					},
				},
				antreaNetworkPolicyStats: map[types.UID]map[string]*statsv1alpha1.TrafficStats{
					annp1.UID: {
						"rule2": {
							Bytes:    30,
							Packets:  5,
							Sessions: 3,
						},
					},
				},
			},
		},
		{
			name: "unknown policy",
			ruleStats: map[uint32]*agenttypes.RuleMetric{
				1: {
					Bytes:    10,
					Packets:  1,
					Sessions: 1,
				},
				2: {
					Bytes:    15,
					Packets:  2,
					Sessions: 1,
				},
			},
			ofIDToPolicyMap: map[uint32]*agenttypes.PolicyRule{
				1: {PolicyRef: &np1},
				2: nil,
			},
			expectedStatsCollection: &statsCollection{
				networkPolicyStats: map[types.UID]*statsv1alpha1.TrafficStats{
					np1.UID: {
						Bytes:    10,
						Packets:  1,
						Sessions: 1,
					},
				},
				antreaClusterNetworkPolicyStats: map[types.UID]map[string]*statsv1alpha1.TrafficStats{},
				antreaNetworkPolicyStats:        map[types.UID]map[string]*statsv1alpha1.TrafficStats{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ofClient := oftest.NewMockClient(ctrl)
			npQuerier := queriertest.NewMockAgentNetworkPolicyInfoQuerier(ctrl)
			mcQuerier := queriertest.NewMockAgentMulticastInfoQuerier(ctrl)
			ofClient.EXPECT().NetworkPolicyMetrics().Return(tt.ruleStats).Times(1)
			for ofID, policy := range tt.ofIDToPolicyMap {
				npQuerier.EXPECT().GetRuleByFlowID(ofID).Return(policy)
			}

			m := &Collector{ofClient: ofClient, networkPolicyQuerier: npQuerier, multicastQuerier: mcQuerier}
			actualPolicyStats := m.collect()
			assert.Equal(t, tt.expectedStatsCollection, actualPolicyStats)
		})
	}
}

func TestCalculateDiff(t *testing.T) {
	tests := []struct {
		name              string
		lastStats         map[types.UID]*statsv1alpha1.TrafficStats
		curStats          map[types.UID]*statsv1alpha1.TrafficStats
		expectedstatsList []cpv1beta.NetworkPolicyStats
	}{
		{
			name: "new networkpolicy and existing networkpolicy",
			lastStats: map[types.UID]*statsv1alpha1.TrafficStats{
				"uid1": {
					Bytes:    1,
					Packets:  1,
					Sessions: 1,
				},
			},
			curStats: map[types.UID]*statsv1alpha1.TrafficStats{
				"uid1": {
					Bytes:    25,
					Packets:  3,
					Sessions: 2,
				},
				"uid2": {
					Bytes:    30,
					Packets:  5,
					Sessions: 3,
				},
			},
			expectedstatsList: []cpv1beta.NetworkPolicyStats{
				{
					NetworkPolicy: cpv1beta.NetworkPolicyReference{UID: "uid1"},
					TrafficStats: statsv1alpha1.TrafficStats{
						Bytes:    24,
						Packets:  2,
						Sessions: 1,
					},
				},
				{
					NetworkPolicy: cpv1beta.NetworkPolicyReference{UID: "uid2"},
					TrafficStats: statsv1alpha1.TrafficStats{
						Bytes:    30,
						Packets:  5,
						Sessions: 3,
					},
				},
			},
		},
		{
			name: "unchanged networkpolicy",
			lastStats: map[types.UID]*statsv1alpha1.TrafficStats{
				"uid1": {
					Bytes:    1,
					Packets:  1,
					Sessions: 1,
				},
				"uid2": {
					Bytes:    0,
					Packets:  0,
					Sessions: 0,
				},
			},
			curStats: map[types.UID]*statsv1alpha1.TrafficStats{
				"uid1": {
					Bytes:    1,
					Packets:  1,
					Sessions: 1,
				},
				"uid2": {
					Bytes:    0,
					Packets:  0,
					Sessions: 0,
				},
			},
			expectedstatsList: []cpv1beta.NetworkPolicyStats{},
		},
		{
			name: "negative statistic",
			lastStats: map[types.UID]*statsv1alpha1.TrafficStats{
				"uid1": {
					Bytes:    10,
					Packets:  10,
					Sessions: 10,
				},
				"uid2": {
					Bytes:    5,
					Packets:  5,
					Sessions: 5,
				},
			},
			curStats: map[types.UID]*statsv1alpha1.TrafficStats{
				"uid1": {
					Bytes:    3,
					Packets:  3,
					Sessions: 3,
				},
				"uid2": {
					Bytes:    1,
					Packets:  1,
					Sessions: 1,
				},
			},
			expectedstatsList: []cpv1beta.NetworkPolicyStats{
				{
					NetworkPolicy: cpv1beta.NetworkPolicyReference{UID: "uid1"},
					TrafficStats: statsv1alpha1.TrafficStats{
						Bytes:    3,
						Packets:  3,
						Sessions: 3,
					},
				},
				{
					NetworkPolicy: cpv1beta.NetworkPolicyReference{UID: "uid2"},
					TrafficStats: statsv1alpha1.TrafficStats{
						Bytes:    1,
						Packets:  1,
						Sessions: 1,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualMetrics := calculateDiff(tt.curStats, tt.lastStats)
			assert.ElementsMatch(t, tt.expectedstatsList, actualMetrics)
		})
	}
}

func TestCalculateNodeStatsSummary(t *testing.T) {
	ctrl := gomock.NewController(t)
	tests := []struct {
		name                string
		lastStatsCollection *statsCollection
		curStatsCollection  *statsCollection
		expectedSummary     *cpv1beta.NodeStatsSummary
	}{
		{
			name: "only multicaststats",
			lastStatsCollection: &statsCollection{
				multicastGroups: map[string][]cpv1beta.PodReference{
					"225.3.4.5": {
						{Name: "bar2", Namespace: "foo2"},
					},
				},
			},
			curStatsCollection: &statsCollection{
				multicastGroups: map[string][]cpv1beta.PodReference{
					"225.3.4.5": {
						{Name: "bar2", Namespace: "foo2"},
					},
				},
			},
			expectedSummary: nil,
		},
		{
			name: "annp and multicaststats",
			lastStatsCollection: &statsCollection{
				multicastGroups: map[string][]cpv1beta.PodReference{
					"225.3.4.5": {
						{Name: "bar3", Namespace: "foo3"},
					},
				},
			},
			curStatsCollection: &statsCollection{
				networkPolicyStats: map[types.UID]*statsv1alpha1.TrafficStats{
					np1.UID: {
						Bytes:    25,
						Packets:  3,
						Sessions: 2,
					},
				},
				multicastGroups: map[string][]cpv1beta.PodReference{
					"225.3.4.5": {
						{Name: "bar3", Namespace: "foo3"},
					},
				},
			},
			expectedSummary: &cpv1beta.NodeStatsSummary{
				Multicast: []cpv1beta.MulticastGroupInfo{
					{
						Group: "225.3.4.5", Pods: []cpv1beta.PodReference{
							{Name: "bar3", Namespace: "foo3"}},
					},
				},
				NetworkPolicies: []cpv1beta.NetworkPolicyStats{
					{
						NetworkPolicy: cpv1beta.NetworkPolicyReference{UID: "uid1"},
						TrafficStats: statsv1alpha1.TrafficStats{
							Bytes:    25,
							Packets:  3,
							Sessions: 2,
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mcQuerier := queriertest.NewMockAgentMulticastInfoQuerier(ctrl)
			mcQuerier.EXPECT().CollectIGMPReportNPStats().AnyTimes()

			m := &Collector{multicastQuerier: mcQuerier, lastStatsCollection: tt.lastStatsCollection, multicastEnabled: true}
			summary := m.calculateNodeStatsSummary(tt.curStatsCollection)
			assert.Equal(t, tt.expectedSummary, summary)
		})
	}
}

func TestConvertMulticastGroups(t *testing.T) {
	tests := []struct {
		name                      string
		multicastGroupMap         map[string][]cpv1beta.PodReference
		expectMulticastGroupInfos []cpv1beta.MulticastGroupInfo
	}{
		{
			name: "test convert group with multiple pods",
			multicastGroupMap: map[string][]cpv1beta.PodReference{
				"224.3.4.5": {
					{Name: "A", Namespace: "B"},
					{Name: "C", Namespace: "B"},
				},
			},
			expectMulticastGroupInfos: []cpv1beta.MulticastGroupInfo{
				{Group: "224.3.4.5", Pods: []cpv1beta.PodReference{
					{Name: "A", Namespace: "B"},
					{Name: "C", Namespace: "B"},
				}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Collector{multicastEnabled: true}
			multicastGroupInfos := m.convertMulticastGroups(tt.multicastGroupMap)
			assert.Equal(t, tt.expectMulticastGroupInfos, multicastGroupInfos)
		})
	}
}

func TestMergeStatsWithIGMPReports(t *testing.T) {
	ctrl := gomock.NewController(t)
	tests := []struct {
		name              string
		curAnnpStats      []cpv1beta.NetworkPolicyStats
		curAcnpStats      []cpv1beta.NetworkPolicyStats
		curMcastAnnpStats map[types.UID]map[string]*agenttypes.RuleMetric
		curMcastAcnpStats map[types.UID]map[string]*agenttypes.RuleMetric
		expectAnnpStats   []cpv1beta.NetworkPolicyStats
		expectAcnpStats   []cpv1beta.NetworkPolicyStats
	}{
		{
			name: "merge annp stats and acnp stats with igmp reports stats",
			curAnnpStats: []cpv1beta.NetworkPolicyStats{
				{
					NetworkPolicy: cpv1beta.NetworkPolicyReference{UID: "uid1"},
					RuleTrafficStats: []statsv1alpha1.RuleTrafficStats{
						{
							Name: "rule1",
							TrafficStats: statsv1alpha1.TrafficStats{
								Bytes:    1,
								Packets:  9,
								Sessions: 9,
							},
						},
						{
							Name: "rule2",
							TrafficStats: statsv1alpha1.TrafficStats{
								Bytes:    5,
								Packets:  5,
								Sessions: 5,
							},
						},
					},
				},
			},
			curAcnpStats: []cpv1beta.NetworkPolicyStats{
				{
					NetworkPolicy: cpv1beta.NetworkPolicyReference{UID: "uid2"},
					RuleTrafficStats: []statsv1alpha1.RuleTrafficStats{
						{
							Name: "rule1",
							TrafficStats: statsv1alpha1.TrafficStats{
								Bytes:    2,
								Packets:  10,
								Sessions: 10,
							},
						},
						{
							Name: "rule2",
							TrafficStats: statsv1alpha1.TrafficStats{
								Bytes:    6,
								Packets:  7,
								Sessions: 8,
							},
						},
					},
				},
			},
			curMcastAnnpStats: map[types.UID]map[string]*agenttypes.RuleMetric{
				"uid1": {
					"rule4": {
						Bytes:   6,
						Packets: 7,
					},
				},
				"uid3": {
					"rule4": {
						Bytes:   6,
						Packets: 7,
					},
				},
			},
			curMcastAcnpStats: map[types.UID]map[string]*agenttypes.RuleMetric{
				"uid2": {
					"rule4": {
						Bytes:   6,
						Packets: 7,
					},
				},
			},
			expectAnnpStats: []cpv1beta.NetworkPolicyStats{
				{
					NetworkPolicy: cpv1beta.NetworkPolicyReference{UID: "uid1"},
					RuleTrafficStats: []statsv1alpha1.RuleTrafficStats{
						{
							Name: "rule1",
							TrafficStats: statsv1alpha1.TrafficStats{
								Bytes:    1,
								Packets:  9,
								Sessions: 9,
							},
						},
						{
							Name: "rule2",
							TrafficStats: statsv1alpha1.TrafficStats{
								Bytes:    5,
								Packets:  5,
								Sessions: 5,
							},
						},
						{
							Name: "rule4",
							TrafficStats: statsv1alpha1.TrafficStats{
								Bytes:   6,
								Packets: 7,
							},
						},
					},
				},
				{
					NetworkPolicy: cpv1beta.NetworkPolicyReference{UID: "uid3"},
					RuleTrafficStats: []statsv1alpha1.RuleTrafficStats{
						{
							Name: "rule4",
							TrafficStats: statsv1alpha1.TrafficStats{
								Bytes:   6,
								Packets: 7,
							},
						},
					},
				},
			},
			expectAcnpStats: []cpv1beta.NetworkPolicyStats{
				{
					NetworkPolicy: cpv1beta.NetworkPolicyReference{UID: "uid2"},
					RuleTrafficStats: []statsv1alpha1.RuleTrafficStats{
						{
							Name: "rule1",
							TrafficStats: statsv1alpha1.TrafficStats{
								Bytes:    2,
								Packets:  10,
								Sessions: 10,
							},
						},
						{
							Name: "rule2",
							TrafficStats: statsv1alpha1.TrafficStats{
								Bytes:    6,
								Packets:  7,
								Sessions: 8,
							},
						},
						{
							Name: "rule4",
							TrafficStats: statsv1alpha1.TrafficStats{
								Bytes:   6,
								Packets: 7,
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mcQuerier := queriertest.NewMockAgentMulticastInfoQuerier(ctrl)
			mcQuerier.EXPECT().CollectIGMPReportNPStats().Return(tt.curMcastAnnpStats, tt.curMcastAcnpStats).Times(1)
			m := &Collector{multicastEnabled: true, multicastQuerier: mcQuerier}
			acnpStats, annpStats := m.mergeStatsWithIGMPReports(tt.curAcnpStats, tt.curAnnpStats)
			assert.Equal(t, tt.expectAcnpStats, acnpStats)
			assert.Equal(t, tt.expectAnnpStats, annpStats)
		})
	}
}

func TestCalculateRuleDiff(t *testing.T) {
	tests := []struct {
		name              string
		lastStats         map[types.UID]map[string]*statsv1alpha1.TrafficStats
		curStats          map[types.UID]map[string]*statsv1alpha1.TrafficStats
		expectedStatsList []cpv1beta.NetworkPolicyStats
	}{
		{
			name: "new networkpolicy and existing networkpolicy",
			lastStats: map[types.UID]map[string]*statsv1alpha1.TrafficStats{
				"uid1": {
					"rule1": {
						Bytes:    1,
						Packets:  1,
						Sessions: 1,
					},
				},
			},
			curStats: map[types.UID]map[string]*statsv1alpha1.TrafficStats{
				"uid1": {
					"rule1": {
						Bytes:    2,
						Packets:  10,
						Sessions: 10,
					},
					"rule2": {
						Bytes:    5,
						Packets:  5,
						Sessions: 5,
					},
					"rule3": {
						Bytes:    0,
						Packets:  0,
						Sessions: 0,
					},
				},
				"uid2": {
					"rule3": {
						Bytes:    1,
						Packets:  1,
						Sessions: 1,
					},
				},
			},
			expectedStatsList: []cpv1beta.NetworkPolicyStats{
				{
					NetworkPolicy: cpv1beta.NetworkPolicyReference{UID: "uid1"},
					RuleTrafficStats: []statsv1alpha1.RuleTrafficStats{
						{
							Name: "rule1",
							TrafficStats: statsv1alpha1.TrafficStats{
								Bytes:    1,
								Packets:  9,
								Sessions: 9,
							},
						},
						{
							Name: "rule2",
							TrafficStats: statsv1alpha1.TrafficStats{
								Bytes:    5,
								Packets:  5,
								Sessions: 5,
							},
						},
					},
				},
				{
					NetworkPolicy: cpv1beta.NetworkPolicyReference{UID: "uid2"},
					RuleTrafficStats: []statsv1alpha1.RuleTrafficStats{
						{
							Name: "rule3",
							TrafficStats: statsv1alpha1.TrafficStats{
								Bytes:    1,
								Packets:  1,
								Sessions: 1,
							},
						},
					},
				},
			},
		},
		{
			name: "unchanged networkpolicy",
			lastStats: map[types.UID]map[string]*statsv1alpha1.TrafficStats{
				"uid1": {
					"rule20": {
						Bytes:    0,
						Packets:  0,
						Sessions: 0,
					},
				},
				"uid2": {
					"rule1": {
						Bytes:    1,
						Packets:  10,
						Sessions: 10,
					},
					"rule2": {
						Bytes:    5,
						Packets:  5,
						Sessions: 5,
					},
					"rule3": {
						Bytes:    1,
						Packets:  1,
						Sessions: 1,
					},
				},
			},
			curStats: map[types.UID]map[string]*statsv1alpha1.TrafficStats{
				"uid1": {
					"rule20": {
						Bytes:    0,
						Packets:  0,
						Sessions: 0,
					},
				},
				"uid2": {
					"rule1": {
						Bytes:    1,
						Packets:  10,
						Sessions: 10,
					},
					"rule2": {
						Bytes:    5,
						Packets:  5,
						Sessions: 5,
					},
					"rule3": {
						Bytes:    1,
						Packets:  1,
						Sessions: 1,
					},
				},
			},
			expectedStatsList: []cpv1beta.NetworkPolicyStats{},
		},
		{
			name: "negative statistic",
			lastStats: map[types.UID]map[string]*statsv1alpha1.TrafficStats{
				"uid1": {
					"rule1": {
						Bytes:    10,
						Packets:  100,
						Sessions: 1,
					},
				},
			},
			curStats: map[types.UID]map[string]*statsv1alpha1.TrafficStats{
				"uid1": {
					"rule1": {
						Bytes:    1,
						Packets:  10,
						Sessions: 10,
					},
					"rule2": {
						Bytes:    5,
						Packets:  5,
						Sessions: 5,
					},
				},
				"uid2": {
					"rule3": {
						Bytes:    1,
						Packets:  1,
						Sessions: 1,
					},
				},
			},
			expectedStatsList: []cpv1beta.NetworkPolicyStats{
				{
					NetworkPolicy: cpv1beta.NetworkPolicyReference{UID: "uid1"},
					RuleTrafficStats: []statsv1alpha1.RuleTrafficStats{
						{
							Name: "rule1",
							TrafficStats: statsv1alpha1.TrafficStats{
								Bytes:    1,
								Packets:  10,
								Sessions: 10,
							},
						},
						{
							Name: "rule2",
							TrafficStats: statsv1alpha1.TrafficStats{
								Bytes:    5,
								Packets:  5,
								Sessions: 5,
							},
						},
					},
				},
				{
					NetworkPolicy: cpv1beta.NetworkPolicyReference{UID: "uid2"},
					RuleTrafficStats: []statsv1alpha1.RuleTrafficStats{
						{
							Name: "rule3",
							TrafficStats: statsv1alpha1.TrafficStats{
								Bytes:    1,
								Packets:  1,
								Sessions: 1,
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualMetrics := calculateRuleDiff(tt.curStats, tt.lastStats)
			for _, v := range actualMetrics {
				sort.SliceStable(v.RuleTrafficStats, func(i, j int) bool {
					return v.RuleTrafficStats[i].Name < v.RuleTrafficStats[j].Name
				})
			}
			for _, v := range tt.expectedStatsList {
				sort.SliceStable(v.RuleTrafficStats, func(i, j int) bool {
					return v.RuleTrafficStats[i].Name < v.RuleTrafficStats[j].Name
				})
			}
			assert.ElementsMatch(t, tt.expectedStatsList, actualMetrics)
		})
	}
}
