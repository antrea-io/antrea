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

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/types"

	oftest "github.com/vmware-tanzu/antrea/pkg/agent/openflow/testing"
	agenttypes "github.com/vmware-tanzu/antrea/pkg/agent/types"
	cpv1beta "github.com/vmware-tanzu/antrea/pkg/apis/controlplane/v1beta2"
	statsv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/stats/v1alpha1"
	queriertest "github.com/vmware-tanzu/antrea/pkg/querier/testing"
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
	anp1 = cpv1beta.NetworkPolicyReference{
		Type:      cpv1beta.AntreaNetworkPolicy,
		Namespace: "foo",
		Name:      "bar",
		UID:       "uid4",
	}
)

func TestCollect(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

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
				3: {Name: "rule2", PolicyRef: &anp1},
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
					anp1.UID: {
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
			ofClient.EXPECT().NetworkPolicyMetrics().Return(tt.ruleStats).Times(1)
			for ofID, policy := range tt.ofIDToPolicyMap {
				npQuerier.EXPECT().GetRuleByFlowID(ofID).Return(policy)
			}

			m := &Collector{ofClient: ofClient, networkPolicyQuerier: npQuerier}
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

func TestCalculateRuleDiff(t *testing.T) {
	tests := []struct {
		name              string
		lastStats         map[types.UID]map[string]*statsv1alpha1.TrafficStats
		curStats          map[types.UID]map[string]*statsv1alpha1.TrafficStats
		expectedstatsList []cpv1beta.NetworkPolicyStats
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
				},
				"uid2": {
					"rule3": {
						Bytes:    1,
						Packets:  1,
						Sessions: 1,
					},
				},
			},
			expectedstatsList: []cpv1beta.NetworkPolicyStats{
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
			expectedstatsList: []cpv1beta.NetworkPolicyStats{},
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
			expectedstatsList: []cpv1beta.NetworkPolicyStats{
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
			for _, v := range tt.expectedstatsList {
				sort.SliceStable(v.RuleTrafficStats, func(i, j int) bool {
					return v.RuleTrafficStats[i].Name < v.RuleTrafficStats[j].Name
				})
			}
			assert.ElementsMatch(t, tt.expectedstatsList, actualMetrics)
		})
	}
}
