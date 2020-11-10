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

package antreaclusternetworkpolicystats

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	featuregatetesting "k8s.io/component-base/featuregate/testing"

	statsv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/stats/v1alpha1"
	"github.com/vmware-tanzu/antrea/pkg/features"
)

type fakeStatsProvider struct {
	stats map[string]statsv1alpha1.AntreaClusterNetworkPolicyStats
}

func (p *fakeStatsProvider) ListAntreaClusterNetworkPolicyStats() []statsv1alpha1.AntreaClusterNetworkPolicyStats {
	list := make([]statsv1alpha1.AntreaClusterNetworkPolicyStats, 0, len(p.stats))
	for _, m := range p.stats {
		list = append(list, m)
	}
	return list
}

func (p *fakeStatsProvider) GetAntreaClusterNetworkPolicyStats(name string) (*statsv1alpha1.AntreaClusterNetworkPolicyStats, bool) {
	m, exists := p.stats[name]
	if !exists {
		return nil, false
	}
	return &m, true
}

func TestRESTGet(t *testing.T) {
	tests := []struct {
		name                      string
		networkPolicyStatsEnabled bool
		antreaPolicyEnabled       bool
		stats                     map[string]statsv1alpha1.AntreaClusterNetworkPolicyStats
		cnp                       string
		expectedObj               runtime.Object
		expectedErr               bool
	}{
		{
			name:                      "NetworkPolicyStats feature disabled",
			networkPolicyStatsEnabled: false,
			antreaPolicyEnabled:       true,
			expectedErr:               true,
		},
		{
			name:                      "AntreaPolicy feature disabled",
			networkPolicyStatsEnabled: true,
			antreaPolicyEnabled:       false,
			expectedErr:               true,
		},
		{
			name:                      "cnp not found",
			networkPolicyStatsEnabled: true,
			antreaPolicyEnabled:       true,
			stats: map[string]statsv1alpha1.AntreaClusterNetworkPolicyStats{
				"foo": {
					ObjectMeta: metav1.ObjectMeta{
						Name: "foo",
					},
				},
			},
			cnp:         "bar",
			expectedErr: true,
		},
		{
			name:                      "cnp found",
			networkPolicyStatsEnabled: true,
			antreaPolicyEnabled:       true,
			stats: map[string]statsv1alpha1.AntreaClusterNetworkPolicyStats{
				"foo": {
					ObjectMeta: metav1.ObjectMeta{
						Name: "foo",
					},
				},
			},
			cnp: "foo",
			expectedObj: &statsv1alpha1.AntreaClusterNetworkPolicyStats{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
			},
			expectedErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer featuregatetesting.SetFeatureGateDuringTest(t, features.DefaultFeatureGate, features.NetworkPolicyStats, tt.networkPolicyStatsEnabled)()
			defer featuregatetesting.SetFeatureGateDuringTest(t, features.DefaultFeatureGate, features.AntreaPolicy, tt.antreaPolicyEnabled)()

			r := &REST{
				statsProvider: &fakeStatsProvider{stats: tt.stats},
			}
			actualObj, err := r.Get(context.TODO(), tt.cnp, &metav1.GetOptions{})
			if tt.expectedErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.expectedObj, actualObj)
		})
	}
}

func TestRESTList(t *testing.T) {
	tests := []struct {
		name                      string
		networkPolicyStatsEnabled bool
		antreaPolicyEnabled       bool
		labelSelector             labels.Selector
		stats                     map[string]statsv1alpha1.AntreaClusterNetworkPolicyStats
		expectedObj               runtime.Object
		expectedErr               bool
	}{
		{
			name:                      "NetworkPolicyStats feature disabled",
			networkPolicyStatsEnabled: false,
			antreaPolicyEnabled:       true,
			expectedErr:               true,
		},
		{
			name:                      "AntreaPolicy feature disabled",
			networkPolicyStatsEnabled: true,
			antreaPolicyEnabled:       false,
			expectedErr:               true,
		},
		{
			name:                      "empty stats",
			networkPolicyStatsEnabled: true,
			antreaPolicyEnabled:       true,
			stats:                     map[string]statsv1alpha1.AntreaClusterNetworkPolicyStats{},
			expectedObj: &statsv1alpha1.AntreaClusterNetworkPolicyStatsList{
				Items: []statsv1alpha1.AntreaClusterNetworkPolicyStats{},
			},
			expectedErr: false,
		},
		{
			name:                      "a few stats",
			networkPolicyStatsEnabled: true,
			antreaPolicyEnabled:       true,
			stats: map[string]statsv1alpha1.AntreaClusterNetworkPolicyStats{
				"foo": {
					ObjectMeta: metav1.ObjectMeta{
						Name: "foo",
					},
				},
				"bar": {
					ObjectMeta: metav1.ObjectMeta{
						Name: "bar",
					},
				},
			},
			expectedObj: &statsv1alpha1.AntreaClusterNetworkPolicyStatsList{
				Items: []statsv1alpha1.AntreaClusterNetworkPolicyStats{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name: "foo",
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							Name: "bar",
						},
					},
				},
			},
			expectedErr: false,
		},
		{
			name:                      "label selector selecting nothing",
			networkPolicyStatsEnabled: true,
			antreaPolicyEnabled:       true,
			labelSelector:             labels.Nothing(),
			stats: map[string]statsv1alpha1.AntreaClusterNetworkPolicyStats{
				"foo": {
					ObjectMeta: metav1.ObjectMeta{
						Name: "foo",
					},
				},
			},
			expectedObj: &statsv1alpha1.AntreaClusterNetworkPolicyStatsList{
				Items: []statsv1alpha1.AntreaClusterNetworkPolicyStats{},
			},
			expectedErr: false,
		},
		{
			name:                      "label selector selecting everything",
			networkPolicyStatsEnabled: true,
			antreaPolicyEnabled:       true,
			labelSelector:             labels.Everything(),
			stats: map[string]statsv1alpha1.AntreaClusterNetworkPolicyStats{
				"foo": {
					ObjectMeta: metav1.ObjectMeta{
						Name: "foo",
					},
				},
			},
			expectedObj: &statsv1alpha1.AntreaClusterNetworkPolicyStatsList{
				Items: []statsv1alpha1.AntreaClusterNetworkPolicyStats{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name: "foo",
						},
					},
				},
			},
			expectedErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer featuregatetesting.SetFeatureGateDuringTest(t, features.DefaultFeatureGate, features.NetworkPolicyStats, tt.networkPolicyStatsEnabled)()
			defer featuregatetesting.SetFeatureGateDuringTest(t, features.DefaultFeatureGate, features.AntreaPolicy, tt.antreaPolicyEnabled)()

			r := &REST{
				statsProvider: &fakeStatsProvider{stats: tt.stats},
			}
			actualObj, err := r.List(context.TODO(), &internalversion.ListOptions{LabelSelector: tt.labelSelector})
			if tt.expectedErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			if tt.expectedObj == nil {
				assert.Nil(t, actualObj)
			} else {
				assert.ElementsMatch(t, tt.expectedObj.(*statsv1alpha1.AntreaClusterNetworkPolicyStatsList).Items, actualObj.(*statsv1alpha1.AntreaClusterNetworkPolicyStatsList).Items)
			}
		})
	}
}
