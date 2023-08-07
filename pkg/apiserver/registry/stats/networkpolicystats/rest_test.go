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

package networkpolicystats

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/endpoints/request"
	featuregatetesting "k8s.io/component-base/featuregate/testing"

	statsv1alpha1 "antrea.io/antrea/pkg/apis/stats/v1alpha1"
	"antrea.io/antrea/pkg/features"
)

type fakeStatsProvider struct {
	stats map[string]map[string]statsv1alpha1.NetworkPolicyStats
}

func (p *fakeStatsProvider) ListNetworkPolicyStats(namespace string) []statsv1alpha1.NetworkPolicyStats {
	var list []statsv1alpha1.NetworkPolicyStats
	if namespace == "" {
		for _, m1 := range p.stats {
			for _, m2 := range m1 {
				list = append(list, m2)
			}
		}
	} else {
		m1, _ := p.stats[namespace]
		for _, m2 := range m1 {
			list = append(list, m2)
		}
	}
	return list
}

func (p *fakeStatsProvider) GetNetworkPolicyStats(namespace, name string) (*statsv1alpha1.NetworkPolicyStats, bool) {
	m, exists := p.stats[namespace][name]
	if !exists {
		return nil, false
	}
	return &m, true
}

func TestREST(t *testing.T) {
	r := NewREST(nil)
	assert.Equal(t, &statsv1alpha1.NetworkPolicyStats{}, r.New())
	assert.Equal(t, &statsv1alpha1.NetworkPolicyStatsList{}, r.NewList())
	assert.True(t, r.NamespaceScoped())
}

func TestRESTGet(t *testing.T) {
	tests := []struct {
		name                      string
		networkPolicyStatsEnabled bool
		stats                     map[string]map[string]statsv1alpha1.NetworkPolicyStats
		npNamespace               string
		npName                    string
		expectedObj               runtime.Object
		expectedErr               bool
	}{
		{
			name:                      "NetworkPolicyStats feature disabled",
			networkPolicyStatsEnabled: false,
			expectedErr:               true,
		},
		{
			name:                      "np not found",
			networkPolicyStatsEnabled: true,
			stats: map[string]map[string]statsv1alpha1.NetworkPolicyStats{
				"foo": {
					"bar": {
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "foo",
							Name:      "foo",
						},
					},
				},
			},
			npNamespace: "non existing namespace",
			npName:      "non existing name",
			expectedErr: true,
		},
		{
			name:                      "np found",
			networkPolicyStatsEnabled: true,
			stats: map[string]map[string]statsv1alpha1.NetworkPolicyStats{
				"foo": {
					"bar": {
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "foo",
							Name:      "bar",
						},
					},
				},
			},
			npNamespace: "foo",
			npName:      "bar",
			expectedObj: &statsv1alpha1.NetworkPolicyStats{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "foo",
					Name:      "bar",
				},
			},
			expectedErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer featuregatetesting.SetFeatureGateDuringTest(t, features.DefaultFeatureGate, features.NetworkPolicyStats, tt.networkPolicyStatsEnabled)()

			r := &REST{
				statsProvider: &fakeStatsProvider{stats: tt.stats},
			}
			ctx := request.WithNamespace(context.TODO(), tt.npNamespace)
			actualObj, err := r.Get(ctx, tt.npName, &metav1.GetOptions{})
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
		labelSelector             labels.Selector
		stats                     map[string]map[string]statsv1alpha1.NetworkPolicyStats
		npNamespace               string
		expectedObj               runtime.Object
		expectedErr               bool
	}{
		{
			name:                      "NetworkPolicyStats feature disabled",
			networkPolicyStatsEnabled: false,
			expectedObj:               &statsv1alpha1.NetworkPolicyStatsList{},
		},
		{
			name:                      "all namespaces",
			networkPolicyStatsEnabled: true,
			stats: map[string]map[string]statsv1alpha1.NetworkPolicyStats{
				"foo": {
					"bar": {
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "foo",
							Name:      "bar",
						},
					},
				},
				"foo1": {
					"bar1": {
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "foo1",
							Name:      "bar1",
						},
					},
				},
			},
			npNamespace: "",
			expectedObj: &statsv1alpha1.NetworkPolicyStatsList{
				Items: []statsv1alpha1.NetworkPolicyStats{
					{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "foo",
							Name:      "bar",
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "foo1",
							Name:      "bar1",
						},
					},
				},
			},
			expectedErr: false,
		},
		{
			name:                      "one namespace",
			networkPolicyStatsEnabled: true,
			stats: map[string]map[string]statsv1alpha1.NetworkPolicyStats{
				"foo": {
					"bar": {
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "foo",
							Name:      "bar",
						},
					},
				},
				"foo1": {
					"bar1": {
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "foo1",
							Name:      "bar1",
						},
					},
				},
			},
			npNamespace: "foo",
			expectedObj: &statsv1alpha1.NetworkPolicyStatsList{
				Items: []statsv1alpha1.NetworkPolicyStats{
					{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "foo",
							Name:      "bar",
						},
					},
				},
			},
			expectedErr: false,
		},
		{
			name:                      "empty stats",
			networkPolicyStatsEnabled: true,
			stats:                     map[string]map[string]statsv1alpha1.NetworkPolicyStats{},
			npNamespace:               "",
			expectedObj: &statsv1alpha1.NetworkPolicyStatsList{
				Items: []statsv1alpha1.NetworkPolicyStats{},
			},
			expectedErr: false,
		},
		{
			name:                      "label selector selecting nothing",
			networkPolicyStatsEnabled: true,
			labelSelector:             labels.Nothing(),
			stats: map[string]map[string]statsv1alpha1.NetworkPolicyStats{
				"foo": {
					"bar": {
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "foo",
							Name:      "bar",
						},
					},
				},
			},
			npNamespace: "foo",
			expectedObj: &statsv1alpha1.NetworkPolicyStatsList{
				Items: []statsv1alpha1.NetworkPolicyStats{},
			},
			expectedErr: false,
		},
		{
			name:                      "label selector selecting everything",
			networkPolicyStatsEnabled: true,
			labelSelector:             labels.Everything(),
			stats: map[string]map[string]statsv1alpha1.NetworkPolicyStats{
				"foo": {
					"bar": {
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "foo",
							Name:      "bar",
						},
					},
				},
			},
			npNamespace: "foo",
			expectedObj: &statsv1alpha1.NetworkPolicyStatsList{
				Items: []statsv1alpha1.NetworkPolicyStats{
					{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "foo",
							Name:      "bar",
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

			r := &REST{
				statsProvider: &fakeStatsProvider{stats: tt.stats},
			}
			ctx := request.WithNamespace(context.TODO(), tt.npNamespace)
			actualObj, err := r.List(ctx, &internalversion.ListOptions{LabelSelector: tt.labelSelector})
			if tt.expectedErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			if tt.expectedObj == nil {
				assert.Nil(t, actualObj)
			} else {
				assert.ElementsMatch(t, tt.expectedObj.(*statsv1alpha1.NetworkPolicyStatsList).Items, actualObj.(*statsv1alpha1.NetworkPolicyStatsList).Items)
			}
		})
	}
}

func TestRESTConvertToTable(t *testing.T) {
	stats := &statsv1alpha1.NetworkPolicyStats{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         "foo",
			Name:              "bar",
			CreationTimestamp: metav1.Time{Time: time.Now()},
		},
		TrafficStats: statsv1alpha1.TrafficStats{
			Packets:  10,
			Bytes:    2000,
			Sessions: 5,
		},
	}
	expectedFormattedCreationTimestamp := stats.CreationTimestamp.UTC().Format(time.RFC3339)
	tests := []struct {
		name          string
		object        runtime.Object
		expectedTable *metav1.Table
	}{
		{
			name:   "one object",
			object: stats,
			expectedTable: &metav1.Table{
				ColumnDefinitions: tableColumnDefinitions,
				Rows: []metav1.TableRow{
					{
						Cells:  []interface{}{"bar", int64(5), int64(10), int64(2000), expectedFormattedCreationTimestamp},
						Object: runtime.RawExtension{Object: stats},
					},
				},
			},
		},
		{
			name:   "multiple objects",
			object: &statsv1alpha1.NetworkPolicyStatsList{Items: []statsv1alpha1.NetworkPolicyStats{*stats}},
			expectedTable: &metav1.Table{
				ColumnDefinitions: tableColumnDefinitions,
				Rows: []metav1.TableRow{
					{
						Cells:  []interface{}{"bar", int64(5), int64(10), int64(2000), expectedFormattedCreationTimestamp},
						Object: runtime.RawExtension{Object: stats},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &REST{}
			actualTable, err := r.ConvertToTable(context.TODO(), tt.object, &metav1.TableOptions{})
			require.NoError(t, err)
			assert.Equal(t, tt.expectedTable, actualTable)
		})
	}
}
