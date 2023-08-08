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

package multicastgroup

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	featuregatetesting "k8s.io/component-base/featuregate/testing"

	statsv1alpha1 "antrea.io/antrea/pkg/apis/stats/v1alpha1"
	"antrea.io/antrea/pkg/features"
)

var (
	group1 = &statsv1alpha1.MulticastGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: "224.0.0.10",
		},
		Group: "224.0.0.10",
		Pods: []statsv1alpha1.PodReference{
			{Name: "foo", Namespace: "default"},
			{Name: "bar", Namespace: "default"},
		},
	}
	group2 = &statsv1alpha1.MulticastGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: "224.0.0.11",
		},
		Group: "224.0.0.11",
		Pods: []statsv1alpha1.PodReference{
			{Name: "foo1", Namespace: "dev"},
			{Name: "foo2", Namespace: "dev"},
			{Name: "bar1", Namespace: "dev"},
			{Name: "bar2", Namespace: "dev"},
		},
	}
	group3 = &statsv1alpha1.MulticastGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: "224.0.0.12",
		},
		Group: "224.0.0.12",
	}
)

type fakeStatsProvider struct {
	groups map[string]*statsv1alpha1.MulticastGroup
}

func (p *fakeStatsProvider) ListMulticastGroups() []statsv1alpha1.MulticastGroup {
	var list []statsv1alpha1.MulticastGroup
	for _, g := range p.groups {
		list = append(list, *g)
	}
	return list
}

func (p *fakeStatsProvider) GetMulticastGroup(name string) (*statsv1alpha1.MulticastGroup, bool) {
	g, exists := p.groups[name]
	return g, exists
}

func TestREST(t *testing.T) {
	r := NewREST(nil)
	assert.Equal(t, &statsv1alpha1.MulticastGroup{}, r.New())
	assert.Equal(t, &statsv1alpha1.MulticastGroupList{}, r.NewList())
	assert.False(t, r.NamespaceScoped())
}

func TestRESTList(t *testing.T) {
	tests := []struct {
		name             string
		multicastEnabled bool
		stats            map[string]*statsv1alpha1.MulticastGroup
		expectedObj      runtime.Object
	}{
		{
			name:             "Multicast feature disabled",
			multicastEnabled: false,
			stats: map[string]*statsv1alpha1.MulticastGroup{
				group1.Name: group1,
				group2.Name: group2,
			},
			expectedObj: &statsv1alpha1.MulticastGroupList{},
		},
		{
			name:             "empty group",
			multicastEnabled: true,
			expectedObj:      &statsv1alpha1.MulticastGroupList{},
		},
		{
			name:             "multiple groups",
			multicastEnabled: true,
			stats: map[string]*statsv1alpha1.MulticastGroup{
				group1.Name: group1,
				group2.Name: group2,
			},
			expectedObj: &statsv1alpha1.MulticastGroupList{
				Items: []statsv1alpha1.MulticastGroup{*group1, *group2},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer featuregatetesting.SetFeatureGateDuringTest(t, features.DefaultFeatureGate, features.Multicast, tt.multicastEnabled)()

			r := &REST{
				statsProvider: &fakeStatsProvider{groups: tt.stats},
			}
			actualObj, err := r.List(context.TODO(), &internalversion.ListOptions{})
			require.NoError(t, err)
			assert.ElementsMatch(t, tt.expectedObj.(*statsv1alpha1.MulticastGroupList).Items, actualObj.(*statsv1alpha1.MulticastGroupList).Items)
		})
	}
}

func TestRESTGet(t *testing.T) {
	tests := []struct {
		name             string
		multicastEnabled bool
		groups           map[string]*statsv1alpha1.MulticastGroup
		groupName        string
		expectedObj      runtime.Object
		expectedErr      error
	}{
		{
			name:             "NetworkPolicyStats feature disabled",
			multicastEnabled: true,
			groupName:        group1.Name,
			groups: map[string]*statsv1alpha1.MulticastGroup{
				group1.Name: group1,
			},
			expectedObj: group1,
		},
		{
			name:             "Multicast feature disabled",
			multicastEnabled: false,
			groupName:        group1.Name,
			groups: map[string]*statsv1alpha1.MulticastGroup{
				group1.Name: group1,
			},
			expectedObj: &statsv1alpha1.MulticastGroup{},
		},
		{
			name:             "group not found",
			multicastEnabled: true,
			groups:           nil,
			groupName:        group1.Name,
			expectedErr:      errors.NewNotFound(statsv1alpha1.Resource("multicastgroup"), "224.0.0.10"),
		},
		{
			name:             "group found",
			multicastEnabled: true,
			groups: map[string]*statsv1alpha1.MulticastGroup{
				group1.Name: group1,
			},
			groupName:   group1.Name,
			expectedObj: group1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer featuregatetesting.SetFeatureGateDuringTest(t, features.DefaultFeatureGate, features.Multicast, tt.multicastEnabled)()

			r := &REST{
				statsProvider: &fakeStatsProvider{groups: tt.groups},
			}
			actualObj, actualErr := r.Get(context.TODO(), tt.groupName, &metav1.GetOptions{})
			assert.Equal(t, tt.expectedErr, actualErr)
			assert.Equal(t, tt.expectedObj, actualObj)
		})
	}
}

func TestRESTConvertToTable(t *testing.T) {
	tests := []struct {
		name          string
		object        runtime.Object
		expectedTable *metav1.Table
	}{
		{
			name:   "one object",
			object: group1,
			expectedTable: &metav1.Table{
				ColumnDefinitions: tableColumnDefinitions,
				Rows: []metav1.TableRow{
					{
						Cells:  []interface{}{group1.Name, "default/foo,default/bar"},
						Object: runtime.RawExtension{Object: group1},
					},
				},
			},
		},
		{
			name:   "multiple objects",
			object: &statsv1alpha1.MulticastGroupList{Items: []statsv1alpha1.MulticastGroup{*group1, *group2, *group3}},
			expectedTable: &metav1.Table{
				ColumnDefinitions: tableColumnDefinitions,
				Rows: []metav1.TableRow{
					{
						Cells:  []interface{}{group1.Name, "default/foo,default/bar"},
						Object: runtime.RawExtension{Object: group1},
					},
					{
						Cells:  []interface{}{group2.Name, "dev/foo1,dev/foo2,dev/bar1 + 1 more..."},
						Object: runtime.RawExtension{Object: group2},
					},
					{
						Cells:  []interface{}{group3.Name, "<none>"},
						Object: runtime.RawExtension{Object: group3},
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
