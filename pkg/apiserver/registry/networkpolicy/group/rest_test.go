// Copyright 2021 Antrea Authors
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

package group

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/apis/meta/internalversion"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"github.com/vmware-tanzu/antrea/pkg/apis/controlplane"
	"github.com/vmware-tanzu/antrea/pkg/controller/networkpolicy/store"
	antreatypes "github.com/vmware-tanzu/antrea/pkg/controller/types"
)

func TestRESTList(t *testing.T) {
	tests := []struct {
		name          string
		groups        []*antreatypes.Group
		labelSelector labels.Selector
		expectedObj   runtime.Object
	}{
		{
			name: "label selector selecting nothing",
			groups: []*antreatypes.Group{
				{
					UID: "foo",
				},
			},
			labelSelector: labels.Nothing(),
			expectedObj:   &controlplane.GroupList{},
		},
		{
			name: "label selector selecting everything",
			groups: []*antreatypes.Group{
				{
					UID: "foo",
				},
			},
			labelSelector: labels.Everything(),
			expectedObj: &controlplane.GroupList{
				Items: []controlplane.Group{
					{
						ObjectMeta: v1.ObjectMeta{
							UID: types.UID("foo"),
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage := store.NewGroupStore()
			for _, obj := range tt.groups {
				storage.Create(obj)
			}
			r := NewREST(storage)
			actualObj, err := r.List(context.TODO(), &internalversion.ListOptions{LabelSelector: tt.labelSelector})
			assert.NoError(t, err)
			assert.ElementsMatch(t, tt.expectedObj.(*controlplane.GroupList).Items, actualObj.(*controlplane.GroupList).Items)
		})
	}
}
