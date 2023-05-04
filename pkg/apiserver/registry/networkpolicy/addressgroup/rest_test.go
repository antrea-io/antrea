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

package addressgroup

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/internalversion"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/watch"

	"antrea.io/antrea/pkg/apis/controlplane"
	"antrea.io/antrea/pkg/controller/networkpolicy/store"
	"antrea.io/antrea/pkg/controller/types"
)

func TestREST(t *testing.T) {
	r := NewREST(nil)
	assert.Equal(t, &controlplane.AddressGroup{}, r.New())
	assert.Equal(t, &controlplane.AddressGroupList{}, r.NewList())
	assert.False(t, r.NamespaceScoped())
}

func TestRESTGet(t *testing.T) {
	tests := []struct {
		name          string
		addressGroups []*types.AddressGroup
		objName       string
		expectedObj   runtime.Object
		expectedErr   error
	}{
		{
			name: "get existing object",
			addressGroups: []*types.AddressGroup{
				{
					Name: "foo",
				},
			},
			objName: "foo",
			expectedObj: &controlplane.AddressGroup{
				ObjectMeta: v1.ObjectMeta{
					Name: "foo",
				},
			},
		},
		{
			name: "get non-existing object",
			addressGroups: []*types.AddressGroup{
				{
					Name: "foo",
				},
			},
			objName:     "bar",
			expectedErr: errors.NewNotFound(controlplane.Resource("addressgroup"), "bar"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage := store.NewAddressGroupStore()
			for _, obj := range tt.addressGroups {
				storage.Create(obj)
			}
			r := NewREST(storage)
			actualObj, err := r.Get(context.TODO(), tt.objName, &v1.GetOptions{})
			assert.Equal(t, tt.expectedErr, err)
			assert.Equal(t, tt.expectedObj, actualObj)
		})
	}
}

func TestRESTList(t *testing.T) {
	tests := []struct {
		name          string
		addressGroups []*types.AddressGroup
		labelSelector labels.Selector
		expectedObj   runtime.Object
	}{
		{
			name: "label selector selecting nothing",
			addressGroups: []*types.AddressGroup{
				{
					Name: "foo",
				},
			},
			labelSelector: labels.Nothing(),
			expectedObj:   &controlplane.AddressGroupList{},
		},
		{
			name: "label selector selecting everything",
			addressGroups: []*types.AddressGroup{
				{
					Name: "foo",
				},
			},
			labelSelector: labels.Everything(),
			expectedObj: &controlplane.AddressGroupList{
				Items: []controlplane.AddressGroup{
					{
						ObjectMeta: v1.ObjectMeta{
							Name: "foo",
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage := store.NewAddressGroupStore()
			for _, obj := range tt.addressGroups {
				storage.Create(obj)
			}
			r := NewREST(storage)
			actualObj, err := r.List(context.TODO(), &internalversion.ListOptions{LabelSelector: tt.labelSelector})
			assert.NoError(t, err)
			assert.ElementsMatch(t, tt.expectedObj.(*controlplane.AddressGroupList).Items, actualObj.(*controlplane.AddressGroupList).Items)
		})
	}
}

func TestRESTWatch(t *testing.T) {
	addressGroups := []*types.AddressGroup{
		{
			Name:     "addressGroup1",
			SpanMeta: types.SpanMeta{NodeNames: sets.New[string]("node1")},
		},
	}
	tests := []struct {
		name           string
		fieldSelector  fields.Selector
		expectedEvents []watch.Event
	}{
		{
			name:          "nodeName selecting nothing",
			fieldSelector: fields.OneTermEqualSelector("nodeName", "foo"),
			expectedEvents: []watch.Event{
				{Type: watch.Bookmark, Object: &controlplane.AddressGroup{}},
			},
		},
		{
			name:          "nodeName provided",
			fieldSelector: fields.OneTermEqualSelector("nodeName", "node1"),
			expectedEvents: []watch.Event{
				{Type: watch.Added, Object: &controlplane.AddressGroup{ObjectMeta: v1.ObjectMeta{Name: "addressGroup1"}}},
				{Type: watch.Bookmark, Object: &controlplane.AddressGroup{}},
			},
		},
		{
			name:          "nodeName not provided",
			fieldSelector: nil,
			expectedEvents: []watch.Event{
				{Type: watch.Added, Object: &controlplane.AddressGroup{ObjectMeta: v1.ObjectMeta{Name: "addressGroup1"}}},
				{Type: watch.Bookmark, Object: &controlplane.AddressGroup{}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage := store.NewAddressGroupStore()
			for _, obj := range addressGroups {
				storage.Create(obj)
			}
			r := NewREST(storage)
			watcher, err := r.Watch(context.TODO(), &internalversion.ListOptions{FieldSelector: tt.fieldSelector})
			assert.NoError(t, err)
			defer watcher.Stop()
			for _, expectedObj := range tt.expectedEvents {
				select {
				case gotObj := <-watcher.ResultChan():
					assert.Equal(t, expectedObj, gotObj)
				case <-time.NewTimer(time.Second).C:
					t.Errorf("Failed to get expected object %v from watcher in time", expectedObj)
				}
			}
			select {
			case gotObj := <-watcher.ResultChan():
				t.Errorf("Got unexpected object %v from watcher", gotObj)
			case <-time.NewTimer(time.Millisecond * 100).C:
			}
		})
	}
}
