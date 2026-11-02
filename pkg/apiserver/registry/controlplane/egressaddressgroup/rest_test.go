// Copyright 2026 Antrea Authors
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

package egressaddressgroup

import (
	"context"
	"net"
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

	"antrea.io/antrea/v2/pkg/apis/controlplane"
	"antrea.io/antrea/v2/pkg/controller/egress/store"
	"antrea.io/antrea/v2/pkg/controller/types"
)

func TestREST(t *testing.T) {
	r := NewREST(nil)
	assert.Equal(t, &controlplane.EgressAddressGroup{}, r.New())
	assert.Equal(t, &controlplane.EgressAddressGroupList{}, r.NewList())
	assert.False(t, r.NamespaceScoped())
}

func TestRESTGet(t *testing.T) {
	tests := []struct {
		name                string
		egressAddressGroups []*types.EgressAddressGroup
		objName             string
		expectedObj         runtime.Object
		expectedErr         error
	}{
		{
			name: "get existing object",
			egressAddressGroups: []*types.EgressAddressGroup{
				{
					Name: "foo",
				},
			},
			objName: "foo",
			expectedObj: &controlplane.EgressAddressGroup{
				ObjectMeta: v1.ObjectMeta{
					Name: "foo",
				},
			},
		},
		{
			name: "get non-existing object",
			egressAddressGroups: []*types.EgressAddressGroup{
				{
					Name: "foo",
				},
			},
			objName:     "bar",
			expectedErr: errors.NewNotFound(controlplane.Resource("egressaddressgroup"), "bar"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage := store.NewEgressAddressGroupStore()
			for _, obj := range tt.egressAddressGroups {
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
		name                string
		egressAddressGroups []*types.EgressAddressGroup
		labelSelector       labels.Selector
		expectedObj         runtime.Object
	}{
		{
			name: "label selector selecting nothing",
			egressAddressGroups: []*types.EgressAddressGroup{
				{
					Name: "foo",
				},
			},
			labelSelector: labels.Nothing(),
			expectedObj:   &controlplane.EgressAddressGroupList{},
		},
		{
			name: "label selector selecting everything",
			egressAddressGroups: []*types.EgressAddressGroup{
				{
					Name: "foo",
				},
			},
			labelSelector: labels.Everything(),
			expectedObj: &controlplane.EgressAddressGroupList{
				Items: []controlplane.EgressAddressGroup{
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
			storage := store.NewEgressAddressGroupStore()
			for _, obj := range tt.egressAddressGroups {
				storage.Create(obj)
			}
			r := NewREST(storage)
			actualObj, err := r.List(context.TODO(), &internalversion.ListOptions{LabelSelector: tt.labelSelector})
			assert.NoError(t, err)
			assert.ElementsMatch(t, tt.expectedObj.(*controlplane.EgressAddressGroupList).Items, actualObj.(*controlplane.EgressAddressGroupList).Items)
		})
	}
}

func TestRESTWatch(t *testing.T) {
	member := &controlplane.GroupMember{
		Pod: &controlplane.PodReference{Name: "pod1", Namespace: "ns1"},
		IPs: []controlplane.IPAddress{controlplane.IPAddress(net.ParseIP("10.10.0.11"))},
	}
	egressAddressGroups := []*types.EgressAddressGroup{
		{
			Name:         "group1",
			SpanMeta:     types.SpanMeta{NodeNames: sets.New[string]("node1")},
			Egresses:     sets.New[string]("egress1", "egress2"),
			GroupMembers: controlplane.NewGroupMemberSet(member),
		},
	}
	expectedObj := &controlplane.EgressAddressGroup{
		ObjectMeta:   v1.ObjectMeta{Name: "group1"},
		Egresses:     []string{"egress1", "egress2"},
		GroupMembers: []controlplane.GroupMember{*member},
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
				{Type: watch.Bookmark, Object: &controlplane.EgressAddressGroup{ObjectMeta: v1.ObjectMeta{ResourceVersion: "1"}}},
			},
		},
		{
			name:          "nodeName provided",
			fieldSelector: fields.OneTermEqualSelector("nodeName", "node1"),
			expectedEvents: []watch.Event{
				{Type: watch.Added, Object: expectedObj},
				{Type: watch.Bookmark, Object: &controlplane.EgressAddressGroup{ObjectMeta: v1.ObjectMeta{ResourceVersion: "1"}}},
			},
		},
		{
			name:          "nodeName not provided",
			fieldSelector: nil,
			expectedEvents: []watch.Event{
				{Type: watch.Added, Object: expectedObj},
				{Type: watch.Bookmark, Object: &controlplane.EgressAddressGroup{ObjectMeta: v1.ObjectMeta{ResourceVersion: "1"}}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage := store.NewEgressAddressGroupStore()
			for _, obj := range egressAddressGroups {
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
