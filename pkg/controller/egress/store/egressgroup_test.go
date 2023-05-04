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

package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/watch"

	"antrea.io/antrea/pkg/apis/controlplane"
	"antrea.io/antrea/pkg/apiserver/storage"
	"antrea.io/antrea/pkg/controller/types"
)

func TestWatchEgressGroupEvent(t *testing.T) {
	egTypeInvalid := types.EgressGroup{}

	egressName := "egress"
	egressUID := k8stypes.UID("uid")
	pod1 := &controlplane.PodReference{Name: "pod1", Namespace: "namespace1"}
	eg1 := &types.EgressGroup{
		SpanMeta: types.SpanMeta{NodeNames: sets.New[string]("node-local")},
		UID:      egressUID,
		Name:     egressName,
		GroupMemberByNode: map[string]controlplane.GroupMemberSet{
			"node-local": controlplane.NewGroupMemberSet(&controlplane.GroupMember{Pod: pod1}),
		},
	}

	eg2 := &types.EgressGroup{
		SpanMeta:          types.SpanMeta{NodeNames: sets.New[string]("node1", "node2")},
		UID:               egressUID,
		Name:              egressName,
		GroupMemberByNode: map[string]controlplane.GroupMemberSet{},
	}

	pod2 := &controlplane.PodReference{Name: "pod2", Namespace: "namespace2"}
	eg3 := &types.EgressGroup{
		SpanMeta: types.SpanMeta{NodeNames: sets.New[string]("node-local")},
		UID:      egressUID,
		Name:     egressName,
		GroupMemberByNode: map[string]controlplane.GroupMemberSet{
			"node-local": controlplane.NewGroupMemberSet(&controlplane.GroupMember{Pod: pod2}),
		},
	}

	tests := []struct {
		name           string
		fieldSelector  fields.Selector
		operations     func(p storage.Interface)
		expectedEvents []watch.Event
	}{
		{
			name:          "Add event",
			fieldSelector: fields.SelectorFromSet(fields.Set{"nodeName": "node-local"}),
			operations: func(store storage.Interface) {
				store.Create(egTypeInvalid)
				store.Create(eg1)
			},
			expectedEvents: []watch.Event{
				{Type: watch.Bookmark, Object: &controlplane.EgressGroup{}},
				{Type: watch.Added, Object: &controlplane.EgressGroup{
					TypeMeta: metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{
						Name: egressName,
						UID:  egressUID,
					},
					GroupMembers: []controlplane.GroupMember{{Pod: pod1}},
				}},
			},
		},
		{
			name:          "Delete event",
			fieldSelector: fields.SelectorFromSet(fields.Set{"nodeName": "node-local"}),
			operations: func(store storage.Interface) {
				store.Create(eg1)
				store.Update(eg2)
			},
			expectedEvents: []watch.Event{
				{Type: watch.Bookmark, Object: &controlplane.EgressGroup{}},
				{Type: watch.Added, Object: &controlplane.EgressGroup{
					TypeMeta: metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{
						Name: egressName,
						UID:  egressUID,
					},
					GroupMembers: []controlplane.GroupMember{{Pod: pod1}},
				}},
				{Type: watch.Deleted, Object: &controlplane.EgressGroup{
					TypeMeta: metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{
						Name: egressName,
						UID:  egressUID,
					},
					GroupMembers: nil,
				}},
			},
		},
		{
			name:          "Modify event",
			fieldSelector: fields.SelectorFromSet(fields.Set{"nodeName": "node-local"}),
			operations: func(store storage.Interface) {
				store.Create(eg1)
				store.Update(eg1)
				store.Update(eg3)
				store.Update(eg3)
			},
			expectedEvents: []watch.Event{
				{Type: watch.Bookmark, Object: &controlplane.EgressGroup{}},
				{Type: watch.Added, Object: &controlplane.EgressGroup{
					TypeMeta: metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{
						Name: egressName,
						UID:  egressUID,
					},
					GroupMembers: []controlplane.GroupMember{{Pod: pod1}},
				}},
				{Type: watch.Modified, Object: &controlplane.EgressGroupPatch{
					TypeMeta: metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{
						Name: egressName,
						UID:  egressUID,
					},
					AddedGroupMembers:   []controlplane.GroupMember{{Pod: pod2}},
					RemovedGroupMembers: []controlplane.GroupMember{{Pod: pod1}},
				}},
			},
		},
		{
			name:          "Node not Specified",
			fieldSelector: fields.Everything(),
			operations: func(store storage.Interface) {
				store.Create(eg1)
				store.Update(eg3)
			},
			expectedEvents: []watch.Event{
				{Type: watch.Bookmark, Object: &controlplane.EgressGroup{}},
				{Type: watch.Added, Object: &controlplane.EgressGroup{
					TypeMeta: metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{
						Name: egressName,
						UID:  egressUID,
					},
					GroupMembers: []controlplane.GroupMember{{Pod: pod1}},
				}},
				{Type: watch.Modified, Object: &controlplane.EgressGroupPatch{
					TypeMeta: metav1.TypeMeta{},
					ObjectMeta: metav1.ObjectMeta{
						Name: egressName,
						UID:  egressUID,
					},
					AddedGroupMembers:   []controlplane.GroupMember{{Pod: pod2}},
					RemovedGroupMembers: []controlplane.GroupMember{{Pod: pod1}},
				}},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := NewEgressGroupStore()
			w, err := store.Watch(context.Background(), "", labels.Everything(), tc.fieldSelector)
			if err != nil {
				t.Fatalf("Failed to watch object: %v", err)
			}
			defer w.Stop()
			tc.operations(store)
			ch := w.ResultChan()
			for _, expectedEvent := range tc.expectedEvents {
				select {
				case actualEvent := <-ch:
					assert.Equal(t, expectedEvent, actualEvent)
				case <-time.After(5 * time.Second):
					t.Errorf("Wait expected event timeout")
				}
			}
			select {
			case obj, ok := <-ch:
				t.Errorf("Unexpected excess event: %v %t", obj, ok)
			default:
			}
		})
	}
}
