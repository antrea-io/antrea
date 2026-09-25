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

package store

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/watch"

	"antrea.io/antrea/v2/pkg/apis/controlplane"
	"antrea.io/antrea/v2/pkg/apiserver/storage"
	"antrea.io/antrea/v2/pkg/controller/types"
)

func TestWatchEgressAddressGroupEvent(t *testing.T) {
	groupName := "group"
	groupUID := k8stypes.UID("group")
	member1 := &controlplane.GroupMember{
		Pod: &controlplane.PodReference{Name: "pod1", Namespace: "namespace1"},
		IPs: []controlplane.IPAddress{controlplane.IPAddress(net.ParseIP("10.10.0.11"))},
	}
	member2 := &controlplane.GroupMember{
		Pod: &controlplane.PodReference{Name: "pod2", Namespace: "namespace1"},
		IPs: []controlplane.IPAddress{controlplane.IPAddress(net.ParseIP("10.10.1.12"))},
	}
	newGroup := func(egresses []string, nodeNames []string, members ...*controlplane.GroupMember) *types.EgressAddressGroup {
		return &types.EgressAddressGroup{
			SpanMeta:     types.SpanMeta{NodeNames: sets.New[string](nodeNames...)},
			UID:          groupUID,
			Name:         groupName,
			Egresses:     sets.New[string](egresses...),
			GroupMembers: controlplane.NewGroupMemberSet(members...),
		}
	}
	// The members are on Node node-a and node-b. The Egress Node is node-1, then node-2.
	group1 := newGroup([]string{"egress1"}, []string{"node-1"}, member1)
	group2 := newGroup([]string{"egress1"}, []string{"node-1"}, member1, member2)
	group3 := newGroup([]string{"egress1", "egress2"}, []string{"node-1"}, member1, member2)
	group4 := newGroup([]string{"egress1", "egress2"}, []string{"node-2"}, member1, member2)
	meta := metav1.ObjectMeta{Name: groupName, UID: groupUID}
	bookmark := watch.Event{Type: watch.Bookmark, Object: &controlplane.EgressAddressGroup{ObjectMeta: metav1.ObjectMeta{ResourceVersion: "0"}}}

	tests := []struct {
		name           string
		fieldSelector  fields.Selector
		operations     func(p storage.Interface)
		expectedEvents []watch.Event
	}{
		{
			name:          "Egress Node gets all members",
			fieldSelector: fields.SelectorFromSet(fields.Set{"nodeName": "node-1"}),
			operations: func(store storage.Interface) {
				store.Create(group2)
			},
			expectedEvents: []watch.Event{
				bookmark,
				{Type: watch.Added, Object: &controlplane.EgressAddressGroup{
					ObjectMeta:   meta,
					Egresses:     []string{"egress1"},
					GroupMembers: []controlplane.GroupMember{*member1, *member2},
				}},
			},
		},
		{
			name:          "Node hosting a member gets nothing",
			fieldSelector: fields.SelectorFromSet(fields.Set{"nodeName": "node-a"}),
			operations: func(store storage.Interface) {
				store.Create(group2)
				store.Update(group3)
			},
			expectedEvents: []watch.Event{bookmark},
		},
		{
			name:          "Member added",
			fieldSelector: fields.SelectorFromSet(fields.Set{"nodeName": "node-1"}),
			operations: func(store storage.Interface) {
				store.Create(group1)
				store.Update(group1)
				store.Update(group2)
			},
			expectedEvents: []watch.Event{
				bookmark,
				{Type: watch.Added, Object: &controlplane.EgressAddressGroup{
					ObjectMeta:   meta,
					Egresses:     []string{"egress1"},
					GroupMembers: []controlplane.GroupMember{*member1},
				}},
				{Type: watch.Modified, Object: &controlplane.EgressAddressGroupPatch{
					ObjectMeta:        meta,
					AddedGroupMembers: []controlplane.GroupMember{*member2},
				}},
			},
		},
		{
			name:          "Egress added",
			fieldSelector: fields.SelectorFromSet(fields.Set{"nodeName": "node-1"}),
			operations: func(store storage.Interface) {
				store.Create(group2)
				store.Update(group3)
			},
			expectedEvents: []watch.Event{
				bookmark,
				{Type: watch.Added, Object: &controlplane.EgressAddressGroup{
					ObjectMeta:   meta,
					Egresses:     []string{"egress1"},
					GroupMembers: []controlplane.GroupMember{*member1, *member2},
				}},
				{Type: watch.Modified, Object: &controlplane.EgressAddressGroupPatch{
					ObjectMeta: meta,
					Egresses:   []string{"egress1", "egress2"},
				}},
			},
		},
		{
			name:          "Egress Node changes, previous Node",
			fieldSelector: fields.SelectorFromSet(fields.Set{"nodeName": "node-1"}),
			operations: func(store storage.Interface) {
				store.Create(group3)
				store.Update(group4)
			},
			expectedEvents: []watch.Event{
				bookmark,
				{Type: watch.Added, Object: &controlplane.EgressAddressGroup{
					ObjectMeta:   meta,
					Egresses:     []string{"egress1", "egress2"},
					GroupMembers: []controlplane.GroupMember{*member1, *member2},
				}},
				{Type: watch.Deleted, Object: &controlplane.EgressAddressGroup{ObjectMeta: meta}},
			},
		},
		{
			name:          "Egress Node changes, new Node",
			fieldSelector: fields.SelectorFromSet(fields.Set{"nodeName": "node-2"}),
			operations: func(store storage.Interface) {
				store.Create(group3)
				store.Update(group4)
			},
			expectedEvents: []watch.Event{
				bookmark,
				{Type: watch.Added, Object: &controlplane.EgressAddressGroup{
					ObjectMeta:   meta,
					Egresses:     []string{"egress1", "egress2"},
					GroupMembers: []controlplane.GroupMember{*member1, *member2},
				}},
			},
		},
		{
			name:          "Group deleted",
			fieldSelector: fields.SelectorFromSet(fields.Set{"nodeName": "node-1"}),
			operations: func(store storage.Interface) {
				store.Create(group1)
				store.Delete(groupName)
			},
			expectedEvents: []watch.Event{
				bookmark,
				{Type: watch.Added, Object: &controlplane.EgressAddressGroup{
					ObjectMeta:   meta,
					Egresses:     []string{"egress1"},
					GroupMembers: []controlplane.GroupMember{*member1},
				}},
				{Type: watch.Deleted, Object: &controlplane.EgressAddressGroup{ObjectMeta: meta}},
			},
		},
		{
			name:          "Node not specified",
			fieldSelector: fields.Everything(),
			operations: func(store storage.Interface) {
				store.Create(group1)
				store.Update(group2)
			},
			expectedEvents: []watch.Event{
				bookmark,
				{Type: watch.Added, Object: &controlplane.EgressAddressGroup{
					ObjectMeta:   meta,
					Egresses:     []string{"egress1"},
					GroupMembers: []controlplane.GroupMember{*member1},
				}},
				{Type: watch.Modified, Object: &controlplane.EgressAddressGroupPatch{
					ObjectMeta:        meta,
					AddedGroupMembers: []controlplane.GroupMember{*member2},
				}},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := NewEgressAddressGroupStore()
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
					// The members of a group are a set, so their order in a message is not fixed.
					switch expected := expectedEvent.Object.(type) {
					case *controlplane.EgressAddressGroup:
						actual, ok := actualEvent.Object.(*controlplane.EgressAddressGroup)
						if assert.True(t, ok, "unexpected object %v", actualEvent.Object) {
							assert.ElementsMatch(t, expected.GroupMembers, actual.GroupMembers)
							expectedCopy, actualCopy := *expected, *actual
							expectedCopy.GroupMembers, actualCopy.GroupMembers = nil, nil
							assert.Equal(t, expectedCopy, actualCopy)
						}
						assert.Equal(t, expectedEvent.Type, actualEvent.Type)
					default:
						assert.Equal(t, expectedEvent, actualEvent)
					}
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
