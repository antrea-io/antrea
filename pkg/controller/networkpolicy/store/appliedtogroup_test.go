// Copyright 2019 Antrea Authors
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

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/watch"

	"antrea.io/antrea/pkg/apis/controlplane"
	"antrea.io/antrea/pkg/apiserver/storage"
	"antrea.io/antrea/pkg/controller/types"
)

func newAppliedToGroupPodMember(name, namespace string) *controlplane.GroupMember {
	return &controlplane.GroupMember{Pod: &controlplane.PodReference{Name: name, Namespace: namespace}}
}

func newAppliedToGroupMemberExternalEntity(name, namespace string) *controlplane.GroupMember {
	return &controlplane.GroupMember{ExternalEntity: &controlplane.ExternalEntityReference{Name: name, Namespace: namespace}}
}

func TestWatchAppliedToGroupEvent(t *testing.T) {
	pod1 := newAppliedToGroupPodMember("pod1", "default")
	pod2 := newAppliedToGroupPodMember("pod2", "default")
	pod3 := newAppliedToGroupPodMember("pod3", "default")
	pod4 := newAppliedToGroupPodMember("pod4", "default")
	ee1 := newAppliedToGroupMemberExternalEntity("ee1", "default")
	ee2 := newAppliedToGroupMemberExternalEntity("ee2", "default")
	ee3 := newAppliedToGroupMemberExternalEntity("ee3", "default")
	ee4 := newAppliedToGroupMemberExternalEntity("ee4", "default")

	testCases := map[string]struct {
		fieldSelector fields.Selector
		// The operations that will be executed on the store.
		operations func(p storage.Interface)
		// The events expected to see.
		expected []watch.Event
	}{
		"non-node-scoped-watcher": {
			// All events should be watched.
			fieldSelector: fields.Everything(),
			operations: func(store storage.Interface) {
				store.Create(&types.AppliedToGroup{
					Name:              "foo",
					SpanMeta:          types.SpanMeta{NodeNames: sets.New[string]("node1", "node2")},
					GroupMemberByNode: map[string]controlplane.GroupMemberSet{"node1": controlplane.NewGroupMemberSet(pod1), "node2": controlplane.NewGroupMemberSet(pod2)},
				})
				store.Update(&types.AppliedToGroup{
					Name:              "foo",
					SpanMeta:          types.SpanMeta{NodeNames: sets.New[string]("node1", "node2")},
					GroupMemberByNode: map[string]controlplane.GroupMemberSet{"node1": controlplane.NewGroupMemberSet(pod1), "node2": controlplane.NewGroupMemberSet(pod3)},
				})
				store.Create(&types.AppliedToGroup{
					Name:              "bar",
					SpanMeta:          types.SpanMeta{NodeNames: sets.New[string]("node1", "node2")},
					GroupMemberByNode: map[string]controlplane.GroupMemberSet{"node1": controlplane.NewGroupMemberSet(ee1), "node2": controlplane.NewGroupMemberSet(ee2)},
				})
				store.Update(&types.AppliedToGroup{
					Name:              "bar",
					SpanMeta:          types.SpanMeta{NodeNames: sets.New[string]("node1", "node2")},
					GroupMemberByNode: map[string]controlplane.GroupMemberSet{"node1": controlplane.NewGroupMemberSet(ee1), "node2": controlplane.NewGroupMemberSet(ee3)},
				})
			},
			expected: []watch.Event{
				{Type: watch.Bookmark, Object: nil},
				{Type: watch.Added, Object: &controlplane.AppliedToGroup{
					ObjectMeta:   metav1.ObjectMeta{Name: "foo"},
					GroupMembers: []controlplane.GroupMember{*pod1, *pod2},
				}},
				{Type: watch.Modified, Object: &controlplane.AppliedToGroupPatch{
					ObjectMeta:          metav1.ObjectMeta{Name: "foo"},
					AddedGroupMembers:   []controlplane.GroupMember{*pod3},
					RemovedGroupMembers: []controlplane.GroupMember{*pod2},
				}},
				{Type: watch.Added, Object: &controlplane.AppliedToGroup{
					ObjectMeta:   metav1.ObjectMeta{Name: "bar"},
					GroupMembers: []controlplane.GroupMember{*ee1, *ee2},
				}},
				{Type: watch.Modified, Object: &controlplane.AppliedToGroupPatch{
					ObjectMeta:          metav1.ObjectMeta{Name: "bar"},
					AddedGroupMembers:   []controlplane.GroupMember{*ee3},
					RemovedGroupMembers: []controlplane.GroupMember{*ee2},
				}},
			},
		},
		"node-scoped-watcher": {
			// Only events that span node3 should be watched.
			fieldSelector: fields.SelectorFromSet(fields.Set{"nodeName": "node3"}),
			operations: func(store storage.Interface) {
				// This should not be seen as it doesn't span node3.
				store.Create(&types.AppliedToGroup{
					Name:              "foo",
					SpanMeta:          types.SpanMeta{NodeNames: sets.New[string]("node1", "node2")},
					GroupMemberByNode: map[string]controlplane.GroupMemberSet{"node1": controlplane.NewGroupMemberSet(pod1, ee1), "node2": controlplane.NewGroupMemberSet(pod2, ee2)},
				})
				// This should be seen as an added event as it makes foo span node3 for the first time.
				store.Update(&types.AppliedToGroup{
					Name:              "foo",
					SpanMeta:          types.SpanMeta{NodeNames: sets.New[string]("node1", "node3")},
					GroupMemberByNode: map[string]controlplane.GroupMemberSet{"node1": controlplane.NewGroupMemberSet(pod1, ee1), "node3": controlplane.NewGroupMemberSet(pod3, ee3)},
				})
				// This should be seen as a modified event as it updates appliedToGroups of node3.
				store.Update(&types.AppliedToGroup{
					Name:              "foo",
					SpanMeta:          types.SpanMeta{NodeNames: sets.New[string]("node1", "node3")},
					GroupMemberByNode: map[string]controlplane.GroupMemberSet{"node1": controlplane.NewGroupMemberSet(pod1, ee1), "node3": controlplane.NewGroupMemberSet(pod4, ee4)},
				})
				// This should not be seen as a modified event as the change doesn't span node3.
				store.Update(&types.AppliedToGroup{
					Name:              "foo",
					SpanMeta:          types.SpanMeta{NodeNames: sets.New[string]("node3")},
					GroupMemberByNode: map[string]controlplane.GroupMemberSet{"node3": controlplane.NewGroupMemberSet(pod4, ee4)},
				})
				// This should be seen as a deleted event as it makes foo not span node3 any more.
				store.Update(&types.AppliedToGroup{
					Name:              "foo",
					SpanMeta:          types.SpanMeta{NodeNames: sets.New[string]("node1")},
					GroupMemberByNode: map[string]controlplane.GroupMemberSet{"node1": controlplane.NewGroupMemberSet(pod1, ee1)},
				})
			},
			expected: []watch.Event{
				{Type: watch.Bookmark, Object: nil},
				{Type: watch.Added, Object: &controlplane.AppliedToGroup{
					ObjectMeta:   metav1.ObjectMeta{Name: "foo"},
					GroupMembers: []controlplane.GroupMember{*pod3, *ee3},
				}},
				{Type: watch.Modified, Object: &controlplane.AppliedToGroupPatch{
					ObjectMeta:          metav1.ObjectMeta{Name: "foo"},
					AddedGroupMembers:   []controlplane.GroupMember{*pod4, *ee4},
					RemovedGroupMembers: []controlplane.GroupMember{*pod3, *ee3},
				}},
				{Type: watch.Deleted, Object: &controlplane.AppliedToGroup{
					ObjectMeta: metav1.ObjectMeta{Name: "foo"},
				}},
			},
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			store := NewAppliedToGroupStore()
			w, err := store.Watch(context.Background(), "", labels.Everything(), testCase.fieldSelector)
			if err != nil {
				t.Fatalf("Failed to watch object: %v", err)
			}
			testCase.operations(store)
			ch := w.ResultChan()
			for _, expectedEvent := range testCase.expected {
				actualEvent := <-ch
				if actualEvent.Type != expectedEvent.Type {
					t.Fatalf("Expected event type %v, got %v", expectedEvent.Type, actualEvent.Type)
				}
				switch actualEvent.Type {
				case watch.Added, watch.Deleted:
					actualObj := actualEvent.Object.(*controlplane.AppliedToGroup)
					expectedObj := expectedEvent.Object.(*controlplane.AppliedToGroup)
					if !assert.Equal(t, expectedObj.ObjectMeta, actualObj.ObjectMeta) {
						t.Errorf("Expected ObjectMeta %v, got %v", expectedObj.ObjectMeta, actualObj.ObjectMeta)
					}
					if !assert.ElementsMatch(t, expectedObj.GroupMembers, actualObj.GroupMembers) {
						t.Errorf("Expected GroupMembers %v, got %v", expectedObj.GroupMembers, actualObj.GroupMembers)
					}
				case watch.Modified:
					actualObj := actualEvent.Object.(*controlplane.AppliedToGroupPatch)
					expectedObj := expectedEvent.Object.(*controlplane.AppliedToGroupPatch)
					if !assert.Equal(t, expectedObj.ObjectMeta, actualObj.ObjectMeta) {
						t.Errorf("Expected ObjectMeta %v, got %v", expectedObj.ObjectMeta, actualObj.ObjectMeta)
					}
					if !assert.ElementsMatch(t, expectedObj.AddedGroupMembers, actualObj.AddedGroupMembers) {
						t.Errorf("Expected GroupMembers %v, got %v", expectedObj.AddedGroupMembers, actualObj.AddedGroupMembers)
					}
					if !assert.ElementsMatch(t, expectedObj.RemovedGroupMembers, actualObj.RemovedGroupMembers) {
						t.Errorf("Expected GroupMembers %v, got %v", expectedObj.RemovedGroupMembers, actualObj.RemovedGroupMembers)
					}
				}
			}
			select {
			case obj, ok := <-ch:
				t.Errorf("Unexpected excess event: %#v %t", obj, ok)
			default:
			}
		})
	}
}
