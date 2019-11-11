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

	"github.com/vmware-tanzu/antrea/pkg/apis/networkpolicy"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/storage"
	"github.com/vmware-tanzu/antrea/pkg/controller/types"
)

func TestWatchAppliedToGroupEvent(t *testing.T) {
	pod1 := networkpolicy.PodReference{"pod1", "default"}
	pod2 := networkpolicy.PodReference{"pod2", "default"}
	pod3 := networkpolicy.PodReference{"pod3", "default"}
	pod4 := networkpolicy.PodReference{"pod4", "default"}

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
					Name:       "foo",
					SpanMeta:   types.SpanMeta{sets.NewString("node1", "node2")},
					PodsByNode: map[string]types.PodSet{"node1": {pod1: sets.Empty{}}, "node2": {pod2: sets.Empty{}}},
				})
				store.Update(&types.AppliedToGroup{
					Name:       "foo",
					SpanMeta:   types.SpanMeta{sets.NewString("node1", "node2")},
					PodsByNode: map[string]types.PodSet{"node1": {pod1: sets.Empty{}}, "node2": {pod3: sets.Empty{}}},
				})
			},
			expected: []watch.Event{
				{watch.Added, &networkpolicy.AppliedToGroup{
					ObjectMeta: metav1.ObjectMeta{Name: "foo"},
					Pods:       []networkpolicy.PodReference{pod1, pod2},
				}},
				{watch.Modified, &networkpolicy.AppliedToGroupPatch{
					ObjectMeta:  metav1.ObjectMeta{Name: "foo"},
					AddedPods:   []networkpolicy.PodReference{pod3},
					RemovedPods: []networkpolicy.PodReference{pod2},
				}},
			},
		},
		"node-scoped-watcher": {
			// Only events that span node3 should be watched.
			fieldSelector: fields.SelectorFromSet(fields.Set{"nodeName": "node3"}),
			operations: func(store storage.Interface) {
				// This should not be seen as it doesn't span node3.
				store.Create(&types.AppliedToGroup{
					Name:       "foo",
					SpanMeta:   types.SpanMeta{sets.NewString("node1", "node2")},
					PodsByNode: map[string]types.PodSet{"node1": {pod1: sets.Empty{}}, "node2": {pod2: sets.Empty{}}},
				})
				// This should be seen as an added event as it makes foo span node3 for the first time.
				store.Update(&types.AppliedToGroup{
					Name:       "foo",
					SpanMeta:   types.SpanMeta{sets.NewString("node1", "node3")},
					PodsByNode: map[string]types.PodSet{"node1": {pod1: sets.Empty{}}, "node3": {pod3: sets.Empty{}}},
				})
				// This should be seen as a modified event as it updates appliedToGroups of node3.
				store.Update(&types.AppliedToGroup{
					Name:       "foo",
					SpanMeta:   types.SpanMeta{sets.NewString("node1", "node3")},
					PodsByNode: map[string]types.PodSet{"node1": {pod1: sets.Empty{}}, "node3": {pod4: sets.Empty{}}},
				})
				// This should not be seen as a modified event as the change doesn't span node3.
				store.Update(&types.AppliedToGroup{
					Name:       "foo",
					SpanMeta:   types.SpanMeta{sets.NewString("node3")},
					PodsByNode: map[string]types.PodSet{"node3": {pod4: sets.Empty{}}},
				})
				// This should be seen as a deleted event as it makes foo not span node3 any more.
				store.Update(&types.AppliedToGroup{
					Name:       "foo",
					SpanMeta:   types.SpanMeta{sets.NewString("node1")},
					PodsByNode: map[string]types.PodSet{"node1": {pod1: sets.Empty{}}},
				})
			},
			expected: []watch.Event{
				{watch.Added, &networkpolicy.AppliedToGroup{
					ObjectMeta: metav1.ObjectMeta{Name: "foo"},
					Pods:       []networkpolicy.PodReference{pod3},
				}},
				{watch.Modified, &networkpolicy.AppliedToGroupPatch{
					ObjectMeta:  metav1.ObjectMeta{Name: "foo"},
					AddedPods:   []networkpolicy.PodReference{pod4},
					RemovedPods: []networkpolicy.PodReference{pod3},
				}},
				{watch.Deleted, &networkpolicy.AppliedToGroup{
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
					actualObj := actualEvent.Object.(*networkpolicy.AppliedToGroup)
					expectedObj := expectedEvent.Object.(*networkpolicy.AppliedToGroup)
					if !assert.Equal(t, expectedObj.ObjectMeta, actualObj.ObjectMeta) {
						t.Errorf("Expected ObjectMeta %v, got %v", expectedObj.ObjectMeta, actualObj.ObjectMeta)
					}
					if !assert.ElementsMatch(t, expectedObj.Pods, actualObj.Pods) {
						t.Errorf("Expected Pods %v, got %v", expectedObj.Pods, actualObj.Pods)
					}
				case watch.Modified:
					actualObj := actualEvent.Object.(*networkpolicy.AppliedToGroupPatch)
					expectedObj := expectedEvent.Object.(*networkpolicy.AppliedToGroupPatch)
					if !assert.Equal(t, expectedObj.ObjectMeta, actualObj.ObjectMeta) {
						t.Errorf("Expected ObjectMeta %v, got %v", expectedObj.ObjectMeta, actualObj.ObjectMeta)
					}
					if !assert.ElementsMatch(t, expectedObj.AddedPods, actualObj.AddedPods) {
						t.Errorf("Expected Pods %v, got %v", expectedObj.AddedPods, actualObj.AddedPods)
					}
					if !assert.ElementsMatch(t, expectedObj.RemovedPods, actualObj.RemovedPods) {
						t.Errorf("Expected Pods %v, got %v", expectedObj.RemovedPods, actualObj.RemovedPods)
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
