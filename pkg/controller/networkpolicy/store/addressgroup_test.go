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
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/watch"

	"github.com/vmware-tanzu/antrea/pkg/apis/controlplane"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/storage"
	"github.com/vmware-tanzu/antrea/pkg/controller/types"
)

func newAddressGroupMemberPod(podName, ip string) *controlplane.GroupMember {
	return &controlplane.GroupMember{
		Pod: &controlplane.PodReference{
			Name: podName,
		},
		IPs: []controlplane.IPAddress{controlplane.IPAddress(net.ParseIP(ip))},
	}
}

func newAddressGroupMemberExternalEntity(eeName, ip string) *controlplane.GroupMember {
	return &controlplane.GroupMember{
		ExternalEntity: &controlplane.ExternalEntityReference{
			Name: eeName,
		},
		IPs: []controlplane.IPAddress{controlplane.IPAddress(net.ParseIP(ip))},
	}
}

func TestWatchAddressGroupEvent(t *testing.T) {
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
				store.Create(&types.AddressGroup{
					Name:     "foo",
					SpanMeta: types.SpanMeta{NodeNames: sets.NewString("node1", "node2")},
					GroupMembers: controlplane.NewGroupMemberSet(
						newAddressGroupMemberPod("pod1", "1.1.1.1"), newAddressGroupMemberPod("pod2", "2.2.2.2"),
						newAddressGroupMemberExternalEntity("ee5", "5.5.5.5"), newAddressGroupMemberExternalEntity("ee6", "6.6.6.6")),
				})
				store.Update(&types.AddressGroup{
					Name:     "foo",
					SpanMeta: types.SpanMeta{NodeNames: sets.NewString("node1", "node2")},
					GroupMembers: controlplane.NewGroupMemberSet(
						newAddressGroupMemberPod("pod1", "1.1.1.1"), newAddressGroupMemberPod("pod3", "3.3.3.3"),
						newAddressGroupMemberExternalEntity("ee5", "5.5.5.5"), newAddressGroupMemberExternalEntity("ee7", "7.7.7.7")),
				})
			},
			expected: []watch.Event{
				{Type: watch.Bookmark, Object: nil},
				{Type: watch.Added, Object: &controlplane.AddressGroup{
					ObjectMeta: metav1.ObjectMeta{Name: "foo"},
					GroupMembers: []controlplane.GroupMember{
						*newAddressGroupMemberPod("pod1", "1.1.1.1"), *newAddressGroupMemberPod("pod2", "2.2.2.2"),
						*newAddressGroupMemberExternalEntity("ee5", "5.5.5.5"), *newAddressGroupMemberExternalEntity("ee6", "6.6.6.6")},
				}},
				{Type: watch.Modified, Object: &controlplane.AddressGroupPatch{
					ObjectMeta: metav1.ObjectMeta{Name: "foo"},
					AddedGroupMembers: []controlplane.GroupMember{
						*newAddressGroupMemberPod("pod3", "3.3.3.3"), *newAddressGroupMemberExternalEntity("ee7", "7.7.7.7")},
					RemovedGroupMembers: []controlplane.GroupMember{
						*newAddressGroupMemberPod("pod2", "2.2.2.2"), *newAddressGroupMemberExternalEntity("ee6", "6.6.6.6")},
				}},
			},
		},
		"node-scoped-watcher": {
			// Only events that span node3 should be watched.
			fieldSelector: fields.SelectorFromSet(fields.Set{"nodeName": "node3"}),
			operations: func(store storage.Interface) {
				// This should not be seen as it doesn't span node3.
				store.Create(&types.AddressGroup{
					Name:     "foo",
					SpanMeta: types.SpanMeta{NodeNames: sets.NewString("node1", "node2")},
					GroupMembers: controlplane.NewGroupMemberSet(
						newAddressGroupMemberPod("pod1", "1.1.1.1"), newAddressGroupMemberPod("pod2", "2.2.2.2"),
						newAddressGroupMemberExternalEntity("ee5", "5.5.5.5"), newAddressGroupMemberExternalEntity("ee6", "6.6.6.6")),
				})
				// This should be seen as an added event as it makes foo span node3 for the first time.
				store.Update(&types.AddressGroup{
					Name:     "foo",
					SpanMeta: types.SpanMeta{NodeNames: sets.NewString("node1", "node3")},
					GroupMembers: controlplane.NewGroupMemberSet(
						newAddressGroupMemberPod("pod1", "1.1.1.1"), newAddressGroupMemberPod("pod2", "2.2.2.2"),
						newAddressGroupMemberExternalEntity("ee5", "5.5.5.5"), newAddressGroupMemberExternalEntity("ee6", "6.6.6.6")),
				})
				// This should be seen as a modified event as it updates addressGroups of node3.
				store.Update(&types.AddressGroup{
					Name:     "foo",
					SpanMeta: types.SpanMeta{NodeNames: sets.NewString("node1", "node3")},
					GroupMembers: controlplane.NewGroupMemberSet(
						newAddressGroupMemberPod("pod1", "1.1.1.1"), newAddressGroupMemberPod("pod3", "3.3.3.3"),
						newAddressGroupMemberExternalEntity("ee5", "5.5.5.5"), newAddressGroupMemberExternalEntity("ee7", "7.7.7.7")),
				})
				// This should be seen as a deleted event as it makes foo not span node3 any more.
				store.Update(&types.AddressGroup{
					Name:     "foo",
					SpanMeta: types.SpanMeta{NodeNames: sets.NewString("node1")},
					GroupMembers: controlplane.NewGroupMemberSet(
						newAddressGroupMemberPod("pod1", "1.1.1.1"), newAddressGroupMemberPod("pod3", "3.3.3.3"),
						newAddressGroupMemberExternalEntity("ee5", "5.5.5.5"), newAddressGroupMemberExternalEntity("ee6", "6.6.6.6")),
				})
			},
			expected: []watch.Event{
				{Type: watch.Bookmark, Object: nil},
				{Type: watch.Added, Object: &controlplane.AddressGroup{
					ObjectMeta: metav1.ObjectMeta{Name: "foo"},
					GroupMembers: []controlplane.GroupMember{
						*newAddressGroupMemberPod("pod1", "1.1.1.1"), *newAddressGroupMemberPod("pod2", "2.2.2.2"),
						*newAddressGroupMemberExternalEntity("ee5", "5.5.5.5"), *newAddressGroupMemberExternalEntity("ee6", "6.6.6.6")},
				}},
				{Type: watch.Modified, Object: &controlplane.AddressGroupPatch{
					ObjectMeta: metav1.ObjectMeta{Name: "foo"},
					AddedGroupMembers: []controlplane.GroupMember{
						*newAddressGroupMemberPod("pod3", "3.3.3.3"), *newAddressGroupMemberExternalEntity("ee7", "7.7.7.7")},
					RemovedGroupMembers: []controlplane.GroupMember{
						*newAddressGroupMemberPod("pod2", "2.2.2.2"), *newAddressGroupMemberExternalEntity("ee6", "6.6.6.6")},
				}},
				{Type: watch.Deleted, Object: &controlplane.AddressGroup{
					ObjectMeta: metav1.ObjectMeta{Name: "foo"},
				}},
			},
		},
		"address-update-after-restart": {
			// All events should be watched.
			fieldSelector: fields.SelectorFromSet(fields.Set{"nodeName": "node1"}),
			operations: func(store storage.Interface) {
				store.Create(&types.AddressGroup{
					Name:     "foo",
					SpanMeta: types.SpanMeta{NodeNames: sets.NewString("node1")},
					GroupMembers: controlplane.NewGroupMemberSet(
						newAddressGroupMemberPod("pod1", "1.1.1.1"), newAddressGroupMemberPod("pod2", "2.2.2.2")),
				})
				store.Update(&types.AddressGroup{
					Name:     "foo",
					SpanMeta: types.SpanMeta{NodeNames: sets.NewString("node1")},
					GroupMembers: controlplane.NewGroupMemberSet(
						newAddressGroupMemberPod("pod1", "3.3.3.3"), newAddressGroupMemberPod("pod2", "4.4.4.4")),
				})
			},
			expected: []watch.Event{
				{Type: watch.Bookmark, Object: nil},
				{Type: watch.Added, Object: &controlplane.AddressGroup{
					ObjectMeta: metav1.ObjectMeta{Name: "foo"},
					GroupMembers: []controlplane.GroupMember{
						*newAddressGroupMemberPod("pod1", "1.1.1.1"), *newAddressGroupMemberPod("pod2", "2.2.2.2")},
				}},
				{Type: watch.Modified, Object: &controlplane.AddressGroupPatch{
					ObjectMeta: metav1.ObjectMeta{Name: "foo"},
					AddedGroupMembers: []controlplane.GroupMember{
						*newAddressGroupMemberPod("pod1", "3.3.3.3"), *newAddressGroupMemberPod("pod2", "4.4.4.4")},
					RemovedGroupMembers: []controlplane.GroupMember{
						*newAddressGroupMemberPod("pod1", "1.1.1.1"), *newAddressGroupMemberPod("pod2", "2.2.2.2")},
				}},
			},
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			store := NewAddressGroupStore()
			w, err := store.Watch(context.Background(), "", labels.Everything(), testCase.fieldSelector)
			if err != nil {
				t.Errorf("Failed to watch object: %v", err)
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
					actualObj := actualEvent.Object.(*controlplane.AddressGroup)
					expectedObj := expectedEvent.Object.(*controlplane.AddressGroup)
					if !assert.Equal(t, expectedObj.ObjectMeta, actualObj.ObjectMeta) {
						t.Errorf("Expected ObjectMeta %v, got %v", expectedObj.ObjectMeta, actualObj.ObjectMeta)
					}
					if !assert.ElementsMatch(t, expectedObj.GroupMembers, actualObj.GroupMembers) {
						t.Errorf("Expected IPAddresses %v, got %v", expectedObj.GroupMembers, actualObj.GroupMembers)
					}
				case watch.Modified:
					actualObj := actualEvent.Object.(*controlplane.AddressGroupPatch)
					expectedObj := expectedEvent.Object.(*controlplane.AddressGroupPatch)
					if !assert.Equal(t, expectedObj.ObjectMeta, actualObj.ObjectMeta) {
						t.Errorf("Expected ObjectMeta %v, got %v", expectedObj.ObjectMeta, actualObj.ObjectMeta)
					}
					if !assert.ElementsMatch(t, expectedObj.AddedGroupMembers, actualObj.AddedGroupMembers) {
						t.Errorf("Expected AddedIPAddresses %v, got %v", expectedObj.AddedGroupMembers, actualObj.AddedGroupMembers)
					}
					if !assert.ElementsMatch(t, expectedObj.RemovedGroupMembers, actualObj.RemovedGroupMembers) {
						t.Errorf("Expected RemovedIPAddresses %v, got %v", expectedObj.RemovedGroupMembers, actualObj.RemovedGroupMembers)
					}
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
