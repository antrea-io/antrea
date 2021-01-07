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

package store

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/watch"

	"github.com/vmware-tanzu/antrea/pkg/apis/controlplane"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/storage"
	"github.com/vmware-tanzu/antrea/pkg/controller/types"
)

func newGroupMemberPod(ip string) *controlplane.GroupMember {
	return &controlplane.GroupMember{IPs: []controlplane.IPAddress{controlplane.IPAddress(net.ParseIP(ip))}}
}

func TestWatchGroupEvent(t *testing.T) {
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
				store.Create(&types.Group{
					UID: "foo",
					GroupMembers: controlplane.NewGroupMemberSet(
						newGroupMemberPod("1.1.1.1"), newGroupMemberPod("2.2.2.2")),
				})
				store.Update(&types.Group{
					UID: "foo",
					GroupMembers: controlplane.NewGroupMemberSet(
						newGroupMemberPod("1.1.1.1"), newGroupMemberPod("3.3.3.3")),
				})
			},
			expected: []watch.Event{
				{Type: watch.Bookmark, Object: nil},
				{Type: watch.Added, Object: &controlplane.Group{
					ObjectMeta: metav1.ObjectMeta{UID: "foo"},
					GroupMembers: []controlplane.GroupMember{
						*newGroupMemberPod("1.1.1.1"), *newGroupMemberPod("2.2.2.2")},
				}},
				{Type: watch.Modified, Object: &controlplane.GroupPatch{
					ObjectMeta: metav1.ObjectMeta{UID: "foo"},
					AddedGroupMembers: []controlplane.GroupMember{
						*newGroupMemberPod("3.3.3.3")},
					RemovedGroupMembers: []controlplane.GroupMember{
						*newGroupMemberPod("2.2.2.2")},
				}},
			},
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			store := NewGroupStore()
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
					actualObj := actualEvent.Object.(*controlplane.Group)
					expectedObj := expectedEvent.Object.(*controlplane.Group)
					if !assert.Equal(t, expectedObj.ObjectMeta, actualObj.ObjectMeta) {
						t.Errorf("Expected ObjectMeta %v, got %v", expectedObj.ObjectMeta, actualObj.ObjectMeta)
					}
					if !assert.ElementsMatch(t, expectedObj.GroupMembers, actualObj.GroupMembers) {
						t.Errorf("Expected IPAddresses %v, got %v", expectedObj.GroupMembers, actualObj.GroupMembers)
					}
				case watch.Modified:
					actualObj := actualEvent.Object.(*controlplane.GroupPatch)
					expectedObj := expectedEvent.Object.(*controlplane.GroupPatch)
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
