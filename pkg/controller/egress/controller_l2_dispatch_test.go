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

package egress

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	featuregatetesting "k8s.io/component-base/featuregate/testing"

	"antrea.io/antrea/v2/pkg/apis/controlplane"
	"antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
	antreatypes "antrea.io/antrea/v2/pkg/controller/types"
	"antrea.io/antrea/v2/pkg/features"
)

// startEgressController starts the controller with the objects and the components it depends on. They stop when the
// test ends.
func startEgressController(t *testing.T, objects, crdObjects []runtime.Object) *egressController {
	stopCh := make(chan struct{})
	t.Cleanup(func() { close(stopCh) })
	controller := newController(objects, crdObjects)
	controller.informerFactory.Start(stopCh)
	controller.crdInformerFactory.Start(stopCh)
	controller.informerFactory.WaitForCacheSync(stopCh)
	controller.crdInformerFactory.WaitForCacheSync(stopCh)
	go controller.externalIPAllocator.Run(stopCh)
	require.True(t, cache.WaitForCacheSync(stopCh, controller.externalIPAllocator.HasSynced))
	go controller.groupingInterface.Run(stopCh)
	go controller.groupingController.Run(stopCh)
	go controller.Run(stopCh)
	return controller
}

// groupMember returns the GroupMember of the Pod, with the Pod IPs if withIPs is true.
func groupMember(pod *v1.Pod, withIPs bool) controlplane.GroupMember {
	member := controlplane.GroupMember{Pod: &controlplane.PodReference{Name: pod.Name, Namespace: pod.Namespace}}
	if withIPs {
		for _, podIP := range pod.Status.PodIPs {
			member.IPs = append(member.IPs, controlplane.IPAddress(net.ParseIP(podIP.IP)))
		}
	}
	return member
}

// newEgressWithEgressNode returns an Egress selecting the Pods of the default Namespace with label app=foo, whose
// Egress IP is on egressNode.
func newEgressWithEgressNode(egressNode string) *v1beta1.Egress {
	egress := newEgress("egressA", "1.1.1.1", "", &metav1.LabelSelector{MatchLabels: map[string]string{"app": "foo"}},
		&metav1.LabelSelector{MatchLabels: nsDefault.Labels}, nil)
	egress.UID = "uidA"
	egress.Status = v1beta1.EgressStatus{EgressIP: "1.1.1.1", EgressNode: egressNode}
	return egress
}

// watchEgressGroups watches the EgressGroups which the Node receives.
func watchEgressGroups(t *testing.T, controller *egressController, nodeName string) watch.Interface {
	selector := fields.ParseSelectorOrDie(fmt.Sprintf("nodeName=%s", nodeName))
	watcher, err := controller.egressGroupStore.Watch(context.TODO(), "", nil, selector)
	require.NoError(t, err)
	t.Cleanup(watcher.Stop)
	return watcher
}

// nextEvent returns the next event of the watcher other than a bookmark, or nil if there is none within the timeout.
func nextEvent(watcher watch.Interface, timeout time.Duration) *watch.Event {
	deadline := time.After(timeout)
	for {
		select {
		case event := <-watcher.ResultChan():
			if event.Type == watch.Bookmark {
				continue
			}
			return &event
		case <-deadline:
			return nil
		}
	}
}

// waitForEgressGroupMembers waits until the stored EgressGroup has the expected members for each Node.
func waitForEgressGroupMembers(t *testing.T, controller *egressController, name string,
	expected map[string][]controlplane.GroupMember) {
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		obj, found, err := controller.egressGroupStore.Get(name)
		if !assert.NoError(c, err) || !assert.True(c, found) {
			return
		}
		group := obj.(*antreatypes.EgressGroup)
		assert.Equal(c, sets.KeySet(expected), group.SpanMeta.NodeNames)
		for nodeName, expectedMembers := range expected {
			var members []controlplane.GroupMember
			for _, member := range group.GroupMemberByNode[nodeName] {
				members = append(members, *member)
			}
			assert.ElementsMatch(c, expectedMembers, members, "Members of Node %s", nodeName)
		}
	}, 2*time.Second, 50*time.Millisecond)
}

func TestEgressGroupSpanWithL2Dispatch(t *testing.T) {
	tests := []struct {
		name        string
		gateEnabled bool
		egressNode  string
		// expectedMembers are the members which each Node receives. A Node which is missing receives no EgressGroup.
		expectedMembers map[string][]controlplane.GroupMember
	}{
		{
			name:        "Egress Node hosts no member",
			gateEnabled: true,
			egressNode:  node3,
			expectedMembers: map[string][]controlplane.GroupMember{
				node1: {groupMember(podFoo1, false), groupMember(podNonIP, false)},
				node2: {groupMember(podFoo2, false)},
				// Only the Egress Node receives the IPs, and it receives every member.
				node3: {groupMember(podFoo1, true), groupMember(podNonIP, true), groupMember(podFoo2, true)},
			},
		},
		{
			name:        "Egress Node hosts members",
			gateEnabled: true,
			egressNode:  node1,
			expectedMembers: map[string][]controlplane.GroupMember{
				node1: {groupMember(podFoo1, true), groupMember(podNonIP, true), groupMember(podFoo2, true)},
				node2: {groupMember(podFoo2, false)},
			},
		},
		{
			name:        "Egress Node not known yet",
			gateEnabled: true,
			expectedMembers: map[string][]controlplane.GroupMember{
				node1: {groupMember(podFoo1, false), groupMember(podNonIP, false)},
				node2: {groupMember(podFoo2, false)},
			},
		},
		{
			name:        "feature gate disabled",
			gateEnabled: false,
			egressNode:  node3,
			expectedMembers: map[string][]controlplane.GroupMember{
				node1: {groupMember(podFoo1, false), groupMember(podNonIP, false)},
				node2: {groupMember(podFoo2, false)},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			featuregatetesting.SetFeatureGateDuringTest(t, features.DefaultFeatureGate, features.EgressDispatchL2,
				tt.gateEnabled)
			controller := startEgressController(t, []runtime.Object{nsDefault, nsOther, podFoo1, podFoo2, podBar1,
				podFoo1InOtherNamespace, podUnscheduled, podNonIP, podWithHostNetwork}, nil)
			egress := newEgressWithEgressNode(tt.egressNode)
			_, err := controller.crdClient.CrdV1beta1().Egresses().Create(context.TODO(), egress, metav1.CreateOptions{})
			require.NoError(t, err)
			waitForEgressGroupMembers(t, controller, egress.Name, tt.expectedMembers)

			for _, nodeName := range []string{node1, node2, node3} {
				event := nextEvent(watchEgressGroups(t, controller, nodeName), 500*time.Millisecond)
				expectedMembers, expected := tt.expectedMembers[nodeName]
				if !expected {
					assert.Nil(t, event, "Node %s should not receive the EgressGroup", nodeName)
					continue
				}
				require.NotNil(t, event, "Node %s should receive the EgressGroup", nodeName)
				require.Equal(t, watch.Added, event.Type)
				gotMembers := event.Object.(*controlplane.EgressGroup).GroupMembers
				assert.ElementsMatch(t, expectedMembers, gotMembers, "Node %s", nodeName)
			}
		})
	}
}

// TestEgressGroupPatchesWithL2Dispatch checks the updates which the Nodes receive when a member Pod gets its IP and
// when the Egress IP moves to another Node.
func TestEgressGroupPatchesWithL2Dispatch(t *testing.T) {
	featuregatetesting.SetFeatureGateDuringTest(t, features.DefaultFeatureGate, features.EgressDispatchL2, true)
	podWithoutIP := newPod("default", "podNew", map[string]string{"app": "foo"}, node2, "", false)
	controller := startEgressController(t, []runtime.Object{nsDefault, podFoo2, podWithoutIP}, nil)
	egress := newEgressWithEgressNode(node3)
	_, err := controller.crdClient.CrdV1beta1().Egresses().Create(context.TODO(), egress, metav1.CreateOptions{})
	require.NoError(t, err)
	waitForEgressGroupMembers(t, controller, egress.Name, map[string][]controlplane.GroupMember{
		node2: {groupMember(podFoo2, false), groupMember(podWithoutIP, false)},
		node3: {groupMember(podFoo2, true), groupMember(podWithoutIP, true)},
	})
	watchers := map[string]watch.Interface{}
	for _, nodeName := range []string{node2, node3} {
		watchers[nodeName] = watchEgressGroups(t, controller, nodeName)
		event := nextEvent(watchers[nodeName], time.Second)
		require.NotNil(t, event)
		require.Equal(t, watch.Added, event.Type)
	}

	// The Pod gets its IP. Only the Egress Node sees a change: the member without IPs is removed, and the member with
	// the IPs is added.
	podWithIP := newPod("default", "podNew", map[string]string{"app": "foo"}, node2, "1.1.2.5", false)
	pods := controller.client.CoreV1().Pods(podWithIP.Namespace)
	_, err = pods.UpdateStatus(context.TODO(), podWithIP, metav1.UpdateOptions{})
	require.NoError(t, err)
	event := nextEvent(watchers[node3], time.Second)
	require.NotNil(t, event, "The Egress Node should receive the IPs of the Pod")
	require.Equal(t, watch.Modified, event.Type)
	patch := event.Object.(*controlplane.EgressGroupPatch)
	assert.ElementsMatch(t, []controlplane.GroupMember{groupMember(podWithoutIP, false)}, patch.RemovedGroupMembers)
	assert.ElementsMatch(t, []controlplane.GroupMember{groupMember(podWithIP, true)}, patch.AddedGroupMembers)
	assert.Nil(t, nextEvent(watchers[node2], 300*time.Millisecond), "The Node of the Pod should see no change")

	// The Egress IP moves to node2, which hosts the Pods. node2 now receives the IPs, and node3 no longer receives the
	// group.
	toUpdate, err := controller.crdClient.CrdV1beta1().Egresses().Get(context.TODO(), egress.Name, metav1.GetOptions{})
	require.NoError(t, err)
	toUpdate.Status.EgressNode = node2
	_, err = controller.crdClient.CrdV1beta1().Egresses().UpdateStatus(context.TODO(), toUpdate, metav1.UpdateOptions{})
	require.NoError(t, err)
	event = nextEvent(watchers[node2], time.Second)
	require.NotNil(t, event, "The new Egress Node should receive the IPs of the Pods")
	require.Equal(t, watch.Modified, event.Type)
	patch = event.Object.(*controlplane.EgressGroupPatch)
	assert.ElementsMatch(t, []controlplane.GroupMember{groupMember(podFoo2, false), groupMember(podWithIP, false)},
		patch.RemovedGroupMembers)
	assert.ElementsMatch(t, []controlplane.GroupMember{groupMember(podFoo2, true), groupMember(podWithIP, true)},
		patch.AddedGroupMembers)
	event = nextEvent(watchers[node3], time.Second)
	require.NotNil(t, event, "The previous Egress Node should stop receiving the group")
	assert.Equal(t, watch.Deleted, event.Type)
}

// TestUpdateEgressWithEgressNodeChange checks that a change of the Egress Node, which is a status update that does not
// change the generation, updates the EgressGroup with the l2 dispatch.
func TestUpdateEgressWithEgressNodeChange(t *testing.T) {
	tests := []struct {
		name             string
		gateEnabled      bool
		oldEgressNode    string
		newEgressNode    string
		expectedQueueLen int
	}{
		{name: "Egress Node changes", gateEnabled: true, oldEgressNode: node1, newEgressNode: node2, expectedQueueLen: 1},
		{name: "Egress Node becomes known", gateEnabled: true, newEgressNode: node2, expectedQueueLen: 1},
		{name: "Egress Node unchanged", gateEnabled: true, oldEgressNode: node1, newEgressNode: node1, expectedQueueLen: 0},
		{name: "feature gate disabled", gateEnabled: false, oldEgressNode: node1, newEgressNode: node2, expectedQueueLen: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			featuregatetesting.SetFeatureGateDuringTest(t, features.DefaultFeatureGate, features.EgressDispatchL2,
				tt.gateEnabled)
			controller := newController(nil, nil)
			oldEgress := newEgressWithEgressNode(tt.oldEgressNode)
			oldEgress.Generation = 1
			newEgress := newEgressWithEgressNode(tt.newEgressNode)
			newEgress.Generation = 1
			controller.updateEgress(oldEgress, newEgress)
			assert.Equal(t, tt.expectedQueueLen, controller.queue.Len())
		})
	}
}
