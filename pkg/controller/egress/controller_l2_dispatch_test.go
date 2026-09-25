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

// watchEgressAddressGroups watches the EgressAddressGroups which the Node receives.
func watchEgressAddressGroups(t *testing.T, controller *egressController, nodeName string) watch.Interface {
	selector := fields.ParseSelectorOrDie(fmt.Sprintf("nodeName=%s", nodeName))
	watcher, err := controller.egressAddressGroupStore.Watch(context.TODO(), "", nil, selector)
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

// waitForEgressAddressGroup waits until the stored EgressAddressGroup of the Egress has the expected Egresses, span
// and members.
func waitForEgressAddressGroup(t *testing.T, controller *egressController, egress *v1beta1.Egress,
	expectedEgresses, expectedNodes []string, expectedMembers []controlplane.GroupMember) {
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		obj, found, err := controller.egressAddressGroupStore.Get(getEgressAddressGroupName(egress))
		if !assert.NoError(c, err) || !assert.True(c, found) {
			return
		}
		group := obj.(*antreatypes.EgressAddressGroup)
		assert.Equal(c, sets.New[string](expectedEgresses...), group.Egresses)
		assert.Equal(c, sets.New[string](expectedNodes...), group.SpanMeta.NodeNames)
		var members []controlplane.GroupMember
		for _, member := range group.GroupMembers {
			members = append(members, *member)
		}
		assert.ElementsMatch(c, expectedMembers, members)
	}, 2*time.Second, 50*time.Millisecond)
}

func TestEgressAddressGroupWithL2Dispatch(t *testing.T) {
	// Whatever the feature gate and the Egress Node, each Node receives its own members in the EgressGroup, without
	// IPs, as without the l2 dispatch.
	expectedEgressGroupMembers := map[string][]controlplane.GroupMember{
		node1: {groupMember(podFoo1, false), groupMember(podNonIP, false)},
		node2: {groupMember(podFoo2, false)},
	}
	tests := []struct {
		name        string
		gateEnabled bool
		egressNode  string
		// expectedSpan is the span of the EgressAddressGroup, nil if there is no group.
		expectedSpan []string
	}{
		{
			name:         "Egress Node hosts no member",
			gateEnabled:  true,
			egressNode:   node3,
			expectedSpan: []string{node3},
		},
		{
			name:         "Egress Node hosts members",
			gateEnabled:  true,
			egressNode:   node1,
			expectedSpan: []string{node1},
		},
		{
			name:         "Egress Node not known yet",
			gateEnabled:  true,
			expectedSpan: []string{},
		},
		{
			name:        "feature gate disabled",
			gateEnabled: false,
			egressNode:  node3,
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
			waitForEgressGroupMembers(t, controller, egress.Name, expectedEgressGroupMembers)
			if tt.expectedSpan == nil {
				assert.Empty(t, controller.egressAddressGroupStore.List(), "No EgressAddressGroup without the gate")
				return
			}
			// The group has the members with an IP, wherever they run. podNonIP has no IP yet.
			expectedMembers := []controlplane.GroupMember{groupMember(podFoo1, true), groupMember(podFoo2, true)}
			waitForEgressAddressGroup(t, controller, egress, []string{egress.Name}, tt.expectedSpan, expectedMembers)

			for _, nodeName := range []string{node1, node2, node3} {
				event := nextEvent(watchEgressAddressGroups(t, controller, nodeName), 500*time.Millisecond)
				if !sets.New[string](tt.expectedSpan...).Has(nodeName) {
					assert.Nil(t, event, "Node %s should not receive the EgressAddressGroup", nodeName)
					continue
				}
				require.NotNil(t, event, "Node %s should receive the EgressAddressGroup", nodeName)
				require.Equal(t, watch.Added, event.Type)
				group := event.Object.(*controlplane.EgressAddressGroup)
				assert.Equal(t, []string{egress.Name}, group.Egresses)
				assert.ElementsMatch(t, expectedMembers, group.GroupMembers, "Node %s", nodeName)
			}
		})
	}
}

// TestEgressAddressGroupUpdatesWithL2Dispatch checks the updates which the Nodes receive when a member Pod gets its IP
// and when the Egress IP moves to another Node.
func TestEgressAddressGroupUpdatesWithL2Dispatch(t *testing.T) {
	featuregatetesting.SetFeatureGateDuringTest(t, features.DefaultFeatureGate, features.EgressDispatchL2, true)
	podWithoutIP := newPod("default", "podNew", map[string]string{"app": "foo"}, node2, "", false)
	controller := startEgressController(t, []runtime.Object{nsDefault, podFoo2, podWithoutIP}, nil)
	egress := newEgressWithEgressNode(node3)
	_, err := controller.crdClient.CrdV1beta1().Egresses().Create(context.TODO(), egress, metav1.CreateOptions{})
	require.NoError(t, err)
	waitForEgressAddressGroup(t, controller, egress, []string{egress.Name}, []string{node3},
		[]controlplane.GroupMember{groupMember(podFoo2, true)})
	groupWatchers := map[string]watch.Interface{}
	addressGroupWatchers := map[string]watch.Interface{}
	for _, nodeName := range []string{node2, node3} {
		groupWatchers[nodeName] = watchEgressGroups(t, controller, nodeName)
		addressGroupWatchers[nodeName] = watchEgressAddressGroups(t, controller, nodeName)
	}
	require.NotNil(t, nextEvent(groupWatchers[node2], time.Second), "node2 should receive its EgressGroup")
	event := nextEvent(addressGroupWatchers[node3], time.Second)
	require.NotNil(t, event, "The Egress Node should receive the EgressAddressGroup")
	require.Equal(t, watch.Added, event.Type)

	// The Pod gets its IP. The Egress Node receives one added member, and the EgressGroups do not change.
	podWithIP := newPod("default", "podNew", map[string]string{"app": "foo"}, node2, "1.1.2.5", false)
	pods := controller.client.CoreV1().Pods(podWithIP.Namespace)
	_, err = pods.UpdateStatus(context.TODO(), podWithIP, metav1.UpdateOptions{})
	require.NoError(t, err)
	event = nextEvent(addressGroupWatchers[node3], time.Second)
	require.NotNil(t, event, "The Egress Node should receive the IP of the Pod")
	require.Equal(t, watch.Modified, event.Type)
	patch := event.Object.(*controlplane.EgressAddressGroupPatch)
	assert.Empty(t, patch.RemovedGroupMembers)
	assert.ElementsMatch(t, []controlplane.GroupMember{groupMember(podWithIP, true)}, patch.AddedGroupMembers)
	assert.Empty(t, patch.Egresses, "The Egresses of the group did not change")
	assert.Nil(t, nextEvent(groupWatchers[node2], 300*time.Millisecond), "The EgressGroup should not change")
	assert.Nil(t, nextEvent(addressGroupWatchers[node2], 300*time.Millisecond), "node2 is not an Egress Node")

	// The Egress IP moves to node2, which hosts the Pods. node2 receives the EgressAddressGroup, and node3 no longer
	// receives it.
	toUpdate, err := controller.crdClient.CrdV1beta1().Egresses().Get(context.TODO(), egress.Name, metav1.GetOptions{})
	require.NoError(t, err)
	toUpdate.Status.EgressNode = node2
	_, err = controller.crdClient.CrdV1beta1().Egresses().UpdateStatus(context.TODO(), toUpdate, metav1.UpdateOptions{})
	require.NoError(t, err)
	event = nextEvent(addressGroupWatchers[node2], time.Second)
	require.NotNil(t, event, "The new Egress Node should receive the EgressAddressGroup")
	require.Equal(t, watch.Added, event.Type)
	assert.ElementsMatch(t, []controlplane.GroupMember{groupMember(podFoo2, true), groupMember(podWithIP, true)},
		event.Object.(*controlplane.EgressAddressGroup).GroupMembers)
	event = nextEvent(addressGroupWatchers[node3], time.Second)
	require.NotNil(t, event, "The previous Egress Node should stop receiving the EgressAddressGroup")
	assert.Equal(t, watch.Deleted, event.Type)
	assert.Nil(t, nextEvent(groupWatchers[node2], 300*time.Millisecond), "The EgressGroup should not change")
}

// TestEgressAddressGroupSharedByEgresses checks that Egresses whose appliedTo is the same share one EgressAddressGroup,
// sent to all their Egress Nodes, and that an Egress leaves the group when it is deleted or its appliedTo changes.
func TestEgressAddressGroupSharedByEgresses(t *testing.T) {
	featuregatetesting.SetFeatureGateDuringTest(t, features.DefaultFeatureGate, features.EgressDispatchL2, true)
	controller := startEgressController(t, []runtime.Object{nsDefault, podFoo1, podFoo2, podBar1}, nil)
	egressA := newEgressWithEgressNode(node1)
	egressB := newEgressWithEgressNode(node3)
	egressB.Name, egressB.UID, egressB.Spec.EgressIP, egressB.Status.EgressIP = "egressB", "uidB", "1.1.1.2", "1.1.1.2"
	for _, egress := range []*v1beta1.Egress{egressA, egressB} {
		_, err := controller.crdClient.CrdV1beta1().Egresses().Create(context.TODO(), egress, metav1.CreateOptions{})
		require.NoError(t, err)
	}
	fooMembers := []controlplane.GroupMember{groupMember(podFoo1, true), groupMember(podFoo2, true)}
	waitForEgressAddressGroup(t, controller, egressA, []string{"egressA", "egressB"}, []string{node1, node3},
		fooMembers)
	assert.Len(t, controller.egressAddressGroupStore.List(), 1)

	// egressA is deleted: the group stays for egressB, and only its Egress Node receives it.
	err := controller.crdClient.CrdV1beta1().Egresses().Delete(context.TODO(), egressA.Name, metav1.DeleteOptions{})
	require.NoError(t, err)
	waitForEgressAddressGroup(t, controller, egressB, []string{"egressB"}, []string{node3}, fooMembers)

	// egressB selects other Pods: it moves to another group, and the previous group, now empty, is deleted.
	toUpdate, err := controller.crdClient.CrdV1beta1().Egresses().Get(context.TODO(), egressB.Name, metav1.GetOptions{})
	require.NoError(t, err)
	toUpdate.Spec.AppliedTo.PodSelector = &metav1.LabelSelector{MatchLabels: podBar1.Labels}
	_, err = controller.crdClient.CrdV1beta1().Egresses().Update(context.TODO(), toUpdate, metav1.UpdateOptions{})
	require.NoError(t, err)
	waitForEgressAddressGroup(t, controller, toUpdate, []string{"egressB"}, []string{node3},
		[]controlplane.GroupMember{groupMember(podBar1, true)})
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Len(c, controller.egressAddressGroupStore.List(), 1)
	}, 2*time.Second, 50*time.Millisecond)
	_, found, _ := controller.egressAddressGroupStore.Get(getEgressAddressGroupName(egressA))
	assert.False(t, found, "The group of the previous appliedTo should be deleted")
}

// TestUpdateEgressWithEgressNodeChange checks that a change of the Egress Node, which is a status update that does not
// change the generation, updates the EgressAddressGroup with the l2 dispatch.
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
