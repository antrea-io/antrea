//go:build !windows

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
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"

	cpv1b2 "antrea.io/antrea/v2/pkg/apis/controlplane/v1beta2"
	crdv1b1 "antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
)

// podMember returns the GroupMember of the Pod with the IPs.
func podMember(namespace, name string, ips ...string) cpv1b2.GroupMember {
	member := cpv1b2.GroupMember{Pod: &cpv1b2.PodReference{Name: name, Namespace: namespace}}
	for _, ip := range ips {
		member.IPs = append(member.IPs, cpv1b2.IPAddress(net.ParseIP(ip)))
	}
	return member
}

func newEgressGroup(name string, members ...cpv1b2.GroupMember) *cpv1b2.EgressGroup {
	return &cpv1b2.EgressGroup{ObjectMeta: metav1.ObjectMeta{Name: name}, GroupMembers: members}
}

// startFakeController starts the informers of the fake controller. They stop when the test ends.
func startFakeController(t *testing.T, c *fakeController) {
	stopCh := make(chan struct{})
	t.Cleanup(func() { close(stopCh) })
	c.crdInformerFactory.Start(stopCh)
	c.informerFactory.Start(stopCh)
	c.crdInformerFactory.WaitForCacheSync(stopCh)
	c.informerFactory.WaitForCacheSync(stopCh)
}

func TestPatchEgressGroup(t *testing.T) {
	tests := []struct {
		name            string
		initialMembers  []cpv1b2.GroupMember
		addedMembers    []cpv1b2.GroupMember
		removedMembers  []cpv1b2.GroupMember
		expectedMembers egressGroupMembers
	}{
		{
			// A member is identified by its Pod and its IPs, so the patch removes the member without IPs and adds the
			// member with them.
			name:            "Pod gets its IP",
			initialMembers:  []cpv1b2.GroupMember{podMember("ns1", "pod1")},
			addedMembers:    []cpv1b2.GroupMember{podMember("ns1", "pod1", "10.10.1.5")},
			removedMembers:  []cpv1b2.GroupMember{podMember("ns1", "pod1")},
			expectedMembers: egressGroupMembers{"ns1/pod1": sets.New("10.10.1.5")},
		},
		{
			name:            "Pod IPs change",
			initialMembers:  []cpv1b2.GroupMember{podMember("ns1", "pod1", "10.10.1.5")},
			addedMembers:    []cpv1b2.GroupMember{podMember("ns1", "pod1", "10.10.1.6", "fd00:10:11::6")},
			removedMembers:  []cpv1b2.GroupMember{podMember("ns1", "pod1", "10.10.1.5")},
			expectedMembers: egressGroupMembers{"ns1/pod1": sets.New("10.10.1.6", "fd00:10:11::6")},
		},
		{
			name:            "Pod added",
			initialMembers:  []cpv1b2.GroupMember{podMember("ns1", "pod1")},
			addedMembers:    []cpv1b2.GroupMember{podMember("ns2", "pod2")},
			expectedMembers: egressGroupMembers{"ns1/pod1": sets.New[string](), "ns2/pod2": sets.New[string]()},
		},
		{
			name:            "Pod removed",
			initialMembers:  []cpv1b2.GroupMember{podMember("ns1", "pod1", "10.10.1.5"), podMember("ns2", "pod2")},
			removedMembers:  []cpv1b2.GroupMember{podMember("ns1", "pod1", "10.10.1.5")},
			expectedMembers: egressGroupMembers{"ns2/pod2": sets.New[string]()},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newFakeController(t, nil)
			c.addEgressGroup(newEgressGroup("egressA", tt.initialMembers...))
			c.patchEgressGroup(&cpv1b2.EgressGroupPatch{
				ObjectMeta:          metav1.ObjectMeta{Name: "egressA"},
				AddedGroupMembers:   tt.addedMembers,
				RemovedGroupMembers: tt.removedMembers,
			})
			assert.Equal(t, tt.expectedMembers, c.egressGroups["egressA"])
		})
	}
}

func TestReplaceEgressGroupsWithPodIPs(t *testing.T) {
	c := newFakeController(t, nil)
	c.replaceEgressGroups([]*cpv1b2.EgressGroup{newEgressGroup("egressA", podMember("ns1", "pod1"))})
	require.Equal(t, 1, c.queue.Len())
	item, _ := c.queue.Get()
	c.queue.Done(item)
	// The Pod got its IP while the watch was restarted, so the EgressGroup must be synced again.
	c.replaceEgressGroups([]*cpv1b2.EgressGroup{newEgressGroup("egressA", podMember("ns1", "pod1", "10.10.1.5"))})
	assert.Equal(t, 1, c.queue.Len())
	assert.Equal(t, egressGroupMembers{"ns1/pod1": sets.New("10.10.1.5")}, c.egressGroups["egressA"])
}

// TestSyncEgressOnEgressNodeWithL2Dispatch checks that the Egress Node puts the IPs of the member Pods on other Nodes
// in the ipset of its Egress IP, with the l2 dispatch.
func TestSyncEgressOnEgressNodeWithL2Dispatch(t *testing.T) {
	// The Egress Node receives every member, with the Pod IPs. ns1/pod1 runs on this Node.
	egressGroup := newEgressGroup("egressA",
		podMember("ns1", "pod1", "10.10.0.5", "fd00:10:10::5"),
		podMember("ns9", "remotePod1", "10.10.1.5", "fd00:10:11::5"),
		podMember("ns9", "remotePod2", "10.10.2.5"),
		// A Pod which has no IP yet.
		podMember("ns9", "remotePod3"),
	)
	tests := []struct {
		name          string
		l2Dispatch    bool
		egressIP      string
		expectedCalls func(c *fakeController, egressIP net.IP)
	}{
		{
			name:       "IPv4 Egress IP",
			l2Dispatch: true,
			egressIP:   "1.1.1.1",
			expectedCalls: func(c *fakeController, egressIP net.IP) {
				c.mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), egressIP, uint32(1))
				c.mockRouteClient.EXPECT().SetEgressRemotePodIPs(uint32(1), sets.New("10.10.1.5", "10.10.2.5"))
			},
		},
		{
			name:       "IPv6 Egress IP",
			l2Dispatch: true,
			egressIP:   "fd00::1",
			expectedCalls: func(c *fakeController, egressIP net.IP) {
				c.mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), egressIP, uint32(1))
				c.mockRouteClient.EXPECT().SetEgressRemotePodIPs(uint32(1), sets.New("fd00:10:11::5"))
			},
		},
		{
			// With the tunnel dispatch, the Egress Node finds the Egress IP from the tunnel destination, and ignores the
			// members on other Nodes.
			name:     "tunnel dispatch",
			egressIP: "1.1.1.1",
			expectedCalls: func(c *fakeController, egressIP net.IP) {
				c.mockOFClient.EXPECT().InstallPodSNATFlows(uint32(1), egressIP, uint32(1))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			egress := &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1b1.EgressSpec{EgressIP: tt.egressIP},
			}
			c := newFakeController(t, []runtime.Object{egress})
			c.l2Dispatch = tt.l2Dispatch
			c.localIPDetector = &fakeLocalIPDetector{localIPs: sets.New(tt.egressIP)}
			startFakeController(t, c)
			c.addEgressGroup(egressGroup)

			egressIP := net.ParseIP(tt.egressIP)
			c.mockIPAssigner.EXPECT().UnassignIP(tt.egressIP).Times(2)
			c.mockOFClient.EXPECT().InstallSNATMarkFlows(egressIP, uint32(1))
			c.mockRouteClient.EXPECT().AddSNATRule(egressIP, uint32(1))
			tt.expectedCalls(c, egressIP)
			require.NoError(t, c.syncEgress(egress.Name))
			// The IPs do not change, so the ipset is not updated again.
			require.NoError(t, c.syncEgress(egress.Name))
		})
	}
}

// TestSyncEgressOnEgressNodeWithSharedEgressIP checks that the ipset of an Egress IP holds the Pods of all the
// Egresses which share it.
func TestSyncEgressOnEgressNodeWithSharedEgressIP(t *testing.T) {
	egressA := &crdv1b1.Egress{
		ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
		Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1},
	}
	egressB := &crdv1b1.Egress{
		ObjectMeta: metav1.ObjectMeta{Name: "egressB", UID: "uidB"},
		Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1},
	}
	c := newFakeController(t, []runtime.Object{egressA, egressB})
	c.l2Dispatch = true
	startFakeController(t, c)
	c.addEgressGroup(newEgressGroup("egressA", podMember("ns9", "remotePod1", "10.10.1.5")))
	c.addEgressGroup(newEgressGroup("egressB", podMember("ns9", "remotePod2", "10.10.2.5")))

	egressIP := net.ParseIP(fakeLocalEgressIP1)
	c.mockIPAssigner.EXPECT().UnassignIP(fakeLocalEgressIP1).AnyTimes()
	c.mockOFClient.EXPECT().InstallSNATMarkFlows(egressIP, uint32(1))
	c.mockRouteClient.EXPECT().AddSNATRule(egressIP, uint32(1))
	c.mockRouteClient.EXPECT().SetEgressRemotePodIPs(uint32(1), sets.New("10.10.1.5"))
	require.NoError(t, c.syncEgress(egressA.Name))
	c.mockRouteClient.EXPECT().SetEgressRemotePodIPs(uint32(1), sets.New("10.10.1.5", "10.10.2.5"))
	require.NoError(t, c.syncEgress(egressB.Name))

	// When egressB is deleted, the ipset keeps the Pods of egressA only.
	require.NoError(t, c.crdClient.CrdV1beta1().Egresses().Delete(context.TODO(), egressB.Name, metav1.DeleteOptions{}))
	require.Eventually(t, func() bool {
		_, err := c.egressLister.Get(egressB.Name)
		return err != nil
	}, time.Second, 10*time.Millisecond)
	c.mockRouteClient.EXPECT().SetEgressRemotePodIPs(uint32(1), sets.New("10.10.1.5"))
	require.NoError(t, c.syncEgress(egressB.Name))

	// When egressA is deleted too, the SNAT rule of the Egress IP and its ipset are deleted.
	require.NoError(t, c.crdClient.CrdV1beta1().Egresses().Delete(context.TODO(), egressA.Name, metav1.DeleteOptions{}))
	require.Eventually(t, func() bool {
		_, err := c.egressLister.Get(egressA.Name)
		return err != nil
	}, time.Second, 10*time.Millisecond)
	c.mockRouteClient.EXPECT().DeleteSNATRule(uint32(1))
	c.mockOFClient.EXPECT().UninstallSNATMarkFlows(uint32(1))
	require.NoError(t, c.syncEgress(egressA.Name))
}

// TestSyncEgressOnEgressNodeWhenEgressIPMoves checks that the IPs of the remote Pods are restored in the ipset when
// the Egress IP comes back to the Node, since the ipset is deleted when it leaves.
func TestSyncEgressOnEgressNodeWhenEgressIPMoves(t *testing.T) {
	egress := &crdv1b1.Egress{
		ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
		Spec:       crdv1b1.EgressSpec{EgressIP: fakeLocalEgressIP1},
	}
	c := newFakeController(t, []runtime.Object{egress})
	c.l2Dispatch = true
	startFakeController(t, c)
	c.addEgressGroup(newEgressGroup("egressA", podMember("ns9", "remotePod1", "10.10.1.5")))

	egressIP := net.ParseIP(fakeLocalEgressIP1)
	c.mockIPAssigner.EXPECT().UnassignIP(fakeLocalEgressIP1).AnyTimes()
	c.mockOFClient.EXPECT().InstallSNATMarkFlows(egressIP, uint32(1))
	c.mockRouteClient.EXPECT().AddSNATRule(egressIP, uint32(1))
	c.mockRouteClient.EXPECT().SetEgressRemotePodIPs(uint32(1), sets.New("10.10.1.5"))
	require.NoError(t, c.syncEgress(egress.Name))

	// The Egress IP leaves the Node: the SNAT rule is deleted with the ipset.
	c.localIPDetector = &fakeLocalIPDetector{localIPs: sets.New[string]()}
	c.mockRouteClient.EXPECT().DeleteSNATRule(uint32(1))
	c.mockOFClient.EXPECT().UninstallSNATMarkFlows(uint32(1))
	require.NoError(t, c.syncEgress(egress.Name))

	// The Egress IP comes back: the new ipset gets the IPs again.
	c.localIPDetector = &fakeLocalIPDetector{localIPs: sets.New(fakeLocalEgressIP1)}
	c.mockOFClient.EXPECT().InstallSNATMarkFlows(egressIP, uint32(1))
	c.mockRouteClient.EXPECT().AddSNATRule(egressIP, uint32(1))
	c.mockRouteClient.EXPECT().SetEgressRemotePodIPs(uint32(1), sets.New("10.10.1.5"))
	require.NoError(t, c.syncEgress(egress.Name))
}
