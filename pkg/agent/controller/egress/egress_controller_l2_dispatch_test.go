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
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	eventsv1 "k8s.io/api/events/v1"
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

func newEgressAddressGroupMsg(name string, egresses []string, members ...cpv1b2.GroupMember) *cpv1b2.EgressAddressGroup {
	return &cpv1b2.EgressAddressGroup{ObjectMeta: metav1.ObjectMeta{Name: name}, Egresses: egresses, GroupMembers: members}
}

// queuedEgresses empties the queue of the controller and returns the Egresses it held.
func queuedEgresses(c *fakeController) sets.Set[string] {
	egresses := sets.New[string]()
	for c.queue.Len() > 0 {
		item, _ := c.queue.Get()
		egresses.Insert(item)
		c.queue.Done(item)
	}
	return egresses
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

func TestPatchEgressAddressGroup(t *testing.T) {
	tests := []struct {
		name             string
		initialMembers   []cpv1b2.GroupMember
		egresses         []string
		addedMembers     []cpv1b2.GroupMember
		removedMembers   []cpv1b2.GroupMember
		expectedMembers  map[string]sets.Set[string]
		expectedEgresses sets.Set[string]
		expectedQueued   sets.Set[string]
	}{
		{
			// A member is identified by its Pod and its IPs, so the patch removes the member with the previous IPs and
			// adds the member with the new ones.
			name:             "Pod IPs change",
			initialMembers:   []cpv1b2.GroupMember{podMember("ns1", "pod1", "10.10.1.5")},
			addedMembers:     []cpv1b2.GroupMember{podMember("ns1", "pod1", "10.10.1.6", "fd00:10:11::6")},
			removedMembers:   []cpv1b2.GroupMember{podMember("ns1", "pod1", "10.10.1.5")},
			expectedMembers:  map[string]sets.Set[string]{"ns1/pod1": sets.New("10.10.1.6", "fd00:10:11::6")},
			expectedEgresses: sets.New("egressA"),
			expectedQueued:   sets.New("egressA"),
		},
		{
			name:           "Pod added",
			initialMembers: []cpv1b2.GroupMember{podMember("ns1", "pod1", "10.10.1.5")},
			addedMembers:   []cpv1b2.GroupMember{podMember("ns2", "pod2", "10.10.2.5")},
			expectedMembers: map[string]sets.Set[string]{
				"ns1/pod1": sets.New("10.10.1.5"),
				"ns2/pod2": sets.New("10.10.2.5"),
			},
			expectedEgresses: sets.New("egressA"),
			expectedQueued:   sets.New("egressA"),
		},
		{
			name:             "Pod removed",
			initialMembers:   []cpv1b2.GroupMember{podMember("ns1", "pod1", "10.10.1.5"), podMember("ns2", "pod2", "10.10.2.5")},
			removedMembers:   []cpv1b2.GroupMember{podMember("ns1", "pod1", "10.10.1.5")},
			expectedMembers:  map[string]sets.Set[string]{"ns2/pod2": sets.New("10.10.2.5")},
			expectedEgresses: sets.New("egressA"),
			expectedQueued:   sets.New("egressA"),
		},
		{
			// Both the Egress which left the group and the one which joined it are synced.
			name:             "Egresses change",
			initialMembers:   []cpv1b2.GroupMember{podMember("ns1", "pod1", "10.10.1.5")},
			egresses:         []string{"egressB"},
			expectedMembers:  map[string]sets.Set[string]{"ns1/pod1": sets.New("10.10.1.5")},
			expectedEgresses: sets.New("egressB"),
			expectedQueued:   sets.New("egressA", "egressB"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newL2DispatchFakeController(t, &fakeL2DispatchPeers{}, nil)
			c.addEgressAddressGroup(newEgressAddressGroupMsg("group1", []string{"egressA"}, tt.initialMembers...))
			queuedEgresses(c)
			c.patchEgressAddressGroup(&cpv1b2.EgressAddressGroupPatch{
				ObjectMeta:          metav1.ObjectMeta{Name: "group1"},
				Egresses:            tt.egresses,
				AddedGroupMembers:   tt.addedMembers,
				RemovedGroupMembers: tt.removedMembers,
			})
			assert.Equal(t, tt.expectedMembers, c.egressAddressGroups["group1"].members)
			assert.Equal(t, tt.expectedEgresses, c.egressAddressGroups["group1"].egresses)
			assert.Equal(t, tt.expectedQueued, queuedEgresses(c))
		})
	}
}

func TestReplaceAndDeleteEgressAddressGroups(t *testing.T) {
	c := newL2DispatchFakeController(t, &fakeL2DispatchPeers{}, nil)
	c.replaceEgressAddressGroups([]*cpv1b2.EgressAddressGroup{
		newEgressAddressGroupMsg("group1", []string{"egressA"}, podMember("ns1", "pod1", "10.10.1.5")),
	})
	assert.Equal(t, sets.New("egressA"), queuedEgresses(c))

	// While the watch was restarted, the group got another Egress and the Pod another IP, and a second group came.
	c.replaceEgressAddressGroups([]*cpv1b2.EgressAddressGroup{
		newEgressAddressGroupMsg("group1", []string{"egressA", "egressB"}, podMember("ns1", "pod1", "10.10.1.6")),
		newEgressAddressGroupMsg("group2", []string{"egressC"}, podMember("ns2", "pod2", "10.10.2.5")),
	})
	assert.Equal(t, sets.New("egressA", "egressB", "egressC"), queuedEgresses(c))
	assert.Equal(t, map[string]sets.Set[string]{"ns1/pod1": sets.New("10.10.1.6")}, c.egressAddressGroups["group1"].members)
	assert.Equal(t, map[string]sets.Set[string]{"ns2/pod2": sets.New("10.10.2.5")}, c.getEgressMembers("egressC"))

	// A Deleted event carries only the metadata, and the Egresses of the stored group are synced.
	c.deleteEgressAddressGroup(&cpv1b2.EgressAddressGroup{ObjectMeta: metav1.ObjectMeta{Name: "group1"}})
	assert.Equal(t, sets.New("egressA", "egressB"), queuedEgresses(c))
	assert.Nil(t, c.getEgressMembers("egressA"))
}

func TestGetEgressMembers(t *testing.T) {
	c := newL2DispatchFakeController(t, &fakeL2DispatchPeers{}, nil)
	// The EgressGroup gives the members on this Node without IPs, the EgressAddressGroup all members with IPs.
	c.addEgressGroup(newEgressGroup("egressA", podMember("ns1", "pod1")))
	c.addEgressAddressGroup(newEgressAddressGroupMsg("group1", []string{"egressA"},
		podMember("ns1", "pod1", "10.10.0.5"), podMember("ns9", "remotePod1", "10.10.1.5")))
	assert.Equal(t, map[string]sets.Set[string]{
		"ns1/pod1":       sets.New("10.10.0.5"),
		"ns9/remotePod1": sets.New("10.10.1.5"),
	}, c.getEgressMembers("egressA"))
	// A Node which is not an Egress Node of the Egress has its own members only.
	c.addEgressGroup(newEgressGroup("egressB", podMember("ns1", "pod2")))
	assert.Equal(t, map[string]sets.Set[string]{"ns1/pod2": nil}, c.getEgressMembers("egressB"))
	assert.Nil(t, c.getEgressMembers("egressC"))
}

// TestSyncEgressOnEgressNodeWithL2Dispatch checks that the Egress Node puts the IPs of the member Pods on other Nodes
// in the ipset of its Egress IP, with the l2 dispatch.
func TestSyncEgressOnEgressNodeWithL2Dispatch(t *testing.T) {
	// ns1/pod1 runs on this Node, so it is in the EgressGroup. With the l2 dispatch, the Egress Node also receives the
	// EgressAddressGroup, with every member which has an IP.
	egressGroup := newEgressGroup("egressA", podMember("ns1", "pod1"))
	egressAddressGroup := newEgressAddressGroupMsg("group1", []string{"egressA"},
		podMember("ns1", "pod1", "10.10.0.5", "fd00:10:10::5"),
		podMember("ns9", "remotePod1", "10.10.1.5", "fd00:10:11::5"),
		podMember("ns9", "remotePod2", "10.10.2.5"),
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
			// With the tunnel dispatch, the Egress Node finds the Egress IP from the tunnel destination, and receives no
			// EgressAddressGroup.
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
			var c *fakeController
			if tt.l2Dispatch {
				c = newL2DispatchFakeController(t, &fakeL2DispatchPeers{}, []runtime.Object{egress})
			} else {
				c = newFakeController(t, []runtime.Object{egress})
			}
			c.localIPDetector = &fakeLocalIPDetector{localIPs: sets.New(tt.egressIP)}
			startFakeController(t, c)
			c.addEgressGroup(egressGroup)
			if tt.l2Dispatch {
				c.addEgressAddressGroup(egressAddressGroup)
			}

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
	c := newL2DispatchFakeController(t, &fakeL2DispatchPeers{}, []runtime.Object{egressA, egressB})
	startFakeController(t, c)
	c.addEgressAddressGroup(newEgressAddressGroupMsg("group1", []string{"egressA"}, podMember("ns9", "remotePod1", "10.10.1.5")))
	c.addEgressAddressGroup(newEgressAddressGroupMsg("group2", []string{"egressB"}, podMember("ns9", "remotePod2", "10.10.2.5")))

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
	c := newL2DispatchFakeController(t, &fakeL2DispatchPeers{}, []runtime.Object{egress})
	startFakeController(t, c)
	c.addEgressAddressGroup(newEgressAddressGroupMsg("group1", []string{"egressA"}, podMember("ns9", "remotePod1", "10.10.1.5")))

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

// fakeL2DispatchPeers gives the l2 dispatch indices of the Nodes whose routing is installed, and the errors of the
// Nodes which the l2 dispatch cannot reach.
type fakeL2DispatchPeers struct {
	indices  map[string]uint32
	errs     map[string]error
	handlers []func(nodeName string)
}

func (f *fakeL2DispatchPeers) GetL2DispatchPeerIndex(nodeName string, isIPv6 bool) (uint32, bool, error) {
	if err := f.errs[nodeName]; err != nil {
		return 0, false, err
	}
	index, installed := f.indices[nodeName]
	return index, installed, nil
}

func (f *fakeL2DispatchPeers) AddL2DispatchPeerEventHandler(handler func(nodeName string)) {
	f.handlers = append(f.handlers, handler)
}

func (f *fakeL2DispatchPeers) notify(nodeName string) {
	for _, handler := range f.handlers {
		handler(nodeName)
	}
}

// newL2DispatchFakeController returns a fake controller which uses the l2 dispatch, with the fake peers.
func newL2DispatchFakeController(t *testing.T, peers *fakeL2DispatchPeers,
	initObjects []runtime.Object) *fakeController {
	c := newFakeController(t, initObjects)
	c.l2Dispatch = true
	c.l2DispatchPeers = peers
	c.l2DispatchEgresses = map[string]sets.Set[string]{}
	c.egressAddressGroups = map[string]*egressAddressGroup{}
	peers.AddL2DispatchPeerEventHandler(c.onL2DispatchPeerUpdate)
	return c
}

// recordEvents returns a function which returns the notes of the events recorded by the controller.
func recordEvents(c *fakeController) func() []string {
	var notes []string
	var mutex sync.Mutex
	c.eventBroadcaster.StartEventWatcher(func(e runtime.Object) {
		mutex.Lock()
		defer mutex.Unlock()
		notes = append(notes, e.(*eventsv1.Event).Note)
	})
	return func() []string {
		mutex.Lock()
		defer mutex.Unlock()
		return append([]string(nil), notes...)
	}
}

// TestSyncEgressOnPodNodeWithL2Dispatch checks the flows of a local Pod whose Egress IP is on another Node, with the
// l2 dispatch.
func TestSyncEgressOnPodNodeWithL2Dispatch(t *testing.T) {
	remoteEgressIP := net.ParseIP(fakeRemoteEgressIP1)
	tests := []struct {
		name           string
		egressNode     string
		schedulable    bool
		peers          *fakeL2DispatchPeers
		expectedCalls  func(c *fakeController)
		expectedEvents []string
	}{
		{
			name:       "Egress IP assigned by the user",
			egressNode: fakeNode2,
			peers:      &fakeL2DispatchPeers{indices: map[string]uint32{fakeNode2: 3}},
			expectedCalls: func(c *fakeController) {
				c.mockOFClient.EXPECT().InstallPodL2DispatchFlows(uint32(1), remoteEgressIP, uint32(3))
			},
		},
		{
			// The Node which the scheduler selects holds the Egress IP of an ExternalIPPool, whatever the status says.
			name:        "Egress IP from an ExternalIPPool",
			egressNode:  "node3",
			schedulable: true,
			peers:       &fakeL2DispatchPeers{indices: map[string]uint32{fakeNode2: 3, "node3": 4}},
			expectedCalls: func(c *fakeController) {
				c.mockOFClient.EXPECT().InstallPodL2DispatchFlows(uint32(1), remoteEgressIP, uint32(3))
			},
		},
		{
			name:          "Egress Node not known yet",
			peers:         &fakeL2DispatchPeers{},
			expectedCalls: func(c *fakeController) {},
		},
		{
			// The Egress IP has left this Node, and the new Egress Node has not updated the status yet.
			name:          "stale status naming this Node",
			egressNode:    fakeNode,
			peers:         &fakeL2DispatchPeers{indices: map[string]uint32{fakeNode: 3}},
			expectedCalls: func(c *fakeController) {},
		},
		{
			name:          "routing to the Egress Node not installed yet",
			egressNode:    fakeNode2,
			peers:         &fakeL2DispatchPeers{},
			expectedCalls: func(c *fakeController) {},
		},
		{
			// The Pods keep the default SNAT, and an event tells why.
			name:       "Egress Node outside the local subnet",
			egressNode: fakeNode2,
			peers: &fakeL2DispatchPeers{errs: map[string]error{
				fakeNode2: fmt.Errorf("its IPv4 transport IP 10.10.20.10 is not in the local transport subnet 10.10.10.0/24"),
			}},
			expectedCalls: func(c *fakeController) {},
			expectedEvents: []string{"The Pods of Egress egressA on Node node1 keep the default SNAT, as the l2 dispatch " +
				"cannot reach Egress Node node2: its IPv4 transport IP 10.10.20.10 is not in the local transport subnet " +
				"10.10.10.0/24"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			egress := &crdv1b1.Egress{
				ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
				Spec:       crdv1b1.EgressSpec{EgressIP: fakeRemoteEgressIP1},
				Status:     crdv1b1.EgressStatus{EgressIP: fakeRemoteEgressIP1, EgressNode: tt.egressNode},
			}
			if tt.schedulable {
				egress.Spec.ExternalIPPool = fakeExternalIPPool
			}
			c := newL2DispatchFakeController(t, tt.peers, []runtime.Object{egress})
			if tt.schedulable {
				c.egressIPScheduler.scheduleResults[egress.Name] = &scheduleResult{ip: fakeRemoteEgressIP1, node: fakeNode2}
			}
			getEvents := recordEvents(c)
			startFakeController(t, c)
			c.addEgressGroup(newEgressGroup("egressA", podMember("ns1", "pod1")))

			c.mockIPAssigner.EXPECT().UnassignIP(fakeRemoteEgressIP1).Times(2)
			tt.expectedCalls(c)
			require.NoError(t, c.syncEgress(egress.Name))
			// Syncing again installs nothing more.
			require.NoError(t, c.syncEgress(egress.Name))
			assert.EventuallyWithT(t, func(t *assert.CollectT) {
				assert.Equal(t, len(tt.expectedEvents) > 0, len(getEvents()) > 0)
				for _, expectedEvent := range tt.expectedEvents {
					assert.Contains(t, getEvents(), expectedEvent)
				}
			}, 2*time.Second, 50*time.Millisecond)
		})
	}
}

// TestL2DispatchIndexChanges checks that the Pod flows follow the l2 dispatch index of the Egress Node, which the
// NodeRouteController notifies.
func TestL2DispatchIndexChanges(t *testing.T) {
	remoteEgressIP := net.ParseIP(fakeRemoteEgressIP1)
	egress := &crdv1b1.Egress{
		ObjectMeta: metav1.ObjectMeta{Name: "egressA", UID: "uidA"},
		Spec:       crdv1b1.EgressSpec{EgressIP: fakeRemoteEgressIP1},
		Status:     crdv1b1.EgressStatus{EgressIP: fakeRemoteEgressIP1, EgressNode: fakeNode2},
	}
	peers := &fakeL2DispatchPeers{indices: map[string]uint32{}, errs: map[string]error{}}
	c := newL2DispatchFakeController(t, peers, []runtime.Object{egress})
	startFakeController(t, c)
	c.addEgressGroup(newEgressGroup("egressA", podMember("ns1", "pod1")))
	item, _ := c.queue.Get()
	c.queue.Done(item)
	c.mockIPAssigner.EXPECT().UnassignIP(fakeRemoteEgressIP1).AnyTimes()

	// The routing to the Egress Node is not installed yet, so the Pod keeps the default SNAT. The Egress follows the
	// notifications for its Egress Node only. The queue can also get the Egress from the events of the informer, so
	// the test checks what the notifications of each Node would enqueue.
	require.NoError(t, c.syncEgress(egress.Name))
	assert.Equal(t, map[string]sets.Set[string]{fakeNode2: sets.New(egress.Name)}, c.l2DispatchEgresses)

	// The routing is installed: the Egress is synced again and the Pod flow uses the index.
	peers.indices[fakeNode2] = 3
	peers.notify(fakeNode2)
	require.Equal(t, 1, c.queue.Len())
	item, _ = c.queue.Get()
	c.queue.Done(item)
	c.mockOFClient.EXPECT().InstallPodL2DispatchFlows(uint32(1), remoteEgressIP, uint32(3))
	require.NoError(t, c.syncEgress(item))

	// The Egress Node got another index, for example after it was deleted and registered again.
	peers.indices[fakeNode2] = 7
	peers.notify(fakeNode2)
	require.Equal(t, 1, c.queue.Len())
	item, _ = c.queue.Get()
	c.queue.Done(item)
	gomock.InOrder(
		c.mockOFClient.EXPECT().UninstallPodSNATFlows(uint32(1)),
		c.mockOFClient.EXPECT().InstallPodL2DispatchFlows(uint32(1), remoteEgressIP, uint32(7)),
	)
	require.NoError(t, c.syncEgress(item))

	// The Egress Node leaves the local subnet: the Pod flow is removed, and the Pod gets the default SNAT.
	delete(peers.indices, fakeNode2)
	peers.errs[fakeNode2] = fmt.Errorf("not in the local transport subnet")
	peers.notify(fakeNode2)
	require.Equal(t, 1, c.queue.Len())
	item, _ = c.queue.Get()
	c.queue.Done(item)
	c.mockOFClient.EXPECT().UninstallPodSNATFlows(uint32(1))
	require.NoError(t, c.syncEgress(item))

	// When the Egress is deleted, it no longer follows the Egress Node.
	require.NoError(t, c.crdClient.CrdV1beta1().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{}))
	require.Eventually(t, func() bool {
		_, err := c.egressLister.Get(egress.Name)
		return err != nil
	}, time.Second, 10*time.Millisecond)
	require.NoError(t, c.syncEgress(egress.Name))
	assert.Empty(t, c.l2DispatchEgresses)
}
