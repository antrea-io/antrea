//go:build !windows

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

package multicast

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"sync"
	"testing"
	"time"

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/libOpenflow/protocol"
	"antrea.io/libOpenflow/util"
	"antrea.io/ofnet/ofctrl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apitypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
	ifaceStoretest "antrea.io/antrea/pkg/agent/interfacestore/testing"
	multicasttest "antrea.io/antrea/pkg/agent/multicast/testing"
	"antrea.io/antrea/pkg/agent/openflow"
	openflowtest "antrea.io/antrea/pkg/agent/openflow/testing"
	"antrea.io/antrea/pkg/agent/types"
	typestest "antrea.io/antrea/pkg/agent/types/testing"
	agentutil "antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	"antrea.io/antrea/pkg/apis/crd/v1beta1"
	ovsopenflow "antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/antrea/pkg/util/channel"
)

var (
	if1 = &interfacestore.InterfaceConfig{
		Type:          interfacestore.ContainerInterface,
		InterfaceName: "if1",
		IPs:           []net.IP{net.ParseIP("192.168.1.1")},
		OVSPortConfig: &interfacestore.OVSPortConfig{
			OFPort: 1,
		},
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: "pod4", PodNamespace: "ns2", ContainerID: "container4"},
	}
	if2 = &interfacestore.InterfaceConfig{
		Type:          interfacestore.ContainerInterface,
		InterfaceName: "if2",
		IPs:           []net.IP{net.ParseIP("192.168.1.2")},
		OVSPortConfig: &interfacestore.OVSPortConfig{
			OFPort: 2,
		},
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{PodName: "pod3", PodNamespace: "ns1", ContainerID: "container3"},
	}
	nodeIf1IP         = net.ParseIP("192.168.20.22")
	igmpQueryVersions = []uint8{1, 2, 3}
)

func TestAddGroupMemberStatus(t *testing.T) {
	mgroup := net.ParseIP("224.96.1.3")
	event := &mcastGroupEvent{
		group: mgroup,
		eType: groupJoin,
		time:  time.Now(),
		iface: if1,
	}
	testController := newTestMulticastController(t, false, false)
	testController.initialize(t)
	testController.mRouteClient.multicastInterfaceConfigs = []multicastInterfaceConfig{
		{Name: if1.InterfaceName, IPv4Addr: &net.IPNet{IP: nodeIf1IP, Mask: net.IPv4Mask(255, 255, 255, 0)}},
	}
	testController.addGroupMemberStatus(event)
	groupCache := testController.groupCache
	compareGroupStatus(t, groupCache, event)
	key, _ := testController.queue.Get()
	assert.Equal(t, mgroup.String(), key)
	testController.mockIfaceStore.EXPECT().GetInterfaceByName(if1.InterfaceName).Return(if1, true)
	testController.mockOFClient.EXPECT().InstallMulticastGroup(gomock.Any(), gomock.Any(), gomock.Any())
	testController.mockOFClient.EXPECT().InstallMulticastFlows(mgroup, gomock.Any()).Times(1)
	testController.mockMulticastSocket.EXPECT().MulticastInterfaceJoinMgroup(mgroup.To4(), nodeIf1IP.To4(), if1.InterfaceName).Times(1)
	assert.NoError(t, testController.syncGroup(key))
	testController.queue.Forget(key)
}

func TestUpdateGroupMemberStatus(t *testing.T) {
	testController := newTestMulticastController(t, false, false)
	testController.initialize(t)
	mgroup := net.ParseIP("224.96.1.4")
	event := &mcastGroupEvent{
		group: mgroup,
		eType: groupJoin,
		time:  time.Now(),
		iface: if1,
	}
	testController.addGroupMemberStatus(event)
	testController.mockOFClient.EXPECT().SendIGMPQueryPacketOut(igmpQueryDstMac, types.McastAllHosts, uint32(0), gomock.Any()).Times(len(testController.igmpSnooper.queryVersions))
	for _, e := range []struct {
		name       string
		groupEvent mcastGroupEvent
	}{
		{
			name: "if1 joins group after 20 seconds",
			groupEvent: mcastGroupEvent{
				group: mgroup, eType: groupJoin, time: event.time.Add(time.Second * 20), iface: if1,
			},
		},
		{
			name: "if1 joins group after 40 seconds",
			groupEvent: mcastGroupEvent{
				group: mgroup, eType: groupJoin, time: event.time.Add(time.Second * 40), iface: if1,
			},
		},
		{
			name: "if2 joins group after 60 seconds",
			groupEvent: mcastGroupEvent{
				group: mgroup, eType: groupJoin, time: event.time.Add(time.Second * 60), iface: if2,
			},
		},
		{
			name: "if1 leaves group after 61 seconds",
			groupEvent: mcastGroupEvent{
				group: mgroup, eType: groupLeave, time: event.time.Add(time.Second * 61), iface: if1,
			},
		},
		{
			name: "if2 leaves group after 62 seconds",
			groupEvent: mcastGroupEvent{
				group: mgroup, eType: groupLeave, time: event.time.Add(time.Second * 62), iface: if2,
			},
		},
	} {
		t.Run(e.name, func(t *testing.T) {
			obj, _, _ := testController.groupCache.GetByKey(event.group.String())
			if e.groupEvent.eType == groupLeave {
				testController.mockIfaceStore.EXPECT().GetInterfaceByName(e.groupEvent.iface.InterfaceName).Return(e.groupEvent.iface, true)
			}
			testController.updateGroupMemberStatus(obj, &e.groupEvent)
			groupCache := testController.groupCache
			compareGroupStatus(t, groupCache, &e.groupEvent)
			groups := testController.getGroupMemberStatusesByPod(e.groupEvent.iface.InterfaceName)
			if e.groupEvent.eType == groupJoin {
				assert.True(t, len(groups) > 0)
			} else {
				assert.True(t, len(groups) == 0)
			}
		})
	}
}

func TestCheckNodeUpdate(t *testing.T) {
	for _, tc := range []struct {
		name        string
		oldNode     *corev1.Node
		curNode     *corev1.Node
		nodeUpdated bool
	}{
		{
			name: "same name, different internal IPs",
			oldNode: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node0",
				},
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "192.168.50.102"}},
				},
			},
			curNode: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node0",
				},
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "192.168.50.101"}},
				},
			},
			nodeUpdated: true,
		},
		{
			name: "same name, different IPs in annotation",
			oldNode: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "node0",
					Annotations: map[string]string{types.NodeTransportAddressAnnotationKey: "172.16.0.1,1::1"},
				},
			},
			curNode: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "node0",
					Annotations: map[string]string{types.NodeTransportAddressAnnotationKey: "172.16.0.2,1::1"},
				},
			},
			nodeUpdated: true,
		},
		{
			name: "same name, same IP",
			oldNode: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "node0",
					Annotations: map[string]string{types.NodeTransportAddressAnnotationKey: "172.16.0.1,1::1"},
				},
			},
			curNode: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "node0",
					Annotations: map[string]string{types.NodeTransportAddressAnnotationKey: "172.16.0.1,1::1"},
				},
			},
			nodeUpdated: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// This test assumes encap mode.
			testController := newTestMulticastController(t, true, false)
			testController.initialize(t)

			testController.checkNodeUpdate(tc.oldNode, tc.curNode)
			if tc.nodeUpdated {
				assert.Equal(t, 1, testController.nodeUpdateQueue.Len())
			} else {
				assert.Zero(t, testController.nodeUpdateQueue.Len())
			}
		})
	}
}

func TestCheckLastMember(t *testing.T) {
	mockIgmpMaxResponseTime(t)
	testController := newTestMulticastController(t, false, false)
	workerCount = 1
	lastProbe := time.Now()
	mgroup := net.ParseIP("224.96.1.2")
	testCheckLastMember := func(ev *mcastGroupEvent, expExist bool) {
		status := &GroupMemberStatus{
			localMembers: map[string]time.Time{},
		}
		if ev != nil {
			status.group = ev.group
			if ev.eType == groupLeave {
				testController.mockOFClient.EXPECT().UninstallMulticastGroup(gomock.Any())
				testController.mockOFClient.EXPECT().UninstallMulticastFlows(status.group)
			}
		} else {
			status.group = mgroup
			testController.mockOFClient.EXPECT().UninstallMulticastGroup(gomock.Any())
			testController.mockOFClient.EXPECT().UninstallMulticastFlows(status.group)
		}
		_ = testController.groupCache.Add(status)
		testController.addInstalledGroup(status.group.String())
		testController.mockOFClient.EXPECT().SendIGMPQueryPacketOut(igmpQueryDstMac, types.McastAllHosts, uint32(0), gomock.Any()).AnyTimes()
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			testController.checkLastMember(status.group)
			// Wait igmpMaxResponseTime to ensure the group is added into testController.queue.
			wg.Done()
		}()
		if ev != nil {
			testController.addOrUpdateGroupEvent(ev)
		}
		wg.Wait()
		key, _ := testController.queue.Get()
		assert.Equal(t, status.group.String(), key)
		err := testController.syncGroup(key)
		assert.NoError(t, err)
		_, exists, err := testController.groupCache.GetByKey(key)
		assert.NoError(t, err)
		assert.Equal(t, expExist, exists)
		// Clear cache to avoid affecting the next test.
		if _, ok, _ := testController.groupCache.GetByKey(key); ok {
			_ = testController.groupCache.Delete(status)
		}
		testController.queue.Forget(key)
	}
	testController.mockIfaceStore.EXPECT().GetInterfaceByName(if1.InterfaceName).Return(if1, true).Times(1)
	testController.mockOFClient.EXPECT().InstallMulticastGroup(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	for _, tc := range []struct {
		name   string
		ev     *mcastGroupEvent
		exists bool
	}{
		{
			name: "group join event",
			ev: &mcastGroupEvent{
				group: net.ParseIP("224.96.1.5"),
				eType: groupJoin,
				time:  lastProbe.Add(time.Second * 1),
				iface: if1,
			},
			exists: true,
		},
		{
			name: "group leave event",
			ev: &mcastGroupEvent{
				group: net.ParseIP("224.96.1.6"),
				eType: groupLeave,
				time:  lastProbe.Add(time.Second * 1),
				iface: if1,
			},
			exists: false,
		},
		{
			name:   "no event",
			ev:     nil,
			exists: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testCheckLastMember(tc.ev, tc.exists)
		})
	}
}

func TestGetGroupPods(t *testing.T) {
	now := time.Now()

	testController := newTestMulticastController(t, false, false)
	testController.initialize(t)
	groupMemberStatuses := []*GroupMemberStatus{
		{
			group:        net.ParseIP("224.96.1.2"),
			localMembers: map[string]time.Time{if1.InterfaceName: now.Add(-10 * time.Second), if2.InterfaceName: now.Add(-20 * time.Second)},
		},
		{
			group:        net.ParseIP("224.96.1.3"),
			localMembers: map[string]time.Time{if2.InterfaceName: now.Add(-20 * time.Second)},
		},
	}
	interfaceNameMap := map[string]*interfacestore.InterfaceConfig{
		if2.InterfaceName: if2,
		if1.InterfaceName: if1,
	}
	expectedGroupPodsMap := map[string][]v1beta2.PodReference{
		"224.96.1.2": {{Name: if2.PodName, Namespace: if2.PodNamespace}, {Name: if1.PodName, Namespace: if1.PodNamespace}},
		"224.96.1.3": {{Name: if2.PodName, Namespace: if2.PodNamespace}},
	}
	for _, g := range groupMemberStatuses {
		err := testController.groupCache.Add(g)
		assert.NoError(t, err)
	}
	for k, v := range interfaceNameMap {
		testController.mockIfaceStore.EXPECT().GetInterfaceByName(k).AnyTimes().Return(v, true)
	}
	groupPodsMap := testController.GetGroupPods()
	assert.Equal(t, len(expectedGroupPodsMap), len(groupPodsMap))
	for k, v := range groupPodsMap {
		assert.ElementsMatch(t, expectedGroupPodsMap[k], v)
	}
}

func TestGetPodStats(t *testing.T) {
	testController := newTestMulticastController(t, false, false)
	testController.initialize(t)

	iface := if1
	egressPodStats := &types.RuleMetric{Packets: 2, Bytes: 30}
	ingressPodStats := &types.RuleMetric{Packets: 4, Bytes: 50}
	expectedPodStats := &PodTrafficStats{Inbound: 4, Outbound: 2}

	testController.mockIfaceStore.EXPECT().GetContainerInterfacesByPod(iface.PodName, iface.PodNamespace).Return([]*interfacestore.InterfaceConfig{iface})
	testController.mockOFClient.EXPECT().MulticastEgressPodMetricsByIP(iface.IPs[0]).Return(egressPodStats)
	testController.mockOFClient.EXPECT().MulticastIngressPodMetricsByOFPort(iface.OVSPortConfig.OFPort).Return(ingressPodStats)
	podStats := testController.GetPodStats(iface.PodName, iface.PodNamespace)
	assert.Equal(t, expectedPodStats, podStats)
}

func TestGetAllPodStats(t *testing.T) {
	testController := newTestMulticastController(t, false, false)
	testController.initialize(t)

	for _, tc := range []struct {
		name            string
		egressPodStats  map[string]*types.RuleMetric
		ingressPodStats map[uint32]*types.RuleMetric
		ifaceByIPMap    map[string]*interfacestore.InterfaceConfig
		ifaceByPortMap  map[uint32]*interfacestore.InterfaceConfig
		expectedStats   map[*interfacestore.InterfaceConfig]*PodTrafficStats
	}{
		{
			name:            "one iterface with inbound and outbound stats",
			egressPodStats:  map[string]*types.RuleMetric{if1.IPs[0].String(): {Packets: 2, Bytes: 30}},
			ingressPodStats: map[uint32]*types.RuleMetric{uint32(if1.OFPort): {Packets: 4, Bytes: 50}},
			ifaceByIPMap:    map[string]*interfacestore.InterfaceConfig{if1.IPs[0].String(): if1},
			ifaceByPortMap:  map[uint32]*interfacestore.InterfaceConfig{uint32(if1.OFPort): if1},
			expectedStats:   map[*interfacestore.InterfaceConfig]*PodTrafficStats{if1: {Inbound: uint64(4), Outbound: uint64(2)}},
		}, {
			name:            "two interfaces",
			egressPodStats:  map[string]*types.RuleMetric{if1.IPs[0].String(): {Packets: 2, Bytes: 30}},
			ingressPodStats: map[uint32]*types.RuleMetric{uint32(if2.OFPort): {Packets: 4, Bytes: 50}},
			ifaceByIPMap:    map[string]*interfacestore.InterfaceConfig{if1.IPs[0].String(): if1},
			ifaceByPortMap:  map[uint32]*interfacestore.InterfaceConfig{uint32(if2.OFPort): if2},
			expectedStats:   map[*interfacestore.InterfaceConfig]*PodTrafficStats{if2: {Inbound: uint64(4)}, if1: {Outbound: uint64(2)}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testController.mockOFClient.EXPECT().MulticastEgressPodMetrics().Return(tc.egressPodStats)
			testController.mockOFClient.EXPECT().MulticastIngressPodMetrics().Return(tc.ingressPodStats)
			for k, v := range tc.ifaceByIPMap {
				testController.mockIfaceStore.EXPECT().GetInterfaceByIP(k).Return(v, true)
			}
			for k, v := range tc.ifaceByPortMap {
				testController.mockIfaceStore.EXPECT().GetInterfaceByOFPort(k).Return(v, true)
			}
			stats := testController.GetAllPodsStats()
			assert.Equal(t, tc.expectedStats, stats)
		})
	}
}

func TestClearStaleGroupsCreatingLeaveEvent(t *testing.T) {
	testController := newTestMulticastController(t, false, false)
	workerCount = 1
	testController.initialize(t)
	now := time.Now()
	staleTime := now.Add(-testController.mcastGroupTimeout - time.Second)
	activeTime := now.Add(-testController.mcastGroupTimeout + time.Second)
	groups := []*GroupMemberStatus{
		{
			group:        net.ParseIP("224.96.1.4"),
			localMembers: map[string]time.Time{"p1": staleTime, "p3": activeTime},
		},
		{
			group:        net.ParseIP("224.96.1.5"),
			localMembers: map[string]time.Time{"p1": activeTime},
		},
	}
	for _, g := range groups {
		err := testController.groupCache.Add(g)
		assert.NoError(t, err)
	}
	testController.clearStaleGroups()
	assert.Equal(t, 1, len(testController.groupEventCh))
	e := <-testController.groupEventCh
	assert.Equal(t, net.ParseIP("224.96.1.4"), e.group)
	assert.Equal(t, groupLeave, e.eType)
	expectedIface := &interfacestore.InterfaceConfig{
		InterfaceName: "p1",
		Type:          interfacestore.ContainerInterface,
	}
	assert.Equal(t, expectedIface, e.iface)
}

func TestClearStaleGroups(t *testing.T) {
	mockIgmpMaxResponseTime(t)
	for _, tc := range []struct {
		name    string
		isEncap bool
	}{
		{
			name:    "noEncap",
			isEncap: false,
		},
		{
			name:    "encap",
			isEncap: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testController := newTestMulticastController(t, tc.isEncap, false)
			// Only use IGMPv3 in this test.
			testController.igmpSnooper.queryVersions = []uint8{3}
			workerCount = 1
			testController.initialize(t)
			testController.mRouteClient.multicastInterfaceConfigs = []multicastInterfaceConfig{
				{Name: if1.InterfaceName, IPv4Addr: &net.IPNet{IP: nodeIf1IP, Mask: net.IPv4Mask(255, 255, 255, 0)}},
			}
			stopCh := make(chan struct{})
			defer close(stopCh)
			go testController.eventHandler(stopCh)

			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				testController.worker()
			}()

			fakePort := int32(1)
			for _, ifName := range []string{"p1", "p2", "p3", "p4"} {
				mockIface := &interfacestore.InterfaceConfig{InterfaceName: ifName, OVSPortConfig: &interfacestore.OVSPortConfig{OFPort: fakePort}}
				testController.mockIfaceStore.EXPECT().GetInterfaceByName(ifName).Return(mockIface, true).AnyTimes()
				fakePort++
			}

			now := time.Now()
			validUpdateTime := now.Add(-testController.queryInterval)
			validGroups := []*GroupMemberStatus{
				{
					group:        net.ParseIP("224.96.1.2"),
					localMembers: map[string]time.Time{"p1": now, "p2": validUpdateTime},
					ofGroupID:    ovsopenflow.GroupIDType(4),
				},
				{
					group:        net.ParseIP("224.96.1.3"),
					localMembers: map[string]time.Time{"p2": validUpdateTime},
					ofGroupID:    ovsopenflow.GroupIDType(5),
				},
			}
			staleUpdateTime := now.Add(-testController.mcastGroupTimeout - time.Second)
			staleGroups := []*GroupMemberStatus{
				{
					group:        net.ParseIP("224.96.1.4"),
					localMembers: map[string]time.Time{"p1": staleUpdateTime, "p3": staleUpdateTime},
					ofGroupID:    ovsopenflow.GroupIDType(6),
				},
				{
					group:        net.ParseIP("224.96.1.5"),
					localMembers: map[string]time.Time{},
					ofGroupID:    ovsopenflow.GroupIDType(7),
				},
			}

			localStaleGroups := []*GroupMemberStatus{}
			if tc.isEncap {
				localStaleGroups = append(localStaleGroups, &GroupMemberStatus{
					group:         net.ParseIP("224.96.1.6"),
					localMembers:  map[string]time.Time{"p4": staleUpdateTime},
					remoteMembers: sets.New[string]("10.10.1.2"),
					ofGroupID:     ovsopenflow.GroupIDType(8),
				})
			}

			for _, g := range validGroups {
				assert.NoError(t, testController.groupCache.Add(g))
				testController.addInstalledGroup(g.group.String())
				testController.addInstalledLocalGroup(g.group.String())
			}
			for _, g := range staleGroups {
				assert.NoError(t, testController.groupCache.Add(g))
				testController.addInstalledGroup(g.group.String())
				testController.addInstalledLocalGroup(g.group.String())
				testController.mockOFClient.EXPECT().UninstallMulticastGroup(g.ofGroupID).Times(1)
				testController.mockOFClient.EXPECT().UninstallMulticastFlows(gomock.Any()).Times(1)
				testController.mockMulticastSocket.EXPECT().MulticastInterfaceLeaveMgroup(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
				testController.mockOFClient.EXPECT().SendIGMPQueryPacketOut(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
				if len(g.localMembers) > 1 {
					// If multiple local members exist in the stale Multicast group, the corresponding OpenFlow group is
					// possibly re-installed len(localMembers)-1 at most. We can't know the exact number in the mock here,
					// since the actual execution depends on the runtime status of the local cache which is updated by the
					// event handler in another goroutine.
					testController.mockOFClient.EXPECT().InstallMulticastGroup(g.ofGroupID, gomock.Any(), gomock.Any()).MaxTimes(len(g.localMembers) - 1)
				}
				if tc.isEncap {
					testController.mockOFClient.EXPECT().SendIGMPRemoteReportPacketOut(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
				}
			}

			for _, g := range localStaleGroups {
				assert.NoError(t, testController.groupCache.Add(g))
				testController.addInstalledGroup(g.group.String())
				testController.addInstalledLocalGroup(g.group.String())
				if tc.isEncap {
					// Send IGMP leave message to other Nodes
					testController.mockOFClient.EXPECT().SendIGMPRemoteReportPacketOut(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
					// Update OpenFlow group corresponding to the Multicast group to remove local members
					testController.mockOFClient.EXPECT().InstallMulticastGroup(g.ofGroupID, gomock.Any(), gomock.Any()).Times(1)
				}

				testController.mockMulticastSocket.EXPECT().MulticastInterfaceLeaveMgroup(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
				// Send IGMP query to ensure the last local member has left.
				testController.mockOFClient.EXPECT().SendIGMPQueryPacketOut(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
			}

			testController.clearStaleGroups()

			// Enqueue an IGMP leave event with an invalid Multicast group, which ensures all the group events
			// generated by the "clearStaleGroups" are processed.
			testController.groupEventCh <- &mcastGroupEvent{
				// 224.96.101.101 is unknown to the groupCache.
				group: net.ParseIP("224.96.101.101"),
				eType: groupLeave,
				time:  now,
			}
			require.Eventually(t, func() bool {
				return len(testController.groupEventCh) == 0
			}, time.Second, time.Millisecond*100)

			testController.queue.ShutDownWithDrain()

			wg.Wait()
			assert.Equal(t, len(validGroups)+len(localStaleGroups), len(testController.groupCache.List()))
			for _, g := range validGroups {
				_, exists, _ := testController.groupCache.GetByKey(g.group.String())
				assert.True(t, exists)
			}
			for _, g := range staleGroups {
				_, exists, _ := testController.groupCache.GetByKey(g.group.String())
				assert.False(t, exists)
			}
			for _, g := range localStaleGroups {
				obj, exists, _ := testController.groupCache.GetByKey(g.group.String())
				require.True(t, exists)
				status := obj.(*GroupMemberStatus)
				assert.Equal(t, 0, len(status.localMembers))
			}
		})
	}

}

func TestProcessPacketIn(t *testing.T) {
	testController := newTestMulticastController(t, false, false)
	snooper := testController.igmpSnooper
	stopCh := make(chan struct{})

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		testController.eventHandler(stopCh)
		wg.Done()
	}()

	getIPs := func(ipStrs []string) []net.IP {
		ips := make([]net.IP, len(ipStrs))
		for i := range ipStrs {
			ips[i] = net.ParseIP(ipStrs[i])
		}
		return ips
	}
	allow := v1beta1.RuleActionAllow
	annp := v1beta2.AntreaNetworkPolicy
	acnp := v1beta2.AntreaClusterNetworkPolicy
	drop := v1beta1.RuleActionDrop
	for _, tc := range []struct {
		name             string
		iface            *interfacestore.InterfaceConfig
		version          uint8
		joinedGroups     sets.Set[string]
		joinedGroupItems map[string]*types.IGMPNPRuleInfo
		leftGroups       sets.Set[string]
		igmpANNPStats    map[apitypes.UID]map[string]*types.RuleMetric
		igmpACNPStats    map[apitypes.UID]map[string]*types.RuleMetric
		expGroups        sets.Set[string]
	}{
		{
			name:         "join multiple groups groups",
			iface:        createInterface("p1", 1),
			joinedGroups: sets.New[string]("224.1.101.2", "224.1.101.3", "224.1.101.4"),
			joinedGroupItems: map[string]*types.IGMPNPRuleInfo{
				"224.1.101.2": nil,
				"224.1.101.3": nil,
				"224.1.101.4": {
					RuleAction: allow,
					UUID:       "annp",
					NPType:     &annp,
					Name:       "allow_1014",
				},
			},
			leftGroups:    sets.New[string](),
			expGroups:     sets.New[string]("224.1.101.2", "224.1.101.3", "224.1.101.4"),
			igmpANNPStats: map[apitypes.UID]map[string]*types.RuleMetric{"annp": {"allow_1014": {Bytes: 42, Packets: 1}}},
			igmpACNPStats: map[apitypes.UID]map[string]*types.RuleMetric{},
			version:       1,
		},
		{
			name:         "join multiple groups and block one group",
			iface:        createInterface("p11", 1),
			joinedGroups: sets.New[string]("224.1.101.20", "224.1.101.21", "224.1.101.22", "224.1.101.23"),
			joinedGroupItems: map[string]*types.IGMPNPRuleInfo{
				"224.1.101.20": {
					RuleAction: drop,
					UUID:       "annp",
					NPType:     &annp,
					Name:       "block10120",
				},
				"224.1.101.2": nil,
				"224.1.101.22": {
					RuleAction: allow,
					UUID:       "annp",
					NPType:     &annp,
					Name:       "allow_10122",
				},
				"224.1.101.23": {
					RuleAction: allow,
					UUID:       "acnp",
					NPType:     &acnp,
					Name:       "allow_10123",
				},
			},
			igmpANNPStats: map[apitypes.UID]map[string]*types.RuleMetric{"annp": {"allow_10122": {Bytes: 42, Packets: 1}, "block10120": {Bytes: 42, Packets: 1}, "allow_1014": {Bytes: 42, Packets: 1}}},
			igmpACNPStats: map[apitypes.UID]map[string]*types.RuleMetric{"acnp": {"allow_10123": {Packets: 1, Bytes: 42}}},
			expGroups:     sets.New[string]("224.1.101.21", "224.1.101.22", "224.1.101.23"),
			version:       1,
		},
		{
			name:         "join multiple groups and leave one group",
			iface:        createInterface("p2", 2),
			joinedGroups: sets.New[string]("224.1.102.2", "224.1.102.3", "224.1.102.4"),
			joinedGroupItems: map[string]*types.IGMPNPRuleInfo{
				"224.1.102.2": nil,
				"224.1.102.3": nil,
				"224.1.102.4": nil,
			},
			leftGroups:    sets.New[string]("224.1.102.3"),
			igmpANNPStats: map[apitypes.UID]map[string]*types.RuleMetric{"annp": {"allow_10122": {Bytes: 42, Packets: 1}, "block10120": {Bytes: 42, Packets: 1}, "allow_1014": {Bytes: 42, Packets: 1}}},
			igmpACNPStats: map[apitypes.UID]map[string]*types.RuleMetric{"acnp": {"allow_10123": {Packets: 1, Bytes: 42}}},
			expGroups:     sets.New[string]("224.1.102.2", "224.1.102.4"),
			version:       2,
		},
		{
			name:         "join multiple groups groups, leave one group and block one group",
			iface:        createInterface("p22", 2),
			joinedGroups: sets.New[string]("224.1.102.21", "224.1.102.22", "224.1.102.23", "224.1.102.24"),
			joinedGroupItems: map[string]*types.IGMPNPRuleInfo{
				"224.1.102.21": nil,
				"224.1.102.22": nil,
				"224.1.102.23": nil,
				"224.1.102.24": {
					RuleAction: drop,
					UUID:       "annp",
					NPType:     &annp,
					Name:       "block10120",
				},
			},
			leftGroups:    sets.New[string]("224.1.102.23"),
			version:       2,
			igmpANNPStats: map[apitypes.UID]map[string]*types.RuleMetric{"annp": {"allow_10122": {Bytes: 42, Packets: 1}, "block10120": {Bytes: 84, Packets: 2}, "allow_1014": {Bytes: 42, Packets: 1}}},
			igmpACNPStats: map[apitypes.UID]map[string]*types.RuleMetric{"acnp": {"allow_10123": {Packets: 1, Bytes: 42}}},
			expGroups:     sets.New[string]("224.1.102.21", "224.1.102.22"),
		},
		{
			name:         "mixed case",
			iface:        createInterface("p33", 3),
			joinedGroups: sets.New[string]("224.1.103.2", "224.1.103.3", "224.1.103.4"),
			joinedGroupItems: map[string]*types.IGMPNPRuleInfo{
				"224.1.103.2": nil,
				"224.1.103.3": {
					RuleAction: drop,
					UUID:       "acnp2",
					NPType:     &acnp,
					Name:       "test",
				},
				"224.1.103.4": {
					RuleAction: allow,
					UUID:       "acnp2",
					NPType:     &acnp,
					Name:       "test2",
				},
			},
			leftGroups:    sets.New[string]("224.1.103.2", "224.1.103.3"),
			igmpANNPStats: map[apitypes.UID]map[string]*types.RuleMetric{"annp": {"allow_10122": {Bytes: 42, Packets: 1}, "block10120": {Bytes: 84, Packets: 2}, "allow_1014": {Bytes: 42, Packets: 1}}},
			igmpACNPStats: map[apitypes.UID]map[string]*types.RuleMetric{"acnp2": {"test": {Packets: 1, Bytes: 58}, "test2": {Packets: 1, Bytes: 66}}, "acnp": {"allow_10123": {Packets: 1, Bytes: 42}}},
			expGroups:     sets.New[string]("224.1.103.4"),
			version:       3,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testController.mockIfaceStore.EXPECT().GetInterfaceByName(tc.iface.InterfaceName).Return(tc.iface, true).AnyTimes()
			packets := createIGMPReportPacketIn(getIPs(sets.List(tc.joinedGroups)), getIPs(sets.List(tc.leftGroups)), tc.version, uint32(tc.iface.OFPort))
			testController.mockOFClient.EXPECT().SendIGMPQueryPacketOut(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

			if tc.version == 3 {
				for _, leftGroup := range sets.List(tc.leftGroups) {
					testController.mockMulticastValidator.EXPECT().GetIGMPNPRuleInfo(tc.iface.InterfaceName, tc.iface.PodNamespace, net.ParseIP(leftGroup).To4(), gomock.Any()).Times(1)
				}
			}
			for _, joinedGroup := range sets.List(tc.joinedGroups) {
				testController.mockMulticastValidator.EXPECT().GetIGMPNPRuleInfo(tc.iface.InterfaceName, tc.iface.PodNamespace, net.ParseIP(joinedGroup).To4(), gomock.Any()).Return(tc.joinedGroupItems[joinedGroup], nil).Times(1)
			}
			for _, pkt := range packets {
				testController.mockIfaceStore.EXPECT().GetInterfaceByOFPort(uint32(tc.iface.OFPort)).Return(tc.iface, true)
				err := snooper.HandlePacketIn(pkt)
				assert.NoError(t, err)
			}

			assert.Equal(t, tc.igmpACNPStats, snooper.igmpReportACNPStats)
			assert.Equal(t, tc.igmpANNPStats, snooper.igmpReportANNPStats)

			assert.Eventually(t, func() bool {
				statuses := testController.getGroupMemberStatusesByPod(tc.iface.InterfaceName)
				if tc.expGroups.Len() != len(statuses) {
					return false
				}
				for _, s := range statuses {
					if !tc.expGroups.Has(s.group.String()) {
						return false
					}
				}
				return true
			}, time.Second, 100*time.Millisecond)
		})
	}
	assert.Eventually(t, func() bool {
		return len(testController.groupEventCh) == 0
	}, time.Second, 100*time.Millisecond)
	close(stopCh)
	wg.Wait()
}

func TestEncapModeInitialize(t *testing.T) {
	testController := newTestMulticastController(t, true, false)
	assert.NotZero(t, testController.nodeGroupID)
	testController.initialize(t)
}

func TestEncapLocalReportAndNotifyRemote(t *testing.T) {
	mockIgmpMaxResponseTime(t)
	testController := newTestMulticastController(t, true, false)
	testController.initialize(t)
	testController.mRouteClient.multicastInterfaceConfigs = []multicastInterfaceConfig{
		{Name: if1.InterfaceName, IPv4Addr: &net.IPNet{IP: nodeIf1IP, Mask: net.IPv4Mask(255, 255, 255, 0)}},
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		testController.worker()
	}()

	iface1 := createInterface("pod1", 3)
	iface2 := createInterface("pod2", 4)
	mgroup := net.ParseIP("224.2.100.4")
	for _, tc := range []struct {
		name         string
		e            *mcastGroupEvent
		interfaces   []*interfacestore.InterfaceConfig
		groupChanged bool
		ifaceCheck   bool
	}{
		{
			name:         "group join event",
			e:            &mcastGroupEvent{group: mgroup, eType: groupJoin, time: time.Now(), iface: iface1},
			interfaces:   []*interfacestore.InterfaceConfig{iface1},
			groupChanged: true,
			ifaceCheck:   true,
		},
		{
			name:         "group join event to same group",
			e:            &mcastGroupEvent{group: mgroup, eType: groupJoin, time: time.Now(), iface: iface1},
			interfaces:   []*interfacestore.InterfaceConfig{iface1},
			groupChanged: false,
			ifaceCheck:   false,
		},
		{
			name:         "group join event to existing group",
			e:            &mcastGroupEvent{group: mgroup, eType: groupJoin, time: time.Now(), iface: iface2},
			interfaces:   []*interfacestore.InterfaceConfig{iface1, iface2},
			groupChanged: false,
			ifaceCheck:   true,
		},
		{
			name:         "group leave event to existing group",
			e:            &mcastGroupEvent{group: mgroup, eType: groupLeave, time: time.Now(), iface: iface2},
			interfaces:   []*interfacestore.InterfaceConfig{iface1, iface2},
			groupChanged: false,
			ifaceCheck:   true,
		},
		{
			name:         "group leave event to existing group with single member",
			e:            &mcastGroupEvent{group: mgroup, eType: groupLeave, time: time.Now(), iface: iface1},
			interfaces:   []*interfacestore.InterfaceConfig{iface1},
			groupChanged: true,
			ifaceCheck:   true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			groupKey := tc.e.group.String()
			if tc.e.eType == groupJoin {
				if tc.groupChanged {
					testController.mockMulticastSocket.EXPECT().MulticastInterfaceJoinMgroup(mgroup.To4(), nodeIf1IP.To4(), if1.InterfaceName).Times(1)
					testController.mockOFClient.EXPECT().SendIGMPRemoteReportPacketOut(igmpReportDstMac, types.IGMPv3Router, gomock.Any())
					testController.mockOFClient.EXPECT().InstallMulticastFlows(mgroup, gomock.Any()).Times(1)
				}
				if tc.ifaceCheck {
					for _, iface := range tc.interfaces {
						testController.mockIfaceStore.EXPECT().GetInterfaceByName(iface.InterfaceName).Return(iface, true)
					}
					testController.mockOFClient.EXPECT().InstallMulticastGroup(gomock.Any(), gomock.Any(), gomock.Any())
				}
			} else {
				if tc.ifaceCheck {
					for _, iface := range tc.interfaces {
						testController.mockIfaceStore.EXPECT().GetInterfaceByName(iface.InterfaceName).Return(iface, true)
					}
					if len(tc.interfaces) == 1 {
						testController.mockOFClient.EXPECT().SendIGMPQueryPacketOut(igmpQueryDstMac, types.McastAllHosts, gomock.Any(), gomock.Any()).AnyTimes()
					}
					if !tc.groupChanged {
						testController.mockOFClient.EXPECT().InstallMulticastGroup(gomock.Any(), gomock.Any(), gomock.Any())
					}
				}
				if tc.groupChanged {
					testController.mockOFClient.EXPECT().UninstallMulticastGroup(gomock.Any())
					testController.mockOFClient.EXPECT().UninstallMulticastFlows(tc.e.group)
					testController.mockMulticastSocket.EXPECT().MulticastInterfaceLeaveMgroup(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
					testController.mockOFClient.EXPECT().SendIGMPRemoteReportPacketOut(igmpReportDstMac, types.IGMPv3Router, gomock.Any())
				}
			}
			testController.addOrUpdateGroupEvent(tc.e)

			assert.Eventually(t, func() bool {
				// Wait until the event is processed.
				if testController.queue.Len() > 0 {
					return false
				}
				// Wait until all expectations are satisfied. This helps keep
				// the "subtests" isolated from each other, as they share the
				// same mock controller. It also helps ensure that the
				// conditions below are evaluated after the event has been fully
				// processed.
				if !testController.mockCtrl.Satisfied() {
					return false
				}
				if tc.groupChanged {
					if tc.e.eType == groupJoin {
						return testController.localGroupHasInstalled(groupKey) && testController.groupHasInstalled(groupKey)
					} else {
						return !testController.localGroupHasInstalled(groupKey) && !testController.groupHasInstalled(groupKey)
					}
				}
				return true
			}, time.Second, time.Millisecond*100)
		})
	}
	testController.queue.Add("unexistgroup")
	// Wait until all events in the queue are processed.
	assert.Eventually(t, func() bool {
		return testController.queue.Len() == 0
	}, time.Second, time.Millisecond*100)
	testController.queue.ShutDown()
	wg.Wait()
}

func TestNodeUpdate(t *testing.T) {
	testController := newTestMulticastController(t, true, false)
	stopCh := make(chan struct{})
	defer close(stopCh)
	testController.informerFactory.Start(stopCh)
	testController.informerFactory.WaitForCacheSync(stopCh)
	testController.addInstalledLocalGroup("224.2.100.1")

	wg := sync.WaitGroup{}
	for _, tc := range []struct {
		name          string
		addedNodes    map[string]map[string]string
		deletedNodes  []string
		expectedNodes sets.Set[string]
	}{
		{
			name: "add two nodes to empty install nodes",
			addedNodes: map[string]map[string]string{
				"n1": {"ip": "10.10.10.11"},
				"n2": {"ip": "10.10.10.12"},
			},
			expectedNodes: sets.New[string]("10.10.10.11", "10.10.10.12"),
		},
		{
			name: "add one node to installed nodes",
			addedNodes: map[string]map[string]string{
				"n3": {"ip": "10.10.10.13"},
			},
			expectedNodes: sets.New[string]("10.10.10.11", "10.10.10.12", "10.10.10.13"),
		},
		{
			name: "delete one node from installed nodes",
			deletedNodes: []string{
				"n1",
			},
			expectedNodes: sets.New[string]("10.10.10.12", "10.10.10.13"),
		},
		{
			name: "delete and add nodes to installed nodes",
			addedNodes: map[string]map[string]string{
				"n4": {"ip": "10.10.10.14", "label": "10.10.10.24"},
			},
			deletedNodes: []string{
				"n2",
			},
			expectedNodes: sets.New[string]("10.10.10.13", "10.10.10.24"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			times := len(tc.addedNodes) + len(tc.deletedNodes)
			testController.mockOFClient.EXPECT().InstallMulticastGroup(testController.nodeGroupID, nil, gomock.Any()).Return(nil).Times(times)
			testController.mockOFClient.EXPECT().SendIGMPRemoteReportPacketOut(igmpReportDstMac, types.IGMPv3Router, gomock.Any()).Times(times)
			wg.Add(1)

			go func() {
				for name, cfg := range tc.addedNodes {
					node := &corev1.Node{
						ObjectMeta: metav1.ObjectMeta{
							Name: name,
						},
					}
					ip, exist := cfg["ip"]
					if exist {
						node.Status = corev1.NodeStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalIP,
									Address: ip,
								},
							},
						}
					}
					label, exist := cfg["label"]
					if exist {
						node.Annotations = map[string]string{
							types.NodeTransportAddressAnnotationKey: label,
						}
					}
					testController.clientset.CoreV1().Nodes().Create(context.TODO(), node, metav1.CreateOptions{})
					testController.processNextNodeItem()
				}
				for _, name := range tc.deletedNodes {
					testController.clientset.CoreV1().Nodes().Delete(context.TODO(), name, metav1.DeleteOptions{})
					testController.processNextNodeItem()
				}
				wg.Done()
			}()

			wg.Wait()
			assert.Equal(t, tc.expectedNodes, testController.installedNodes, fmt.Sprintf("installedNodes: %v, expectedNodes: %v", testController.installedNodes, tc.expectedNodes))
		})
	}
}

func TestMemberChanged(t *testing.T) {
	testController := newTestMulticastController(t, false, false)
	testController.initialize(t)

	containerA := &interfacestore.ContainerInterfaceConfig{PodNamespace: "nameA", PodName: "podA", ContainerID: "tttt"}
	containerB := &interfacestore.ContainerInterfaceConfig{PodNamespace: "nameA", PodName: "podB", ContainerID: "mmmm"}
	containerInterfaceNameMap := make(map[*interfacestore.ContainerInterfaceConfig]string)
	for _, iface := range []*interfacestore.ContainerInterfaceConfig{containerA, containerB} {
		containerInterfaceNameMap[iface] = agentutil.GenerateContainerInterfaceName(iface.PodName, iface.PodNamespace, iface.ContainerID)
	}
	for _, tc := range []struct {
		name                 string
		podUpdateEvent       types.PodUpdate
		podJoinGroups        map[string][]*interfacestore.ContainerInterfaceConfig
		groupLeaveEventCount int
	}{
		{
			name:                 "pod add event",
			podUpdateEvent:       types.PodUpdate{PodNamespace: containerA.PodNamespace, PodName: containerA.PodName, IsAdd: true, ContainerID: containerA.ContainerID},
			groupLeaveEventCount: 0,
		},
		{
			name:           "pod update event with two groups joined",
			podUpdateEvent: types.PodUpdate{PodNamespace: containerA.PodNamespace, PodName: containerA.PodName, IsAdd: false, ContainerID: containerA.ContainerID},
			podJoinGroups: map[string][]*interfacestore.ContainerInterfaceConfig{
				"224.4.5.5": {containerA, containerB},
				"224.4.5.6": {containerA},
			},
			groupLeaveEventCount: 2,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testController.groupEventCh = make(chan *mcastGroupEvent, 100)
			for group, containers := range tc.podJoinGroups {
				podTimeMap := make(map[string]time.Time)
				for _, container := range containers {
					podTimeMap[containerInterfaceNameMap[container]] = time.Now().Add(-10 * time.Second)
				}
				status := &GroupMemberStatus{
					group:        net.ParseIP(group),
					localMembers: podTimeMap,
				}
				testController.groupCache.Add(status)
			}
			testController.memberChanged(tc.podUpdateEvent)
			assert.Equal(t, 1+tc.groupLeaveEventCount, len(testController.groupEventCh))
			e := <-testController.groupEventCh
			assert.Equal(t, types.McastAllHosts, e.group)
			for i := 0; i < tc.groupLeaveEventCount; i++ {
				e := <-testController.groupEventCh
				podUpdateEventInterfaceName := agentutil.GenerateContainerInterfaceName(tc.podUpdateEvent.PodName, tc.podUpdateEvent.PodNamespace, tc.podUpdateEvent.ContainerID)
				assert.Equal(t, podUpdateEventInterfaceName, e.iface.InterfaceName)
			}
		})
	}
}

func TestConcurrentEventHandlerAndWorkers(t *testing.T) {
	testController := newTestMulticastController(t, true, false)
	testController.ifaceStore = interfacestore.NewInterfaceStore()
	stopCh := make(chan struct{})
	defer close(stopCh)
	groupIP := net.ParseIP("224.3.4.5")
	numEvents := 10
	var wg sync.WaitGroup
	wg.Add(4)

	eventFunc := func(eType eventType, isLocal bool) {
		leastSignificantByteArr := rand.Perm(numEvents)
		ifaceNamePrefix := "local-interfaceName"
		ifaceType := interfacestore.ContainerInterface

		if !isLocal {
			ifaceNamePrefix = "remote-interfaceName"
			ifaceType = interfacestore.TunnelInterface
		}
		for i := 0; i < len(leastSignificantByteArr); i++ {
			var srcNode net.IP
			var containerCfg *interfacestore.ContainerInterfaceConfig
			if !isLocal {
				srcNode = net.ParseIP(fmt.Sprintf("10.20.30.%d", leastSignificantByteArr[i]+2))
			} else {
				containerCfg = &interfacestore.ContainerInterfaceConfig{
					ContainerID: fmt.Sprintf("container-%d", i),
				}
			}
			iface := &interfacestore.InterfaceConfig{
				Type:          ifaceType,
				InterfaceName: fmt.Sprintf("%s-%d", ifaceNamePrefix, i),
				OVSPortConfig: &interfacestore.OVSPortConfig{
					OFPort: int32(i),
				},
				ContainerInterfaceConfig: containerCfg,
			}
			if eType == groupJoin {
				testController.ifaceStore.AddInterface(iface)
			}
			testController.groupEventCh <- &mcastGroupEvent{
				group:   groupIP,
				eType:   eType,
				time:    time.Now(),
				iface:   iface,
				srcNode: srcNode,
			}
		}
	}
	// Below func adds local group join events.
	go func() {
		defer wg.Done()
		eventFunc(groupJoin, true)
	}()
	// Below func adds local group leave events.
	go func() {
		defer wg.Done()
		eventFunc(groupLeave, true)
	}()
	// Below func adds remote group join events.
	go func() {
		defer wg.Done()
		eventFunc(groupJoin, false)
	}()
	// Below func adds remote group leave events.
	go func() {
		defer wg.Done()
		eventFunc(groupLeave, false)
	}()

	testController.mockOFClient.EXPECT().InstallMulticastGroup(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	testController.mockOFClient.EXPECT().InstallMulticastFlows(groupIP, gomock.Any()).AnyTimes()
	testController.mockOFClient.EXPECT().UninstallMulticastGroup(gomock.Any()).AnyTimes()
	testController.mockOFClient.EXPECT().UninstallMulticastFlows(groupIP).AnyTimes()
	testController.mockOFClient.EXPECT().SendIGMPRemoteReportPacketOut(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	testController.mockOFClient.EXPECT().SendIGMPQueryPacketOut(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	go testController.eventHandler(stopCh)
	for i := 0; i < 2; i++ {
		go wait.Until(testController.worker, time.Second, stopCh)
	}
	wg.Wait()
	assert.Eventually(t, func() bool {
		return len(testController.groupEventCh) == 0 && testController.queue.Len() == 0
	}, time.Second, time.Millisecond*100)
}

func TestRemoteMemberJoinLeave(t *testing.T) {
	testController := newTestMulticastController(t, true, false)
	testController.initialize(t)
	stopCh := make(chan struct{})
	defer close(stopCh)

	stopStr := "done"
	eventHandler := func(stopCh <-chan struct{}) {
		for {
			select {
			case e := <-testController.groupEventCh:
				if e.group.Equal(net.IPv4zero) {
					testController.queue.Add(stopStr)
				} else {
					testController.addOrUpdateGroupEvent(e)
				}
			case <-stopCh:
				return
			}
		}
	}
	go eventHandler(stopCh)

	for _, tc := range []struct {
		name      string
		groupStrs []string
		nodeStr   string
		isJoin    bool
	}{
		{
			name:      "node joins two groups",
			groupStrs: []string{"224.2.100.2", "224.2.100.3"},
			nodeStr:   "10.10.10.11",
			isJoin:    true,
		},
		{
			name:      "node joins one group",
			groupStrs: []string{"224.2.100.3"},
			nodeStr:   "10.10.10.11",
			isJoin:    true,
		},
		{
			name:      "another node joins two groups",
			groupStrs: []string{"224.2.100.2", "224.2.100.5"},
			nodeStr:   "10.10.10.12",
			isJoin:    true,
		},
		{
			name:      "another node leaves group",
			groupStrs: []string{"224.2.100.2"},
			nodeStr:   "10.10.10.12",
			isJoin:    false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			groups := make([]net.IP, len(tc.groupStrs))
			for i, g := range tc.groupStrs {
				groups[i] = net.ParseIP(g)
			}
			node := net.ParseIP(tc.nodeStr)
			testRemoteReport(t, testController, groups, node, tc.isJoin, stopStr)
		})
	}
}

func testRemoteReport(t *testing.T, testController *testMulticastController, groups []net.IP, node net.IP, nodeJoin bool, stopStr string) {
	tunnelPort := uint32(2)
	proto := uint8(protocol.IGMPIsEx)
	if !nodeJoin {
		proto = uint8(protocol.IGMPToIn)
	}
	for _, g := range groups {
		var exists bool
		obj, exists, _ := testController.groupCache.GetByKey(g.String())
		if !exists {
			testController.mockOFClient.EXPECT().InstallMulticastFlows(gomock.Any(), gomock.Any())
		} else {
			status := obj.(*GroupMemberStatus)
			exists = status.remoteMembers.Has(node.String())
			if nodeJoin && exists || !nodeJoin && !exists {
				continue
			}
		}
		testController.mockOFClient.EXPECT().InstallMulticastGroup(gomock.Any(), []uint32{config.DefaultHostGatewayOFPort}, gomock.Any())
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		processNextItem(t, testController, stopStr)
		wg.Done()
	}()

	err := processRemoteReport(t, testController, groups, node, proto, tunnelPort)
	assert.NoError(t, err)
	testController.groupEventCh <- &mcastGroupEvent{group: net.IPv4zero}
	wg.Wait()

	for _, g := range groups {
		obj, exists, _ := testController.groupCache.GetByKey(g.String())
		assert.True(t, exists)
		status := obj.(*GroupMemberStatus)
		if nodeJoin {
			assert.True(t, status.remoteMembers.Has(node.String()))
		} else {
			assert.False(t, status.remoteMembers.Has(node.String()))
		}
	}
	for _, g := range groups {
		assert.True(t, testController.groupHasInstalled(g.String()))
	}
}

func processNextItem(t *testing.T, testController *testMulticastController, stopStr string) {
	for {
		key, quit := testController.queue.Get()
		if quit {
			return
		}
		if key == stopStr {
			testController.queue.Forget(key)
			testController.queue.Done(key)
			return
		}
		if err := testController.syncGroup(key); err != nil {
			t.Errorf("Failed to process %s: %v", key, err)
		}
		testController.queue.Forget(key)
		testController.queue.Done(key)
	}
}

func processRemoteReport(t *testing.T, testController *testMulticastController, groups []net.IP, remoteNode net.IP, reportType uint8, tunnelPort uint32) error {
	pkt := generatePacketInForRemoteReport(t, testController.igmpSnooper, groups, remoteNode, reportType, tunnelPort)
	testController.mockIfaceStore.EXPECT().GetInterfaceByOFPort(tunnelPort).Return(createTunnelInterface(tunnelPort, nodeIf1IP), true)
	return testController.igmpSnooper.HandlePacketIn(&pkt)
}

func compareGroupStatus(t *testing.T, cache cache.Indexer, event *mcastGroupEvent) {
	obj, exits, err := cache.GetByKey(event.group.String())
	assert.NoError(t, err)
	assert.Truef(t, exits, "failed to add group to cache")
	status, ok := obj.(*GroupMemberStatus)
	assert.Equal(t, true, ok)
	assert.Equal(t, event.group, status.group)
	if event.eType == groupJoin {
		_, exists := status.localMembers[event.iface.InterfaceName]
		assert.Truef(t, exists, "member is not added into cache")
	} else {
		_, exists := status.localMembers[event.iface.InterfaceName]
		assert.Falsef(t, exists, "member is not removed from cache")
	}
}

type testMulticastController struct {
	*Controller
	mockCtrl               *gomock.Controller
	mockOFClient           *openflowtest.MockClient
	mockMulticastSocket    *multicasttest.MockRouteInterface
	mockIfaceStore         *ifaceStoretest.MockInterfaceStore
	mockMulticastValidator *typestest.MockMcastNetworkPolicyController
	clientset              *fake.Clientset
	informerFactory        informers.SharedInformerFactory
}

func newTestMulticastController(t *testing.T, isEncap bool, enableFlexibleIPAM bool) *testMulticastController {
	ctrl := gomock.NewController(t)
	mockOFClient := openflowtest.NewMockClient(ctrl)
	mockIfaceStore := ifaceStoretest.NewMockInterfaceStore(ctrl)
	mockMulticastSocket := multicasttest.NewMockRouteInterface(ctrl)
	mockMulticastValidator := typestest.NewMockMcastNetworkPolicyController(ctrl)
	addr := &net.IPNet{IP: nodeIf1IP, Mask: net.IPv4Mask(255, 255, 255, 0)}
	nodeConfig := &config.NodeConfig{
		GatewayConfig: &config.GatewayConfig{Name: "antrea-gw0", OFPort: config.DefaultHostGatewayOFPort},
		NodeIPv4Addr:  addr,
	}
	if enableFlexibleIPAM {
		// These ofPort numbers are required to configure Multicast Group member ports.
		nodeConfig.UplinkNetConfig = &config.AdapterNetConfig{
			OFPort: config.DefaultUplinkOFPort,
		}
		nodeConfig.HostInterfaceOFPort = config.DefaultHostInterfaceOFPort
	}
	mockOFClient.EXPECT().RegisterPacketInHandler(gomock.Any(), gomock.Any()).Times(1)
	groupAllocator := openflow.NewGroupAllocator()
	podUpdateSubscriber := channel.NewSubscribableChannel("PodUpdate", 100)

	clientset := fake.NewSimpleClientset()
	informerFactory := informers.NewSharedInformerFactory(clientset, 12*time.Hour)
	nodeInformer := informerFactory.Core().V1().Nodes()
	testController := NewMulticastController(mockOFClient, groupAllocator, nodeConfig, mockIfaceStore, mockMulticastSocket, sets.New[string](), podUpdateSubscriber, time.Second*5, igmpQueryVersions, mockMulticastValidator, isEncap, nodeInformer, enableFlexibleIPAM, true, false)
	return &testMulticastController{
		Controller:             testController,
		mockCtrl:               ctrl,
		mockOFClient:           mockOFClient,
		mockMulticastSocket:    mockMulticastSocket,
		mockIfaceStore:         mockIfaceStore,
		mockMulticastValidator: mockMulticastValidator,
		clientset:              clientset,
		informerFactory:        informerFactory,
	}
}

func TestFlexibleIPAMModeInitialize(t *testing.T) {
	testController := newTestMulticastController(t, false, true)
	testController.initialize(t)
}

func TestMulticastControllerOnIPv6Cluster(t *testing.T) {
	for _, tc := range []struct {
		name        string
		ipv4Enabled bool
		ipv6Enabled bool
		expErr      string
	}{
		{
			name:        "Fails on IPv6-only cluster",
			ipv4Enabled: false,
			ipv6Enabled: true,
			expErr:      "Multicast is not supported on an IPv6-only cluster",
		},
		{
			name:        "Succeeds on dual-stack cluster",
			ipv4Enabled: true,
			ipv6Enabled: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testController := newTestMulticastController(t, true, false)
			testController.ipv4Enabled = tc.ipv4Enabled
			testController.ipv6Enabled = tc.ipv6Enabled
			if tc.expErr == "" {
				testController.initMocks()
			}
			err := testController.Initialize()
			if tc.expErr != "" {
				assert.EqualError(t, err, tc.expErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func (c *testMulticastController) initialize(t *testing.T) {
	c.initMocks()
	require.NoError(t, c.Initialize())
	require.True(t, c.mockCtrl.Satisfied())
}

func (c *testMulticastController) initMocks() {
	c.mockOFClient.EXPECT().InstallMulticastGroup(c.queryGroupId, gomock.Any(), gomock.Any()).Times(1)
	c.mockOFClient.EXPECT().InstallMulticastFlows(gomock.Any(), gomock.Any())
	c.mockIfaceStore.EXPECT().GetInterfacesByType(interfacestore.InterfaceType(0)).Times(1).Return([]*interfacestore.InterfaceConfig{})
	c.mockMulticastSocket.EXPECT().AllocateVIFs(gomock.Any(), uint16(0)).Times(1).Return([]uint16{0}, nil)
	c.mockMulticastSocket.EXPECT().AllocateVIFs(gomock.Any(), uint16(1)).Times(1).Return([]uint16{1, 2}, nil)
	if c.encapEnabled {
		c.mockOFClient.EXPECT().InstallMulticastGroup(c.nodeGroupID, gomock.Any(), gomock.Any()).Times(1)
		c.mockOFClient.EXPECT().InstallMulticastRemoteReportFlows(c.nodeGroupID).Times(1)
	}
	if c.flexibleIPAMEnabled {
		c.mockOFClient.EXPECT().InstallMulticastFlexibleIPAMFlows().Times(1)
	}
}

func createInterface(name string, ofport uint32) *interfacestore.InterfaceConfig {
	return &interfacestore.InterfaceConfig{
		InterfaceName: name,
		Type:          interfacestore.ContainerInterface,
		OVSPortConfig: &interfacestore.OVSPortConfig{
			OFPort: int32(ofport),
		},
		ContainerInterfaceConfig: &interfacestore.ContainerInterfaceConfig{
			PodName: name,
		},
	}
}

func createIGMPReportPacketIn(joinedGroups []net.IP, leftGroups []net.IP, version uint8, ofport uint32) []*ofctrl.PacketIn {
	joinMessages := createIGMPJoinMessage(joinedGroups, version)
	leaveMessages := createIGMPLeaveMessage(leftGroups, version)
	pkts := make([]*ofctrl.PacketIn, 0)
	for _, m := range joinMessages {
		pkt := generatePacketWithMatches(m, ofport, nil, []openflow15.MatchField{*openflow15.NewInPortField(ofport)})
		pkts = append(pkts, &pkt)
	}
	for _, m := range leaveMessages {
		pkt := generatePacketWithMatches(m, ofport, nil, []openflow15.MatchField{*openflow15.NewInPortField(ofport)})
		pkts = append(pkts, &pkt)
	}
	return pkts
}

func createIGMPLeaveMessage(groups []net.IP, version uint8) []util.Message {
	pkts := make([]util.Message, 0)
	switch version {
	case 2:
		for i := range groups {
			pkts = append(pkts, protocol.NewIGMPv2Leave(groups[i]))
		}
		return pkts
	case 3:
		records := make([]protocol.IGMPv3GroupRecord, 0)
		for _, g := range groups {
			records = append(records, protocol.NewGroupRecord(protocol.IGMPIsIn, g, nil))
		}
		pkts = append(pkts, protocol.NewIGMPv3Report(records))
	}
	return pkts
}

func createIGMPJoinMessage(groups []net.IP, version uint8) []util.Message {
	pkts := make([]util.Message, 0)
	switch version {
	case 1:
		for i := range groups {
			pkts = append(pkts, protocol.NewIGMPv1Report(groups[i]))
		}
	case 2:
		for i := range groups {
			pkts = append(pkts, protocol.NewIGMPv2Report(groups[i]))
		}
	case 3:
		records := make([]protocol.IGMPv3GroupRecord, 0)
		for _, g := range groups {
			records = append(records, protocol.NewGroupRecord(protocol.IGMPIsEx, g, nil))
		}
		pkts = append(pkts, protocol.NewIGMPv3Report(records))
	}
	return pkts
}

func mockIgmpMaxResponseTime(t *testing.T) {
	originalMaxResponseTime := igmpMaxResponseTime
	igmpMaxResponseTime = -1
	t.Cleanup(func() {
		igmpMaxResponseTime = originalMaxResponseTime
	})
}
