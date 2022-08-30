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
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"antrea.io/libOpenflow/protocol"
	"antrea.io/libOpenflow/util"
	"antrea.io/ofnet/ofctrl"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
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
	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
	ovsconfigtest "antrea.io/antrea/pkg/ovs/ovsconfig/testing"
	"antrea.io/antrea/pkg/util/channel"
)

var (
	mockOFClient           *openflowtest.MockClient
	mockMulticastSocket    *multicasttest.MockRouteInterface
	mockIfaceStore         *ifaceStoretest.MockInterfaceStore
	mockMulticastValidator *typestest.MockMcastNetworkPolicyController
	ovsClient              *ovsconfigtest.MockOVSBridgeClient
	clientset              *fake.Clientset
	informerFactory        informers.SharedInformerFactory
	if1                    = &interfacestore.InterfaceConfig{
		Type:          interfacestore.ContainerInterface,
		InterfaceName: "if1",
		IPs:           []net.IP{net.ParseIP("192.168.1.1")},
		OVSPortConfig: &interfacestore.OVSPortConfig{
			OFPort: 1,
		},
	}
	if2 = &interfacestore.InterfaceConfig{
		Type:          interfacestore.ContainerInterface,
		InterfaceName: "if2",
		IPs:           []net.IP{net.ParseIP("192.168.1.2")},
		OVSPortConfig: &interfacestore.OVSPortConfig{
			OFPort: 2,
		},
	}
	nodeIf1IP = net.ParseIP("192.168.20.22")
)

func TestAddGroupMemberStatus(t *testing.T) {
	mgroup := net.ParseIP("224.96.1.3")
	event := &mcastGroupEvent{
		group: mgroup,
		eType: groupJoin,
		time:  time.Now(),
		iface: if1,
	}
	mctrl := newMockMulticastController(t, false)
	err := mctrl.initialize(t)
	mctrl.mRouteClient.multicastInterfaceConfigs = []multicastInterfaceConfig{
		{Name: if1.InterfaceName, IPv4Addr: &net.IPNet{IP: nodeIf1IP, Mask: net.IPv4Mask(255, 255, 255, 0)}},
	}
	assert.Nil(t, err)
	mctrl.addGroupMemberStatus(event)
	groupCache := mctrl.groupCache
	compareGroupStatus(t, groupCache, event)
	obj, _ := mctrl.queue.Get()
	key, ok := obj.(string)
	assert.True(t, ok)
	assert.Equal(t, mgroup.String(), key)
	mockIfaceStore.EXPECT().GetInterfaceByName(if1.InterfaceName).Return(if1, true)
	mockOFClient.EXPECT().InstallMulticastGroup(gomock.Any(), gomock.Any(), gomock.Any())
	mockOFClient.EXPECT().InstallMulticastFlows(mgroup, gomock.Any()).Times(1)
	mockMulticastSocket.EXPECT().MulticastInterfaceJoinMgroup(mgroup.To4(), nodeIf1IP.To4(), if1.InterfaceName).Times(1)
	err = mctrl.syncGroup(key)
	assert.Nil(t, err)
	mctrl.queue.Forget(obj)
}

func TestUpdateGroupMemberStatus(t *testing.T) {
	mctrl := newMockMulticastController(t, false)
	err := mctrl.initialize(t)
	assert.Nil(t, err)
	mgroup := net.ParseIP("224.96.1.4")
	event := &mcastGroupEvent{
		group: mgroup,
		eType: groupJoin,
		time:  time.Now(),
		iface: if1,
	}
	mctrl.addGroupMemberStatus(event)
	mockOFClient.EXPECT().SendIGMPQueryPacketOut(igmpQueryDstMac, types.McastAllHosts, uint32(0), gomock.Any()).Times(len(queryVersions))
	for _, e := range []*mcastGroupEvent{
		{group: mgroup, eType: groupJoin, time: event.time.Add(time.Second * 20), iface: if1},
		{group: mgroup, eType: groupJoin, time: event.time.Add(time.Second * 40), iface: if1},
		{group: mgroup, eType: groupJoin, time: event.time.Add(time.Second * 60), iface: if2},
		{group: mgroup, eType: groupLeave, time: event.time.Add(time.Second * 61), iface: if1},
		{group: mgroup, eType: groupLeave, time: event.time.Add(time.Second * 62), iface: if2},
	} {
		obj, _, _ := mctrl.groupCache.GetByKey(event.group.String())
		if e.eType == groupLeave {
			mockIfaceStore.EXPECT().GetInterfaceByName(e.iface.InterfaceName).Return(e.iface, true)
		}
		mctrl.updateGroupMemberStatus(obj, e)
		groupCache := mctrl.groupCache
		compareGroupStatus(t, groupCache, e)
		groups := mctrl.getGroupMemberStatusesByPod(e.iface.InterfaceName)
		if e.eType == groupJoin {
			assert.True(t, len(groups) > 0)
		} else {
			assert.True(t, len(groups) == 0)
		}
	}
}

func TestCheckLastMember(t *testing.T) {
	mctrl := newMockMulticastController(t, false)
	workerCount = 1
	lastProbe := time.Now()
	mgroup := net.ParseIP("224.96.1.2")
	testCheckLastMember := func(ev *mcastGroupEvent, expExist bool) {
		status := &GroupMemberStatus{
			localMembers:   map[string]time.Time{},
			lastIGMPReport: lastProbe,
		}
		if ev != nil {
			status.group = ev.group
			if ev.eType == groupLeave {
				mockOFClient.EXPECT().UninstallMulticastGroup(gomock.Any())
				mockOFClient.EXPECT().UninstallMulticastFlows(status.group)
			}
		} else {
			status.group = mgroup
			mockOFClient.EXPECT().UninstallMulticastGroup(gomock.Any())
			mockOFClient.EXPECT().UninstallMulticastFlows(status.group)
		}
		_ = mctrl.groupCache.Add(status)
		mctrl.addInstalledGroup(status.group.String())
		mockOFClient.EXPECT().SendIGMPQueryPacketOut(igmpQueryDstMac, types.McastAllHosts, uint32(0), gomock.Any()).AnyTimes()
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			mctrl.checkLastMember(status.group)
			// Wait igmpMaxResponseTime to ensure the group is added into mctrl.queue.
			time.Sleep(igmpMaxResponseTime)
			wg.Done()
		}()
		if ev != nil {
			mctrl.addOrUpdateGroupEvent(ev)
		}
		wg.Wait()
		obj, _ := mctrl.queue.Get()
		key, ok := obj.(string)
		assert.True(t, ok)
		assert.Equal(t, status.group.String(), key)
		err := mctrl.syncGroup(key)
		assert.Nil(t, err)
		_, exists, err := mctrl.groupCache.GetByKey(key)
		assert.Nil(t, err)
		assert.Equal(t, expExist, exists)
		// Clear cache to avoid affecting the next test.
		if _, ok, _ := mctrl.groupCache.GetByKey(key); ok {
			_ = mctrl.groupCache.Delete(status)
		}
		mctrl.queue.Forget(obj)
	}
	mockIfaceStore.EXPECT().GetInterfaceByName(if1.InterfaceName).Return(if1, true).Times(1)
	mockOFClient.EXPECT().InstallMulticastGroup(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	for _, tc := range []struct {
		ev     *mcastGroupEvent
		exists bool
	}{
		{ev: &mcastGroupEvent{group: net.ParseIP("224.96.1.5"), eType: groupJoin, time: lastProbe.Add(time.Second * 1), iface: if1}, exists: true},
		{ev: &mcastGroupEvent{group: net.ParseIP("224.96.1.6"), eType: groupLeave, time: lastProbe.Add(time.Second * 1), iface: if1}, exists: false},
		{ev: nil, exists: false},
	} {
		testCheckLastMember(tc.ev, tc.exists)
	}
}

func TestClearStaleGroups(t *testing.T) {
	mctrl := newMockMulticastController(t, false)
	workerCount = 1
	err := mctrl.initialize(t)
	assert.Nil(t, err)
	mctrl.mRouteClient.multicastInterfaceConfigs = []multicastInterfaceConfig{
		{Name: if1.InterfaceName, IPv4Addr: &net.IPNet{IP: nodeIf1IP, Mask: net.IPv4Mask(255, 255, 255, 0)}},
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		mctrl.worker()
		wg.Done()
	}()
	now := time.Now()
	validUpdateTime := now.Add(-mctrl.queryInterval)
	validGroups := []*GroupMemberStatus{
		{
			group:          net.ParseIP("224.96.1.2"),
			localMembers:   map[string]time.Time{"p1": now, "p2": validUpdateTime},
			lastIGMPReport: validUpdateTime,
		},
		{
			group:          net.ParseIP("224.96.1.3"),
			localMembers:   map[string]time.Time{"p2": validUpdateTime},
			lastIGMPReport: validUpdateTime,
		},
	}
	staleUpdateTime := now.Add(-mctrl.mcastGroupTimeout - time.Second)
	staleGroups := []*GroupMemberStatus{
		{
			group:          net.ParseIP("224.96.1.4"),
			localMembers:   map[string]time.Time{"p1": staleUpdateTime, "p3": staleUpdateTime},
			lastIGMPReport: staleUpdateTime,
		},
		{
			group:          net.ParseIP("224.96.1.5"),
			localMembers:   map[string]time.Time{},
			lastIGMPReport: staleUpdateTime,
		},
	}
	for _, g := range validGroups {
		err := mctrl.groupCache.Add(g)
		assert.Nil(t, err)
		mctrl.addInstalledGroup(g.group.String())
		mctrl.addInstalledLocalGroup(g.group.String())
	}
	fakePort := int32(1)
	for _, g := range staleGroups {
		err := mctrl.groupCache.Add(g)
		assert.Nil(t, err)
		mctrl.addInstalledGroup(g.group.String())
		mctrl.addInstalledLocalGroup(g.group.String())
		for m := range g.localMembers {
			mockIface := &interfacestore.InterfaceConfig{InterfaceName: m, OVSPortConfig: &interfacestore.OVSPortConfig{OFPort: fakePort}}
			mockIfaceStore.EXPECT().GetInterfaceByName(m).Return(mockIface, true)
			fakePort++
		}
	}
	mockOFClient.EXPECT().UninstallMulticastGroup(gomock.Any()).Times(len(staleGroups))
	mockOFClient.EXPECT().UninstallMulticastFlows(gomock.Any()).Times(len(staleGroups))
	mockMulticastSocket.EXPECT().MulticastInterfaceLeaveMgroup(gomock.Any(), gomock.Any(), gomock.Any()).Times(len(staleGroups))
	mctrl.clearStaleGroups()
	mctrl.queue.ShutDown()
	wg.Wait()
	assert.Equal(t, len(validGroups), len(mctrl.groupCache.List()))
	for _, g := range validGroups {
		_, exists, _ := mctrl.groupCache.GetByKey(g.group.String())
		assert.True(t, exists)
	}
	for _, g := range staleGroups {
		_, exists, _ := mctrl.groupCache.GetByKey(g.group.String())
		assert.False(t, exists)
	}
}

func TestProcessPacketIn(t *testing.T) {
	mockController := newMockMulticastController(t, false)
	snooper := mockController.igmpSnooper
	stopCh := make(chan struct{})
	defer close(stopCh)
	go func() {
		mockController.eventHandler(stopCh)
	}()

	getIPs := func(ipStrs []string) []net.IP {
		ips := make([]net.IP, len(ipStrs))
		for i := range ipStrs {
			ips[i] = net.ParseIP(ipStrs[i])
		}
		return ips
	}
	allow := v1alpha1.RuleActionAllow
	anp := v1beta2.AntreaNetworkPolicy
	acnp := v1beta2.AntreaClusterNetworkPolicy
	drop := v1alpha1.RuleActionDrop
	for _, tc := range []struct {
		iface            *interfacestore.InterfaceConfig
		version          uint8
		joinedGroups     sets.String
		joinedGroupItems map[string]*types.IGMPNPRuleInfo
		leftGroups       sets.String
		igmpANPStats     map[apitypes.UID]map[string]*types.RuleMetric
		igmpACNPStats    map[apitypes.UID]map[string]*types.RuleMetric
		expGroups        sets.String
	}{
		{
			iface:        createInterface("p1", 1),
			joinedGroups: sets.NewString("224.1.101.2", "224.1.101.3", "224.1.101.4"),
			joinedGroupItems: map[string]*types.IGMPNPRuleInfo{
				"224.1.101.2": nil,
				"224.1.101.3": nil,
				"224.1.101.4": {
					RuleAction: allow,
					UUID:       "anp",
					NPType:     &anp,
					Name:       "allow_1014",
				},
			},
			leftGroups:    sets.NewString(),
			expGroups:     sets.NewString("224.1.101.2", "224.1.101.3", "224.1.101.4"),
			igmpANPStats:  map[apitypes.UID]map[string]*types.RuleMetric{"anp": {"allow_1014": {Bytes: 42, Packets: 1}}},
			igmpACNPStats: map[apitypes.UID]map[string]*types.RuleMetric{},
			version:       1,
		},
		{
			iface:        createInterface("p11", 1),
			joinedGroups: sets.NewString("224.1.101.20", "224.1.101.21", "224.1.101.22", "224.1.101.23"),
			joinedGroupItems: map[string]*types.IGMPNPRuleInfo{
				"224.1.101.20": {
					RuleAction: drop,
					UUID:       "anp",
					NPType:     &anp,
					Name:       "block10120",
				},
				"224.1.101.2": nil,
				"224.1.101.22": {
					RuleAction: allow,
					UUID:       "anp",
					NPType:     &anp,
					Name:       "allow_10122",
				},
				"224.1.101.23": {
					RuleAction: allow,
					UUID:       "acnp",
					NPType:     &acnp,
					Name:       "allow_10123",
				},
			},
			igmpANPStats:  map[apitypes.UID]map[string]*types.RuleMetric{"anp": {"allow_10122": {Bytes: 42, Packets: 1}, "block10120": {Bytes: 42, Packets: 1}, "allow_1014": {Bytes: 42, Packets: 1}}},
			igmpACNPStats: map[apitypes.UID]map[string]*types.RuleMetric{"acnp": {"allow_10123": {Packets: 1, Bytes: 42}}},
			expGroups:     sets.NewString("224.1.101.21", "224.1.101.22", "224.1.101.23"),
			version:       1,
		},
		{
			iface:        createInterface("p2", 2),
			joinedGroups: sets.NewString("224.1.102.2", "224.1.102.3", "224.1.102.4"),
			joinedGroupItems: map[string]*types.IGMPNPRuleInfo{
				"224.1.102.2": nil,
				"224.1.102.3": nil,
				"224.1.102.4": nil,
			},
			leftGroups:    sets.NewString("224.1.102.3"),
			igmpANPStats:  map[apitypes.UID]map[string]*types.RuleMetric{"anp": {"allow_10122": {Bytes: 42, Packets: 1}, "block10120": {Bytes: 42, Packets: 1}, "allow_1014": {Bytes: 42, Packets: 1}}},
			igmpACNPStats: map[apitypes.UID]map[string]*types.RuleMetric{"acnp": {"allow_10123": {Packets: 1, Bytes: 42}}},
			expGroups:     sets.NewString("224.1.102.2", "224.1.102.4"),
			version:       2,
		},
		{
			iface:        createInterface("p22", 2),
			joinedGroups: sets.NewString("224.1.102.21", "224.1.102.22", "224.1.102.23", "224.1.102.24"),
			joinedGroupItems: map[string]*types.IGMPNPRuleInfo{
				"224.1.102.21": nil,
				"224.1.102.22": nil,
				"224.1.102.23": nil,
				"224.1.102.24": {
					RuleAction: drop,
					UUID:       "anp",
					NPType:     &anp,
					Name:       "block10120",
				},
			},
			leftGroups:    sets.NewString("224.1.102.23"),
			version:       2,
			igmpANPStats:  map[apitypes.UID]map[string]*types.RuleMetric{"anp": {"allow_10122": {Bytes: 42, Packets: 1}, "block10120": {Bytes: 84, Packets: 2}, "allow_1014": {Bytes: 42, Packets: 1}}},
			igmpACNPStats: map[apitypes.UID]map[string]*types.RuleMetric{"acnp": {"allow_10123": {Packets: 1, Bytes: 42}}},
			expGroups:     sets.NewString("224.1.102.21", "224.1.102.22"),
		},
		{
			iface:        createInterface("p33", 3),
			joinedGroups: sets.NewString("224.1.103.2", "224.1.103.3", "224.1.103.4"),
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
			leftGroups:    sets.NewString("224.1.103.2", "224.1.103.3"),
			igmpANPStats:  map[apitypes.UID]map[string]*types.RuleMetric{"anp": {"allow_10122": {Bytes: 42, Packets: 1}, "block10120": {Bytes: 84, Packets: 2}, "allow_1014": {Bytes: 42, Packets: 1}}},
			igmpACNPStats: map[apitypes.UID]map[string]*types.RuleMetric{"acnp2": {"test": {Packets: 1, Bytes: 58}, "test2": {Packets: 1, Bytes: 66}}, "acnp": {"allow_10123": {Packets: 1, Bytes: 42}}},
			expGroups:     sets.NewString("224.1.103.4"),
			version:       3,
		},
	} {
		mockIfaceStore.EXPECT().GetInterfaceByName(tc.iface.InterfaceName).Return(tc.iface, true).AnyTimes()
		packets := createIGMPReportPacketIn(getIPs(tc.joinedGroups.List()), getIPs(tc.leftGroups.List()), tc.version, uint32(tc.iface.OFPort))
		mockOFClient.EXPECT().SendIGMPQueryPacketOut(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

		if tc.version == 3 {
			for _, leftGroup := range tc.leftGroups.List() {
				mockMulticastValidator.EXPECT().GetIGMPNPRuleInfo(tc.iface.InterfaceName, tc.iface.PodNamespace, net.ParseIP(leftGroup).To4(), gomock.Any()).Times(1)
			}
		}
		for _, joinedGroup := range tc.joinedGroups.List() {
			mockMulticastValidator.EXPECT().GetIGMPNPRuleInfo(tc.iface.InterfaceName, tc.iface.PodNamespace, net.ParseIP(joinedGroup).To4(), gomock.Any()).Return(tc.joinedGroupItems[joinedGroup], nil).Times(1)
		}
		for _, pkt := range packets {
			mockIfaceStore.EXPECT().GetInterfaceByOFPort(uint32(tc.iface.OFPort)).Return(tc.iface, true)
			err := snooper.processPacketIn(pkt)
			assert.Nil(t, err)
		}

		assert.Equal(t, tc.igmpACNPStats, snooper.igmpReportACNPStats)
		assert.Equal(t, tc.igmpANPStats, snooper.igmpReportANPStats)

		time.Sleep(time.Second)
		statuses := mockController.getGroupMemberStatusesByPod(tc.iface.InterfaceName)
		assert.Equal(t, tc.expGroups.Len(), len(statuses))
		for _, s := range statuses {
			assert.True(t, tc.expGroups.Has(s.group.String()))
		}
	}
}

func TestEncapModeInitialize(t *testing.T) {
	mockController := newMockMulticastController(t, true)
	assert.True(t, mockController.nodeGroupID != 0)
	err := mockController.initialize(t)
	assert.Nil(t, err)
}

func TestEncapLocalReportAndNotifyRemote(t *testing.T) {
	mockController := newMockMulticastController(t, true)
	_ = mockController.initialize(t)
	mockController.mRouteClient.multicastInterfaceConfigs = []multicastInterfaceConfig{
		{Name: if1.InterfaceName, IPv4Addr: &net.IPNet{IP: nodeIf1IP, Mask: net.IPv4Mask(255, 255, 255, 0)}},
	}
	stopCh := make(chan struct{})
	defer close(stopCh)

	go wait.Until(mockController.worker, time.Second, stopCh)

	iface1 := createInterface("pod1", 3)
	iface2 := createInterface("pod2", 4)
	mgroup := net.ParseIP("224.2.100.4")
	for _, tc := range []struct {
		e            *mcastGroupEvent
		interfaces   []*interfacestore.InterfaceConfig
		groupChanged bool
		ifaceCheck   bool
	}{
		{e: &mcastGroupEvent{group: mgroup, eType: groupJoin, time: time.Now(), iface: iface1}, interfaces: []*interfacestore.InterfaceConfig{iface1}, groupChanged: true, ifaceCheck: true},
		{e: &mcastGroupEvent{group: mgroup, eType: groupJoin, time: time.Now(), iface: iface1}, interfaces: []*interfacestore.InterfaceConfig{iface1}, groupChanged: false, ifaceCheck: false},
		{e: &mcastGroupEvent{group: mgroup, eType: groupJoin, time: time.Now(), iface: iface2}, interfaces: []*interfacestore.InterfaceConfig{iface1, iface2}, groupChanged: false, ifaceCheck: true},
		{e: &mcastGroupEvent{group: mgroup, eType: groupLeave, time: time.Now(), iface: iface2}, interfaces: []*interfacestore.InterfaceConfig{iface1, iface2}, groupChanged: false, ifaceCheck: true},
		{e: &mcastGroupEvent{group: mgroup, eType: groupLeave, time: time.Now(), iface: iface1}, interfaces: []*interfacestore.InterfaceConfig{iface1}, groupChanged: true, ifaceCheck: true},
	} {
		groupKey := tc.e.group.String()
		if tc.e.eType == groupJoin {
			if tc.groupChanged {
				mockMulticastSocket.EXPECT().MulticastInterfaceJoinMgroup(mgroup.To4(), nodeIf1IP.To4(), if1.InterfaceName).Times(1)
				mockOFClient.EXPECT().SendIGMPRemoteReportPacketOut(igmpReportDstMac, types.IGMPv3Router, gomock.Any())
				mockOFClient.EXPECT().InstallMulticastFlows(mgroup, gomock.Any()).Times(1)
			}
			if tc.ifaceCheck {
				for _, iface := range tc.interfaces {
					mockIfaceStore.EXPECT().GetInterfaceByName(iface.InterfaceName).Return(iface, true)
				}
				mockOFClient.EXPECT().InstallMulticastGroup(gomock.Any(), gomock.Any(), gomock.Any())
			}
		} else {
			if tc.ifaceCheck {
				for _, iface := range tc.interfaces {
					mockIfaceStore.EXPECT().GetInterfaceByName(iface.InterfaceName).Return(iface, true)
				}
				if len(tc.interfaces) == 1 {
					mockOFClient.EXPECT().SendIGMPQueryPacketOut(igmpQueryDstMac, types.McastAllHosts, gomock.Any(), gomock.Any()).AnyTimes()
				}
				if !tc.groupChanged {
					mockOFClient.EXPECT().InstallMulticastGroup(gomock.Any(), gomock.Any(), gomock.Any())
				}
			}
			if tc.groupChanged {
				mockOFClient.EXPECT().UninstallMulticastGroup(gomock.Any())
				mockOFClient.EXPECT().UninstallMulticastFlows(tc.e.group)
				mockMulticastSocket.EXPECT().MulticastInterfaceLeaveMgroup(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
				mockOFClient.EXPECT().SendIGMPRemoteReportPacketOut(igmpReportDstMac, types.IGMPv3Router, gomock.Any())
			}
		}
		mockController.addOrUpdateGroupEvent(tc.e)

		if tc.groupChanged {
			err := wait.PollImmediate(time.Millisecond*100, time.Second*3, func() (done bool, err error) {
				if tc.e.eType == groupJoin {
					return mockController.localGroupHasInstalled(groupKey) && mockController.groupHasInstalled(groupKey), nil
				} else {
					return !mockController.localGroupHasInstalled(groupKey) && !mockController.groupHasInstalled(groupKey), nil
				}
			})
			assert.Nil(t, err)
		} else {
			time.Sleep(time.Millisecond * 200)
		}
	}
}

func TestNodeUpdate(t *testing.T) {
	mockController := newMockMulticastController(t, true)
	stopCh := make(chan struct{})
	defer close(stopCh)
	informerFactory.Start(stopCh)
	informerFactory.WaitForCacheSync(stopCh)
	mockController.addInstalledLocalGroup("224.2.100.1")

	wg := sync.WaitGroup{}
	for _, tc := range []struct {
		addedNodes    map[string]map[string]string
		deletedNodes  []string
		expectedNodes sets.String
	}{
		{
			addedNodes: map[string]map[string]string{
				"n1": {"ip": "10.10.10.11"},
				"n2": {"ip": "10.10.10.12"},
			},
			expectedNodes: sets.NewString("10.10.10.11", "10.10.10.12"),
		},
		{
			addedNodes: map[string]map[string]string{
				"n3": {"ip": "10.10.10.13"},
			},
			expectedNodes: sets.NewString("10.10.10.11", "10.10.10.12", "10.10.10.13"),
		},
		{
			deletedNodes: []string{
				"n1",
			},
			expectedNodes: sets.NewString("10.10.10.12", "10.10.10.13"),
		},
		{
			addedNodes: map[string]map[string]string{
				"n4": {"ip": "10.10.10.14", "label": "10.10.10.24"},
			},
			deletedNodes: []string{
				"n2",
			},
			expectedNodes: sets.NewString("10.10.10.13", "10.10.10.24"),
		},
	} {
		times := len(tc.addedNodes) + len(tc.deletedNodes)
		mockOFClient.EXPECT().InstallMulticastGroup(mockController.nodeGroupID, nil, gomock.Any()).Return(nil).Times(times)
		mockOFClient.EXPECT().SendIGMPRemoteReportPacketOut(igmpReportDstMac, types.IGMPv3Router, gomock.Any()).Times(times)
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
				clientset.CoreV1().Nodes().Create(context.TODO(), node, metav1.CreateOptions{})
				mockController.processNextNodeItem()
			}
			for _, name := range tc.deletedNodes {
				clientset.CoreV1().Nodes().Delete(context.TODO(), name, metav1.DeleteOptions{})
				mockController.processNextNodeItem()
			}
			wg.Done()
		}()

		wg.Wait()
		assert.Equal(t, tc.expectedNodes, mockController.installedNodes, fmt.Sprintf("installedNodes: %v, expectedNodes: %v", mockController.installedNodes, tc.expectedNodes))
	}
}

func TestRemoteMemberJoinLeave(t *testing.T) {
	mockController := newMockMulticastController(t, true)
	_ = mockController.initialize(t)
	stopCh := make(chan struct{})
	defer close(stopCh)

	stopStr := "done"
	eventHandler := func(stopCh <-chan struct{}) {
		for {
			select {
			case e := <-mockController.groupEventCh:
				if e.group.Equal(net.IPv4zero) {
					mockController.queue.Add(stopStr)
				} else {
					mockController.addOrUpdateGroupEvent(e)
				}
			case <-stopCh:
				return
			}
		}
	}
	go eventHandler(stopCh)

	for _, tc := range []struct {
		groupStrs []string
		nodeStr   string
		isJoin    bool
	}{
		{groupStrs: []string{"224.2.100.2", "224.2.100.3"}, nodeStr: "10.10.10.11", isJoin: true},
		{groupStrs: []string{"224.2.100.3"}, nodeStr: "10.10.10.11", isJoin: true},
		{groupStrs: []string{"224.2.100.2", "224.2.100.5"}, nodeStr: "10.10.10.12", isJoin: true},
		{groupStrs: []string{"224.2.100.2"}, nodeStr: "10.10.10.12", isJoin: false},
	} {
		groups := make([]net.IP, len(tc.groupStrs))
		for i, g := range tc.groupStrs {
			groups[i] = net.ParseIP(g)
		}
		node := net.ParseIP(tc.nodeStr)
		testRemoteReport(t, mockController, groups, node, tc.isJoin, stopStr)
	}
}

func testRemoteReport(t *testing.T, mockController *Controller, groups []net.IP, node net.IP, nodeJoin bool, stopStr string) {
	tunnelPort := uint32(2)
	proto := uint8(protocol.IGMPIsEx)
	if !nodeJoin {
		proto = uint8(protocol.IGMPToIn)
	}
	for _, g := range groups {
		var exists bool
		obj, exists, _ := mockController.groupCache.GetByKey(g.String())
		if !exists {
			mockOFClient.EXPECT().InstallMulticastFlows(gomock.Any(), gomock.Any())
		} else {
			status := obj.(*GroupMemberStatus)
			exists = status.remoteMembers.Has(node.String())
			if nodeJoin && exists || !nodeJoin && !exists {
				continue
			}
		}
		mockOFClient.EXPECT().InstallMulticastGroup(gomock.Any(), []uint32{config.HostGatewayOFPort}, gomock.Any())
	}

	processNextItem := func(stopStr string) {
		for {
			obj, quit := mockController.queue.Get()
			if quit {
				return
			}
			key := obj.(string)
			if key == stopStr {
				mockController.queue.Forget(key)
				mockController.queue.Done(obj)
				return
			}
			if err := mockController.syncGroup(key); err != nil {
				t.Errorf("Failed to process %s: %v", key, err)
			}
			mockController.queue.Forget(key)
			mockController.queue.Done(obj)
		}
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		processNextItem(stopStr)
		wg.Done()
	}()

	err := processRemoteReport(t, mockController, groups, node, proto, tunnelPort)
	assert.Nil(t, err)
	mockController.groupEventCh <- &mcastGroupEvent{group: net.IPv4zero}
	wg.Wait()

	for _, g := range groups {
		obj, exists, _ := mockController.groupCache.GetByKey(g.String())
		assert.True(t, exists)
		status := obj.(*GroupMemberStatus)
		if nodeJoin {
			assert.True(t, status.remoteMembers.Has(node.String()))
		} else {
			assert.False(t, status.remoteMembers.Has(node.String()))
		}
	}
	for _, g := range groups {
		assert.True(t, mockController.groupHasInstalled(g.String()))
	}
}

func processRemoteReport(t *testing.T, mockController *Controller, groups []net.IP, remoteNode net.IP, reportType uint8, tunnelPort uint32) error {
	pkt := generatePacketInForRemoteReport(t, mockController.igmpSnooper, groups, remoteNode, reportType, tunnelPort)
	mockIfaceStore.EXPECT().GetInterfaceByOFPort(tunnelPort).Return(createTunnelInterface(tunnelPort, nodeIf1IP), true)
	return mockController.igmpSnooper.processPacketIn(&pkt)
}

func compareGroupStatus(t *testing.T, cache cache.Indexer, event *mcastGroupEvent) {
	obj, exits, err := cache.GetByKey(event.group.String())
	assert.Nil(t, err)
	assert.Truef(t, exits, "failed to add group to cache")
	status, ok := obj.(*GroupMemberStatus)
	assert.Equal(t, true, ok)
	assert.Equal(t, event.group, status.group)
	if event.eType == groupJoin {
		assert.True(t, status.lastIGMPReport.Equal(event.time) || status.lastIGMPReport.After(event.time))
		_, exists := status.localMembers[event.iface.InterfaceName]
		assert.Truef(t, exists, "member is not added into cache")
	} else {
		assert.True(t, status.lastIGMPReport.Before(event.time))
		_, exists := status.localMembers[event.iface.InterfaceName]
		assert.Falsef(t, exists, "member is not removed from cache")
	}
}

func newMockMulticastController(t *testing.T, isEncap bool) *Controller {
	controller := gomock.NewController(t)
	mockOFClient = openflowtest.NewMockClient(controller)
	mockIfaceStore = ifaceStoretest.NewMockInterfaceStore(controller)
	mockMulticastSocket = multicasttest.NewMockRouteInterface(controller)
	mockMulticastValidator = typestest.NewMockMcastNetworkPolicyController(controller)
	ovsClient = ovsconfigtest.NewMockOVSBridgeClient(controller)
	addr := &net.IPNet{IP: nodeIf1IP, Mask: net.IPv4Mask(255, 255, 255, 0)}
	nodeConfig := &config.NodeConfig{GatewayConfig: &config.GatewayConfig{Name: "antrea-gw0"}, NodeIPv4Addr: addr}
	mockOFClient.EXPECT().RegisterPacketInHandler(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	groupAllocator := openflow.NewGroupAllocator(false)
	podUpdateSubscriber := channel.NewSubscribableChannel("PodUpdate", 100)

	clientset = fake.NewSimpleClientset()
	informerFactory = informers.NewSharedInformerFactory(clientset, 12*time.Hour)
	mctrl := NewMulticastController(mockOFClient, groupAllocator, nodeConfig, mockIfaceStore, mockMulticastSocket, sets.NewString(), ovsClient, podUpdateSubscriber, time.Second*5, mockMulticastValidator, isEncap, informerFactory)
	return mctrl
}

func (c *Controller) initialize(t *testing.T) error {
	mockOFClient.EXPECT().InstallMulticastInitialFlows(uint8(0)).Times(1)
	mockOFClient.EXPECT().InstallMulticastGroup(c.queryGroupId, gomock.Any(), gomock.Any()).Times(1)
	mockOFClient.EXPECT().InstallMulticastFlows(gomock.Any(), gomock.Any())
	mockIfaceStore.EXPECT().GetInterfacesByType(interfacestore.InterfaceType(0)).Times(1).Return([]*interfacestore.InterfaceConfig{})
	mockMulticastSocket.EXPECT().AllocateVIFs(gomock.Any(), uint16(0)).Times(1).Return([]uint16{0}, nil)
	mockMulticastSocket.EXPECT().AllocateVIFs(gomock.Any(), uint16(1)).Times(1).Return([]uint16{1, 2}, nil)
	if c.encapEnabled {
		mockOFClient.EXPECT().InstallMulticastGroup(c.nodeGroupID, gomock.Any(), gomock.Any()).Times(1)
		mockOFClient.EXPECT().InstallMulticastRemoteReportFlows(c.nodeGroupID).Times(1)
	}
	return c.Initialize()
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
		pkt := generatePacket(m, ofport, nil)
		pkts = append(pkts, &pkt)
	}
	for _, m := range leaveMessages {
		pkt := generatePacket(m, ofport, nil)
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

func TestMain(m *testing.M) {
	igmpMaxResponseTime = time.Second
	os.Exit(m.Run())
}
