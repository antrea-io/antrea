//go:build linux
// +build linux

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
	"net"
	"sync"
	"testing"
	"time"

	"antrea.io/libOpenflow/openflow13"
	"antrea.io/libOpenflow/protocol"
	"antrea.io/libOpenflow/util"
	"antrea.io/ofnet/ofctrl"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	apitypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
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
	mockMulticastValidator *typestest.MockMulticastValidator
	ovsClient              *ovsconfigtest.MockOVSBridgeClient
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
	nodeIf1IP           = net.ParseIP("192.168.20.22")
	externalInterfaceIP = net.ParseIP("192.168.50.23")
	pktInSrcMAC, _      = net.ParseMAC("11:22:33:44:55:66")
	pktInDstMAC, _      = net.ParseMAC("01:00:5e:00:00:16")
)

func TestAddGroupMemberStatus(t *testing.T) {
	mgroup := net.ParseIP("224.96.1.3")
	event := &mcastGroupEvent{
		group: mgroup,
		eType: groupJoin,
		time:  time.Now(),
		iface: if1,
	}
	mctrl := newMockMulticastController(t)
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
	mockOFClient.EXPECT().InstallMulticastGroup(gomock.Any(), gomock.Any())
	mockOFClient.EXPECT().InstallMulticastFlows(mgroup, gomock.Any()).Times(1)
	mockMulticastSocket.EXPECT().MulticastInterfaceJoinMgroup(mgroup.To4(), nodeIf1IP.To4(), if1.InterfaceName).Times(1)
	err = mctrl.syncGroup(key)
	assert.Nil(t, err)
	mctrl.queue.Forget(obj)
}

func TestUpdateGroupMemberStatus(t *testing.T) {
	mctrl := newMockMulticastController(t)
	err := mctrl.initialize(t)
	assert.Nil(t, err)
	igmpMaxResponseTime = time.Second * 1
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
	mctrl := newMockMulticastController(t)
	workerCount = 1
	igmpMaxResponseTime = time.Second * 1
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
	mockOFClient.EXPECT().InstallMulticastGroup(gomock.Any(), gomock.Any()).Times(1)
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
	mctrl := newMockMulticastController(t)
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
	}
	fakePort := int32(1)
	for _, g := range staleGroups {
		err := mctrl.groupCache.Add(g)
		assert.Nil(t, err)
		mctrl.addInstalledGroup(g.group.String())
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
	mockController := newMockMulticastController(t)
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
		joinedGroupItems map[string]types.McastNPValidationItem
		leftGroups       sets.String
		igmpANPStats     map[apitypes.UID]map[string]*types.RuleMetric
		igmpACNPStats    map[apitypes.UID]map[string]*types.RuleMetric
		expGroups        sets.String
	}{
		{
			iface:        createInterface("p1", 1),
			joinedGroups: sets.NewString("224.1.101.2", "224.1.101.3", "224.1.101.4"),
			joinedGroupItems: map[string]types.McastNPValidationItem{
				"224.1.101.2": {
					RuleAction: allow,
					UUID:       "",
					NPType:     nil,
					Name:       "",
				},
				"224.1.101.3": {
					RuleAction: allow,
					UUID:       "",
					NPType:     nil,
					Name:       "",
				},
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
			joinedGroupItems: map[string]types.McastNPValidationItem{
				"224.1.101.20": {
					RuleAction: drop,
					UUID:       "anp",
					NPType:     &anp,
					Name:       "block10120",
				},
				"224.1.101.2": {
					RuleAction: allow,
					UUID:       "",
					NPType:     nil,
					Name:       "",
				},
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
			joinedGroupItems: map[string]types.McastNPValidationItem{
				"224.1.102.2": {
					RuleAction: allow,
					UUID:       "",
					NPType:     nil,
					Name:       "",
				},
				"224.1.102.3": {
					RuleAction: allow,
					UUID:       "",
					NPType:     nil,
					Name:       "",
				},
				"224.1.102.4": {
					RuleAction: allow,
					UUID:       "",
					NPType:     nil,
					Name:       "",
				},
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
			joinedGroupItems: map[string]types.McastNPValidationItem{
				"224.1.102.21": {
					RuleAction: allow,
					UUID:       "",
					NPType:     nil,
					Name:       "",
				},
				"224.1.102.22": {
					RuleAction: allow,
					UUID:       "",
					NPType:     nil,
					Name:       "",
				},
				"224.1.102.23": {
					RuleAction: allow,
					UUID:       "",
					NPType:     nil,
					Name:       "",
				},
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
			joinedGroupItems: map[string]types.McastNPValidationItem{
				"224.1.103.2": {
					RuleAction: allow,
					UUID:       "",
					NPType:     nil,
					Name:       "",
				},
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
				mockMulticastValidator.EXPECT().Validate(tc.iface.InterfaceName, tc.iface.PodNamespace, net.ParseIP(leftGroup).To4(), gomock.Any()).Times(1)
			}
		}
		for _, joinedGroup := range tc.joinedGroups.List() {
			mockMulticastValidator.EXPECT().Validate(tc.iface.InterfaceName, tc.iface.PodNamespace, net.ParseIP(joinedGroup).To4(), gomock.Any()).Return(tc.joinedGroupItems[joinedGroup], nil).Times(1)
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

func newMockMulticastController(t *testing.T) *Controller {
	controller := gomock.NewController(t)
	mockOFClient = openflowtest.NewMockClient(controller)
	mockIfaceStore = ifaceStoretest.NewMockInterfaceStore(controller)
	mockMulticastSocket = multicasttest.NewMockRouteInterface(controller)
	mockMulticastValidator = typestest.NewMockMulticastValidator(controller)
	ovsClient = ovsconfigtest.NewMockOVSBridgeClient(controller)
	addr := &net.IPNet{IP: nodeIf1IP, Mask: net.IPv4Mask(255, 255, 255, 0)}
	nodeConfig := &config.NodeConfig{GatewayConfig: &config.GatewayConfig{Name: "antrea-gw0"}, NodeIPv4Addr: addr}
	mockOFClient.EXPECT().RegisterPacketInHandler(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	groupAllocator := openflow.NewGroupAllocator(false)
	podUpdateSubscriber := channel.NewSubscribableChannel("PodUpdate", 100)
	mctrl := NewMulticastController(mockOFClient, groupAllocator, nodeConfig, mockIfaceStore, mockMulticastSocket, sets.NewString(), ovsClient, podUpdateSubscriber, time.Second*5, mockMulticastValidator)
	return mctrl
}

func (c *Controller) initialize(t *testing.T) error {
	mockOFClient.EXPECT().InstallMulticastInitialFlows(uint8(0)).Times(1)
	mockOFClient.EXPECT().InstallMulticastGroup(gomock.Any(), gomock.Any())
	mockOFClient.EXPECT().InstallMulticastFlows(gomock.Any(), gomock.Any())
	mockIfaceStore.EXPECT().GetInterfacesByType(interfacestore.InterfaceType(0)).Times(1).Return([]*interfacestore.InterfaceConfig{})
	mockMulticastSocket.EXPECT().AllocateVIFs(gomock.Any(), uint16(0)).Times(1).Return([]uint16{0}, nil)
	mockMulticastSocket.EXPECT().AllocateVIFs(gomock.Any(), uint16(1)).Times(1).Return([]uint16{1, 2}, nil)
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
	generatePacket := func(m util.Message) ofctrl.PacketIn {
		pkt := openflow13.NewPacketIn()
		matchInport := openflow13.NewInPortField(ofport)
		pkt.Match.AddField(*matchInport)
		ipPacket := &protocol.IPv4{
			Version:  0x4,
			IHL:      5,
			Protocol: IGMPProtocolNumber,
			Length:   20 + m.Len(),
			Data:     m,
		}
		pkt.Data = protocol.Ethernet{
			HWDst:     pktInDstMAC,
			HWSrc:     pktInSrcMAC,
			Ethertype: protocol.IPv4_MSG,
			Data:      ipPacket,
		}
		return ofctrl.PacketIn(*pkt)
	}
	pkts := make([]*ofctrl.PacketIn, 0)
	for _, m := range joinMessages {
		pkt := generatePacket(m)
		pkts = append(pkts, &pkt)
	}
	for _, m := range leaveMessages {
		pkt := generatePacket(m)
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
