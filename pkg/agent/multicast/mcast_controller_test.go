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
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
	ifaceStoretest "antrea.io/antrea/pkg/agent/interfacestore/testing"
	openflowtest "antrea.io/antrea/pkg/agent/openflow/testing"
)

var (
	mockOFClient   *openflowtest.MockClient
	mockIfaceStore *ifaceStoretest.MockInterfaceStore
	mgroup         = net.ParseIP("224.96.1.3")
	if1            = &interfacestore.InterfaceConfig{
		Type:          interfacestore.ContainerInterface,
		InterfaceName: "if1",
		IPs:           []net.IP{net.ParseIP("192.168.1.1")},
	}
	if2 = &interfacestore.InterfaceConfig{
		Type:          interfacestore.ContainerInterface,
		InterfaceName: "if2",
		IPs:           []net.IP{net.ParseIP("192.168.1.2")},
	}
)

func TestAddGroupMemberStatus(t *testing.T) {
	event := &mcastGroupEvent{
		group: mgroup,
		eType: groupJoin,
		time:  time.Now(),
		iface: if1,
	}
	mctrl := newMockMulticastController(t)
	mctrl.addGroupMemberStatus(event)
	groupCache := mctrl.groupCache
	compareGroupStatus(t, groupCache, event)
	obj, _ := mctrl.queue.Get()
	key, ok := obj.(string)
	assert.True(t, ok)
	assert.Equal(t, mgroup.String(), key)
	mockOFClient.EXPECT().InstallMulticastFlow(mgroup).Times(1)
	err := mctrl.syncGroup(key)
	assert.Nil(t, err)
	mctrl.queue.Forget(obj)
}

func TestUpdateGroupMemberStatus(t *testing.T) {
	mctrl := newMockMulticastController(t)
	igmpMaxResponseTime = time.Second * 1
	event := &mcastGroupEvent{
		group: mgroup,
		eType: groupJoin,
		time:  time.Now(),
		iface: if1,
	}
	mctrl.addGroupMemberStatus(event)
	obj, _, _ := mctrl.groupCache.GetByKey(event.group.String())
	mockOFClient.EXPECT().SendIGMPQueryPacketOut(igmpQueryDstMac, mcastAllHosts, uint32(openflow13.P_NORMAL), gomock.Any()).Times(1)
	for _, e := range []*mcastGroupEvent{
		{group: mgroup, eType: groupJoin, time: event.time.Add(time.Second * 20), iface: if1},
		{group: mgroup, eType: groupJoin, time: event.time.Add(time.Second * 40), iface: if1},
		{group: mgroup, eType: groupJoin, time: event.time.Add(time.Second * 60), iface: if2},
		{group: mgroup, eType: groupLeave, time: event.time.Add(time.Second * 61), iface: if1},
		{group: mgroup, eType: groupLeave, time: event.time.Add(time.Second * 62), iface: if2},
	} {
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
	testCheckLastMember := func(ev *mcastGroupEvent, expExist bool) {
		status := &GroupMemberStatus{
			localMembers:   sets.NewString(),
			lastIGMPReport: lastProbe,
		}
		if ev != nil {
			status.group = ev.group
		} else {
			status.group = mgroup
		}
		_ = mctrl.groupCache.Add(status)
		mctrl.addInstalledGroup(status.group.String())
		mockOFClient.EXPECT().SendIGMPQueryPacketOut(igmpQueryDstMac, mcastAllHosts, uint32(openflow13.P_NORMAL), gomock.Any()).AnyTimes()
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
	mockOFClient.EXPECT().UninstallMulticastFlow(gomock.Any()).Times(2)
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

	mockOFClient.EXPECT().InstallMulticastInitialFlows(gomock.Any()).Times(1)
	err := mctrl.Initialize()
	assert.Nil(t, err)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		mctrl.worker()
		wg.Done()
	}()

	now := time.Now()
	validGroups := []*GroupMemberStatus{
		{
			group:          net.ParseIP("224.96.1.2"),
			localMembers:   sets.NewString("p1", "p2"),
			lastIGMPReport: now.Add(-queryInterval),
		},
		{
			group:          net.ParseIP("224.96.1.3"),
			localMembers:   sets.NewString(),
			lastIGMPReport: now.Add(-queryInterval),
		},
	}
	staleGroups := []*GroupMemberStatus{
		{
			group:          net.ParseIP("224.96.1.4"),
			localMembers:   sets.NewString("p1", "p3"),
			lastIGMPReport: now.Add(-mcastGroupTimeout - time.Second),
		},
		{
			group:          net.ParseIP("224.96.1.5"),
			localMembers:   sets.NewString(),
			lastIGMPReport: now.Add(-mcastGroupTimeout - time.Second),
		},
	}
	for _, g := range validGroups {
		err := mctrl.groupCache.Add(g)
		assert.Nil(t, err)
		mctrl.addInstalledGroup(g.group.String())
	}
	for _, g := range staleGroups {
		err := mctrl.groupCache.Add(g)
		assert.Nil(t, err)
		mctrl.addInstalledGroup(g.group.String())
	}
	mockOFClient.EXPECT().UninstallMulticastFlow(gomock.Any()).Times(len(staleGroups))
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

func compareGroupStatus(t *testing.T, cache cache.Indexer, event *mcastGroupEvent) {
	obj, exits, err := cache.GetByKey(event.group.String())
	assert.Nil(t, err)
	assert.Truef(t, exits, "failed to add group to cache")
	status, ok := obj.(*GroupMemberStatus)
	assert.Equal(t, true, ok)
	assert.Equal(t, event.group, status.group)
	if event.eType == groupJoin {
		assert.True(t, status.lastIGMPReport.Equal(event.time) || status.lastIGMPReport.After(event.time))
		exists := status.localMembers.Has(event.iface.InterfaceName)
		assert.Truef(t, exists, "member is not added into cache")
	} else {
		assert.True(t, status.lastIGMPReport.Before(event.time))
		exists := status.localMembers.Has(event.iface.InterfaceName)
		assert.Falsef(t, exists, "member is not removed from cache")
	}
}

func newMockMulticastController(t *testing.T) *Controller {
	controller := gomock.NewController(t)
	mockOFClient = openflowtest.NewMockClient(controller)
	mockIfaceStore = ifaceStoretest.NewMockInterfaceStore(controller)
	nodeConfig := &config.NodeConfig{}
	mockOFClient.EXPECT().RegisterPacketInHandler(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	return NewMulticastController(mockOFClient, nodeConfig, mockIfaceStore)
}
