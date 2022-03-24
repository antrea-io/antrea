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
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
	ifaceStoretest "antrea.io/antrea/pkg/agent/interfacestore/testing"
	multicasttest "antrea.io/antrea/pkg/agent/multicast/testing"
	openflowtest "antrea.io/antrea/pkg/agent/openflow/testing"
	ovsconfigtest "antrea.io/antrea/pkg/ovs/ovsconfig/testing"
)

var (
	mockOFClient        *openflowtest.MockClient
	mockMulticastSocket *multicasttest.MockRouteInterface
	mockIfaceStore      *ifaceStoretest.MockInterfaceStore
	ovsClient           *ovsconfigtest.MockOVSBridgeClient
	mgroup              = net.ParseIP("224.96.1.3")
	if1                 = &interfacestore.InterfaceConfig{
		Type:          interfacestore.ContainerInterface,
		InterfaceName: "if1",
		IPs:           []net.IP{net.ParseIP("192.168.1.1")},
	}
	if2 = &interfacestore.InterfaceConfig{
		Type:          interfacestore.ContainerInterface,
		InterfaceName: "if2",
		IPs:           []net.IP{net.ParseIP("192.168.1.2")},
	}
	nodeIf1IP           = net.ParseIP("192.168.20.22")
	externalInterfaceIP = net.ParseIP("192.168.50.23")
	pktInSrcMAC, _      = net.ParseMAC("11:22:33:44:55:66")
	pktInDstMAC, _      = net.ParseMAC("01:00:5e:00:00:16")
)

func TestAddGroupMemberStatus(t *testing.T) {
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
	mockOFClient.EXPECT().InstallMulticastFlow(mgroup).Times(1)
	mockMulticastSocket.EXPECT().MulticastInterfaceJoinMgroup(mgroup, gomock.Any(), if1.InterfaceName).Times(1)
	err = mctrl.syncGroup(key)
	assert.Nil(t, err)
	mctrl.queue.Forget(obj)
}

func TestUpdateGroupMemberStatus(t *testing.T) {
	mctrl := newMockMulticastController(t)
	err := mctrl.initialize(t)
	assert.Nil(t, err)
	igmpMaxResponseTime = time.Second * 1
	event := &mcastGroupEvent{
		group: mgroup,
		eType: groupJoin,
		time:  time.Now(),
		iface: if1,
	}
	mctrl.addGroupMemberStatus(event)
	obj, _, _ := mctrl.groupCache.GetByKey(event.group.String())
	mockOFClient.EXPECT().SendIGMPQueryPacketOut(igmpQueryDstMac, mcastAllHosts, uint32(openflow13.P_NORMAL), gomock.Any()).Times(len(queryVersions))
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
	go mockController.eventHandler(stopCh)

	getIPs := func(ipStrs []string) []net.IP {
		ips := make([]net.IP, len(ipStrs))
		for i := range ipStrs {
			ips[i] = net.ParseIP(ipStrs[i])
		}
		return ips
	}
	for _, tc := range []struct {
		iface        *interfacestore.InterfaceConfig
		version      uint8
		joinedGroups sets.String
		leftGroups   sets.String
	}{
		{
			iface:        createInterface("p1", 1),
			joinedGroups: sets.NewString("224.1.101.2", "224.1.101.3", "224.1.101.4"),
			leftGroups:   sets.NewString(),
			version:      1,
		},
		{
			iface:        createInterface("p2", 2),
			joinedGroups: sets.NewString("224.1.102.2", "224.1.102.3", "224.1.102.4"),
			leftGroups:   sets.NewString("224.1.102.3"),
			version:      2,
		},
		{
			iface:        createInterface("p3", 3),
			joinedGroups: sets.NewString("224.1.103.2", "224.1.103.3", "224.1.103.4"),
			leftGroups:   sets.NewString("224.1.103.2"),
			version:      3,
		},
	} {
		packets := createIGMPReportPacketIn(getIPs(tc.joinedGroups.List()), getIPs(tc.leftGroups.List()), tc.version, uint32(tc.iface.OFPort))
		mockOFClient.EXPECT().SendIGMPQueryPacketOut(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
		for _, pkt := range packets {
			mockIfaceStore.EXPECT().GetInterfaceByOFPort(uint32(tc.iface.OFPort)).Return(tc.iface, true)
			err := snooper.processPacketIn(pkt)
			assert.Nil(t, err)
		}
		time.Sleep(time.Second)
		expGroups := tc.joinedGroups.Difference(tc.leftGroups)
		statuses := mockController.getGroupMemberStatusesByPod(tc.iface.InterfaceName)
		assert.Equal(t, expGroups.Len(), len(statuses))
		for _, s := range statuses {
			assert.True(t, expGroups.Has(s.group.String()))
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
	mockMulticastSocket = multicasttest.NewMockRouteInterface(controller)
	ovsClient = ovsconfigtest.NewMockOVSBridgeClient(controller)
	addr := &net.IPNet{IP: nodeIf1IP, Mask: net.IPv4Mask(255, 255, 255, 0)}
	nodeConfig := &config.NodeConfig{GatewayConfig: &config.GatewayConfig{Name: "antrea-gw0"}, NodeIPv4Addr: addr}
	mockOFClient.EXPECT().RegisterPacketInHandler(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	mctrl := NewMulticastController(mockOFClient, nodeConfig, mockIfaceStore, mockMulticastSocket, sets.NewString(), ovsClient)
	return mctrl
}

func (c *Controller) initialize(t *testing.T) error {
	ovsClient.EXPECT().SetBridgeMcastSnooping(true).Times(1)
	ovsClient.EXPECT().AddBridgeOtherConfig(map[string]interface{}{"mcast-snooping-disable-flood-unregistered": "true"}).Times(1)
	mockOFClient.EXPECT().InstallMulticastInitialFlows(uint8(0)).Times(1)
	mockMulticastSocket.EXPECT().AllocateVIFs(gomock.Any(), uint16(0), uint16(0)).Times(1).Return([]uint16{0}, []uint16{0}, nil)
	mockMulticastSocket.EXPECT().AllocateVIFs(gomock.Any(), uint16(1), uint16(1)).Times(1).Return([]uint16{1, 2}, []uint16{1, 2}, nil)
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
