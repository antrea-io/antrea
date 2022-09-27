// Copyright 2022 Antrea Authors
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

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/libOpenflow/protocol"
	"antrea.io/libOpenflow/util"
	"antrea.io/ofnet/ofctrl"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/sets"

	"antrea.io/antrea/pkg/agent/interfacestore"
	ifaceStoretest "antrea.io/antrea/pkg/agent/interfacestore/testing"
	openflowtest "antrea.io/antrea/pkg/agent/openflow/testing"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
)

var (
	pktInSrcMAC, _ = net.ParseMAC("11:22:33:44:55:66")
	pktInDstMAC, _ = net.ParseMAC("01:00:5e:00:00:16")
)

type snooperValidator struct {
	eventCh          chan *mcastGroupEvent
	groupJoinedNodes map[string]sets.String
	groupLeftNodes   map[string]sets.String
}

func (v *snooperValidator) processPackets(expectedPackets int) {
	appendSrcNode := func(groupKey string, groupNodes map[string]sets.String, nodeIP net.IP) map[string]sets.String {
		_, exists := groupNodes[groupKey]
		if !exists {
			groupNodes[groupKey] = sets.NewString()
		}
		groupNodes[groupKey] = groupNodes[groupKey].Insert(nodeIP.String())
		return groupNodes
	}
	for i := 0; i < expectedPackets; i++ {
		select {
		case e := <-v.eventCh:
			groupKey := e.group.String()
			if e.eType == groupJoin {
				v.groupJoinedNodes = appendSrcNode(groupKey, v.groupJoinedNodes, e.srcNode)
			} else {
				v.groupLeftNodes = appendSrcNode(groupKey, v.groupLeftNodes, e.srcNode)
			}
		}
	}
}

func TestIGMPRemoteReport(t *testing.T) {
	controller := gomock.NewController(t)
	mockOFClient := openflowtest.NewMockClient(controller)
	mockIfaceStore := ifaceStoretest.NewMockInterfaceStore(controller)
	eventCh := make(chan *mcastGroupEvent, 100)
	snooper := &IGMPSnooper{ofClient: mockOFClient, eventCh: eventCh, ifaceStore: mockIfaceStore}

	localNodeIP := net.ParseIP("1.2.3.4")
	tunnelPort := uint32(1)
	wg := sync.WaitGroup{}

	generateRemotePackets := func(groups []net.IP, nodes []net.IP, igmpMsgType uint8) []ofctrl.PacketIn {
		packets := make([]ofctrl.PacketIn, 0, len(nodes))
		for _, srcNode := range nodes {
			pkt := generatePacketInForRemoteReport(t, snooper, groups, srcNode, igmpMsgType, tunnelPort)
			packets = append(packets, pkt)
		}
		return packets
	}
	validateGroupNodes := func(groups []net.IP, expectedNodesIPs []net.IP, testGroupNodes map[string]sets.String) {
		if len(expectedNodesIPs) == 0 {
			return
		}
		for _, g := range groups {
			expectedNodes := sets.NewString()
			for _, n := range expectedNodesIPs {
				expectedNodes.Insert(n.String())
			}
			nodes, exists := testGroupNodes[g.String()]
			assert.True(t, exists)
			assert.True(t, nodes.HasAll(expectedNodes.List()...))
		}
	}
	testPacketProcess := func(groups []net.IP, joinedNodes []net.IP, leftNodes []net.IP) {
		validator := snooperValidator{eventCh: eventCh, groupJoinedNodes: make(map[string]sets.String), groupLeftNodes: make(map[string]sets.String)}
		packets := make([]ofctrl.PacketIn, 0, len(joinedNodes)+len(leftNodes))
		packets = append(packets, generateRemotePackets(groups, joinedNodes, protocol.IGMPIsEx)...)
		packets = append(packets, generateRemotePackets(groups, leftNodes, protocol.IGMPToIn)...)

		eventCount := len(groups) * len(packets)
		wg.Add(1)
		go func() {
			validator.processPackets(eventCount)
			wg.Done()
		}()

		mockIfaceStore.EXPECT().GetInterfaceByOFPort(tunnelPort).Return(createTunnelInterface(tunnelPort, localNodeIP), true).Times(len(packets))
		for i := range packets {
			pkt := &packets[i]
			err := snooper.processPacketIn(pkt)
			assert.Nil(t, err, "Failed to process IGMP Report message")
		}

		wg.Wait()

		validateGroupNodes(groups, joinedNodes, validator.groupJoinedNodes)
		validateGroupNodes(groups, leftNodes, validator.groupLeftNodes)
	}

	for _, tc := range []struct {
		groupsStrings      []string
		joinedNodesStrings []string
		leftNodesStrings   []string
	}{
		{groupsStrings: []string{"225.1.2.3", "225.1.2.4"}, joinedNodesStrings: []string{"1.2.3.5", "1.2.3.6"}, leftNodesStrings: []string{"1.2.3.6"}},
		{groupsStrings: []string{"225.1.2.5"}, joinedNodesStrings: []string{"1.2.3.5"}},
		{groupsStrings: []string{"225.1.2.6"}, leftNodesStrings: []string{"1.2.3.6"}},
	} {
		var groups, joinedNodes, leftNodes []net.IP
		for _, g := range tc.groupsStrings {
			groups = append(groups, net.ParseIP(g))
		}
		for _, n := range tc.joinedNodesStrings {
			joinedNodes = append(joinedNodes, net.ParseIP(n))
		}
		for _, n := range tc.leftNodesStrings {
			leftNodes = append(leftNodes, net.ParseIP(n))
		}
		testPacketProcess(groups, joinedNodes, leftNodes)
	}
}

func generatePacket(m util.Message, ofport uint32, srcNodeIP net.IP) ofctrl.PacketIn {
	pkt := openflow15.NewPacketIn()
	matchInport := openflow15.NewInPortField(ofport)
	pkt.Match.AddField(*matchInport)
	if srcNodeIP != nil {
		matchTunSrc := openflow15.NewTunnelIpv4SrcField(srcNodeIP, nil)
		pkt.Match.AddField(*matchTunSrc)
	}
	ipPacket := &protocol.IPv4{
		Version:  0x4,
		IHL:      5,
		Protocol: IGMPProtocolNumber,
		Length:   20 + m.Len(),
		Data:     m,
	}
	ethernetPkt := protocol.NewEthernet()
	ethernetPkt.HWDst = pktInDstMAC
	ethernetPkt.HWSrc = pktInSrcMAC
	ethernetPkt.Ethertype = protocol.IPv4_MSG
	ethernetPkt.Data = ipPacket
	pktBytes, _ := ethernetPkt.MarshalBinary()
	pkt.Data = util.NewBuffer(pktBytes)
	return ofctrl.PacketIn(*pkt)
}

func generatePacketInForRemoteReport(t *testing.T, snooper *IGMPSnooper, groups []net.IP, srcNode net.IP, igmpMsgType uint8, tunnelPort uint32) ofctrl.PacketIn {
	msg, err := snooper.generateIGMPReportPacket(igmpMsgType, groups)
	assert.Nil(t, err, "Failed to generate IGMP Report message")
	return generatePacket(msg, tunnelPort, srcNode)
}

func createTunnelInterface(tunnelPort uint32, localNodeIP net.IP) *interfacestore.InterfaceConfig {
	tunnelInterface := interfacestore.NewTunnelInterface("antrea-tun0", ovsconfig.GeneveTunnel, 6081, localNodeIP, false, &interfacestore.OVSPortConfig{OFPort: int32(tunnelPort)})
	return tunnelInterface
}
