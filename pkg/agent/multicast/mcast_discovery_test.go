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
	"errors"
	"net"
	"sync"
	"testing"

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/libOpenflow/protocol"
	"antrea.io/libOpenflow/util"
	"antrea.io/ofnet/ofctrl"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	apitypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"

	"antrea.io/antrea/pkg/agent/interfacestore"
	ifaceStoretest "antrea.io/antrea/pkg/agent/interfacestore/testing"
	openflowtest "antrea.io/antrea/pkg/agent/openflow/testing"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
)

var (
	pktInSrcMAC, _ = net.ParseMAC("11:22:33:44:55:66")
	pktInDstMAC, _ = net.ParseMAC("01:00:5e:00:00:16")
)

type snooperValidator struct {
	eventCh          chan *mcastGroupEvent
	groupJoinedNodes map[string]sets.Set[string]
	groupLeftNodes   map[string]sets.Set[string]
}

func (v *snooperValidator) processPackets(expectedPackets int) {
	appendSrcNode := func(groupKey string, groupNodes map[string]sets.Set[string], nodeIP net.IP) map[string]sets.Set[string] {
		_, exists := groupNodes[groupKey]
		if !exists {
			groupNodes[groupKey] = sets.New[string]()
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

func TestCollectStats(t *testing.T) {
	curANNPStats := map[apitypes.UID]map[string]*types.RuleMetric{"annp": {"block10120": {Bytes: 42, Packets: 1}, "allow_1014": {Bytes: 42, Packets: 1}}}
	curACNPStats := map[apitypes.UID]map[string]*types.RuleMetric{"acnp": {"allow_10122": {Bytes: 42, Packets: 1}}}
	snooper := &IGMPSnooper{igmpReportANNPStats: curANNPStats, igmpReportACNPStats: curACNPStats}
	igmpANNPStats, igmpACNPStats := snooper.collectStats()
	assert.Equal(t, curACNPStats, igmpACNPStats)
	assert.Equal(t, curANNPStats, igmpANNPStats)
	assert.Equal(t, map[apitypes.UID]map[string]*types.RuleMetric{}, snooper.igmpReportANNPStats)
	assert.Equal(t, map[apitypes.UID]map[string]*types.RuleMetric{}, snooper.igmpReportACNPStats)
}

func TestParseIGMPPacket(t *testing.T) {
	for _, tc := range []struct {
		name    string
		packet  protocol.Ethernet
		igmpMsg protocol.IGMPMessage
		err     error
	}{
		{
			name: "IPv6 packet",
			packet: protocol.Ethernet{
				Ethertype: protocol.IPv6_MSG,
			},
			err: errors.New("not IPv4 packet"),
		},
		{
			name: "IPv4 packet with wrong data",
			packet: protocol.Ethernet{
				Ethertype: protocol.IPv4_MSG,
				Data:      &protocol.IPv6{},
			},
			err: errors.New("failed to parse IPv4 packet"),
		},
		{
			name: "not IGMP packet",
			packet: protocol.Ethernet{
				Ethertype: protocol.IPv4_MSG,
				Data:      &protocol.IPv4{Protocol: 3},
			},
			err: errors.New("not IGMP packet"),
		},
		{
			name: "wrong IGMP packet",
			packet: protocol.Ethernet{
				Ethertype: protocol.IPv4_MSG,
				Data: &protocol.IPv4{
					Protocol: 2,
					Data:     protocol.NewIGMPv1Report(net.ParseIP("224.3.4.5")),
				},
			},
			err: errors.New("unknown IGMP packet"),
		},
		{
			name: "correct IGMP packet",
			packet: protocol.Ethernet{
				Ethertype: protocol.IPv4_MSG,
				Data: &protocol.IPv4{
					Protocol: 2,
					Data:     protocol.NewIGMPv3Query(net.ParseIP("224.3.4.5"), 3, 10, []net.IP{net.ParseIP("10.3.4.5")}),
				},
			},
			igmpMsg: &protocol.IGMPv3Query{
				Type:                     17,
				MaxResponseTime:          3,
				Checksum:                 0,
				GroupAddress:             net.IP{224, 3, 4, 5},
				Reserved:                 0,
				SuppressRouterProcessing: false,
				RobustnessValue:          0,
				IntervalTime:             10,
				NumberOfSources:          1,
				SourceAddresses:          []net.IP{{10, 3, 4, 5}},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			igmpMsg, err := parseIGMPPacket(tc.packet)
			assert.Equal(t, tc.igmpMsg, igmpMsg)
			assert.Equal(t, tc.err, err)
		})
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
	validateGroupNodes := func(groups []net.IP, expectedNodesIPs []net.IP, testGroupNodes map[string]sets.Set[string]) {
		if len(expectedNodesIPs) == 0 {
			return
		}
		for _, g := range groups {
			expectedNodes := sets.New[string]()
			for _, n := range expectedNodesIPs {
				expectedNodes.Insert(n.String())
			}
			nodes, exists := testGroupNodes[g.String()]
			assert.True(t, exists)
			assert.True(t, nodes.HasAll(sets.List(expectedNodes)...))
		}
	}
	testPacketProcess := func(groups []net.IP, joinedNodes []net.IP, leftNodes []net.IP) {
		validator := snooperValidator{eventCh: eventCh, groupJoinedNodes: make(map[string]sets.Set[string]), groupLeftNodes: make(map[string]sets.Set[string])}
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
			err := snooper.HandlePacketIn(pkt)
			assert.NoError(t, err, "Failed to process IGMP Report message")
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

func generatePacketWithMatches(m util.Message, ofport uint32, srcNodeIP net.IP, matches []openflow15.MatchField) ofctrl.PacketIn {
	pkt := openflow15.NewPacketIn()
	for i := range matches {
		pkt.Match.AddField(matches[i])
	}
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
	return ofctrl.PacketIn{PacketIn: pkt}
}

func generatePacketInForRemoteReport(t *testing.T, snooper *IGMPSnooper, groups []net.IP, srcNode net.IP, igmpMsgType uint8, tunnelPort uint32) ofctrl.PacketIn {
	msg, err := snooper.generateIGMPReportPacket(igmpMsgType, groups)
	assert.NoError(t, err, "Failed to generate IGMP Report message")
	return generatePacketWithMatches(msg, tunnelPort, srcNode, []openflow15.MatchField{*openflow15.NewInPortField(tunnelPort)})
}

func createTunnelInterface(tunnelPort uint32, localNodeIP net.IP) *interfacestore.InterfaceConfig {
	tunnelInterface := interfacestore.NewTunnelInterface("antrea-tun0", ovsconfig.GeneveTunnel, 6081, localNodeIP, false, &interfacestore.OVSPortConfig{OFPort: int32(tunnelPort)})
	return tunnelInterface
}
