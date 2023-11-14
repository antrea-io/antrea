// Copyright 2020 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package connections

import (
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ti-mo/conntrack"
	"go.uber.org/mock/gomock"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/flowexporter"
	connectionstest "antrea.io/antrea/pkg/agent/flowexporter/connections/testing"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/util/sysctl"
	ovsctltest "antrea.io/antrea/pkg/ovs/ovsctl/testing"
)

var (
	srcAddr       = netip.MustParseAddr("1.2.3.4")
	dstAddr       = netip.MustParseAddr("4.3.2.1")
	svcAddr       = netip.MustParseAddr("100.50.25.5")
	gwAddr        = netip.MustParseAddr("8.7.6.5")
	_, podCIDR, _ = net.ParseCIDR("1.2.3.0/24")
	svcCIDR       = netip.MustParsePrefix("100.50.25.0/24")

	conntrackFlowTuple = conntrack.Tuple{
		IP: conntrack.IPTuple{
			SourceAddress:      srcAddr,
			DestinationAddress: dstAddr,
		},
		Proto: conntrack.ProtoTuple{
			Protocol:        6,
			SourcePort:      65280,
			DestinationPort: 255,
		},
	}
	conntrackFlowTupleReply = conntrack.Tuple{
		IP: conntrack.IPTuple{
			SourceAddress:      dstAddr,
			DestinationAddress: srcAddr,
		},
		Proto: conntrack.ProtoTuple{
			Protocol:        6,
			SourcePort:      255,
			DestinationPort: 65280,
		},
	}
)

func TestConnTrackSystem_DumpFlows(t *testing.T) {
	ctrl := gomock.NewController(t)

	// Create flows for test
	tuple := flowexporter.Tuple{SourceAddress: srcAddr, DestinationAddress: dstAddr, Protocol: 6, SourcePort: 65280, DestinationPort: 255}
	antreaFlow := &flowexporter.Connection{
		FlowKey: tuple,
		Zone:    openflow.CtZone,
	}
	tuple = flowexporter.Tuple{SourceAddress: srcAddr, DestinationAddress: svcAddr, Protocol: 6, SourcePort: 60001, DestinationPort: 200}
	antreaServiceFlow := &flowexporter.Connection{
		FlowKey: tuple,
		Zone:    openflow.CtZone,
	}
	tuple = flowexporter.Tuple{SourceAddress: srcAddr, DestinationAddress: gwAddr, Protocol: 6, SourcePort: 60001, DestinationPort: 200}
	antreaGWFlow := &flowexporter.Connection{
		FlowKey: tuple,
		Zone:    openflow.CtZone,
	}
	nonAntreaFlow := &flowexporter.Connection{
		FlowKey: tuple,
		Zone:    100,
	}
	testFlows := []*flowexporter.Connection{antreaFlow, antreaServiceFlow, antreaGWFlow, nonAntreaFlow}

	// Create nodeConfig and gateWayConfig
	// Set antreaGWFlow.TupleOrig.IP.DestinationAddress as gateway IP
	gwConfig := &config.GatewayConfig{
		IPv4: gwAddr.AsSlice(),
	}
	nodeConfig := &config.NodeConfig{
		GatewayConfig: gwConfig,
		PodIPv4CIDR:   podCIDR,
	}
	// Test the DumpFlows implementation of connTrackSystem
	mockNetlinkCT := connectionstest.NewMockNetFilterConnTrack(ctrl)
	connDumperDPSystem := NewConnTrackSystem(nodeConfig, svcCIDR, netip.Prefix{}, false)

	connDumperDPSystem.connTrack = mockNetlinkCT
	// Set expects for mocks
	mockNetlinkCT.EXPECT().Dial().Return(nil)
	mockNetlinkCT.EXPECT().DumpFlowsInCtZone(uint16(openflow.CtZone)).Return(testFlows, nil)

	conns, totalConns, err := connDumperDPSystem.DumpFlows(openflow.CtZone)
	assert.NoErrorf(t, err, "Dump flows function returned error: %v", err)
	assert.Equal(t, 1, len(conns), "number of filtered connections should be equal")
	assert.Equal(t, len(testFlows), totalConns, "Number of connections in conntrack table should be equal to testFlows")
}

func TestConnTrackOvsAppCtl_DumpFlows(t *testing.T) {
	ctrl := gomock.NewController(t)

	// Create mock interface
	mockOVSCtlClient := ovsctltest.NewMockOVSCtlClient(ctrl)

	// Create nodeConfig and gateWayConfig
	// Set antreaGWFlow.TupleOrig.IP.DestinationAddress as gateway IP
	gwConfig := &config.GatewayConfig{
		IPv4: gwAddr.AsSlice(),
	}
	nodeConfig := &config.NodeConfig{
		GatewayConfig: gwConfig,
	}

	connDumper := &connTrackOvsCtl{
		nodeConfig,
		svcCIDR,
		netip.Prefix{},
		mockOVSCtlClient,
		false,
	}
	// Set expect call for mock ovsCtlClient
	ovsctlCmdOutput := []byte("tcp,orig=(src=127.0.0.1,dst=127.0.0.1,sport=45218,dport=2379,packets=320108,bytes=24615344),reply=(src=127.0.0.1,dst=127.0.0.1,sport=2379,dport=45218,packets=239595,bytes=24347883),start=2020-07-24T05:07:03.998,id=3750535678,status=SEEN_REPLY|ASSURED|CONFIRMED|SRC_NAT_DONE|DST_NAT_DONE,timeout=86399,protoinfo=(state_orig=ESTABLISHED,state_reply=ESTABLISHED,wscale_orig=7,wscale_reply=7,flags_orig=WINDOW_SCALE|SACK_PERM|MAXACK_SET,flags_reply=WINDOW_SCALE|SACK_PERM|MAXACK_SET)\n" +
		"tcp,orig=(src=127.0.0.1,dst=8.7.6.5,sport=45170,dport=2379,packets=80743,bytes=5416239),reply=(src=8.7.6.5,dst=127.0.0.1,sport=2379,dport=45170,packets=63361,bytes=4811261),start=2020-07-24T05:07:01.591,id=462801621,zone=65520,status=SEEN_REPLY|ASSURED|CONFIRMED|SRC_NAT_DONE|DST_NAT_DONE,timeout=86397,protoinfo=(state_orig=ESTABLISHED,state_reply=ESTABLISHED,wscale_orig=7,wscale_reply=7,flags_orig=WINDOW_SCALE|SACK_PERM|MAXACK_SET,flags_reply=WINDOW_SCALE|SACK_PERM|MAXACK_SET)\n" +
		"tcp,orig=(src=100.10.0.105,dst=100.50.25.1,sport=41284,dport=443,packets=343260,bytes=19340621),reply=(src=100.10.0.106,dst=100.10.0.105,sport=6443,dport=41284,packets=381035,bytes=181176472),start=2020-07-25T08:40:08.959,id=982464968,zone=65520,status=SEEN_REPLY|ASSURED|CONFIRMED|DST_NAT|DST_NAT_DONE,timeout=86399,labels=0x200000001,mark=16,protoinfo=(state_orig=ESTABLISHED,state_reply=ESTABLISHED,wscale_orig=7,wscale_reply=7,flags_orig=WINDOW_SCALE|SACK_PERM|MAXACK_SET,flags_reply=WINDOW_SCALE|SACK_PERM|MAXACK_SET)")
	outputFlow := strings.Split(string(ovsctlCmdOutput), "\n")
	expConn := &flowexporter.Connection{
		ID:         982464968,
		Timeout:    86399,
		StartTime:  time.Date(2020, 7, 25, 8, 40, 8, 959000000, time.UTC),
		StopTime:   time.Time{},
		IsPresent:  true,
		Zone:       65520,
		StatusFlag: 302,
		Mark:       openflow.ServiceCTMark.GetValue(),
		FlowKey: flowexporter.Tuple{
			SourceAddress:      netip.MustParseAddr("100.10.0.105"),
			DestinationAddress: netip.MustParseAddr("100.10.0.106"),
			Protocol:           6,
			SourcePort:         uint16(41284),
			DestinationPort:    uint16(6443),
		},
		OriginalDestinationAddress: netip.MustParseAddr("100.50.25.1"),
		OriginalDestinationPort:    uint16(443),
		OriginalPackets:            343260,
		OriginalBytes:              19340621,
		ReversePackets:             381035,
		ReverseBytes:               181176472,
		SourcePodNamespace:         "",
		SourcePodName:              "",
		DestinationPodNamespace:    "",
		DestinationPodName:         "",
		TCPState:                   "ESTABLISHED",
		Labels:                     []byte{1, 0, 0, 0, 2, 0, 0, 0},
	}
	mockOVSCtlClient.EXPECT().RunAppctlCmd("dpctl/dump-conntrack", false, "-m", "-s").Return(ovsctlCmdOutput, nil)

	conns, totalConns, err := connDumper.DumpFlows(uint16(openflow.CtZone))
	if err != nil {
		t.Errorf("conntrackNetdev.DumpConnections function returned error: %v", err)
	}
	assert.Equal(t, len(conns), 1)
	// stop time is the current time when the dumped flows are parsed. Therefore,
	// validating is difficult.
	expConn.StopTime = conns[0].StopTime
	assert.Equal(t, conns[0], expConn, "filtered connection and expected connection should be same")
	assert.Equal(t, len(outputFlow), totalConns, "Number of connections in conntrack table should be equal to outputFlow")
}

func TestConnTrackSystem_GetMaxConnections(t *testing.T) {
	connDumperDPSystem := NewConnTrackSystem(&config.NodeConfig{}, netip.Prefix{}, netip.Prefix{}, false)
	maxConns, err := connDumperDPSystem.GetMaxConnections()
	assert.NoErrorf(t, err, "GetMaxConnections function returned error: %v", err)
	expMaxConns, err := sysctl.GetSysctlNet("netfilter/nf_conntrack_max")
	require.NoError(t, err, "Cannot read netfilter/nf_conntrack_max")
	assert.Equal(t, expMaxConns, maxConns, "The return value of GetMaxConnections function should be equal to netfilter/nf_conntrack_max")
}

func TestConnTrackOvsAppCtl_GetMaxConnections(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockOVSCtlClient := ovsctltest.NewMockOVSCtlClient(ctrl)
	// Set expect call of dpctl/ct-get-maxconns for mock ovsCtlClient
	expMaxConns := 300000
	mockOVSCtlClient.EXPECT().RunAppctlCmd("dpctl/ct-get-maxconns", false).Return([]byte(strconv.Itoa(expMaxConns)), nil)
	connDumper := &connTrackOvsCtl{
		&config.NodeConfig{},
		netip.Prefix{},
		netip.Prefix{},
		mockOVSCtlClient,
		false,
	}
	maxConns, err := connDumper.GetMaxConnections()
	assert.NoErrorf(t, err, "GetMaxConnections function returned error: %v", err)
	assert.Equal(t, expMaxConns, maxConns, "The return value of GetMaxConnections function should be equal to the previous hard-coded value")
}

func TestNetLinkFlowToAntreaConnection(t *testing.T) {
	// Create new conntrack flow with status set to assured.
	netlinkFlow := &conntrack.Flow{
		TupleOrig: conntrackFlowTuple, TupleReply: conntrackFlowTupleReply, TupleMaster: conntrackFlowTuple,
		Timeout: 123, Status: conntrack.Status{Value: conntrack.StatusAssured}, Mark: 0x1234, Zone: 2,
		Timestamp: conntrack.Timestamp{Start: time.Date(2020, 7, 25, 8, 40, 8, 959000000, time.UTC)},
	}

	tuple := flowexporter.Tuple{
		SourceAddress:      conntrackFlowTuple.IP.SourceAddress,
		DestinationAddress: conntrackFlowTupleReply.IP.SourceAddress,
		Protocol:           conntrackFlowTuple.Proto.Protocol,
		SourcePort:         conntrackFlowTuple.Proto.SourcePort,
		DestinationPort:    conntrackFlowTupleReply.Proto.SourcePort,
	}
	expectedAntreaFlow := &flowexporter.Connection{
		Timeout:                    netlinkFlow.Timeout,
		StartTime:                  netlinkFlow.Timestamp.Start,
		IsPresent:                  true,
		Zone:                       2,
		StatusFlag:                 0x4,
		Mark:                       0x1234,
		FlowKey:                    tuple,
		OriginalDestinationAddress: conntrackFlowTuple.IP.DestinationAddress,
		OriginalDestinationPort:    conntrackFlowTuple.Proto.DestinationPort,
		OriginalPackets:            netlinkFlow.CountersOrig.Packets,
		OriginalBytes:              netlinkFlow.CountersOrig.Bytes,
		ReversePackets:             netlinkFlow.CountersReply.Packets,
		ReverseBytes:               netlinkFlow.CountersReply.Bytes,
		SourcePodNamespace:         "",
		SourcePodName:              "",
		DestinationPodNamespace:    "",
		DestinationPodName:         "",
		TCPState:                   "",
	}

	antreaFlow := NetlinkFlowToAntreaConnection(netlinkFlow)
	// Just add the stop time directly as it will be set to the time of day at
	// which the function was executed.
	expectedAntreaFlow.StopTime = antreaFlow.StopTime
	assert.Equalf(t, expectedAntreaFlow, antreaFlow, "both flows should be equal")

	// Create new conntrack flow with status set to dying connection.
	netlinkFlow = &conntrack.Flow{
		TupleOrig: conntrackFlowTuple, TupleReply: conntrackFlowTupleReply, TupleMaster: conntrackFlowTuple,
		Timeout: 123, Status: conntrack.Status{Value: conntrack.StatusAssured | conntrack.StatusDying}, Mark: 0x1234, Zone: 2,
		Timestamp: conntrack.Timestamp{
			Start: time.Date(2020, 7, 25, 8, 40, 8, 959000000, time.UTC),
			Stop:  time.Date(2020, 7, 25, 8, 45, 10, 959683808, time.UTC),
		},
	}
	expectedAntreaFlow = &flowexporter.Connection{
		Timeout:                    netlinkFlow.Timeout,
		StartTime:                  netlinkFlow.Timestamp.Start,
		StopTime:                   netlinkFlow.Timestamp.Stop,
		IsPresent:                  true,
		Zone:                       2,
		StatusFlag:                 0x204,
		Mark:                       0x1234,
		FlowKey:                    tuple,
		OriginalDestinationAddress: conntrackFlowTuple.IP.DestinationAddress,
		OriginalDestinationPort:    conntrackFlowTuple.Proto.DestinationPort,
		OriginalPackets:            netlinkFlow.CountersOrig.Packets,
		OriginalBytes:              netlinkFlow.CountersOrig.Bytes,
		ReversePackets:             netlinkFlow.CountersReply.Packets,
		ReverseBytes:               netlinkFlow.CountersReply.Bytes,
		SourcePodNamespace:         "",
		SourcePodName:              "",
		DestinationPodNamespace:    "",
		DestinationPodName:         "",
		TCPState:                   "",
	}

	antreaFlow = NetlinkFlowToAntreaConnection(netlinkFlow)
	assert.Equalf(t, expectedAntreaFlow, antreaFlow, "both flows should be equal")
}

func TestStateToString(t *testing.T) {
	for _, tc := range []struct {
		state          uint8
		expectedResult string
	}{
		{0, "NONE"},
		{1, "SYN_SENT"},
		{2, "SYN_RECV"},
		{3, "ESTABLISHED"},
		{4, "FIN_WAIT"},
		{5, "CLOSE_WAIT"},
		{6, "LAST_ACK"},
		{7, "TIME_WAIT"},
		{8, "CLOSE"},
		{9, "SYN_SENT2"},
	} {
		result := stateToString(tc.state)
		assert.Equal(t, tc.expectedResult, result)
	}
}
