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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ti-mo/conntrack"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/flowexporter"
	connectionstest "antrea.io/antrea/pkg/agent/flowexporter/connections/testing"
	"antrea.io/antrea/pkg/agent/metrics"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/util/sysctl"
	ovsctltest "antrea.io/antrea/pkg/ovs/ovsctl/testing"
)

var (
	conntrackFlowTuple = conntrack.Tuple{
		IP: conntrack.IPTuple{
			SourceAddress:      net.IP{1, 2, 3, 4},
			DestinationAddress: net.IP{4, 3, 2, 1},
		},
		Proto: conntrack.ProtoTuple{
			Protocol:        6,
			SourcePort:      65280,
			DestinationPort: 255,
		},
	}
)

func TestConnTrackSystem_DumpFlows(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	metrics.InitializeConnectionMetrics()
	// Create flows for test

	tuple := flowexporter.Tuple{SourceAddress: net.IP{1, 2, 3, 4}, DestinationAddress: net.IP{4, 3, 2, 1}, Protocol: 6, SourcePort: 65280, DestinationPort: 255}
	antreaFlow := &flowexporter.Connection{
		FlowKey: tuple,
		Zone:    openflow.CtZone,
	}
	tuple = flowexporter.Tuple{SourceAddress: net.IP{1, 2, 3, 4}, DestinationAddress: net.IP{100, 50, 25, 5}, Protocol: 6, SourcePort: 60001, DestinationPort: 200}
	antreaServiceFlow := &flowexporter.Connection{
		FlowKey: tuple,
		Zone:    openflow.CtZone,
	}
	tuple = flowexporter.Tuple{SourceAddress: net.IP{5, 6, 7, 8}, DestinationAddress: net.IP{8, 7, 6, 5}, Protocol: 6, SourcePort: 60001, DestinationPort: 200}
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
		IPv4: net.IP{8, 7, 6, 5},
	}
	nodeConfig := &config.NodeConfig{
		GatewayConfig: gwConfig,
		PodIPv4CIDR: &net.IPNet{
			IP:   net.IP{1, 2, 3, 0},
			Mask: net.IPMask{255, 255, 255, 0},
		},
	}
	// Create serviceCIDR
	serviceCIDR := &net.IPNet{
		IP:   net.IP{100, 50, 25, 0},
		Mask: net.IPMask{255, 255, 255, 0},
	}
	// Test the DumpFlows implementation of connTrackSystem
	mockNetlinkCT := connectionstest.NewMockNetFilterConnTrack(ctrl)
	connDumperDPSystem := NewConnTrackSystem(nodeConfig, serviceCIDR, nil, false)

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
	defer ctrl.Finish()
	metrics.InitializeConnectionMetrics()

	// Create mock interface
	mockOVSCtlClient := ovsctltest.NewMockOVSCtlClient(ctrl)

	// Create nodeConfig and gateWayConfig
	// Set antreaGWFlow.TupleOrig.IP.DestinationAddress as gateway IP
	gwConfig := &config.GatewayConfig{
		IPv4: net.IP{8, 7, 6, 5},
	}
	nodeConfig := &config.NodeConfig{
		GatewayConfig: gwConfig,
	}
	// Create serviceCIDR
	serviceCIDR := &net.IPNet{
		IP:   net.IP{100, 50, 25, 0},
		Mask: net.IPMask{255, 255, 255, 0},
	}

	connDumper := &connTrackOvsCtl{
		nodeConfig,
		serviceCIDR,
		nil,
		mockOVSCtlClient,
		false,
	}
	// Set expect call for mock ovsCtlClient
	ovsctlCmdOutput := []byte("tcp,orig=(src=127.0.0.1,dst=127.0.0.1,sport=45218,dport=2379,packets=320108,bytes=24615344),reply=(src=127.0.0.1,dst=127.0.0.1,sport=2379,dport=45218,packets=239595,bytes=24347883),start=2020-07-24T05:07:03.998,id=3750535678,status=SEEN_REPLY|ASSURED|CONFIRMED|SRC_NAT_DONE|DST_NAT_DONE,timeout=86399,protoinfo=(state_orig=ESTABLISHED,state_reply=ESTABLISHED,wscale_orig=7,wscale_reply=7,flags_orig=WINDOW_SCALE|SACK_PERM|MAXACK_SET,flags_reply=WINDOW_SCALE|SACK_PERM|MAXACK_SET)\n" +
		"tcp,orig=(src=127.0.0.1,dst=8.7.6.5,sport=45170,dport=2379,packets=80743,bytes=5416239),reply=(src=8.7.6.5,dst=127.0.0.1,sport=2379,dport=45170,packets=63361,bytes=4811261),start=2020-07-24T05:07:01.591,id=462801621,zone=4096,status=SEEN_REPLY|ASSURED|CONFIRMED|SRC_NAT_DONE|DST_NAT_DONE,timeout=86397,protoinfo=(state_orig=ESTABLISHED,state_reply=ESTABLISHED,wscale_orig=7,wscale_reply=7,flags_orig=WINDOW_SCALE|SACK_PERM|MAXACK_SET,flags_reply=WINDOW_SCALE|SACK_PERM|MAXACK_SET)\n" +
		"tcp,orig=(src=100.10.0.105,dst=10.96.0.1,sport=41284,dport=443,packets=343260,bytes=19340621),reply=(src=100.10.0.106,dst=100.10.0.105,sport=6443,dport=41284,packets=381035,bytes=181176472),start=2020-07-25T08:40:08.959,id=982464968,zone=4096,status=SEEN_REPLY|ASSURED|CONFIRMED|DST_NAT|DST_NAT_DONE,timeout=86399,labels=0x200000001,mark=16,protoinfo=(state_orig=ESTABLISHED,state_reply=ESTABLISHED,wscale_orig=7,wscale_reply=7,flags_orig=WINDOW_SCALE|SACK_PERM|MAXACK_SET,flags_reply=WINDOW_SCALE|SACK_PERM|MAXACK_SET)")
	outputFlow := strings.Split(string(ovsctlCmdOutput), "\n")
	expConn := &flowexporter.Connection{
		ID:         982464968,
		Timeout:    86399,
		StartTime:  time.Date(2020, 7, 25, 8, 40, 8, 959000000, time.UTC),
		StopTime:   time.Time{},
		IsPresent:  true,
		Zone:       4096,
		StatusFlag: 302,
		Mark:       openflow.ServiceCTMark.GetValue(),
		FlowKey: flowexporter.Tuple{
			SourceAddress:      net.ParseIP("100.10.0.105"),
			DestinationAddress: net.ParseIP("100.10.0.106"),
			Protocol:           6,
			SourcePort:         uint16(41284),
			DestinationPort:    uint16(6443),
		},
		DestinationServiceAddress: net.ParseIP("10.96.0.1"),
		DestinationServicePort:    uint16(443),
		OriginalPackets:           343260,
		OriginalBytes:             19340621,
		ReversePackets:            381035,
		ReverseBytes:              181176472,
		SourcePodNamespace:        "",
		SourcePodName:             "",
		DestinationPodNamespace:   "",
		DestinationPodName:        "",
		TCPState:                  "ESTABLISHED",
		Labels:                    []byte{1, 0, 0, 0, 2, 0, 0, 0},
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
	connDumperDPSystem := NewConnTrackSystem(&config.NodeConfig{}, &net.IPNet{}, &net.IPNet{}, false)
	maxConns, err := connDumperDPSystem.GetMaxConnections()
	assert.NoErrorf(t, err, "GetMaxConnections function returned error: %v", err)
	expMaxConns, err := sysctl.GetSysctlNet("netfilter/nf_conntrack_max")
	require.NoError(t, err, "Cannot read netfilter/nf_conntrack_max")
	assert.Equal(t, expMaxConns, maxConns, "The return value of GetMaxConnections function should be equal to netfilter/nf_conntrack_max")
}

func TestConnTrackOvsAppCtl_GetMaxConnections(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockOVSCtlClient := ovsctltest.NewMockOVSCtlClient(ctrl)
	// Set expect call of dpctl/ct-get-maxconns for mock ovsCtlClient
	expMaxConns := 300000
	mockOVSCtlClient.EXPECT().RunAppctlCmd("dpctl/ct-get-maxconns", false).Return([]byte(strconv.Itoa(expMaxConns)), nil)
	connDumper := &connTrackOvsCtl{
		&config.NodeConfig{},
		&net.IPNet{},
		&net.IPNet{},
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
		TupleOrig: conntrackFlowTuple, TupleReply: conntrackFlowTuple, TupleMaster: conntrackFlowTuple,
		Timeout: 123, Status: conntrack.Status{Value: conntrack.StatusAssured}, Mark: 0x1234, Zone: 2,
		Timestamp: conntrack.Timestamp{Start: time.Date(2020, 7, 25, 8, 40, 8, 959000000, time.UTC)},
	}
	tuple := flowexporter.Tuple{SourceAddress: conntrackFlowTuple.IP.SourceAddress, DestinationAddress: conntrackFlowTuple.IP.SourceAddress, Protocol: conntrackFlowTuple.Proto.Protocol, SourcePort: conntrackFlowTuple.Proto.SourcePort, DestinationPort: conntrackFlowTuple.Proto.SourcePort}
	expectedAntreaFlow := &flowexporter.Connection{
		Timeout:                   netlinkFlow.Timeout,
		StartTime:                 netlinkFlow.Timestamp.Start,
		IsPresent:                 true,
		Zone:                      2,
		StatusFlag:                0x4,
		Mark:                      0x1234,
		FlowKey:                   tuple,
		DestinationServiceAddress: conntrackFlowTuple.IP.DestinationAddress,
		DestinationServicePort:    conntrackFlowTuple.Proto.DestinationPort,
		OriginalPackets:           netlinkFlow.CountersOrig.Packets,
		OriginalBytes:             netlinkFlow.CountersOrig.Bytes,
		ReversePackets:            netlinkFlow.CountersReply.Packets,
		ReverseBytes:              netlinkFlow.CountersReply.Bytes,
		SourcePodNamespace:        "",
		SourcePodName:             "",
		DestinationPodNamespace:   "",
		DestinationPodName:        "",
		TCPState:                  "",
	}

	antreaFlow := NetlinkFlowToAntreaConnection(netlinkFlow)
	// Just add the stop time directly as it will be set to the time of day at
	// which the function was executed.
	expectedAntreaFlow.StopTime = antreaFlow.StopTime
	assert.Equalf(t, expectedAntreaFlow, antreaFlow, "both flows should be equal")

	// Create new conntrack flow with status set to dying connection.
	netlinkFlow = &conntrack.Flow{
		TupleOrig: conntrackFlowTuple, TupleReply: conntrackFlowTuple, TupleMaster: conntrackFlowTuple,
		Timeout: 123, Status: conntrack.Status{Value: conntrack.StatusAssured | conntrack.StatusDying}, Mark: 0x1234, Zone: 2,
		Timestamp: conntrack.Timestamp{
			Start: time.Date(2020, 7, 25, 8, 40, 8, 959000000, time.UTC),
			Stop:  time.Date(2020, 7, 25, 8, 45, 10, 959683808, time.UTC),
		},
	}
	expectedAntreaFlow = &flowexporter.Connection{
		Timeout:                   netlinkFlow.Timeout,
		StartTime:                 netlinkFlow.Timestamp.Start,
		StopTime:                  netlinkFlow.Timestamp.Stop,
		IsPresent:                 true,
		Zone:                      2,
		StatusFlag:                0x204,
		Mark:                      0x1234,
		FlowKey:                   tuple,
		DestinationServiceAddress: conntrackFlowTuple.IP.DestinationAddress,
		DestinationServicePort:    conntrackFlowTuple.Proto.DestinationPort,
		OriginalPackets:           netlinkFlow.CountersOrig.Packets,
		OriginalBytes:             netlinkFlow.CountersOrig.Bytes,
		ReversePackets:            netlinkFlow.CountersReply.Packets,
		ReverseBytes:              netlinkFlow.CountersReply.Bytes,
		SourcePodNamespace:        "",
		SourcePodName:             "",
		DestinationPodNamespace:   "",
		DestinationPodName:        "",
		TCPState:                  "",
	}

	antreaFlow = NetlinkFlowToAntreaConnection(netlinkFlow)
	assert.Equalf(t, expectedAntreaFlow, antreaFlow, "both flows should be equal")
}
