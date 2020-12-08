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

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/flowexporter"
	connectionstest "github.com/vmware-tanzu/antrea/pkg/agent/flowexporter/connections/testing"
	"github.com/vmware-tanzu/antrea/pkg/agent/metrics"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	"github.com/vmware-tanzu/antrea/pkg/agent/util/sysctl"
	ovsctltest "github.com/vmware-tanzu/antrea/pkg/ovs/ovsctl/testing"
)

func TestConnTrackSystem_DumpFlows(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	metrics.InitializeConnectionMetrics()
	// Create flows for test
	tuple, revTuple := makeTuple(&net.IP{1, 2, 3, 4}, &net.IP{4, 3, 2, 1}, 6, 65280, 255)
	antreaFlow := &flowexporter.Connection{
		TupleOrig:  tuple,
		TupleReply: revTuple,
		Zone:       openflow.CtZone,
	}
	tuple, revTuple = makeTuple(&net.IP{1, 2, 3, 4}, &net.IP{100, 50, 25, 5}, 6, 60001, 200)
	antreaServiceFlow := &flowexporter.Connection{
		TupleOrig:  tuple,
		TupleReply: revTuple,
		Zone:       openflow.CtZone,
	}
	tuple, revTuple = makeTuple(&net.IP{5, 6, 7, 8}, &net.IP{8, 7, 6, 5}, 6, 60001, 200)
	antreaGWFlow := &flowexporter.Connection{
		TupleOrig:  tuple,
		TupleReply: revTuple,
		Zone:       openflow.CtZone,
	}
	nonAntreaFlow := &flowexporter.Connection{
		TupleOrig:  tuple,
		TupleReply: revTuple,
		Zone:       100,
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
		"tcp,orig=(src=127.0.0.1,dst=8.7.6.5,sport=45170,dport=2379,packets=80743,bytes=5416239),reply=(src=8.7.6.5,dst=127.0.0.1,sport=2379,dport=45170,packets=63361,bytes=4811261),start=2020-07-24T05:07:01.591,id=462801621,zone=65520,status=SEEN_REPLY|ASSURED|CONFIRMED|SRC_NAT_DONE|DST_NAT_DONE,timeout=86397,protoinfo=(state_orig=ESTABLISHED,state_reply=ESTABLISHED,wscale_orig=7,wscale_reply=7,flags_orig=WINDOW_SCALE|SACK_PERM|MAXACK_SET,flags_reply=WINDOW_SCALE|SACK_PERM|MAXACK_SET)\n" +
		"tcp,orig=(src=100.10.0.105,dst=10.96.0.1,sport=41284,dport=443,packets=343260,bytes=19340621),reply=(src=100.10.0.106,dst=100.10.0.105,sport=6443,dport=41284,packets=381035,bytes=181176472),start=2020-07-25T08:40:08.959,id=982464968,zone=65520,status=SEEN_REPLY|ASSURED|CONFIRMED|DST_NAT|DST_NAT_DONE,timeout=86399,mark=33,protoinfo=(state_orig=ESTABLISHED,state_reply=ESTABLISHED,wscale_orig=7,wscale_reply=7,flags_orig=WINDOW_SCALE|SACK_PERM|MAXACK_SET,flags_reply=WINDOW_SCALE|SACK_PERM|MAXACK_SET)")
	outputFlow := strings.Split(string(ovsctlCmdOutput), "\n")
	expConn := &flowexporter.Connection{
		ID:         982464968,
		Timeout:    86399,
		StartTime:  time.Date(2020, 7, 25, 8, 40, 8, 959000000, time.UTC),
		StopTime:   time.Time{},
		IsActive:   true,
		DoExport:   true,
		Zone:       65520,
		StatusFlag: 302,
		Mark:       0x21,
		TupleOrig: flowexporter.Tuple{
			SourceAddress:      net.ParseIP("100.10.0.105"),
			DestinationAddress: net.ParseIP("10.96.0.1"),
			Protocol:           6,
			SourcePort:         uint16(41284),
			DestinationPort:    uint16(443),
		},
		TupleReply: flowexporter.Tuple{
			SourceAddress:      net.ParseIP("100.10.0.106"),
			DestinationAddress: net.ParseIP("100.10.0.105"),
			Protocol:           6,
			SourcePort:         6443,
			DestinationPort:    41284,
		},
		OriginalPackets:         343260,
		OriginalBytes:           19340621,
		ReversePackets:          381035,
		ReverseBytes:            181176472,
		SourcePodNamespace:      "",
		SourcePodName:           "",
		DestinationPodNamespace: "",
		DestinationPodName:      "",
	}
	mockOVSCtlClient.EXPECT().RunAppctlCmd("dpctl/dump-conntrack", false, "-m", "-s").Return(ovsctlCmdOutput, nil)

	conns, totalConns, err := connDumper.DumpFlows(uint16(openflow.CtZone))
	if err != nil {
		t.Errorf("conntrackNetdev.DumpConnections function returned error: %v", err)
	}
	assert.Equal(t, len(conns), 1)
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
