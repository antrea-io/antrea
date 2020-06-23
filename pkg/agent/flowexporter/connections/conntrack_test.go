// +build linux

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
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/ti-mo/conntrack"

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/flowexporter"
	connectionstest "github.com/vmware-tanzu/antrea/pkg/agent/flowexporter/connections/testing"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsconfig"
	ovsctltest "github.com/vmware-tanzu/antrea/pkg/ovs/ovsctl/testing"
)

var (
	tuple3 = flowexporter.Tuple{
		SourceAddress:      net.IP{1, 2, 3, 4},
		DestinationAddress: net.IP{4, 3, 2, 1},
		Protocol:           6,
		SourcePort:         65280,
		DestinationPort:    255,
	}
	revTuple3 = flowexporter.Tuple{
		SourceAddress:      net.IP{4, 3, 2, 1},
		DestinationAddress: net.IP{1, 2, 3, 4},
		Protocol:           6,
		SourcePort:         255,
		DestinationPort:    65280,
	}
	tuple4 = flowexporter.Tuple{
		SourceAddress:      net.IP{5, 6, 7, 8},
		DestinationAddress: net.IP{8, 7, 6, 5},
		Protocol:           6,
		SourcePort:         60001,
		DestinationPort:    200,
	}
	revTuple4 = flowexporter.Tuple{
		SourceAddress:      net.IP{8, 7, 6, 5},
		DestinationAddress: net.IP{5, 6, 7, 8},
		Protocol:           6,
		SourcePort:         200,
		DestinationPort:    60001,
	}
	tuple5 = flowexporter.Tuple{
		SourceAddress:      net.IP{1, 2, 3, 4},
		DestinationAddress: net.IP{100, 50, 25, 5},
		Protocol:           6,
		SourcePort:         60001,
		DestinationPort:    200,
	}
	revTuple5 = flowexporter.Tuple{
		SourceAddress:      net.IP{100, 50, 25, 5},
		DestinationAddress: net.IP{1, 2, 3, 4},
		Protocol:           6,
		SourcePort:         200,
		DestinationPort:    60001,
	}
)

func TestConnTrack_DumpFlows(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	// Create flows to test
	antreaFlow := &flowexporter.Connection{
		TupleOrig:  tuple3,
		TupleReply: revTuple3,
		Zone:       openflow.CtZone,
	}
	antreaServiceFlow := &flowexporter.Connection{
		TupleOrig:  tuple5,
		TupleReply: revTuple5,
		Zone:       openflow.CtZone,
	}
	antreaGWFlow := &flowexporter.Connection{
		TupleOrig:  tuple4,
		TupleReply: revTuple4,
		Zone:       openflow.CtZone,
	}
	nonAntreaFlow := &flowexporter.Connection{
		TupleOrig:  tuple4,
		TupleReply: revTuple4,
		Zone:       100,
	}

	testFlows := []*flowexporter.Connection{antreaFlow, antreaServiceFlow, antreaGWFlow, nonAntreaFlow}

	// Create mock interfaces
	mockCTInterfacer := connectionstest.NewMockConnTrackInterfacer(ctrl)
	mockOVSCtlClient := ovsctltest.NewMockOVSCtlClient(ctrl)
	// Create nodeConfig and gateWayConfig
	// Set antreaGWFlow.TupleOrig.IP.DestinationAddress as gateway IP
	gwConfig := &config.GatewayConfig{
		IP: net.IP{8, 7, 6, 5},
	}
	nodeConfig := &config.NodeConfig{
		GatewayConfig: gwConfig,
	}
	// Create serviceCIDR
	serviceCIDR := &net.IPNet{
		IP:   net.IP{100, 50, 25, 0},
		Mask: net.IPMask{255, 255, 255, 0},
	}
	// set expects for mocks
	mockCTInterfacer.EXPECT().GetConnTrack(nil).Return(nil)
	mockCTInterfacer.EXPECT().DumpFilter(conntrack.Filter{}).Return(testFlows, nil)

	connDumper := NewConnTrackDumper(mockCTInterfacer, nodeConfig, serviceCIDR, ovsconfig.OVSDatapathSystem, mockOVSCtlClient)
	conns, err := connDumper.DumpFlows(openflow.CtZone)
	if err != nil {
		t.Errorf("Dump flows function returned error: %v", err)
	}
	assert.Equal(t, 1, len(conns), "number of filtered connections should be equal")
}
