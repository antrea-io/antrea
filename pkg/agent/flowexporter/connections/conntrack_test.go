// +build linux

package connections

import (
	"net"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/ti-mo/conntrack"

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	connectionstest "github.com/vmware-tanzu/antrea/pkg/agent/flowexporter/connections/testing"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
)

var (
	tuple3 = conntrack.Tuple{
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
	revTuple3 = conntrack.Tuple{
		IP: conntrack.IPTuple{
			SourceAddress:      net.IP{4, 3, 2, 1},
			DestinationAddress: net.IP{1, 2, 3, 4},
		},
		Proto: conntrack.ProtoTuple{
			Protocol:        6,
			SourcePort:      255,
			DestinationPort: 65280,
		},
	}
	tuple4 = conntrack.Tuple{
		IP: conntrack.IPTuple{
			SourceAddress:      net.IP{5, 6, 7, 8},
			DestinationAddress: net.IP{8, 7, 6, 5},
		},
		Proto: conntrack.ProtoTuple{
			Protocol:        6,
			SourcePort:      60001,
			DestinationPort: 200,
		},
	}
	revTuple4 = conntrack.Tuple{
		IP: conntrack.IPTuple{
			SourceAddress:      net.IP{8, 7, 6, 5},
			DestinationAddress: net.IP{5, 6, 7, 8},
		},
		Proto: conntrack.ProtoTuple{
			Protocol:        6,
			SourcePort:      200,
			DestinationPort: 60001,
		},
	}
	tuple5 = conntrack.Tuple{
		IP: conntrack.IPTuple{
			SourceAddress:      net.IP{1, 2, 3, 4},
			DestinationAddress: net.IP{100, 50, 25, 5},
		},
		Proto: conntrack.ProtoTuple{
			Protocol:        6,
			SourcePort:      60001,
			DestinationPort: 200,
		},
	}
	revTuple5 = conntrack.Tuple{
		IP: conntrack.IPTuple{
			SourceAddress:      net.IP{100, 50, 25, 5},
			DestinationAddress: net.IP{1, 2, 3, 4},
		},
		Proto: conntrack.ProtoTuple{
			Protocol:        6,
			SourcePort:      200,
			DestinationPort: 60001,
		},
	}
)

func TestConnTrack_DumpFilter(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	// Create flows to test
	antreaFlow := conntrack.Flow{
		TupleOrig:  tuple3,
		TupleReply: revTuple3,
		Zone:       openflow.CtZone,
	}
	antreaServiceFlow := conntrack.Flow{
		TupleOrig:  tuple5,
		TupleReply: revTuple5,
		Zone:       openflow.CtZone,
	}
	antreaGWFlow := conntrack.Flow{
		TupleOrig:  tuple4,
		TupleReply: revTuple4,
		Zone:       openflow.CtZone,
	}
	nonAntreaFlow := conntrack.Flow{
		TupleOrig:  tuple4,
		TupleReply: revTuple4,
		Zone:       100,
	}

	testFlows := []conntrack.Flow{antreaFlow, antreaServiceFlow, antreaGWFlow, nonAntreaFlow}

	// Create mock ConnTrack interface
	mockCT := connectionstest.NewMockConnTrack(ctrl)

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
	mockCT.EXPECT().Dial().Return(nil)
	mockCT.EXPECT().DumpFilter(conntrack.Filter{}).Return(testFlows, nil)

	connTrackPoller := NewConnTrackPoller(nodeConfig, serviceCIDR, mockCT)
	conns, err := connTrackPoller.DumpFlows(openflow.CtZone)
	if err != nil {
		t.Errorf("Dump filter function returned error: %v", err)
	}
	assert.Equal(t, 1, len(conns), "number of filtered connections should be equal")
}
