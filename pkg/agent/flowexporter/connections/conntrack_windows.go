// +build windows

package connections

import (
	"net"

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/flowexporter"
)

var _ ConnTrackPoller = new(connTrackPoller)

type connTrackPoller struct {
	nodeConfig *config.NodeConfig
	serviceCIDR *net.IPNet
	conntrack  ConnTrack
}

func NewConnTrackPoller(nodeConfig *config.NodeConfig, serviceCIDR *net.IPNet, conntrack ConnTrack) *connTrackPoller {
	return &connTrackPoller{
		nodeConfig,
		serviceCIDR,
		conntrack,
	}
}

// TODO: These will be defined when polling from ovs-dpctl dump conntrack is supported
var _ ConnTrack = new(connTrack)

type ConnTrack interface{}

type connTrack struct{}

func NewConnTrack() *connTrack {
	return &connTrack{}
}

func (c *connTrackPoller) DumpFlows(zoneFilter uint16) ([]*flowexporter.Connection, error) {
	return nil, nil
}
