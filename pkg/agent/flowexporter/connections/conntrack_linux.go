// +build linux

package connections

import (
	"net"

	"github.com/ti-mo/conntrack"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/flowexporter"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
)

var _ ConnTrackPoller = new(connTrackPoller)

type connTrackPoller struct {
	nodeConfig  *config.NodeConfig
	serviceCIDR *net.IPNet
	conntrack   ConnTrack
}

func NewConnTrackPoller(nodeConfig *config.NodeConfig, serviceCIDR *net.IPNet, conntrack ConnTrack) *connTrackPoller {
	return &connTrackPoller{
		nodeConfig,
		serviceCIDR,
		conntrack,
	}
}

// DumpFlows opens netlink connection and dumps all the flows in Antrea ZoneID
// of conntrack table, i.e., corresponding to Antrea OVS bridge.
func (cp *connTrackPoller) DumpFlows(zoneFilter uint16) ([]*flowexporter.Connection, error) {
	// Get netlink Connection to netfilter
	err := cp.conntrack.Dial()
	if err != nil {
		klog.Errorf("Error when getting netlink conn: %v", err)
		return nil, err
	}

	// ZoneID filter is not supported currently in tl-mo/conntrack library.
	// Link to issue: https://github.com/ti-mo/conntrack/issues/23
	// Dump all flows in the conntrack table for now.
	conns, err := cp.conntrack.DumpFilter(conntrack.Filter{})
	if err != nil {
		klog.Errorf("Error when dumping flows from conntrack: %v", err)
		return nil, err
	}

	filteredConns := make([]*flowexporter.Connection, 0, len(conns))
	for _, conn := range conns {
		if conn.Zone != openflow.CtZone {
			continue
		}
		srcIP := conn.TupleOrig.IP.SourceAddress
		dstIP := conn.TupleReply.IP.SourceAddress
		// Only get Pod-to-Pod flows. Pod-to-ExternalService flows are ignored for now.
		if srcIP.Equal(cp.nodeConfig.GatewayConfig.IP) || dstIP.Equal(cp.nodeConfig.GatewayConfig.IP) {
			continue
		}

		// Pod-to-Service flows w/ kube-proxy: There are two conntrack flows for every Pod-to-Service flow.
		// One is with ClusterIP as source or destination, where other IP is podIP. Second conntrack flow is
		// with resolved Endpoint Pod IP corresponding to ClusterIP. Both conntrack flows have same stats, which makes them duplicate.
		// Ideally, we have to correlate these two connections and maintain one connection with both Endpoint Pod IP and ClusterIP.
		// To do the correlation, we need ClusterIP-to-EndpointIP mapping info, which is not available at Agent.
		// Therefore, we ignore the connection with ClusterIP and keep the connection with Endpoint Pod IP.
		// Conntrack flows will be different for Pod-to-Service flows w/ Antrea-proxy. This implementation will be simpler, when the
		// Antrea proxy is supported.
		if cp.serviceCIDR.Contains(srcIP) || cp.serviceCIDR.Contains(dstIP) {
			continue
		}
		filteredConns = append(filteredConns, createAntreaConn(&conn))
	}

	klog.V(2).Infof("Finished poll cycle -- total flows: %d flows in Antrea zoneID: %d", len(conns), len(filteredConns))

	return filteredConns, nil
}

// ConnTrack is an interface created to consume the required functions from the third party
// conntrack library. This is helpful in writing unit tests.
var _ ConnTrack = new(connTrack)

type ConnTrack interface {
	Dial() error
	DumpFilter(filter conntrack.Filter) ([]conntrack.Flow, error)
}

type connTrack struct {
	netlinkConn *conntrack.Conn
}

func NewConnTrack() *connTrack {
	return &connTrack{}
}

func (c *connTrack) Dial() error {
	// Get conntrack in current namespace
	conn, err := conntrack.Dial(nil)
	if err != nil {
		klog.Errorf("Error when dialing conntrack: %v", err)
		return err
	}
	c.netlinkConn = conn
	return nil
}

func (c *connTrack) DumpFilter(filter conntrack.Filter) ([]conntrack.Flow, error) {
	conns, err := c.netlinkConn.DumpFilter(filter)
	if err != nil {
		klog.Errorf("Error when dumping flows from conntrack: %v", err)
		return nil, err
	}
	return conns, nil
}

func createAntreaConn(conn *conntrack.Flow) *flowexporter.Connection {
	tupleOrig := flowexporter.Tuple{
		SourceAddress:      conn.TupleOrig.IP.SourceAddress,
		DestinationAddress: conn.TupleOrig.IP.DestinationAddress,
		Protocol:           conn.TupleOrig.Proto.Protocol,
		SourcePort:         conn.TupleOrig.Proto.SourcePort,
		DestinationPort:    conn.TupleOrig.Proto.DestinationPort,
	}

	tupleReply := flowexporter.Tuple{
		SourceAddress:      conn.TupleReply.IP.SourceAddress,
		DestinationAddress: conn.TupleReply.IP.DestinationAddress,
		Protocol:           conn.TupleReply.Proto.Protocol,
		SourcePort:         conn.TupleReply.Proto.SourcePort,
		DestinationPort:    conn.TupleReply.Proto.DestinationPort,
	}
	// Assign all the applicable fields
	newConn := flowexporter.Connection{
		conn.ID,
		conn.Timeout,
		conn.Timestamp.Start,
		conn.Timestamp.Stop,
		conn.Zone,
		uint32(conn.Status.Value),
		tupleOrig,
		tupleReply,
		conn.CountersOrig.Packets,
		conn.CountersOrig.Bytes,
		conn.CountersReply.Packets,
		conn.CountersReply.Bytes,
		"",
		"",
		"",
		"",
	}

	return &newConn
}
