//+build linux

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
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/ti-mo/conntrack"
	"k8s.io/klog/v2"

	"github.com/vmware-tanzu/antrea/pkg/agent/flowexporter"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	"github.com/vmware-tanzu/antrea/pkg/agent/util/sysctl"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsconfig"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsctl"
	"github.com/vmware-tanzu/antrea/pkg/util/ip"
)

// DumpFlows opens netlink connection and dumps all the flows in Antrea ZoneID
// of conntrack table, i.e., corresponding to Antrea OVS bridge.
func (ctdump *connTrackDumper) DumpFlows(zoneFilter uint16) ([]*flowexporter.Connection, error) {
if ctdump.datapathType == ovsconfig.OVSDatapathSystem {
		// Get connection to netlink socket
		err := ctdump.connTrack.GetConnTrack(nil)
		if err != nil {
			klog.Errorf("Error when getting netlink conn: %v", err)
			return nil, err
		}
	} else if ctdump.datapathType == ovsconfig.OVSDatapathNetdev {
		// Set ovsCtlClient to dump conntrack flows
		err := ctdump.connTrack.GetConnTrack(ctdump.ovsctlClient)
		if err != nil {
			klog.Errorf("Error when getting ovsclient: %v", err)
			return nil, err
		}
	}

	// ZoneID filter is not supported currently in tl-mo/conntrack library.
	// Link to issue: https://github.com/ti-mo/conntrack/issues/23
	// Dump all flows in the conntrack table for now.
	var conns []*flowexporter.Connection
	var err error
	if ctdump.datapathType == ovsconfig.OVSDatapathSystem {
		conns, err = ctdump.connTrack.DumpFilter(conntrack.Filter{})
		if err != nil {
			klog.Errorf("Error when dumping flows from conntrack: %v", err)
			return nil, err
		}
	} else if ctdump.datapathType == ovsconfig.OVSDatapathNetdev {
		// This is supported for kind clusters. Ovs-appctl access in kind clusters is unstable currently.
		// This will be used once the issue with Ovs-appctl is fixed on kind cluster nodes.
		conns, err = ctdump.connTrack.DumpFilter(uint16(openflow.CtZone))
		if err != nil {
			klog.Errorf("Error when dumping flows from conntrack: %v", err)
			return nil, err
		}
	}

	for i := 0; i < len(conns); i++ {
		if conns[i].Zone != openflow.CtZone {
			// Delete the element from the slice
			conns[i] = conns[len(conns)-1]
			conns[len(conns)-1] = nil
			conns = conns[:len(conns)-1]
			// Decrement i to iterate over swapped element
			i = i - 1
			continue
		}
		srcIP := conns[i].TupleOrig.SourceAddress
		dstIP := conns[i].TupleReply.SourceAddress

		// Only get Pod-to-Pod flows. Pod-to-ExternalService flows are ignored for now.
		if srcIP.Equal(ctdump.nodeConfig.GatewayConfig.IP) || dstIP.Equal(ctdump.nodeConfig.GatewayConfig.IP) {
			// Delete the element from the slice
			conns[i] = conns[len(conns)-1]
			conns[len(conns)-1] = nil
			conns = conns[:len(conns)-1]
			// Decrement i to iterate over swapped element
			i = i - 1
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
		if ctdump.serviceCIDR.Contains(srcIP) || ctdump.serviceCIDR.Contains(dstIP) {
			// Delete element from the slice
			conns[i] = conns[len(conns)-1]
			conns[len(conns)-1] = nil
			conns = conns[:len(conns)-1]
			// Decrement i to iterate over swapped element
			i = i - 1
			continue
		}
	}
	klog.V(2).Infof("No. of flow exporter considered flows in Antrea zoneID: %d", len(conns))

	return conns, nil
}

// connTrackSystem implements ConnTrackInterfacer
var _ ConnTrackInterfacer = new(connTrackSystem)
var _ ConnTrackInterfacer = new(connTrackNetdev)

type connTrackSystem struct {
	netlinkConn *conntrack.Conn
}

func NewConnTrackSystem() *connTrackSystem {
	// Ensure net.netfilter.nf_conntrack_acct value to be 1. This will enable flow exporter to export stats of connections.
	// Do not handle error and continue with creation of interfacer object as we can still dump flows with no stats.
	// If log says permission error, please ensure net.netfilter.nf_conntrack_acct to be set to 1.
	sysctl.EnsureSysctlNetValue("netfilter/nf_conntrack_acct", 1)
	// Ensure net.netfilter.nf_conntrack_timestamp value to be 1. This will enable flow exporter to export timestamps of connections.
	// Do not handle error and continue with creation of interfacer object as we can still dump flows with no timestamps.
	// If log says permission error, please ensure net.netfilter.nf_conntrack_timestamp to be set to 1.
	sysctl.EnsureSysctlNetValue("netfilter/nf_conntrack_timestamp", 1)

	return &connTrackSystem{}
}

type connTrackNetdev struct {
	ovsCtl ovsctl.OVSCtlClient
}

func NewConnTrackNetdev() *connTrackNetdev {
	return &connTrackNetdev{}
}

func (ctnl *connTrackSystem) GetConnTrack(config interface{}) error {
	if config != nil {
		return fmt.Errorf("this function does not expect any netlink config")
	}
	// Get netlink client in current namespace
	conn, err := conntrack.Dial(nil)
	if err != nil {
		klog.Errorf("Error when dialing conntrack: %v", err)
		return err
	}
	ctnl.netlinkConn = conn
	return nil
}

func (ctnl *connTrackSystem) DumpFilter(filter interface{}) ([]*flowexporter.Connection, error) {
	netlinkFilter, ok := filter.(conntrack.Filter)
	if !ok {
		return nil, fmt.Errorf("error: filter should be of type conntrack.Filter")
	}
	conns, err := ctnl.netlinkConn.DumpFilter(netlinkFilter)
	if err != nil {
		klog.Errorf("Error when dumping flows from conntrack: %v", err)
		return nil, err
	}
	antreaConns := make([]*flowexporter.Connection, len(conns))
	for i, conn := range conns {
		antreaConns[i] = createAntreaConn(&conn)
	}
	conns = nil

	klog.V(2).Infof("Finished dumping -- total no. of flows in conntrack: %d", len(antreaConns))

	ctnl.netlinkConn.Close()
	return antreaConns, nil
}

func (ctnd *connTrackNetdev) GetConnTrack(config interface{}) error {
	client, ok := config.(ovsctl.OVSCtlClient)
	if !ok {
		return fmt.Errorf("config should be ovsCtlClient of type OVSCtlClient")
	}
	ctnd.ovsCtl = client
	return nil
}

func (ctnd *connTrackNetdev) DumpFilter(filter interface{}) ([]*flowexporter.Connection, error) {
	zoneFilter, ok := filter.(uint16)
	if !ok {
		return nil, fmt.Errorf("filter should be of type uint16")
	}

	// Dump conntrack using ovs-appctl dpctl/dump-conntrack
	cmdOutput, execErr := ctnd.ovsCtl.RunAppctlCmd("dpctl/dump-conntrack", false, "-m", "-s")
	if execErr != nil {
		return nil, fmt.Errorf("error when executing dump-conntrack command: %v", execErr)
	}

	// Parse the output to get the flows
	antreaConns := make([]*flowexporter.Connection, 0)
	outputFlow := strings.Split(string(cmdOutput), "\n")
	var err error
	for _, flow := range outputFlow {
		conn := flowexporter.Connection{}
		flowSlice := strings.Split(flow, ",")
		isReply := false
		inZone := true
		for _, fs := range flowSlice {
			// Indicator to populate reply or reverse fields
			if strings.Contains(fs, "reply") {
				isReply = true
			}
			if !strings.Contains(fs, "=") {
				// Proto identifier
				conn.TupleOrig.Protocol, err = ip.LookupProtocolMap(fs)
				if err != nil {
					klog.Errorf("Unknown protocol to convert to ID: %s", fs)
					continue
				}
				conn.TupleReply.Protocol = conn.TupleOrig.Protocol
			} else if strings.Contains(fs, "src") {
				fields := strings.Split(fs, "=")
				if !isReply {
					conn.TupleOrig.SourceAddress = net.ParseIP(fields[len(fields)-1])
				} else {
					conn.TupleReply.SourceAddress = net.ParseIP(fields[len(fields)-1])
				}
			} else if strings.Contains(fs, "dst") {
				fields := strings.Split(fs, "=")
				if !isReply {
					conn.TupleOrig.DestinationAddress = net.ParseIP(fields[len(fields)-1])
				} else {
					conn.TupleReply.DestinationAddress = net.ParseIP(fields[len(fields)-1])
				}
			} else if strings.Contains(fs, "sport") {
				fields := strings.Split(fs, "=")
				val, err := strconv.Atoi(fields[len(fields)-1])
				if err != nil {
					klog.Errorf("Conversion of sport: %s to int failed", fields[len(fields)-1])
					continue
				}
				if !isReply {
					conn.TupleOrig.SourcePort = uint16(val)
				} else {
					conn.TupleReply.SourcePort = uint16(val)
				}
			} else if strings.Contains(fs, "dport") {
				// dport field could be the last tuple field in ovs-dpctl output format.
				fs = strings.TrimSuffix(fs, ")")

				fields := strings.Split(fs, "=")
				val, err := strconv.Atoi(fields[len(fields)-1])
				if err != nil {
					klog.Errorf("Conversion of dport: %s to int failed", fields[len(fields)-1])
					continue
				}
				if !isReply {
					conn.TupleOrig.DestinationPort = uint16(val)
				} else {
					conn.TupleReply.DestinationPort = uint16(val)
				}
			} else if strings.Contains(fs, "zone") {
				fields := strings.Split(fs, "=")
				val, err := strconv.Atoi(fields[len(fields)-1])
				if err != nil {
					klog.Errorf("Conversion of zone: %s to int failed", fields[len(fields)-1])
					continue
				}
				if zoneFilter != uint16(val) {
					inZone = false
					break
				} else {
					conn.Zone = uint16(val)
				}
			} else if strings.Contains(fs, "timeout") {
				fields := strings.Split(fs, "=")
				val, err := strconv.Atoi(fields[len(fields)-1])
				if err != nil {
					klog.Errorf("Conversion of timeout: %s to int failed", fields[len(fields)-1])
					continue
				}
				conn.Timeout = uint32(val)
			} else if strings.Contains(fs, "id") {
				fields := strings.Split(fs, "=")
				val, err := strconv.Atoi(fields[len(fields)-1])
				if err != nil {
					klog.Errorf("Conversion of id: %s to int failed", fields[len(fields)-1])
					continue
				}
				conn.ID = uint32(val)
			}
		}
		if inZone {
			antreaConns = append(antreaConns, &conn)
		}
	}
	klog.V(2).Infof("Finished dumping -- total no. of flows in conntrack: %d", len(antreaConns))
	return antreaConns, nil
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
