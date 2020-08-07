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
	"net"

	"github.com/ti-mo/conntrack"
	"k8s.io/klog/v2"

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/flowexporter"
	"github.com/vmware-tanzu/antrea/pkg/agent/util/sysctl"
)

// connTrackSystem implements ConnTrackDumper. This is for linux kernel datapath.
var _ ConnTrackDumper = new(connTrackSystem)

type connTrackSystem struct {
	nodeConfig  *config.NodeConfig
	serviceCIDR *net.IPNet
	connTrack   NetFilterConnTrack
}

func NewConnTrackSystem(nodeConfig *config.NodeConfig, serviceCIDR *net.IPNet) *connTrackSystem {
	// Ensure net.netfilter.nf_conntrack_acct value to be 1. This will enable flow exporter to export stats of connections.
	// Do not handle error and continue with creation of interfacer object as we can still dump flows with no stats.
	// If log says permission error, please ensure net.netfilter.nf_conntrack_acct to be set to 1.
	sysctl.EnsureSysctlNetValue("netfilter/nf_conntrack_acct", 1)
	// Ensure net.netfilter.nf_conntrack_timestamp value to be 1. This will enable flow exporter to export timestamps of connections.
	// Do not handle error and continue with creation of interfacer object as we can still dump flows with no timestamps.
	// If log says permission error, please ensure net.netfilter.nf_conntrack_timestamp to be set to 1.
	sysctl.EnsureSysctlNetValue("netfilter/nf_conntrack_timestamp", 1)

	return &connTrackSystem{
		nodeConfig,
		serviceCIDR,
		&netFilterConnTrack{},
	}
}

// DumpFlows opens netlink connection and dumps all the flows in Antrea ZoneID of conntrack table.
func (ct *connTrackSystem) DumpFlows(zoneFilter uint16) ([]*flowexporter.Connection, error) {
	// Get connection to netlink socket
	err := ct.connTrack.Dial()
	if err != nil {
		klog.Errorf("Error when getting netlink socket: %v", err)
		return nil, err
	}

	// ZoneID filter is not supported currently in tl-mo/conntrack library.
	// Link to issue: https://github.com/ti-mo/conntrack/issues/23
	// Dump all flows in the conntrack table for now.
	conns, err := ct.connTrack.DumpFilter(conntrack.Filter{})
	if err != nil {
		klog.Errorf("Error when dumping flows from conntrack: %v", err)
		return nil, err
	}
	filteredConns := filterAntreaConns(conns, ct.nodeConfig, ct.serviceCIDR, zoneFilter)
	klog.V(2).Infof("No. of flow exporter considered flows in Antrea zoneID: %d", len(filteredConns))

	return filteredConns, nil
}

// NetFilterConnTrack interface helps for testing the code that contains the third party library functions ("github.com/ti-mo/conntrack")
type NetFilterConnTrack interface {
	Dial() error
	DumpFilter(filter conntrack.Filter) ([]*flowexporter.Connection, error)
}

type netFilterConnTrack struct {
	netlinkConn *conntrack.Conn
}

func (nfct *netFilterConnTrack) Dial() error {
	// Get netlink client in current namespace
	conn, err := conntrack.Dial(nil)
	if err != nil {
		return err
	}
	nfct.netlinkConn = conn
	return nil
}

func (nfct *netFilterConnTrack) DumpFilter(filter conntrack.Filter) ([]*flowexporter.Connection, error) {
	conns, err := nfct.netlinkConn.DumpFilter(filter)
	if err != nil {
		return nil, err
	}
	antreaConns := make([]*flowexporter.Connection, len(conns))
	for i, conn := range conns {
		antreaConns[i] = createAntreaConn(&conn)
	}

	klog.V(2).Infof("Finished dumping -- total no. of flows in conntrack: %d", len(antreaConns))

	nfct.netlinkConn.Close()
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
		true,
		true,
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
