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
	"time"

	"github.com/ti-mo/conntrack"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/flowexporter"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	"github.com/vmware-tanzu/antrea/pkg/agent/util/sysctl"
)

// connTrackSystem implements ConnTrackDumper. This is for linux kernel datapath.
var _ ConnTrackDumper = new(connTrackSystem)

type connTrackSystem struct {
	nodeConfig           *config.NodeConfig
	serviceCIDRv4        *net.IPNet
	serviceCIDRv6        *net.IPNet
	isAntreaProxyEnabled bool
	connTrack            NetFilterConnTrack
}

func NewConnTrackSystem(nodeConfig *config.NodeConfig, serviceCIDRv4 *net.IPNet, serviceCIDRv6 *net.IPNet, isAntreaProxyEnabled bool) *connTrackSystem {
	if err := SetupConntrackParameters(); err != nil {
		// Do not fail, but continue after logging an error as we can still dump flows with missing information.
		klog.Errorf("Error when setting up conntrack parameters, some information may be missing from exported flows: %v", err)
	}
	return &connTrackSystem{
		nodeConfig,
		serviceCIDRv4,
		serviceCIDRv6,
		isAntreaProxyEnabled,
		&netFilterConnTrack{},
	}
}

// DumpFlows opens netlink connection and dumps all the flows in Antrea ZoneID of conntrack table.
func (ct *connTrackSystem) DumpFlows(zoneFilter uint16) ([]*flowexporter.Connection, int, error) {
	svcCIDR := ct.serviceCIDRv4
	if zoneFilter == openflow.CtZoneV6 {
		svcCIDR = ct.serviceCIDRv6
	}
	// Get connection to netlink socket
	err := ct.connTrack.Dial()
	if err != nil {
		return nil, 0, fmt.Errorf("error when getting netlink socket: %v", err)
	}

	// ZoneID filter is not supported currently in tl-mo/conntrack library.
	// Link to issue: https://github.com/ti-mo/conntrack/issues/23
	// Dump all flows in the conntrack table for now.
	conns, err := ct.connTrack.DumpFlowsInCtZone(zoneFilter)
	if err != nil {
		return nil, 0, fmt.Errorf("error when dumping flows from conntrack: %v", err)
	}

	filteredConns := filterAntreaConns(conns, ct.nodeConfig, svcCIDR, zoneFilter, ct.isAntreaProxyEnabled)
	klog.V(2).Infof("No. of flow exporter considered flows in Antrea zoneID: %d", len(filteredConns))

	return filteredConns, len(conns), nil
}

// NetFilterConnTrack interface helps for testing the code that contains the third party library functions ("github.com/ti-mo/conntrack")
type NetFilterConnTrack interface {
	Dial() error
	DumpFlowsInCtZone(zoneFilter uint16) ([]*flowexporter.Connection, error)
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

func (nfct *netFilterConnTrack) DumpFlowsInCtZone(zoneFilter uint16) ([]*flowexporter.Connection, error) {
	conns, err := nfct.netlinkConn.DumpFilter(conntrack.Filter{})
	if err != nil {
		return nil, err
	}
	antreaConns := make([]*flowexporter.Connection, len(conns))
	for i := range conns {
		conn := conns[i]
		antreaConns[i] = NetlinkFlowToAntreaConnection(&conn)
	}

	klog.V(2).Infof("Finished dumping -- total no. of flows in conntrack: %d", len(antreaConns))

	nfct.netlinkConn.Close()
	return antreaConns, nil
}

func NetlinkFlowToAntreaConnection(conn *conntrack.Flow) *flowexporter.Connection {
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
		ID:                      conn.ID,
		Timeout:                 conn.Timeout,
		StartTime:               conn.Timestamp.Start,
		IsPresent:               true,
		Zone:                    conn.Zone,
		Mark:                    conn.Mark,
		Labels:                  conn.Labels,
		LabelsMask:              conn.LabelsMask,
		StatusFlag:              uint32(conn.Status.Value),
		TupleOrig:               tupleOrig,
		TupleReply:              tupleReply,
		OriginalPackets:         conn.CountersOrig.Packets,
		OriginalBytes:           conn.CountersOrig.Bytes,
		ReversePackets:          conn.CountersReply.Packets,
		ReverseBytes:            conn.CountersReply.Bytes,
		SourcePodNamespace:      "",
		SourcePodName:           "",
		DestinationPodNamespace: "",
		DestinationPodName:      "",
	}

	// Get the stop time from dumped connection if the connection is terminated(dying state).
	if conn.Status.Dying() {
		newConn.StopTime = conn.Timestamp.Stop
	} else {
		newConn.StopTime = time.Now()
	}

	return &newConn
}

func SetupConntrackParameters() error {
	parametersWithErrors := []string{}
	if sysctl.EnsureSysctlNetValue("netfilter/nf_conntrack_acct", 1) != nil {
		parametersWithErrors = append(parametersWithErrors, "net.netfilter.nf_conntrack_acct")
	}
	if sysctl.EnsureSysctlNetValue("netfilter/nf_conntrack_timestamp", 1) != nil {
		parametersWithErrors = append(parametersWithErrors, "net.netfilter.nf_conntrack_timestamp")
	}
	if len(parametersWithErrors) > 0 {
		return fmt.Errorf("the following kernel parameters could not be verified / set: %v", parametersWithErrors)
	}
	return nil
}

func (ct *connTrackSystem) GetMaxConnections() (int, error) {
	maxConns, err := sysctl.GetSysctlNet("netfilter/nf_conntrack_max")
	return maxConns, err
}
