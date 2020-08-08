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

	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/flowexporter"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsctl"
)

// Following map is for converting protocol name (string) to protocol identifier
var protocols = map[string]uint8{
	"icmp":      1,
	"igmp":      2,
	"tcp":       6,
	"udp":       17,
	"ipv6-icmp": 58,
}

// connTrackOvsCtl implements ConnTrackDumper. This supports OVS userspace datapath scenarios.
var _ ConnTrackDumper = new(connTrackOvsCtl)

type connTrackOvsCtl struct {
	nodeConfig   *config.NodeConfig
	serviceCIDR  *net.IPNet
	ovsctlClient ovsctl.OVSCtlClient
}

func NewConnTrackOvsAppCtl(nodeConfig *config.NodeConfig, serviceCIDR *net.IPNet, ovsctlClient ovsctl.OVSCtlClient) *connTrackOvsCtl {
	if ovsctlClient == nil {
		return nil
	}
	return &connTrackOvsCtl{
		nodeConfig,
		serviceCIDR,
		ovsctlClient,
	}
}

// DumpFlows uses "ovs-appctl dpctl/dump-conntrack" to dump conntrack flows in the Antrea ZoneID.
func (ct *connTrackOvsCtl) DumpFlows(zoneFilter uint16) ([]*flowexporter.Connection, error) {
	conns, err := ct.ovsAppctlDumpConnections(zoneFilter)
	if err != nil {
		klog.Errorf("Error when dumping flows from conntrack: %v", err)
		return nil, err
	}

	filteredConns := filterAntreaConns(conns, ct.nodeConfig, ct.serviceCIDR, zoneFilter)
	klog.V(2).Infof("Flow exporter considered flows: %d", len(filteredConns))

	return filteredConns, nil
}

func (ct *connTrackOvsCtl) ovsAppctlDumpConnections(zoneFilter uint16) ([]*flowexporter.Connection, error) {
	// Dump conntrack using ovs-appctl dpctl/dump-conntrack
	cmdOutput, execErr := ct.ovsctlClient.RunAppctlCmd("dpctl/dump-conntrack", false, "-m", "-s")
	if execErr != nil {
		return nil, fmt.Errorf("error when executing dump-conntrack command: %v", execErr)
	}

	// Parse the output to get the flow strings and convert them to Antrea connections.
	antreaConns := make([]*flowexporter.Connection, 0)
	outputFlow := strings.Split(string(cmdOutput), "\n")
	for _, flow := range outputFlow {
		conn, err := flowStringToAntreaConnection(flow, zoneFilter)
		if err != nil {
			klog.Warningf("Ignoring the flow from conntrack dump due to the error: %v", err)
			continue
		}
		if conn != nil {
			antreaConns = append(antreaConns, conn)
		}
	}
	klog.V(2).Infof("Finished dumping -- total no. of flows in conntrack: %d", len(antreaConns))
	return antreaConns, nil
}

// flowStringToAntreaConnection parses the flow string and converts to Antrea connection.
// Example of flow string:
// tcp,orig=(src=10.10.1.2,dst=10.96.0.1,sport=42540,dport=443),reply=(src=10.96.0.1,dst=10.10.1.2,sport=443,dport=42540),zone=65520,protoinfo=(state=TIME_WAIT)
func flowStringToAntreaConnection(flow string, zoneFilter uint16) (*flowexporter.Connection, error) {
	conn := flowexporter.Connection{}
	flowSlice := strings.Split(flow, ",")
	isReply := false
	inZone := false
	var err error
	for _, fs := range flowSlice {
		// Indicator to populate reply or reverse fields
		if strings.Contains(fs, "reply") {
			isReply = true
		}
		if !strings.Contains(fs, "=") {
			// Proto identifier
			conn.TupleOrig.Protocol, err = lookupProtocolMap(fs)
			if err != nil {
				return nil, err
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
				return nil, fmt.Errorf("conversion of sport %s to int failed", fields[len(fields)-1])
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
				return nil, fmt.Errorf("conversion of dport %s to int failed", fields[len(fields)-1])
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
				return nil, fmt.Errorf("conversion of zone %s to int failed", fields[len(fields)-1])
			}
			if zoneFilter != uint16(val) {
				break
			} else {
				inZone = true
				conn.Zone = uint16(val)
			}
		} else if strings.Contains(fs, "timeout") {
			fields := strings.Split(fs, "=")
			val, err := strconv.Atoi(fields[len(fields)-1])
			if err != nil {
				return nil, fmt.Errorf("conversion of timeout %s to int failed", fields[len(fields)-1])
			}
			conn.Timeout = uint32(val)
		} else if strings.Contains(fs, "id") {
			fields := strings.Split(fs, "=")
			val, err := strconv.Atoi(fields[len(fields)-1])
			if err != nil {
				return nil, fmt.Errorf("conversion of id %s to int failed", fields[len(fields)-1])
			}
			conn.ID = uint32(val)
		}
	}
	if !inZone {
		return nil, nil
	}
	conn.IsActive = true
	conn.DoExport = true

	return &conn, nil
}

// lookupProtocolMap returns protocol identifier given protocol name
func lookupProtocolMap(name string) (uint8, error) {
	name = strings.TrimSpace(name)
	lowerCaseStr := strings.ToLower(name)
	proto, found := protocols[lowerCaseStr]
	if !found {
		return 0, fmt.Errorf("unknown IP protocol specified: %s", name)
	}
	return proto, nil
}
