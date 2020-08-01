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
	"github.com/vmware-tanzu/antrea/pkg/util/ip"
)

// connTrackOvsCtl implements ConnTrackDumper. This supports OVS userspace datapath scenarios.
var _ ConnTrackDumper = new(connTrackOvsCtl)

type connTrackOvsCtl struct {
	nodeConfig   *config.NodeConfig
	serviceCIDR  *net.IPNet
	ovsctlClient ovsctl.OVSCtlClient
}

func NewConnTrackOvsAppCtl(nodeConfig *config.NodeConfig, serviceCIDR *net.IPNet, ovsctlClient ovsctl.OVSCtlClient) *connTrackOvsCtl {
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

	// Parse the output to get the flows
	antreaConns := make([]*flowexporter.Connection, 0)
	outputFlow := strings.Split(string(cmdOutput), "\n")
	var err error
	for _, flow := range outputFlow {
		conn := flowexporter.Connection{}
		flowSlice := strings.Split(flow, ",")
		isReply := false
		inZone := false
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
					break
				} else {
					inZone = true
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
			conn.IsActive = true
			conn.DoExport = true
			antreaConns = append(antreaConns, &conn)
		}
	}
	klog.V(2).Infof("Finished dumping -- total no. of flows in conntrack: %d", len(antreaConns))
	return antreaConns, nil
}

func filterAntreaConns(conns []*flowexporter.Connection, nodeConfig *config.NodeConfig, serviceCIDR *net.IPNet, zoneFilter uint16) []*flowexporter.Connection {
	filteredConns := conns[:0]
	for _, conn := range conns {
		if conn.Zone != zoneFilter {
			continue
		}
		srcIP := conn.TupleOrig.SourceAddress
		dstIP := conn.TupleReply.SourceAddress

		// Only get Pod-to-Pod flows.
		if srcIP.Equal(nodeConfig.GatewayConfig.IP) || dstIP.Equal(nodeConfig.GatewayConfig.IP) {
			klog.V(4).Infof("Detected flow through gateway")
			continue
		}

		// Pod-to-Service flows w/ kube-proxy: There are two conntrack flows for every Pod-to-Service flow.
		// One is with ClusterIP as source or destination, where other IP is podIP. Second conntrack flow is
		// with resolved Endpoint Pod IP corresponding to ClusterIP. Both conntrack flows have same stats, which makes them duplicate.
		// Ideally, we have to correlate these two Connections and maintain one connection with both Endpoint Pod IP and ClusterIP.
		// To do the correlation, we need ClusterIP-to-EndpointIP mapping info, which is not available at Agent.
		// Therefore, we ignore the connection with ClusterIP and keep the connection with Endpoint Pod IP.
		// Conntrack flows will be different for Pod-to-Service flows w/ Antrea-proxy. This implementation will be simpler, when the
		// Antrea proxy is supported.
		if serviceCIDR.Contains(srcIP) || serviceCIDR.Contains(dstIP) {
			continue
		}
		filteredConns = append(filteredConns, conn)
	}
	return filteredConns
}
