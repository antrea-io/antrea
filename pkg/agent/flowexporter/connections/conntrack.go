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

	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/flowexporter"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsconfig"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsctl"
)

func InitializeConnTrackDumper(nodeConfig *config.NodeConfig, serviceCIDR *net.IPNet, ovsctlClient ovsctl.OVSCtlClient, ovsDatapathType string) ConnTrackDumper {
	var connTrackDumper ConnTrackDumper
	if ovsDatapathType == ovsconfig.OVSDatapathSystem {
		connTrackDumper = NewConnTrackSystem(nodeConfig, serviceCIDR)
	} else if ovsDatapathType == ovsconfig.OVSDatapathNetdev {
		connTrackDumper = NewConnTrackOvsAppCtl(nodeConfig, serviceCIDR, ovsctlClient)
	}
	return connTrackDumper
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
			klog.V(4).Infof("Detected flow through gateway :%v", conn)
			continue
		}

		// Pod-to-Service flows w/ kube-proxy: There are two conntrack flows for every Pod-to-Service flow.
		// One is with ClusterIP as source or destination, where other IP is podIP. Second conntrack flow is
		// with resolved Endpoint Pod IP corresponding to ClusterIP. Both conntrack flows have same stats, which makes them duplicates.
		// Ideally, we have to correlate these two connections and maintain one connection with both Endpoint Pod IP and ClusterIP.
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
