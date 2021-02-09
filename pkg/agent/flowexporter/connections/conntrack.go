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
)

// InitializeConnTrackDumper initializes the ConnTrackDumper interface for different OS and datapath types.
func InitializeConnTrackDumper(nodeConfig *config.NodeConfig, serviceCIDRv4 *net.IPNet, serviceCIDRv6 *net.IPNet, ovsDatapathType ovsconfig.OVSDatapathType, isAntreaProxyEnabled bool) ConnTrackDumper {
	var connTrackDumper ConnTrackDumper
	if ovsDatapathType == ovsconfig.OVSDatapathSystem {
		connTrackDumper = NewConnTrackSystem(nodeConfig, serviceCIDRv4, serviceCIDRv6, isAntreaProxyEnabled)
	} else if ovsDatapathType == ovsconfig.OVSDatapathNetdev {
		connTrackDumper = NewConnTrackOvsAppCtl(nodeConfig, serviceCIDRv4, serviceCIDRv6, isAntreaProxyEnabled)
	}
	return connTrackDumper
}

func filterAntreaConns(conns []*flowexporter.Connection, nodeConfig *config.NodeConfig, serviceCIDR *net.IPNet, zoneFilter uint16, isAntreaProxyEnabled bool) []*flowexporter.Connection {
	filteredConns := conns[:0]
	for _, conn := range conns {
		if conn.Zone != zoneFilter {
			continue
		}
		srcIP := conn.TupleOrig.SourceAddress
		dstIP := conn.TupleReply.SourceAddress

		// Consider Pod-to-Pod, Pod-To-Service and Pod-To-External flows.
		if srcIP.Equal(nodeConfig.GatewayConfig.IPv4) || dstIP.Equal(nodeConfig.GatewayConfig.IPv4) {
			klog.V(4).Infof("Detected flow for which one of the endpoint is host gateway %s :%+v", nodeConfig.GatewayConfig.IPv4.String(), conn)
			continue
		}
		if srcIP.Equal(nodeConfig.GatewayConfig.IPv6) || dstIP.Equal(nodeConfig.GatewayConfig.IPv6) {
			klog.V(4).Infof("Detected flow for which one of the endpoint is host gateway %s :%+v", nodeConfig.GatewayConfig.IPv6.String(), conn)
			continue
		}

		if !isAntreaProxyEnabled {
			// Pod-to-Service flows with kube-proxy: There are two conntrack flows
			// for every Pod-to-Service flow. One is with ClusterIP as destination
			// and the other one is with resolved endpoint PodIP as destination.
			// Both conntrack flows have same stats, which makes them duplicates.
			// We ignore the connection with ClusterIP and keep the connection with
			// the endpoint PodIP, which is essentially Pod-to-Pod flow.
			// TODO: Consider the conntrack flows from default zoneID to get iptables
			// related flow that has both ClusterIP and resolved endpoint PodIP.
			if serviceCIDR.Contains(dstIP) {
				klog.V(4).Infof("Detected a flow with Cluster IP with kube-proxy enabled :%+v", conn)
				continue
			}
		}
		filteredConns = append(filteredConns, conn)
	}
	return filteredConns
}
