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
	"net/netip"
	"slices"
	"strings"

	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/flowexporter"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
)

// InitializeConnTrackDumper initializes the ConnTrackDumper interface for different OS and datapath types.
func InitializeConnTrackDumper(nodeConfig *config.NodeConfig, serviceCIDRv4 *net.IPNet, serviceCIDRv6 *net.IPNet, ovsDatapathType ovsconfig.OVSDatapathType, isAntreaProxyEnabled bool, protocolFilter []string) ConnTrackDumper {
	var svcCIDRv4, svcCIDRv6 netip.Prefix
	if serviceCIDRv4 != nil {
		svcCIDRv4 = netip.MustParsePrefix(serviceCIDRv4.String())
	}
	if serviceCIDRv6 != nil {
		svcCIDRv6 = netip.MustParsePrefix(serviceCIDRv6.String())
	}

	protocolFilter = validateProtocolFilter(protocolFilter)
	var connTrackDumper ConnTrackDumper
	if ovsDatapathType == ovsconfig.OVSDatapathSystem {
		connTrackDumper = NewConnTrackSystem(nodeConfig, svcCIDRv4, svcCIDRv6, isAntreaProxyEnabled, protocolFilter)
	}
	return connTrackDumper
}

// Return a subset of protocols of only supported protocols and log a mesasge
// if unsupported protocols were found
func validateProtocolFilter(protocols []string) []string {
	validProtocols := []string{}
	for _, v := range serviceProtocolMap {
		validProtocols = append(validProtocols, string(v))
	}

	validatedProtocols := []string{}
	invalidProtocols := []string{}
	for _, protocol := range protocols {
		if slices.Contains(validProtocols, protocol) {
			validatedProtocols = append(validatedProtocols, protocol)
		} else {
			invalidProtocols = append(invalidProtocols, protocol)
		}
	}
	if len(invalidProtocols) > 0 {
		klog.Warningf("Parsing protocols for filtering and found an unsupported protocol(s) %q. Supported protocols include: %q", strings.Join(invalidProtocols, ","), strings.Join(validProtocols, ","))
	}

	return validatedProtocols
}

func filterAntreaConns(conns []*flowexporter.Connection, nodeConfig *config.NodeConfig, serviceCIDR netip.Prefix, zoneFilter uint16, isAntreaProxyEnabled bool, protocolFilter []string) []*flowexporter.Connection {

	filteredConns := conns[:0]
	gwIPv4, _ := netip.AddrFromSlice(nodeConfig.GatewayConfig.IPv4)
	gwIPv6, _ := netip.AddrFromSlice(nodeConfig.GatewayConfig.IPv6)
	protocolFilterSpecified := len(protocolFilter) > 0

	for _, conn := range conns {
		if conn.Zone != zoneFilter {
			continue
		}
		srcIP := conn.FlowKey.SourceAddress
		dstIP := conn.FlowKey.DestinationAddress

		// Consider Pod-to-Pod, Pod-To-Service and Pod-To-External flows.
		if srcIP == gwIPv4 || dstIP == gwIPv4 {
			continue
		}
		if srcIP == gwIPv6 || dstIP == gwIPv6 {
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

		if protocolFilterSpecified {
			protocol := string(serviceProtocolMap[conn.FlowKey.Protocol])
			if !slices.Contains(protocolFilter, protocol) {
				continue
			}
		}

		filteredConns = append(filteredConns, conn)
	}
	return filteredConns
}
