// Copyright 2026 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
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

	"antrea.io/antrea/v2/pkg/agent/config"
	"antrea.io/antrea/v2/pkg/agent/flowexporter/connection"
)

// PodSubnetChecker determines whether an IP belongs to a Pod subnet and whether it is a gateway IP.
// *noderoute.Controller implements this interface.
type PodSubnetChecker interface {
	LookupIPInPodSubnets(ip netip.Addr) (isPod bool, isGw bool)
}

// HostNetworkClassifier holds the information needed to identify the connections initiated by the
// host network stack of this Node towards Pods, such as kubelet probes or connections from
// hostNetwork Pods.
//
// The route to the local Pod subnet goes through antrea-gw0, and so do the routes to the Pod
// subnets of other Nodes in encap mode (but not with WireGuard encryption, in which case they go
// through the WireGuard device, bypassing OVS). The host therefore selects the IP of antrea-gw0 as
// the source address when connecting to such a Pod IP. The source address of an Antrea-zone
// connection is not enough to identify these connections, as the same gateway IP is used to
// masquerade connections from external clients to Services. Instead, the FromExternalCorrelator
// matches each Antrea-zone connection with the default-zone (host) conntrack entry of the same
// connection, whose original source address is the gateway IP only if the connection was initiated
// by the host itself (see FromExternalCorrelator.Correlate). This requires the default zone to be
// the host's conntrack table, which is only the case on Linux.
//
// The host may also connect to a ClusterIP using another IP of this Node (e.g., its Node IP), and
// have the connection masqueraded with the gateway IP by kube-proxy. Such a connection is
// correlated with its default-zone counterpart like a connection from an external client, and is
// identified by its original source address, which is an IP of this Node.
//
// In networkPolicyOnly mode, the gateway IP is the transport IP of this Node, which is the source
// address selected by the host when connecting to a local Pod through antrea-gw0, and the Pod
// subnets of other Nodes are unknown.
type HostNetworkClassifier struct {
	podSubnetChecker PodSubnetChecker
	gatewayIPs       []netip.Addr
	// nodeIPs holds all the IPs of this Node known to the agent, including the gateway IPs.
	nodeIPs       []netip.Addr
	localPodCIDRs []netip.Prefix
}

// NewHostNetworkClassifier returns a HostNetworkClassifier for this Node. podSubnetChecker is
// used to determine whether a destination IP belongs to the Pod subnet of another Node; if nil, no
// IP is identified as such.
func NewHostNetworkClassifier(nodeConfig *config.NodeConfig, podSubnetChecker PodSubnetChecker) *HostNetworkClassifier {
	c := &HostNetworkClassifier{
		podSubnetChecker: podSubnetChecker,
	}
	addNodeIP := func(ip net.IP) {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			return
		}
		addr = addr.Unmap()
		if !slices.Contains(c.nodeIPs, addr) {
			c.nodeIPs = append(c.nodeIPs, addr)
		}
	}
	if nodeConfig.GatewayConfig != nil {
		for _, ip := range []net.IP{nodeConfig.GatewayConfig.IPv4, nodeConfig.GatewayConfig.IPv6} {
			if addr, ok := netip.AddrFromSlice(ip); ok {
				c.gatewayIPs = append(c.gatewayIPs, addr.Unmap())
			}
			addNodeIP(ip)
		}
	}
	for _, ipNet := range []*net.IPNet{nodeConfig.NodeIPv4Addr, nodeConfig.NodeIPv6Addr, nodeConfig.NodeTransportIPv4Addr, nodeConfig.NodeTransportIPv6Addr} {
		if ipNet != nil {
			addNodeIP(ipNet.IP)
		}
	}
	for _, cidr := range []*net.IPNet{nodeConfig.PodIPv4CIDR, nodeConfig.PodIPv6CIDR} {
		if cidr == nil {
			continue
		}
		addr, ok := netip.AddrFromSlice(cidr.IP)
		if !ok {
			continue
		}
		size, _ := cidr.Mask.Size()
		if prefix, err := addr.Unmap().Prefix(size); err == nil {
			c.localPodCIDRs = append(c.localPodCIDRs, prefix)
		}
	}
	return c
}

// IsFromHostNetwork returns whether conn, a default-zone connection, was initiated by the host
// network stack of this Node towards antrea-gw0. Its original source address is the gateway IP of
// this Node, which, as a local address, cannot be the original source address of a connection
// received by this Node.
func (c *HostNetworkClassifier) IsFromHostNetwork(conn *connection.Connection) bool {
	return c.isGatewayIP(conn.FlowKey.SourceAddress)
}

// IsRemotePodIP returns whether ip belongs to the Pod subnet of another Node, and is not the
// gateway IP of that Node.
func (c *HostNetworkClassifier) IsRemotePodIP(ip netip.Addr) bool {
	if c.podSubnetChecker == nil {
		return false
	}
	isPod, isGw := c.podSubnetChecker.LookupIPInPodSubnets(ip)
	if !isPod || isGw {
		return false
	}
	for _, prefix := range c.localPodCIDRs {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

// IsNodeIP returns whether ip is an IP of this Node known to the agent: a Node IP, a transport IP
// or a gateway IP. A default-zone connection whose original source address is such an IP was
// initiated by the host network stack of this Node.
func (c *HostNetworkClassifier) IsNodeIP(ip netip.Addr) bool {
	return slices.Contains(c.nodeIPs, ip)
}

func (c *HostNetworkClassifier) isGatewayIP(ip netip.Addr) bool {
	return slices.Contains(c.gatewayIPs, ip)
}
