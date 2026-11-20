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

package flowexporter

import (
	"net"
	"net/netip"

	"antrea.io/antrea/v2/pkg/agent/config"
	"antrea.io/antrea/v2/pkg/agent/flowexporter/connections"
)

// remotePodSubnetQuerier provides information about the Pod subnets of the Nodes.
// *noderoute.Controller implements this interface.
type remotePodSubnetQuerier interface {
	podSubnetChecker
	// GetNodeIPForPodIP returns the transport IP of the other Node whose Pod subnet contains the
	// IP. It returns false for the IPs of the Pod subnets of this Node.
	GetNodeIPForPodIP(ip netip.Addr) (net.IP, bool)
}

// remotePodQuerier implements connections.RemotePodQuerier.
type remotePodQuerier struct {
	nodeRouteQuerier remotePodSubnetQuerier
	networkConfig    *config.NetworkConfig
	nodeConfig       *config.NodeConfig
}

var _ connections.RemotePodQuerier = (*remotePodQuerier)(nil)

func newRemotePodQuerier(nodeRouteQuerier remotePodSubnetQuerier, networkConfig *config.NetworkConfig, nodeConfig *config.NodeConfig) *remotePodQuerier {
	return &remotePodQuerier{
		nodeRouteQuerier: nodeRouteQuerier,
		networkConfig:    networkConfig,
		nodeConfig:       nodeConfig,
	}
}

// IsRemotePodIP implements connections.RemotePodQuerier.
//
// The host network of this Node sends its traffic to a Pod running on another Node through
// antrea-gw0 with the gateway IP as the source address (masquerading it if needed), and OVS tunnels
// it to the other Node, when the traffic to that Node needs to be tunneled. With WireGuard, the
// host sends its traffic to a Pod IP through antrea-wg0, which bypasses OVS, but its traffic to a
// Service handled by AntreaProxy is sent back by OVS to the host after the Service translation,
// and masqueraded with the address of antrea-wg0, which is also the gateway IP. Otherwise (in
// noEncap mode, and in hybrid mode for the Nodes in the same subnet), the host routes its traffic
// to the Pods running on the other Node through the uplink, and masquerades it with its own IP if
// it is first sent to OVS for a Service: the other Node then sees a different 5-tuple, and this
// Node only reports the connection if it knows that 5-tuple (see IsRemotePodIPRoutedByHost).
func (q *remotePodQuerier) IsRemotePodIP(ip netip.Addr) bool {
	peerIP, ok := q.nodeRouteQuerier.GetNodeIPForPodIP(ip)
	if !ok {
		return false
	}
	if _, isGw := q.nodeRouteQuerier.LookupIPInPodSubnets(ip); isGw {
		return false
	}
	if q.networkConfig.TrafficEncryptionMode == config.TrafficEncryptionModeWireGuard {
		return true
	}
	return q.networkConfig.NeedsTunnelToPeer(peerIP, q.localTransportIP(ip))
}

// IsRemotePodIPRoutedByHost implements connections.RemotePodQuerier.
//
// The host network of this Node routes its traffic to a Pod running on another Node through
// antrea-gw0 only when the traffic to that Node is tunneled by OVS. Otherwise, it routes it through
// the uplink (in noEncap mode, and in hybrid mode for the Nodes in the same subnet), or through
// antrea-wg0 with WireGuard, for which NeedsTunnelToPeer returns false.
func (q *remotePodQuerier) IsRemotePodIPRoutedByHost(ip netip.Addr) bool {
	peerIP, ok := q.nodeRouteQuerier.GetNodeIPForPodIP(ip)
	if !ok {
		return false
	}
	if _, isGw := q.nodeRouteQuerier.LookupIPInPodSubnets(ip); isGw {
		return false
	}
	return !q.networkConfig.NeedsTunnelToPeer(peerIP, q.localTransportIP(ip))
}

// IsPodSubnetIP implements connections.RemotePodQuerier.
func (q *remotePodQuerier) IsPodSubnetIP(ip netip.Addr) bool {
	isPod, _ := q.nodeRouteQuerier.LookupIPInPodSubnets(ip)
	return isPod
}

// localTransportIP returns the transport IP of this Node in the IP family of ip.
func (q *remotePodQuerier) localTransportIP(ip netip.Addr) *net.IPNet {
	if ip.Is6() {
		return q.nodeConfig.NodeTransportIPv6Addr
	}
	return q.nodeConfig.NodeTransportIPv4Addr
}
