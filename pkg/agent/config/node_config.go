// Copyright 2019 Antrea Authors
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

package config

import (
	"fmt"
	"net"

	"antrea.io/antrea/pkg/ovs/ovsconfig"
)

const (
	// Invalid ofport_request number is in range 1 to 65,279. For ofport_request number not in the range, OVS
	// ignore the it and automatically assign a port number.
	// Here we use an invalid port number "0" to request for automatically port allocation.
	AutoAssignedOFPort = 0
	DefaultTunOFPort   = 1
	HostGatewayOFPort  = 2
	UplinkOFPort       = 3
	OVSPatchOFPort     = 4
	// 0xfffffffe is a reserved port number in OpenFlow protocol, which is dedicated for the Bridge interface.
	BridgeOFPort = 0xfffffffe
)

const (
	VXLANOverhead     = 50
	GeneveOverhead    = 50
	GREOverhead       = 38
	WireGuardOverhead = 80
	// IPsec ESP can add a maximum of 38 bytes to the packet including the ESP
	// header and trailer.
	IPSecESPOverhead  = 38
	IPv6ExtraOverhead = 20
)

var (
	// VirtualServiceIPv4 / VirtualServiceIPv6 are used in the following situations:
	// - Use the virtual IP to perform SNAT for packets of Service from Antrea gateway and the Endpoint is not on
	//   local Pod CIDR or any remote Pod CIDRs. It is used in OVS flow of table serviceConntrackCommitTable.
	// - Use the virtual IP to perform DNAT for packets of NodePort on host. It is used in iptables rules on host.
	// - Use the virtual IP as onlink routing entry gateway in host routing entry.
	// - Use the virtual IP as destination IP in host routing entry. It is used to forward DNATed NodePort packets
	//   or replied SNATed Service packets back to Antrea gateway.
	// - Use the virtual IP for InternalIPAddress parameter of Add-NetNatStaticMapping.
	//   The IP cannot be one used in the network, and cannot be within the 169.254.1.0 - 169.254.254.255 range
	//   according to https://datatracker.ietf.org/doc/html/rfc3927#section-2.1
	VirtualServiceIPv4 = net.ParseIP("169.254.0.253")
	VirtualServiceIPv6 = net.ParseIP("fc01::aabb:ccdd:eeff")
)

type GatewayConfig struct {
	// Name is the name of host gateway, e.g. antrea-gw0.
	Name string

	IPv4 net.IP
	IPv6 net.IP
	MAC  net.HardwareAddr
	// LinkIndex is the link index of host gateway.
	LinkIndex int
}

func (g *GatewayConfig) String() string {
	return fmt.Sprintf("Name %s: IPv4 %s, IPv6 %s, MAC %s", g.Name, g.IPv4, g.IPv6, g.MAC)
}

type AdapterNetConfig struct {
	Name       string
	Index      int
	MAC        net.HardwareAddr
	IP         *net.IPNet
	Gateway    string
	DNSServers string
	Routes     []interface{}
}

type WireGuardConfig struct {
	// Name is the name of WireGurad interface. e.g. antrea-wg0.
	Name string
	// LinkIndex is the link index of WireGuard interface.
	LinkIndex int
	// Port is the port for the WireGuard to receive traffic.
	Port int
	// The MTU of WireGuard interface.
	MTU int
}

type EgressConfig struct {
	ExceptCIDRs []net.IPNet
}

// Local Node configurations retrieved from K8s API or host networking state.
type NodeConfig struct {
	// The Node's name used in Kubernetes.
	Name string
	// The name of the OpenVSwitch bridge antrea-agent uses.
	OVSBridge string
	// The name of the default tunnel interface. Defaults to "antrea-tun0", but can
	// be overridden by the discovered tunnel interface name from the OVS bridge.
	DefaultTunName string
	// The CIDR block from which to allocate IPv4 address to Pod.
	// It's nil for the networkPolicyOnly trafficEncapMode which doesn't do IPAM.
	PodIPv4CIDR *net.IPNet
	// The CIDR block from where to allocate IPv6 address to Pod.
	// It's nil for the networkPolicyOnly trafficEncapMode which doesn't do IPAM.
	PodIPv6CIDR *net.IPNet
	// The Node's IPv4 address used in Kubernetes. It has the network mask information.
	NodeIPv4Addr *net.IPNet
	// The Node's IPv6 address used in Kubernetes. It has the network mask information.
	NodeIPv6Addr *net.IPNet
	// The name of the Node's transport interface. The transport interface defaults to the interface that has the K8s
	// Node IP, and can be overridden by the configuration parameters TransportInterface and TransportInterfaceCIDRs.
	NodeTransportInterfaceName string
	// The IPv4 address on the Node's transport interface. It is used for tunneling or routing the Pod traffic across Nodes.
	NodeTransportIPv4Addr *net.IPNet
	// The IPv6 address on the Node's transport interface. It is used for tunneling or routing the Pod traffic across Nodes.
	NodeTransportIPv6Addr *net.IPNet
	// The original MTU of the Node's transport interface.
	NodeTransportInterfaceMTU int
	// Set either via defaultMTU config in antrea.yaml or auto discovered.
	// Auto discovery will use MTU value of the Node's primary interface.
	// For Encap and Hybrid mode, Node MTU will be adjusted to account for encap header.
	NodeMTU int
	// The config of the gateway interface on the OVS bridge.
	GatewayConfig *GatewayConfig
	// The config of the OVS bridge uplink interface. Only for Windows Node.
	UplinkNetConfig *AdapterNetConfig
	// The config of the WireGuard interface.
	WireGuardConfig *WireGuardConfig
	// The config of the Egress interface.
	EgressConfig *EgressConfig
}

func (n *NodeConfig) String() string {
	return fmt.Sprintf("NodeName: %s, OVSBridge: %s, PodIPv4CIDR: %s, PodIPv6CIDR: %s, NodeIPv4: %s, NodeIPv6: %s, TransportIPv4: %s, TransportIPv6: %s, Gateway: %s",
		n.Name, n.OVSBridge, n.PodIPv4CIDR, n.PodIPv6CIDR, n.NodeIPv4Addr, n.NodeIPv6Addr, n.NodeTransportIPv4Addr, n.NodeTransportIPv6Addr, n.GatewayConfig)
}

// NetworkConfig includes user provided network configuration parameters.
type NetworkConfig struct {
	TrafficEncapMode      TrafficEncapModeType
	TunnelType            ovsconfig.TunnelType
	TrafficEncryptionMode TrafficEncryptionModeType
	IPSecPSK              string
	TransportIface        string
	TransportIfaceCIDRs   []string
	IPv4Enabled           bool
	IPv6Enabled           bool
}

// IsIPv4Enabled returns true if the cluster network supports IPv4.
func IsIPv4Enabled(nodeConfig *NodeConfig, trafficEncapMode TrafficEncapModeType) bool {
	return nodeConfig.PodIPv4CIDR != nil ||
		(trafficEncapMode.IsNetworkPolicyOnly() && nodeConfig.NodeIPv4Addr != nil)
}

// IsIPv6Enabled returns true if the cluster network supports IPv6.
func IsIPv6Enabled(nodeConfig *NodeConfig, trafficEncapMode TrafficEncapModeType) bool {
	return nodeConfig.PodIPv6CIDR != nil ||
		(trafficEncapMode.IsNetworkPolicyOnly() && nodeConfig.NodeIPv6Addr != nil)
}

// NeedsTunnelToPeer returns true if Pod traffic to peer Node needs to be encapsulated by OVS tunneling.
func (nc *NetworkConfig) NeedsTunnelToPeer(peerIP net.IP, localIP *net.IPNet) bool {
	if nc.TrafficEncryptionMode == TrafficEncryptionModeWireGuard {
		return false
	}
	return nc.TrafficEncapMode == TrafficEncapModeEncap || (nc.TrafficEncapMode == TrafficEncapModeHybrid && !localIP.Contains(peerIP))
}

// NeedsDirectRoutingToPeer returns true if Pod traffic to peer Node needs a direct route installed to the routing table.
func (nc *NetworkConfig) NeedsDirectRoutingToPeer(peerIP net.IP, localIP *net.IPNet) bool {
	return (nc.TrafficEncapMode == TrafficEncapModeNoEncap || nc.TrafficEncapMode == TrafficEncapModeHybrid) && localIP.Contains(peerIP)
}
