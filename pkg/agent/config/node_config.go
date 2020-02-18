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

	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsconfig"
)

const (
	DefaultTunPortName = "tun0"
	// Invalid ofport_request number is in range 1 to 65,279. For ofport_request number not in the range, OVS
	// ignore the it and automatically assign a port number.
	// Here we use an invalid port number "0" to request for automatically port allocation.
	AutoAssignedOFPort = 0
	DefaultTunOFPort   = 1
	HostGatewayOFPort  = 2
	UplinkOFPort       = 3
	// 0xfffffffe is a reserved port number in OpenFlow protocol, which is dedicated for the Bridge interface.
	BridgeOFPort = 0xfffffffe
)

type GatewayConfig struct {
	IP  net.IP
	MAC net.HardwareAddr
	// LinkIndex is the link index of host gateway.
	LinkIndex int
	// Name is the name of host gateway, e.g. gw0.
	Name string
}

func (g *GatewayConfig) String() string {
	return fmt.Sprintf("Name %s: IP %s, MAC %s", g.Name, g.IP, g.MAC)
}

type AdapterNetConfig struct {
	Name       string
	Index      int
	MAC        net.HardwareAddr
	IP         *net.IPNet
	Gateway    string
	DNSServers string
}

// Local Node configurations retrieved from K8s API or host networking state.
type NodeConfig struct {
	Name            string
	OVSBridge       string
	PodCIDR         *net.IPNet
	NodeIPAddr      *net.IPNet
	GatewayConfig   *GatewayConfig
	BridgeName      string
	UplinkNetConfig *AdapterNetConfig
}

func (n *NodeConfig) String() string {
	return fmt.Sprintf("NodeName: %s, OVSBridge: %s, PodCIDR: %s, NodeIP: %s, Gateway: %s",
		n.Name, n.OVSBridge, n.PodCIDR, n.NodeIPAddr, n.GatewayConfig)
}

// User provided network configuration parameters.
type NetworkConfig struct {
	TrafficEncapMode  TrafficEncapModeType
	TunnelType        ovsconfig.TunnelType
	EnableIPSecTunnel bool
	IPSecPSK          string
}
