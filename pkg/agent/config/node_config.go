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
	DefaultTunOFPort   = 1
	HostGatewayOFPort  = 2
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

// Local Node configurations retrieved from K8s API or host networking state.
type NodeConfig struct {
	Name          string
	PodCIDR       *net.IPNet
	NodeIPAddr    *net.IPNet
	GatewayConfig *GatewayConfig
}

func (n *NodeConfig) String() string {
	return fmt.Sprintf("NodeName: %s, PodCIDR: %s, NodeIP: %s, Gateway: %s",
		n.Name, n.PodCIDR, n.NodeIPAddr, n.GatewayConfig)
}

// User provided network configuration parameters.
type NetworkConfig struct {
	TrafficEncapMode  TrafficEncapModeType
	TunnelType        ovsconfig.TunnelType
	EnableIPSecTunnel bool
	IPSecPSK          string
}
