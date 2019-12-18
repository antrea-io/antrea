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

package types

import (
	"fmt"
	"github.com/vishvananda/netlink"
	"net"
)

const (
	DefaultTunPortName = "tun0"
	DefaultTunOFPort   = 1
	HostGatewayOFPort  = 2
)

type GatewayConfig struct {
	IP   net.IP
	MAC  net.HardwareAddr
	Name string
}

func (g *GatewayConfig) String() string {
	return fmt.Sprintf("%s: IP %s, MAC %s", g.Name, g.IP, g.MAC)
}

type ServiceRtTableConfig struct {
	Idx  int
	Name string
}

func (s *ServiceRtTableConfig) String() string {
	return fmt.Sprintf("%s: idx %d", s.Name, s.Idx)
}

func (s *ServiceRtTableConfig) IsMainTable() bool {
	return s.Name == "main"
}

type NodeConfig struct {
	Bridge         string
	Name           string
	PodCIDR        *net.IPNet
	NodeIPAddr     *net.IPNet
	NodeDefaultDev netlink.Link
	PodEncapMode   PodEncapMode
	GatewayConfig  *GatewayConfig
	ServiceCIDR    *net.IPNet
	ServiceRtTable *ServiceRtTableConfig
}

func (n *NodeConfig) String() string {
	return fmt.Sprintf("\nNodeName: %s\nPodCIDR: %s\nNodeIP: %s\nDev:%s\nEncapMode: %s\nGateway: %s\n"+
		"ServiceCIDR: %s\nServieRT: %s", n.Name, n.PodCIDR, n.NodeIPAddr, n.NodeDefaultDev.Attrs().Name, n.PodEncapMode, n.GatewayConfig,
		n.ServiceCIDR, n.ServiceRtTable)
}
