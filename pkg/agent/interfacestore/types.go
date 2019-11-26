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

package interfacestore

import (
	"net"
)

const (
	// ContainerInterface is used to mark current interface is for container
	ContainerInterface InterfaceType = iota
	// GatewayInterface is used to mark current interface is for host gateway
	GatewayInterface
	// TunnelInterface is used to mark current interface is for tunnel port
	TunnelInterface
)

type InterfaceType uint8

type OVSPortConfig struct {
	IfaceName string
	PortUUID  string
	OFPort    int32
}

type InterfaceConfig struct {
	ID           string
	Type         InterfaceType
	IP           net.IP
	MAC          net.HardwareAddr
	PodName      string
	PodNamespace string
	NetNS        string
	*OVSPortConfig
}

// InterfaceStore is a service interface to create local interfaces for container, host gateway, and tunnel port.
// Support add/delete/get operations
type InterfaceStore interface {
	Initialize(interfaces []*InterfaceConfig)
	AddInterface(ifaceID string, interfaceConfig *InterfaceConfig)
	DeleteInterface(ifaceID string)
	GetInterface(ifaceID string) (*InterfaceConfig, bool)
	GetContainerInterface(podName string, podNamespace string) (*InterfaceConfig, bool)
	GetContainerInterfaceNum() int
	Len() int
	GetInterfaceIDs() []string
}

// NewContainerInterface creates container interface configuration
func NewContainerInterface(containerID string, podName string, podNamespace string, containerNetNS string, mac net.HardwareAddr, ip net.IP) *InterfaceConfig {
	containerConfig := &InterfaceConfig{ID: containerID, PodName: podName, PodNamespace: podNamespace, NetNS: containerNetNS, MAC: mac, IP: ip, Type: ContainerInterface}
	return containerConfig
}

// NewGatewayInterface creates host gateway interface configuration
func NewGatewayInterface(gatewayName string) *InterfaceConfig {
	gatewayConfig := &InterfaceConfig{ID: gatewayName, Type: GatewayInterface}
	return gatewayConfig
}

// NewTunnelInterface creates tunnel port interface configuration
func NewTunnelInterface(tunnelName string) *InterfaceConfig {
	tunnelConfig := &InterfaceConfig{ID: tunnelName, Type: TunnelInterface}
	return tunnelConfig
}
