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
	"strconv"

	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
)

const (
	// ContainerInterface is used to mark current interface is for container
	ContainerInterface InterfaceType = iota
	// GatewayInterface is used to mark current interface is for host gateway
	GatewayInterface
	// TunnelInterface is used to mark current interface is for tunnel port
	TunnelInterface
	// UplinkInterface is used to mark current interface is for uplink port
	UplinkInterface
	// TrafficControlInterface is used to mark current interface is for traffic control port
	TrafficControlInterface
	// ExternalEntityInterface is used to mark current interface is for ExternalEntity Endpoint
	ExternalEntityInterface
	// IPSecTunnelInterface is used to mark current interface is for IPSec tunnel port
	IPSecTunnelInterface

	AntreaInterfaceTypeKey = "antrea-type"
	AntreaGateway          = "gateway"
	AntreaContainer        = "container"
	AntreaTunnel           = "tunnel"
	AntreaUplink           = "uplink"
	AntreaHost             = "host"
	AntreaTrafficControl   = "traffic-control"
	AntreaIPsecTunnel      = "ipsec-tunnel"
	AntreaUnset            = ""
)

type InterfaceType uint8

func (t InterfaceType) String() string {
	return strconv.Itoa(int(t))
}

type OVSPortConfig struct {
	PortUUID string
	OFPort   int32
}

type ContainerInterfaceConfig struct {
	ContainerID  string
	PodName      string
	PodNamespace string
	// Interface name inside container.
	IFDev string
}

type TunnelInterfaceConfig struct {
	Type ovsconfig.TunnelType
	// Name of the remote Node.
	NodeName string
	// IP address of the local Node.
	LocalIP net.IP
	// IP address of the remote Node.
	RemoteIP net.IP
	// Destination port of the remote Node.
	DestinationPort int32
	// CommonName of the remote Name for certificate based authentication.
	RemoteName string
	// Pre-shard key for authentication.
	PSK string
	// Whether options:csum is set for this tunnel interface.
	// If true, encapsulation header UDP checksums will be computed on outgoing packets.
	Csum bool
}

type EntityInterfaceConfig struct {
	EntityName      string
	EntityNamespace string
	// UplinkPort is the OVS port configuration for the uplink, which is a pair port of this interface on OVS.
	UplinkPort *OVSPortConfig
}

type InterfaceConfig struct {
	Type InterfaceType
	// Unique name of the interface, also used for the OVS port name.
	InterfaceName string
	IPs           []net.IP
	MAC           net.HardwareAddr
	// VLAN ID of the interface
	VLANID uint16
	*OVSPortConfig
	*ContainerInterfaceConfig
	*TunnelInterfaceConfig
	*EntityInterfaceConfig
}

// InterfaceStore is a service interface to create local interfaces for container, host gateway, and tunnel port.
// Support add/delete/get operations
type InterfaceStore interface {
	Initialize(interfaces []*InterfaceConfig)
	AddInterface(interfaceConfig *InterfaceConfig)
	ListInterfaces() []*InterfaceConfig
	DeleteInterface(interfaceConfig *InterfaceConfig)
	GetInterface(interfaceKey string) (*InterfaceConfig, bool)
	GetInterfaceByName(interfaceName string) (*InterfaceConfig, bool)
	GetContainerInterface(containerID string) (*InterfaceConfig, bool)
	GetInterfacesByEntity(name string, namespace string) []*InterfaceConfig
	GetContainerInterfacesByPod(podName string, podNamespace string) []*InterfaceConfig
	GetInterfaceByIP(interfaceIP string) (*InterfaceConfig, bool)
	GetNodeTunnelInterface(nodeName string) (*InterfaceConfig, bool)
	GetInterfaceByOFPort(ofPort uint32) (*InterfaceConfig, bool)
	GetContainerInterfaceNum() int
	GetInterfacesByType(interfaceType InterfaceType) []*InterfaceConfig
	Len() int
	GetInterfaceKeysByType(interfaceType InterfaceType) []string
}

// NewContainerInterface creates InterfaceConfig for a Pod.
func NewContainerInterface(
	interfaceName string,
	containerID string,
	podName string,
	podNamespace string,
	ifDev string,
	mac net.HardwareAddr,
	ips []net.IP,
	vlanID uint16) *InterfaceConfig {
	containerConfig := &ContainerInterfaceConfig{
		ContainerID:  containerID,
		PodName:      podName,
		PodNamespace: podNamespace,
		IFDev:        ifDev}
	return &InterfaceConfig{
		InterfaceName:            interfaceName,
		Type:                     ContainerInterface,
		IPs:                      ips,
		MAC:                      mac,
		VLANID:                   vlanID,
		ContainerInterfaceConfig: containerConfig}
}

// NewGatewayInterface creates InterfaceConfig for the host gateway interface.
func NewGatewayInterface(gatewayName string, gatewayMAC net.HardwareAddr) *InterfaceConfig {
	gatewayConfig := &InterfaceConfig{InterfaceName: gatewayName, Type: GatewayInterface, MAC: gatewayMAC}
	return gatewayConfig
}

// NewTunnelInterface creates InterfaceConfig for the default tunnel port
// interface.
func NewTunnelInterface(tunnelName string, tunnelType ovsconfig.TunnelType, destinationPort int32, localIP net.IP, csum bool, ovsPortConfig *OVSPortConfig) *InterfaceConfig {
	tunnelConfig := &TunnelInterfaceConfig{Type: tunnelType, DestinationPort: destinationPort, LocalIP: localIP, Csum: csum}
	return &InterfaceConfig{InterfaceName: tunnelName, Type: TunnelInterface, TunnelInterfaceConfig: tunnelConfig, OVSPortConfig: ovsPortConfig}
}

// NewIPSecTunnelInterface creates InterfaceConfig for the IPsec tunnel to the
// Node.
func NewIPSecTunnelInterface(interfaceName string, tunnelType ovsconfig.TunnelType, nodeName string, nodeIP net.IP, psk, remoteName string, ovsPortConfig *OVSPortConfig) *InterfaceConfig {
	tunnelConfig := &TunnelInterfaceConfig{Type: tunnelType, NodeName: nodeName, RemoteIP: nodeIP, PSK: psk, RemoteName: remoteName}
	return &InterfaceConfig{InterfaceName: interfaceName, Type: IPSecTunnelInterface, TunnelInterfaceConfig: tunnelConfig, OVSPortConfig: ovsPortConfig}
}

// NewUplinkInterface creates InterfaceConfig for the uplink interface.
func NewUplinkInterface(uplinkName string) *InterfaceConfig {
	uplinkConfig := &InterfaceConfig{InterfaceName: uplinkName, Type: UplinkInterface}
	return uplinkConfig
}

func NewTrafficControlInterface(interfaceName string, ovsPortConfig *OVSPortConfig) *InterfaceConfig {
	trafficControlConfig := &InterfaceConfig{InterfaceName: interfaceName, Type: TrafficControlInterface, OVSPortConfig: ovsPortConfig}
	return trafficControlConfig
}

// TODO: remove this method after IPv4/IPv6 dual-stack is supported completely.
func (c *InterfaceConfig) GetIPv4Addr() net.IP {
	return util.GetIPv4Addr(c.IPs)
}

func (c *InterfaceConfig) GetIPv6Addr() net.IP {
	ipv6, _ := util.GetIPWithFamily(c.IPs, util.FamilyIPv6)
	return ipv6
}
