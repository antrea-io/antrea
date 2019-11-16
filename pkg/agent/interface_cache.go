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

package agent

import (
	"net"
	"sync"

	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/util"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsconfig"
)

const (
	OVSExternalIDMAC          = "attached-mac"
	OVSExternalIDIP           = "ip-address"
	OVSExternalIDContainerID  = "container-id"
	OVSExternalIDPodName      = "pod-name"
	OVSExternalIDPodNamespace = "pod-namespace"
)

type InterfaceType uint8

const (
	// ContainerInterface is used to mark current interface is for container
	ContainerInterface InterfaceType = iota
	// GatewayInterface is used to mark current interface is for host gateway
	GatewayInterface
	// TunnelInterface is used to mark current interface is for tunnel port
	TunnelInterface
)

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
	Initialize(ovsBridgeClient ovsconfig.OVSBridgeClient, gatewayPort string, tunnelPort string) error
	AddInterface(ifaceID string, interfaceConfig *InterfaceConfig)
	DeleteInterface(ifaceID string)
	GetInterface(ifaceID string) (*InterfaceConfig, bool)
	GetContainerInterface(podName string, podNamespace string) (*InterfaceConfig, bool)
	GetContainerInterfaceNum() int
	Len() int
	GetInterfaceIDs() []string
}

// Local cache for interfaces created on node, including container, host gateway, and tunnel
// ports, `Type` field is used to differentiate interface category
//  1) For container interface, the fields should include: containerID, podName, namespace, netns,
//     IP, MAC, and OVS Port configurations, and IfaceName is the cache key
//  2) For host gateway/tunnel port, the fields should include: name, IP, MAC, and OVS port
//     configurations, and IfaceName is the cache key
// OVS Port configurations include IfaceName, PortUUID and OFport. OFPort might be filled
// later when it is used to install openflow entry.
// Container interface is added into cache after invocation of cniserver.CmdAdd, and removed
// from cache after invocation of cniserver.CmdDel. For cniserver.CmdCheck, the server would
// check previousResult with local cache.
// Host gateway and tunnel interfaces are added into cache in node initialization phase or
// retrieved from existing OVS ports
// Todo: add periodic task to sync local cache with container veth pair

type interfaceCache struct {
	sync.RWMutex
	cache map[string]*InterfaceConfig
}

func (c *interfaceCache) Initialize(ovsBridgeClient ovsconfig.OVSBridgeClient, gatewayPort string, tunnelPort string) error {
	ovsPorts, err := ovsBridgeClient.GetPortList()
	if err != nil {
		klog.Errorf("Failed to list OVS ports: %v", err)
		return err
	}

	for _, port := range ovsPorts {
		ovsPort := &OVSPortConfig{IfaceName: port.Name, PortUUID: port.UUID, OFPort: port.OFPort}
		var intf *InterfaceConfig
		switch {
		case port.Name == gatewayPort:
			intf = &InterfaceConfig{Type: GatewayInterface, OVSPortConfig: ovsPort, ID: gatewayPort}
		case port.Name == tunnelPort:
			intf = &InterfaceConfig{Type: TunnelInterface, OVSPortConfig: ovsPort, ID: tunnelPort}
		default:
			if port.ExternalIDs == nil {
				klog.V(2).Infof("OVS port %s has no external_ids, continue to next", port.Name)
				continue
			}

			if containerID, found := port.ExternalIDs[OVSExternalIDContainerID]; found {
				containerIP := net.ParseIP(port.ExternalIDs[OVSExternalIDIP])
				containerMAC, err := net.ParseMAC(port.ExternalIDs[OVSExternalIDMAC])
				if err != nil {
					klog.Errorf("Failed to parse MAC address from OVS external config %s: %v",
						port.ExternalIDs[OVSExternalIDMAC], err)
					return err
				}
				podName, _ := port.ExternalIDs[OVSExternalIDPodName]
				podNamespace, _ := port.ExternalIDs[OVSExternalIDPodNamespace]
				intf = &InterfaceConfig{Type: ContainerInterface, OVSPortConfig: ovsPort, ID: containerID,
					IP: containerIP, MAC: containerMAC, PodName: podName, PodNamespace: podNamespace}
			}
		}
		if intf != nil {
			c.cache[intf.IfaceName] = intf
		}
	}
	return nil
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

// BuildOVSPortExternalIDs parses OVS port external_ids from local cache, it is used to check container configuration
func BuildOVSPortExternalIDs(containerConfig *InterfaceConfig) map[string]interface{} {
	externalIDs := make(map[string]interface{})
	externalIDs[OVSExternalIDMAC] = containerConfig.MAC.String()
	externalIDs[OVSExternalIDContainerID] = containerConfig.ID
	externalIDs[OVSExternalIDIP] = containerConfig.IP.String()
	externalIDs[OVSExternalIDPodName] = containerConfig.PodName
	externalIDs[OVSExternalIDPodNamespace] = containerConfig.PodNamespace
	return externalIDs
}

// AddInterface adds interfaceConfig into localCache
func (c *interfaceCache) AddInterface(ifaceID string, interfaceConfig *InterfaceConfig) {
	c.Lock()
	defer c.Unlock()
	c.cache[ifaceID] = interfaceConfig
}

// DeleteInterface deletes interface from local cache
func (c *interfaceCache) DeleteInterface(ifaceID string) {
	c.Lock()
	defer c.Unlock()
	delete(c.cache, ifaceID)
}

// GetInterface retrieves interface from local cache
func (c *interfaceCache) GetInterface(ifaceID string) (*InterfaceConfig, bool) {
	c.RLock()
	defer c.RUnlock()
	iface, found := c.cache[ifaceID]
	return iface, found
}

func (c *interfaceCache) GetContainerInterfaceNum() int {
	num := 0
	c.RLock()
	defer c.RUnlock()
	for _, v := range c.cache {
		if v.Type == ContainerInterface {
			num++
		}
	}
	return num
}

func (c *interfaceCache) Len() int {
	c.RLock()
	defer c.RUnlock()
	return len(c.cache)
}

func (c *interfaceCache) GetInterfaceIDs() []string {
	c.RLock()
	defer c.RUnlock()
	ids := make([]string, 0, len(c.cache))
	for id := range c.cache {
		ids = append(ids, id)
	}
	return ids
}

// GetPodInterface retrieves interface for Pod filtered by Pod name and Pod namespace.
func (c *interfaceCache) GetContainerInterface(podName string, podNamespace string) (*InterfaceConfig, bool) {
	ovsPortName := util.GenerateContainerInterfaceName(podName, podNamespace)
	c.RLock()
	defer c.RUnlock()
	iface, ok := c.cache[ovsPortName]
	return iface, ok
}

func NewInterfaceStore() InterfaceStore {
	return &interfaceCache{cache: map[string]*InterfaceConfig{}}
}
