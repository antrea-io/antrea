package agent

import (
	"k8s.io/klog"
	"okn/pkg/ovs/ovsconfig"
)

const (
	OVSExternalIDMAC         = "attached-mac"
	OVSExternalIDIP          = "ip-address"
	OVSExternalIDContainerID = "container-id"
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

type OvsPortConfig struct {
	IfaceName string
	PortUUID  string
	OFPort    int32
}

type InterfaceConfig struct {
	ID           string
	Type         InterfaceType
	IP           string
	MAC          string
	PodName      string
	PodNamespace string
	NetNS        string
	*OvsPortConfig
}

// Service interface to create local interfaces for container, host gateway, and tunnel port. Support
// add/delete/get operations
type InterfaceStore interface {
	Initialize(ovsBridgeClient ovsconfig.OVSBridgeClient, gatewayPort string, tunnelPort string) error
	AddInterface(key string, interfaceConfig *InterfaceConfig)
	DeleteInterface(ifaceID string)
	GetInterface(ifaceID string) (*InterfaceConfig, bool)
	Len() int
}

// Local cache for interfaces created on node, including container, host gateway, and tunnel
// ports, `Type` field is used to differentiate interface category
//  1) For container interface, the fields should include: containerID, podName, namespace, netns,
//     IP, MAC, and OVS Port configurations, and containerID is the cache key
//  2) For host gateway/tunnel port, the fields should include: name, IP, MAC, and OVS port
//     configurations, and ifaceName is the cache key
// OVS Port configurations include ifacename, portUUID and OFport. OFPort might be filled
// later when it is used to install openflow entry.
// Container interface is added into cache after invocation of cniserver.CmdAdd, and removed
// from cache after invocation of cniserver.CmdDel. For cniserver.CmdCheck, the server would
// check previousResult with local cache.
// Host gateway and tunnel interfaces are added into cache in node initialization phase or
// retrieved from exited OVS ports
// Todo: add periodic task to sync local cache with container veth pair

type interfaceCache struct {
	cache map[string]*InterfaceConfig
}

var ifaceCache *interfaceCache

func (c *interfaceCache) Initialize(ovsBridgeClient ovsconfig.OVSBridgeClient, gatewayPort string, tunnelPort string) error {
	if ovsPorts, err := ovsBridgeClient.GetPortList(); err != nil {
		klog.Errorf("Failed to list OVS ports: %v", err)
		return err
	} else {
		for _, port := range ovsPorts {
			ovsPort := &OvsPortConfig{IfaceName: port.Name, PortUUID: port.UUID, OFPort: port.OFPort}
			var intf *InterfaceConfig
			if port.Name == gatewayPort {
				intf = &InterfaceConfig{Type: GatewayInterface, OvsPortConfig: ovsPort, ID: gatewayPort}
			} else if port.Name == tunnelPort {
				intf = &InterfaceConfig{Type: TunnelInterface, OvsPortConfig: ovsPort, ID: tunnelPort}
			} else if port.ExternalIDs != nil {
				if containerID, found := port.ExternalIDs[OVSExternalIDContainerID]; found {
					intf = &InterfaceConfig{Type: ContainerInterface, OvsPortConfig: ovsPort, ID: containerID,
						IP: port.ExternalIDs[OVSExternalIDIP], MAC: port.ExternalIDs[OVSExternalIDMAC]}
				}
			}
			if intf != nil {
				c.cache[intf.ID] = intf
			}
		}
	}
	return nil
}

// Create container interface configuration
func NewContainerInterface(containerID string, podName string, podNamespace string, containerNetNS string, mac string, ip string) *InterfaceConfig {
	containerConfig := &InterfaceConfig{ID: containerID, PodName: podName, PodNamespace: podNamespace, NetNS: containerNetNS, MAC: mac, IP: ip, Type: ContainerInterface}
	return containerConfig
}

// Create host gateway interface configuration
func NewGatewayInterface(gatewayName string) *InterfaceConfig {
	gatewayConfig := &InterfaceConfig{ID: gatewayName, Type: GatewayInterface}
	return gatewayConfig
}

// Create tunnel port interface configuration
func NewTunnelInterface(tunnelName string) *InterfaceConfig {
	tunnelConfig := &InterfaceConfig{ID: TunPortName, Type: TunnelInterface}
	return tunnelConfig
}

// Parse OVS port external_ids from local cache, it is used to check container configuration
func BuildOVSPortExternalIDs(containerConfig *InterfaceConfig) map[string]interface{} {
	externalIDs := make(map[string]interface{})
	externalIDs[OVSExternalIDMAC] = containerConfig.MAC
	externalIDs[OVSExternalIDContainerID] = containerConfig.ID
	externalIDs[OVSExternalIDIP] = containerConfig.IP
	return externalIDs
}

// Add interfaceConfig into localCache
func (c *interfaceCache) AddInterface(key string, interfaceConfig *InterfaceConfig) {
	c.cache[key] = interfaceConfig
}

// Delete interface from local cache
func (c *interfaceCache) DeleteInterface(ifaceID string) {
	delete(c.cache, ifaceID)
}

// Retrieve interface from local cache
func (c *interfaceCache) GetInterface(ifaceID string) (*InterfaceConfig, bool) {
	iface, found := c.cache[ifaceID]
	return iface, found
}

func (c *interfaceCache) Len() int {
	return len(c.cache)
}

func NewInterfaceStore() InterfaceStore {
	if ifaceCache == nil {
		ifaceCache = &interfaceCache{cache: map[string]*InterfaceConfig{}}
	}
	return ifaceCache
}
