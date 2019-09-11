package agent

import (
	"k8s.io/klog"
	"net"
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
	IP           net.IP
	MAC          net.HardwareAddr
	PodName      string
	PodNamespace string
	NetNS        string
	*OvsPortConfig
}

// InterfaceStore is a service interface to create local interfaces for container, host gateway, and tunnel port.
// Support add/delete/get operations
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
// retrieved from existing OVS ports
// Todo: add periodic task to sync local cache with container veth pair

type interfaceCache struct {
	cache map[string]*InterfaceConfig
}

var ifaceCache *interfaceCache

func (c *interfaceCache) Initialize(ovsBridgeClient ovsconfig.OVSBridgeClient, gatewayPort string, tunnelPort string) error {
	ovsPorts, err := ovsBridgeClient.GetPortList()
	if err != nil {
		klog.Errorf("Failed to list OVS ports: %v", err)
		return err
	}

	for _, port := range ovsPorts {
		ovsPort := &OvsPortConfig{IfaceName: port.Name, PortUUID: port.UUID, OFPort: port.OFPort}
		var intf *InterfaceConfig
		switch {
		case port.Name == gatewayPort:
			intf = &InterfaceConfig{Type: GatewayInterface, OvsPortConfig: ovsPort, ID: gatewayPort}
		case port.Name == tunnelPort:
			intf = &InterfaceConfig{Type: TunnelInterface, OvsPortConfig: ovsPort, ID: tunnelPort}
		default:
			if port.ExternalIDs == nil {
				klog.Infof("OVS port %s has no external_ids, continue to next", port.Name)
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
				intf = &InterfaceConfig{Type: ContainerInterface, OvsPortConfig: ovsPort, ID: containerID,
					IP: containerIP, MAC: containerMAC}
			}
		}
		if intf != nil {
			c.cache[intf.ID] = intf
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
	return externalIDs
}

// AddInterface adds interfaceConfig into localCache
func (c *interfaceCache) AddInterface(key string, interfaceConfig *InterfaceConfig) {
	c.cache[key] = interfaceConfig
}

// DeleteInterface deletes interface from local cache
func (c *interfaceCache) DeleteInterface(ifaceID string) {
	delete(c.cache, ifaceID)
}

// GetInterface retrieves interface from local cache
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
