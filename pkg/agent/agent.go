package agent

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/vishvananda/netlink"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog"
	"okn/pkg/ovs/ovsconfig"
)

const (
	TunPortName         = "tun0"
	tunOFPort           = 1
	hostGatewayOFPort   = 2
	maxRetryForHostLink = 5
)

type NodeConfig struct {
	Bridge  string
	Name    string
	PodCIDR *net.IPNet
	*Gateway
}

type Gateway struct {
	IP   net.IP
	MAC  string
	Name string
}

type agentInitializer struct {
	ifaceStore      InterfaceStore
	ovsBridgeClient ovsconfig.OVSBridgeClient
}

func disableICMPSendRedirects(intfName string) error {
	cmdStr := fmt.Sprintf("echo 0 > /proc/sys/net/ipv4/conf/%s/send_redirects", intfName)
	cmd := exec.Command("/bin/sh", "-c", cmdStr)
	if err := cmd.Run(); err != nil {
		klog.Errorf("Failed to disable send_redirect for interface %s: %v", intfName, err)
		return err
	}
	return nil
}

// Setup OVS bridge and create host gateway interface and tunnel port
func (ai *agentInitializer) setupOVSBridge(bridge string, gatewayIface string, tunType string, nodeConfig *NodeConfig) error {
	// Initialize interface cache
	if err := ai.ifaceStore.Initialize(ai.ovsBridgeClient, gatewayIface, TunPortName); err != nil {
		return err
	}
	// Setup Tunnel port on OVS
	if err := ai.setupTunnelInterface(TunPortName, tunType); err != nil {
		return err
	}

	// Setup host gateway interface
	err := ai.setupGatewayInterface(bridge, gatewayIface, nodeConfig)
	if err != nil {
		return err
	}

	// Disable `all` send ICMP redirects, otherwise disable send_redirects for other interfaces may not work
	if err := disableICMPSendRedirects("all"); err != nil {
		return err
	}
	// Disable host gateway send ICMP redirects
	if err := disableICMPSendRedirects(gatewayIface); err != nil {
		return err
	}
	return nil
}

func (ai *agentInitializer) SetupNodeNetwork(bridge string, gatewayIface string, tunType string, nodeConfig *NodeConfig) error {
	// Create OVS bridge, add host gateway interface and tunnel port
	if err := ai.setupOVSBridge(bridge, gatewayIface, tunType, nodeConfig); err != nil {
		return err
	}

	return nil
}

// Create host gateway interface which is an internal port on OVS. The ofport for host gateway interface
// is predefined, so invoke CreateInternalPort with a specific ofportRequest
func (ai *agentInitializer) setupGatewayInterface(bridge string, gatewayIfaceName string, nodeConfig *NodeConfig) error {
	// Create host Gateway port if not existent
	gatewayIface, existed := ai.ifaceStore.GetInterface(gatewayIfaceName)
	if !existed {
		gwPortUUID, err := ai.ovsBridgeClient.CreateInternalPort(gatewayIfaceName, hostGatewayOFPort, nil)
		if err != nil {
			klog.Errorf("Failed to add host interface %s on OVS %s: %v", gatewayIfaceName, bridge, err)
			return err
		}
		gatewayIface = NewGatewayInterface(gatewayIfaceName)
		gatewayIface.OvsPortConfig = &OvsPortConfig{gatewayIfaceName, gwPortUUID, hostGatewayOFPort}
		ai.ifaceStore.AddInterface(gatewayIfaceName, gatewayIface)
	}
	// host link might not be queried at once after create OVS internal port, retry max 5 times with 1s
	// delay each time to ensure the link is ready. If still failed after max retry return error.
	link, err := func() (netlink.Link, error) {
		for i := 0; i < maxRetryForHostLink; i++ {
			if link, err := netlink.LinkByName(gatewayIfaceName); err != nil {
				klog.V(2).Infof("Not found host link for gateway %s, retry after 1s", gatewayIfaceName)
				if _, ok := err.(netlink.LinkNotFoundError); ok {
					time.Sleep(1 * time.Second)
				} else {
					return link, err
				}
			} else {
				return link, nil
			}
		}
		return nil, fmt.Errorf("Link %s not found", gatewayIfaceName)
	}()
	if err != nil {
		klog.Errorf("Failed to find host link for gateway %s: %v", gatewayIfaceName, err)
		return err
	}

	// Set host gateway interface up
	if err := netlink.LinkSetUp(link); err != nil {
		klog.Errorf("Failed to set host link for %s up: %v", gatewayIfaceName, err)
		return err
	}

	// Configure host gateway IP using the first address of node localSubnet
	localSubnet := nodeConfig.PodCIDR
	subnetID := localSubnet.IP.Mask(localSubnet.Mask)
	gwIP := &net.IPNet{IP: ip.NextIP(subnetID), Mask: localSubnet.Mask}
	gwAddr := &netlink.Addr{IPNet: gwIP, Label: ""}
	gwMAC := link.Attrs().HardwareAddr.String()
	nodeConfig.Gateway = &Gateway{Name: gatewayIfaceName, IP: gwIP.IP, MAC: gwMAC}
	gatewayIface.IP = gwIP.IP.String()
	gatewayIface.MAC = gwMAC

	// Check IP address configuration on existing interface, return if already has target address
	if existed {
		if addrs, err := netlink.AddrList(link, netlink.FAMILY_V4); err != nil {
			klog.Errorf("Failed to query gateway interface %s with address %v: %v", gatewayIfaceName, gwAddr, err)
			return err
		} else if addrs != nil {
			for _, addr := range addrs {
				klog.V(2).Infof("Found existing addr %s from host", addr.IP.String())
				if addr.IP.Equal(gwAddr.IPNet.IP) {
					return nil
				}
			}
		} else {
			// Address is not configured on existing interface, try to configure it.
			klog.V(2).Infof("Link %s has not configured any address", gatewayIfaceName)
		}
	}
	if err := netlink.AddrAdd(link, gwAddr); err != nil {
		klog.Errorf("Failed to set gateway interface %s with address %v: %v", gatewayIfaceName, gwAddr, err)
		return err
	}
	return nil
}

func (ai *agentInitializer) setupTunnelInterface(tunnelPortName string, tunnelType string) error {
	tunnelIntf, existed := ai.ifaceStore.GetInterface(tunnelPortName)
	if existed {
		klog.V(2).Infof("Already exist port %s on OVS", tunnelPortName)
		return nil
	} else {
		var err error
		var tunnelPortUUID string
		switch tunnelType {
		case ovsconfig.GENEVE_TUNNEL:
			tunnelPortUUID, err = ai.ovsBridgeClient.CreateGenevePort(tunnelPortName, tunOFPort, "")
		case ovsconfig.VXLAN_TUNNEL:
			tunnelPortUUID, err = ai.ovsBridgeClient.CreateVXLANPort(tunnelPortName, tunOFPort, "")
		default:
			err = fmt.Errorf("Unsupported tunnel type %s", tunnelType)
		}
		if err != nil {
			klog.Errorf("Failed to add Tunnel port %s type %s on OVS: %v", tunnelPortName, tunnelType, err)
			return err
		}
		tunnelIntf = NewTunnelInterface(tunnelPortName)
		tunnelIntf.OvsPortConfig = &OvsPortConfig{tunnelPortName, tunnelPortUUID, tunOFPort}
		ai.ifaceStore.AddInterface(tunnelPortName, tunnelIntf)
	}
	return nil
}

func NewInitializer(ovsBridgeClient ovsconfig.OVSBridgeClient, ifaceStore InterfaceStore) *agentInitializer {
	return &agentInitializer{ovsBridgeClient: ovsBridgeClient, ifaceStore: ifaceStore}
}

// Retrieve node's subnet CDIR from node.spec.PodCIDR, which is used for IPAM and setup
// host Gateway interface.
func GetNodeLocalConfig(client clientset.Interface) (*NodeConfig, error) {
	// Todo: change other valid functions to find node except for hostname
	nodeName, err := os.Hostname()
	if err != nil {
		klog.Errorf("Failed to get local hostname: %v", err)
		return nil, err
	}
	node, err := client.CoreV1().Nodes().Get(nodeName, metav1.GetOptions{})
	if err != nil || node == nil {
		klog.Errorf("Failed to get node from K8S with name %s: %v", nodeName, err)
		return nil, err
	}
	localCidr := node.Spec.PodCIDR
	_, localSubnet, err := net.ParseCIDR(localCidr)
	if err != nil {
		klog.Errorf("Failed to parse subnet from CIDR string %s: %v", localCidr, err)
		return nil, err
	}

	return &NodeConfig{Name: nodeName, PodCIDR: localSubnet}, nil
}
