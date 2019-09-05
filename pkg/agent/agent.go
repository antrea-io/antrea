package agent

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/TomCodeLV/OVSDB-golang-lib/pkg/ovsdb"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/vishvananda/netlink"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog"
	"okn/pkg/agent/openflow"
	"okn/pkg/iptables"
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

type AgentInitializer struct {
	ovsBridge       string
	hostGateway     string
	tunnelType      string
	client          clientset.Interface
	ifaceStore      InterfaceStore
	nodeConfig      *NodeConfig
	ovsdbConnection *ovsdb.OVSDB
	ovsBridgeClient ovsconfig.OVSBridgeClient
	serviceCIDR     *net.IPNet
	ofClient        openflow.Client
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

func NewInitializer(
	ovsBridge, hostGateway, tunnelType string,
	serviceCIDR string,
	client clientset.Interface,
	ifaceStore InterfaceStore,
) *AgentInitializer {
	// Parse service CIDR configuration. config.ServiceCIDR is checked in option.validate, so
	// it should be a valid configuration here.
	_, serviceCIDRNet, _ := net.ParseCIDR(serviceCIDR)
	return &AgentInitializer{
		ovsBridge:   ovsBridge,
		hostGateway: hostGateway,
		tunnelType:  tunnelType,
		client:      client,
		ifaceStore:  ifaceStore,
		serviceCIDR: serviceCIDRNet,
	}
}

// Close OVSDB connection.
func (ai *AgentInitializer) Cleanup() {
	ai.ovsdbConnection.Close()
}

// Return InterfaceStore.
func (ai *AgentInitializer) GetInterfaceStore() InterfaceStore {
	return ai.ifaceStore
}

// Return NodeConfig.
func (ai *AgentInitializer) GetNodeConfig() *NodeConfig {
	return ai.nodeConfig
}

// Return GetOVSBridgeClient.
func (ai *AgentInitializer) GetOVSBridgeClient() ovsconfig.OVSBridgeClient {
	return ai.ovsBridgeClient
}

// Return openflow client
func (ai *AgentInitializer) GetOFClient() openflow.Client {
	return ai.ofClient
}

// Setup OVS bridge and create host gateway interface and tunnel port
func (ai *AgentInitializer) setupOVSBridge() error {
	if err := ai.ovsBridgeClient.Create(); err != nil {
		klog.Error("Failed to create OVS bridge: ", err)
		return err
	}

	// Initialize interface cache
	if err := ai.ifaceStore.Initialize(ai.ovsBridgeClient, ai.hostGateway, TunPortName); err != nil {
		return err
	}
	// Setup Tunnel port on OVS
	if err := ai.setupTunnelInterface(TunPortName); err != nil {
		return err
	}

	// Setup host gateway interface
	err := ai.setupGatewayInterface()
	if err != nil {
		return err
	}

	// Disable `all` send ICMP redirects, otherwise disable send_redirects for other interfaces may not work
	if err := disableICMPSendRedirects("all"); err != nil {
		return err
	}
	// Disable host gateway send ICMP redirects
	if err := disableICMPSendRedirects(ai.hostGateway); err != nil {
		return err
	}
	return nil
}

func (ai *AgentInitializer) SetupNodeNetwork() error {
	klog.Info("Setting up node network")
	if err := ai.initNodeLocalConfig(ai.client); err != nil {
		return err
	}
	// Setup iptables chain and rules
	if err := iptables.SetupIPTables(); err != nil {
		return err
	}
	if err := iptables.SetupHostIPTablesRules(ai.hostGateway); err != nil {
		return err
	}

	ovsdbConnection, err := ovsconfig.NewOVSDBConnectionUDS("")
	if err != nil {
		// Todo: ovsconfig.NewOVSDBConnectionUDS might return timeout in the future, need to add retry
		// Currently it return nil
		klog.Errorf("Failed to open OVSDB connection")
		return err
	}

	// Create OVS bridge, add host gateway interface and tunnel port
	ai.ovsBridgeClient = ovsconfig.NewOVSBridge(ai.ovsBridge, ovsdbConnection)
	if err := ai.setupOVSBridge(); err != nil {
		ovsdbConnection.Close()
		return err
	}

	ai.ovsdbConnection = ovsdbConnection

	// Install Openflow entries on OVS bridge
	if err := ai.initOpenFlowPipeline(); err != nil {
		return err
	}

	return nil
}

// Setup necessary Openflow entries, including pipeline, classifiers, conn_track, and gateway flows
func (ai *AgentInitializer) initOpenFlowPipeline() error {
	var err error

	// Openflow pipeline is built while creating openflow client
	ai.ofClient, err = openflow.NewClient(ai.ovsBridge)
	if err != nil {
		klog.Errorf("Failed to create openflow client: %v", err)
		return err
	}

	// Setup flow entries for gateway interface, including classifier, skip spoof guard check,
	// L3 forwarding and L2 forwarding
	gateway, _ := ai.ifaceStore.GetInterface(ai.hostGateway)
	gatewayIP := net.ParseIP(gateway.IP)
	gatewayMAC, _ := net.ParseMAC(gateway.MAC)
	gatewayOFPort := uint32(gateway.OFPort)
	err = ai.ofClient.InstallGatewayFlows(gatewayIP, gatewayMAC, gatewayOFPort)
	if err != nil {
		klog.Errorf("Failed to setup openflow entries for gateway: %v", err)
		return err
	}

	// Setup flow entries for tunnel port Interface, including classifier and L2 Forwarding(match
	// vMAC as dst)
	if err := ai.ofClient.InstallTunnelFlows(tunOFPort); err != nil {
		klog.Errorf("Failed to setup openflow entries for tunnel interface: %v", err)
		return err
	}

	// Setup flow entries to enable service connectivity. Upstream kube-proxy is leveraged to
	// provide service feature, and this flow entry is to ensure traffic sent from pod to service
	// address could be forwarded to host gateway interface correctly. Otherwise packets might be
	// dropped by egress rules before they are DNATed to backend Pods.
	if err := ai.ofClient.InstallServiceFlows(ai.serviceCIDR.String(), ai.serviceCIDR, gatewayOFPort); err != nil {
		klog.Errorf("Failed to setup openflow entries for serviceCIDR %s: %v", ai.serviceCIDR, err)
		return err
	}
	return nil
}

// Create host gateway interface which is an internal port on OVS. The ofport for host gateway interface
// is predefined, so invoke CreateInternalPort with a specific ofport_request
func (ai *AgentInitializer) setupGatewayInterface() error {
	// Create host Gateway port if not existent
	gatewayIface, existed := ai.ifaceStore.GetInterface(ai.hostGateway)
	if !existed {
		gwPortUUID, err := ai.ovsBridgeClient.CreateInternalPort(ai.hostGateway, hostGatewayOFPort, nil)
		if err != nil {
			klog.Errorf("Failed to add host interface %s on OVS: %v", ai.hostGateway, err)
			return err
		}
		gatewayIface = NewGatewayInterface(ai.hostGateway)
		gatewayIface.OvsPortConfig = &OvsPortConfig{ai.hostGateway, gwPortUUID, hostGatewayOFPort}
		ai.ifaceStore.AddInterface(ai.hostGateway, gatewayIface)
	}
	// host link might not be queried at once after create OVS internal port, retry max 5 times with 1s
	// delay each time to ensure the link is ready. If still failed after max retry return error.
	link, err := func() (netlink.Link, error) {
		for i := 0; i < maxRetryForHostLink; i++ {
			if link, err := netlink.LinkByName(ai.hostGateway); err != nil {
				klog.V(2).Infof("Not found host link for gateway %s, retry after 1s", ai.hostGateway)
				if _, ok := err.(netlink.LinkNotFoundError); ok {
					time.Sleep(1 * time.Second)
				} else {
					return link, err
				}
			} else {
				return link, nil
			}
		}
		return nil, fmt.Errorf("Link %s not found", ai.hostGateway)
	}()
	if err != nil {
		klog.Errorf("Failed to find host link for gateway %s: %v", ai.hostGateway, err)
		return err
	}

	// Set host gateway interface up
	if err := netlink.LinkSetUp(link); err != nil {
		klog.Errorf("Failed to set host link for %s up: %v", ai.hostGateway, err)
		return err
	}

	// Configure host gateway IP using the first address of node localSubnet
	localSubnet := ai.nodeConfig.PodCIDR
	subnetID := localSubnet.IP.Mask(localSubnet.Mask)
	gwIP := &net.IPNet{IP: ip.NextIP(subnetID), Mask: localSubnet.Mask}
	gwAddr := &netlink.Addr{IPNet: gwIP, Label: ""}
	gwMAC := link.Attrs().HardwareAddr.String()
	ai.nodeConfig.Gateway = &Gateway{Name: ai.hostGateway, IP: gwIP.IP, MAC: gwMAC}
	gatewayIface.IP = gwIP.IP.String()
	gatewayIface.MAC = gwMAC

	// Check IP address configuration on existing interface, return if already has target address
	if existed {
		if addrs, err := netlink.AddrList(link, netlink.FAMILY_V4); err != nil {
			klog.Errorf("Failed to query gateway interface %s with address %v: %v", ai.hostGateway, gwAddr, err)
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
			klog.V(2).Infof("Link %s has not configured any address", ai.hostGateway)
		}
	}
	if err := netlink.AddrAdd(link, gwAddr); err != nil {
		klog.Errorf("Failed to set gateway interface %s with address %v: %v", ai.hostGateway, gwAddr, err)
		return err
	}
	return nil
}

func (ai *AgentInitializer) setupTunnelInterface(tunnelPortName string) error {
	tunnelIntf, existed := ai.ifaceStore.GetInterface(tunnelPortName)
	if existed {
		klog.V(2).Infof("Already exist port %s on OVS", tunnelPortName)
		return nil
	} else {
		var err error
		var tunnelPortUUID string
		switch ai.tunnelType {
		case ovsconfig.GENEVE_TUNNEL:
			tunnelPortUUID, err = ai.ovsBridgeClient.CreateGenevePort(tunnelPortName, tunOFPort, "")
		case ovsconfig.VXLAN_TUNNEL:
			tunnelPortUUID, err = ai.ovsBridgeClient.CreateVXLANPort(tunnelPortName, tunOFPort, "")
		default:
			err = fmt.Errorf("Unsupported tunnel type %s", ai.tunnelType)
		}
		if err != nil {
			klog.Errorf("Failed to add Tunnel port %s type %s on OVS: %v", tunnelPortName, ai.tunnelType, err)
			return err
		}
		tunnelIntf = NewTunnelInterface(tunnelPortName)
		tunnelIntf.OvsPortConfig = &OvsPortConfig{tunnelPortName, tunnelPortUUID, tunOFPort}
		ai.ifaceStore.AddInterface(tunnelPortName, tunnelIntf)
	}
	return nil
}

// Retrieve node's subnet CIDR from node.spec.PodCIDR, which is used for IPAM and setup
// host Gateway interface.
func (ai *AgentInitializer) initNodeLocalConfig(client clientset.Interface) error {
	// Todo: change other valid functions to find node except for hostname
	nodeName, err := os.Hostname()
	if err != nil {
		klog.Errorf("Failed to get local hostname: %v", err)
		return err
	}
	node, err := client.CoreV1().Nodes().Get(nodeName, metav1.GetOptions{})
	if err != nil || node == nil {
		klog.Errorf("Failed to get node from K8S with name %s: %v", nodeName, err)
		return err
	}
	localCidr := node.Spec.PodCIDR
	_, localSubnet, err := net.ParseCIDR(localCidr)
	if err != nil {
		klog.Errorf("Failed to parse subnet from CIDR string %s: %v", localCidr, err)
		return err
	}

	ai.nodeConfig = &NodeConfig{Name: nodeName, PodCIDR: localSubnet}
	return nil
}
