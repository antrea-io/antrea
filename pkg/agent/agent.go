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
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/vishvananda/netlink"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/cniserver"
	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/agent/controller/noderoute"
	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	"github.com/vmware-tanzu/antrea/pkg/agent/iptables"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow/cookie"
	"github.com/vmware-tanzu/antrea/pkg/agent/route"
	"github.com/vmware-tanzu/antrea/pkg/agent/types"
	"github.com/vmware-tanzu/antrea/pkg/agent/util"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsconfig"
)

const (
	maxRetryForHostLink = 5
	// nodeNameEnvKey is environment variable.
	nodeNameEnvKey = "NODE_NAME"
	// ipsecPSKEnvKey is environment variable.
	ipsecPSKEnvKey          = "ANTREA_IPSEC_PSK"
	roundNumKey             = "roundNum" // round number key in externalIDs.
	initialRoundNum         = 1
	maxRetryForRoundNumSave = 5
)

// Initializer knows how to setup host networking, OpenVSwitch, and Openflow.
type Initializer struct {
	client          clientset.Interface
	ovsBridgeClient ovsconfig.OVSBridgeClient
	ofClient        openflow.Client
	routeClient     *route.Client
	iptablesClient  *iptables.Client
	ifaceStore      interfacestore.InterfaceStore
	hostGateway     string     // name of gateway port on the OVS bridge
	mtu             int        // Pod network interface MTU
	serviceCIDR     *net.IPNet // K8s Service ClusterIP CIDR
	networkConfig   *config.NetworkConfig
	nodeConfig      *config.NodeConfig
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
	k8sClient clientset.Interface,
	ovsBridgeClient ovsconfig.OVSBridgeClient,
	ofClient openflow.Client,
	routeClient *route.Client,
	iptablesClient *iptables.Client,
	ifaceStore interfacestore.InterfaceStore,
	hostGateway string,
	mtu int,
	serviceCIDR *net.IPNet,
	networkConfig *config.NetworkConfig) *Initializer {
	return &Initializer{
		ovsBridgeClient: ovsBridgeClient,
		client:          k8sClient,
		ifaceStore:      ifaceStore,
		ofClient:        ofClient,
		routeClient:     routeClient,
		iptablesClient:  iptablesClient,
		hostGateway:     hostGateway,
		mtu:             mtu,
		serviceCIDR:     serviceCIDR,
		networkConfig:   networkConfig,
	}
}

// GetNodeConfig returns the NodeConfig.
func (i *Initializer) GetNodeConfig() *config.NodeConfig {
	return i.nodeConfig
}

// setupOVSBridge sets up the OVS bridge and create host gateway interface and tunnel port
func (i *Initializer) setupOVSBridge() error {
	if err := i.ovsBridgeClient.Create(); err != nil {
		klog.Error("Failed to create OVS bridge: ", err)
		return err
	}

	// Initialize interface cache
	if err := i.initInterfaceStore(); err != nil {
		return err
	}

	if err := i.setupDefaultTunnelInterface(config.DefaultTunPortName); err != nil {
		return err
	}

	// Setup host gateway interface
	err := i.setupGatewayInterface()
	if err != nil {
		return err
	}

	// send_redirects for the interface will be enabled if at least one of
	// conf/{all,interface}/send_redirects is set to TRUE, so "all" and the
	// interface must be disabled together.
	// See https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt.
	if err := disableICMPSendRedirects("all"); err != nil {
		return err
	}
	if err := disableICMPSendRedirects(i.hostGateway); err != nil {
		return err
	}
	return nil
}

// initInterfaceStore initializes InterfaceStore with all OVS ports retrieved
// from the OVS bridge.
func (i *Initializer) initInterfaceStore() error {
	ovsPorts, err := i.ovsBridgeClient.GetPortList()
	if err != nil {
		klog.Errorf("Failed to list OVS ports: %v", err)
		return err
	}

	ifaceList := make([]*interfacestore.InterfaceConfig, 0, len(ovsPorts))
	for index := range ovsPorts {
		port := &ovsPorts[index]
		ovsPort := &interfacestore.OVSPortConfig{
			PortUUID: port.UUID,
			OFPort:   port.OFPort}
		var intf *interfacestore.InterfaceConfig
		switch {
		case port.Name == i.hostGateway:
			intf = &interfacestore.InterfaceConfig{
				Type:          interfacestore.GatewayInterface,
				InterfaceName: port.Name,
				OVSPortConfig: ovsPort}
		case port.IFType == ovsconfig.VXLANTunnel:
			fallthrough
		case port.IFType == ovsconfig.GeneveTunnel:
			fallthrough
		case port.IFType == ovsconfig.GRETunnel:
			fallthrough
		case port.IFType == ovsconfig.STTTunnel:
			intf = noderoute.ParseTunnelInterfaceConfig(port, ovsPort)
		default:
			// The port should be for a container interface.
			intf = cniserver.ParseOVSPortInterfaceConfig(port, ovsPort)
		}
		if intf != nil {
			ifaceList = append(ifaceList, intf)
		}
	}

	i.ifaceStore.Initialize(ifaceList)
	return nil
}

// Initialize sets up agent initial configurations.
func (i *Initializer) Initialize() error {
	klog.Info("Setting up node network")

	if err := i.initNodeLocalConfig(); err != nil {
		return err
	}

	if err := i.readIPSecPSK(); err != nil {
		return err
	}

	// Setup iptables chains and rules.
	if err := i.iptablesClient.Initialize(i.nodeConfig); err != nil {
		return fmt.Errorf("error setting up iptables rules: %v", err)
	}

	if err := i.setupOVSBridge(); err != nil {
		return err
	}

	// Install Openflow entries on OVS bridge
	if err := i.initOpenFlowPipeline(); err != nil {
		return err
	}

	if err := i.routeClient.Initialize(i.nodeConfig); err != nil {
		return err
	}

	klog.Infof("Agent initialized NodeConfig=%v, NetworkConfig=%v", i.nodeConfig, i.networkConfig)
	return nil
}

// persistRoundNum will save the provided round number to OVSDB as an external ID. To account for
// transient failures, this (synchronous) function includes a retry mechanism.
func persistRoundNum(num uint64, bridgeClient ovsconfig.OVSBridgeClient, interval time.Duration, maxRetries int) {
	klog.Infof("Persisting round number %d to OVSDB", num)
	retry := 0
	for {
		err := saveRoundNum(num, bridgeClient)
		if err == nil {
			klog.Infof("Round number %d was persisted to OVSDB", num)
			return // success
		}
		klog.Errorf("Error when writing round number to OVSDB: %v", err)
		if retry >= maxRetries {
			break
		}
		time.Sleep(interval)
	}
	klog.Errorf("Unable to persist round number %d to OVSDB after %d tries", num, maxRetries+1)
}

// initOpenFlowPipeline sets up necessary Openflow entries, including pipeline, classifiers, conn_track, and gateway flows
// Every time the agent is (re)started, we go through the following sequence:
//   1. agent determines the new round number (this is done by incrementing the round number
//   persisted in OVSDB, or if it's not available by picking round 1).
//   2. any existing flow for which the round number matches the round number obtained from step 1
//   is deleted.
//   3. all required flows are installed, using the round number obtained from step 1.
//   4. after convergence, all existing flows for which the round number matches the previous round
//   number (i.e. the round number which was persisted in OVSDB, if any) are deleted.
//   5. the new round number obtained from step 1 is persisted to OVSDB.
// The rationale for not persisting the new round number until after all previous flows have been
// deleted is to avoid a situation in which some stale flows are never deleted because of successive
// agent restarts (with the agent crashing before step 4 can be completed). With the sequence
// described above, We guarantee that at most two rounds of flows exist in the switch at any given
// time.
func (i *Initializer) initOpenFlowPipeline() error {
	roundInfo := getRoundInfo(i.ovsBridgeClient)
	// Setup all basic flows.
	ofConnCh, err := i.ofClient.Initialize(roundInfo, i.nodeConfig, i.networkConfig.TrafficEncapMode)
	if err != nil {
		klog.Errorf("Failed to initialize openflow client: %v", err)
		return err
	}

	// Setup flow entries for gateway interface, including classifier, skip spoof guard check,
	// L3 forwarding and L2 forwarding
	gateway, _ := i.ifaceStore.GetInterface(i.hostGateway)
	gatewayOFPort := uint32(gateway.OFPort)
	if err := i.ofClient.InstallGatewayFlows(gateway.IP, gateway.MAC, gatewayOFPort); err != nil {
		klog.Errorf("Failed to setup openflow entries for gateway: %v", err)
		return err
	}

	// When IPSec encyption is enabled, no flow is needed for the default tunnel interface.
	if i.networkConfig.TrafficEncapMode.SupportsEncap() {
		// Setup flow entries for the default tunnel port interface.
		if err := i.ofClient.InstallDefaultTunnelFlows(config.DefaultTunOFPort); err != nil {
			klog.Errorf("Failed to setup openflow entries for tunnel interface: %v", err)
			return err
		}
	}

	// Setup flow entries to enable service connectivity. Upstream kube-proxy is leveraged to
	// provide load-balancing, and the flows installed by this method ensure that traffic sent
	// from local Pods to any Service address can be forwarded to the host gateway interface
	// correctly. Otherwise packets might be dropped by egress rules before they are DNATed to
	// backend Pods.
	if err := i.ofClient.InstallClusterServiceCIDRFlows(i.serviceCIDR, gatewayOFPort); err != nil {
		klog.Errorf("Failed to setup openflow entries for Cluster Service CIDR %s: %v", i.serviceCIDR, err)
		return err
	}

	go func() {
		// Delete stale flows from previous round. We need to wait long enough to ensure
		// that all the flow which are still required have received an updated cookie (with
		// the new round number), otherwise we would disrupt the dataplane. Unfortunately,
		// the time required for convergence may be large and there is no simple way to
		// determine when is a right time to perform the cleanup task.
		// TODO: introduce a deterministic mechanism through which the different entities
		// responsible for installing flows can notify the agent that this deletion
		// operation can take place.
		time.Sleep(10 * time.Second)
		klog.Info("Deleting stale flows from previous round if any")
		if err := i.ofClient.DeleteStaleFlows(); err != nil {
			klog.Errorf("Error when deleting stale flows from previous round: %v", err)
			return
		}
		persistRoundNum(roundInfo.RoundNum, i.ovsBridgeClient, 1*time.Second, maxRetryForRoundNumSave)
	}()

	go func() {
		for {
			if _, ok := <-ofConnCh; !ok {
				return
			}
			klog.Info("Replaying OF flows to OVS bridge")
			i.ofClient.ReplayFlows()
			klog.Info("Flow replay completed")
		}
	}()

	return nil
}

// setupGatewayInterface creates the host gateway interface which is an internal port on OVS. The ofport for host
// gateway interface is predefined, so invoke CreateInternalPort with a specific ofport_request
func (i *Initializer) setupGatewayInterface() error {
	// Create host Gateway port if it does not exist
	gatewayIface, portExists := i.ifaceStore.GetInterface(i.hostGateway)
	if !portExists {
		klog.V(2).Infof("Creating gateway port %s on OVS bridge", i.hostGateway)
		gwPortUUID, err := i.ovsBridgeClient.CreateInternalPort(i.hostGateway, config.HostGatewayOFPort, nil)
		if err != nil {
			klog.Errorf("Failed to add host interface %s on OVS: %v", i.hostGateway, err)
			return err
		}
		gatewayIface = interfacestore.NewGatewayInterface(i.hostGateway)
		gatewayIface.OVSPortConfig = &interfacestore.OVSPortConfig{gwPortUUID, config.HostGatewayOFPort}
		i.ifaceStore.AddInterface(gatewayIface)
	} else {
		klog.V(2).Infof("Gateway port %s already exists on OVS bridge", i.hostGateway)
	}

	// Idempotent operation to set the gateway's MTU: we perform this operation regardless of
	// whether or not the gateway interface already exists, as the desired MTU may change across
	// restarts.
	klog.V(4).Infof("Setting gateway interface %s MTU to %d", i.hostGateway, i.mtu)
	_ = i.ovsBridgeClient.SetInterfaceMTU(i.hostGateway, i.mtu)
	// host link might not be queried at once after create OVS internal port, retry max 5 times with 1s
	// delay each time to ensure the link is ready. If still failed after max retry return error.
	link, err := func() (netlink.Link, error) {
		for retry := 0; retry < maxRetryForHostLink; retry++ {
			if link, err := netlink.LinkByName(i.hostGateway); err != nil {
				klog.V(2).Infof("Not found host link for gateway %s, retry after 1s", i.hostGateway)
				if _, ok := err.(netlink.LinkNotFoundError); ok {
					time.Sleep(1 * time.Second)
				} else {
					return link, err
				}
			} else {
				return link, nil
			}
		}
		return nil, fmt.Errorf("link %s not found", i.hostGateway)
	}()
	if err != nil {
		klog.Errorf("Failed to find host link for gateway %s: %v", i.hostGateway, err)
		return err
	}

	// Set host gateway interface up
	if err := netlink.LinkSetUp(link); err != nil {
		klog.Errorf("Failed to set host link for %s up: %v", i.hostGateway, err)
		return err
	}

	// Configure host gateway IP using the first address of node localSubnet
	localSubnet := i.nodeConfig.PodCIDR
	subnetID := localSubnet.IP.Mask(localSubnet.Mask)
	gwIP := &net.IPNet{IP: ip.NextIP(subnetID), Mask: localSubnet.Mask}
	gwAddr := &netlink.Addr{IPNet: gwIP, Label: ""}
	gwMAC := link.Attrs().HardwareAddr
	i.nodeConfig.GatewayConfig = &config.GatewayConfig{LinkIndex: link.Attrs().Index, Name: i.hostGateway, IP: gwIP.IP, MAC: gwMAC}
	gatewayIface.IP = gwIP.IP
	gatewayIface.MAC = gwMAC

	// Check IP address configuration on existing interface, return if already has target
	// address
	// We perform this check unconditionally, even if the OVS port did not exist when this
	// function was called (i.e. portExists is false). Indeed, it may be possible for the Linux
	// interface to exist even if the OVS bridge does not exist.
	if addrs, err := netlink.AddrList(link, netlink.FAMILY_V4); err != nil {
		klog.Errorf("Failed to query IPv4 address list for interface %s: %v", i.hostGateway, err)
		return err
	} else if addrs != nil {
		for _, addr := range addrs {
			klog.V(4).Infof("Found IPv4 address %s for interface %s", addr.IP.String(), i.hostGateway)
			if addr.IP.Equal(gwAddr.IPNet.IP) {
				klog.V(2).Infof("IPv4 address %s already assigned to interface %s", addr.IP.String(), i.hostGateway)
				return nil
			}
		}
	} else {
		klog.V(2).Infof("Link %s has no configured IPv4 address", i.hostGateway)
	}

	klog.V(2).Infof("Adding address %v to gateway interface %s", gwAddr, i.hostGateway)
	if err := netlink.AddrAdd(link, gwAddr); err != nil {
		klog.Errorf("Failed to set gateway interface %s with address %v: %v", i.hostGateway, gwAddr, err)
		return err
	}

	return nil
}

func (i *Initializer) setupDefaultTunnelInterface(tunnelPortName string) error {
	tunnelIface, portExists := i.ifaceStore.GetInterface(tunnelPortName)

	if !i.networkConfig.TrafficEncapMode.SupportsEncap() {
		if portExists {
			if err := i.ovsBridgeClient.DeletePort(tunnelIface.PortUUID); err != nil {
				klog.Errorf("Failed to removed tunnel port %s in NoEncapMode, err %s", tunnelPortName, err)
			} else {
				klog.V(2).Infof("Tunnel port %s removed for NoEncapMode", tunnelPortName)
			}
			i.ifaceStore.DeleteInterface(tunnelIface)
		}
		return nil
	}

	if portExists {
		klog.V(2).Infof("Tunnel port %s already exists on OVS", tunnelPortName)
		return nil
	}
	tunnelPortUUID, err := i.ovsBridgeClient.CreateTunnelPort(tunnelPortName, i.networkConfig.TunnelType, config.DefaultTunOFPort)
	if err != nil {
		klog.Errorf("Failed to add tunnel port %s type %s on OVS: %v", tunnelPortName, i.networkConfig.TunnelType, err)
		return err
	}
	tunnelIface = interfacestore.NewTunnelInterface(tunnelPortName, i.networkConfig.TunnelType)
	tunnelIface.OVSPortConfig = &interfacestore.OVSPortConfig{tunnelPortUUID, config.DefaultTunOFPort}
	i.ifaceStore.AddInterface(tunnelIface)
	return nil
}

// initNodeLocalConfig retrieves node's subnet CIDR from node.spec.PodCIDR, which is used for IPAM and setup
// host gateway interface.
func (i *Initializer) initNodeLocalConfig() error {
	nodeName, err := getNodeName()
	if err != nil {
		return err
	}
	node, err := i.client.CoreV1().Nodes().Get(nodeName, metav1.GetOptions{})
	if err != nil {
		klog.Errorf("Failed to get node from K8s with name %s: %v", nodeName, err)
		return err
	}
	// Spec.PodCIDR can be empty due to misconfiguration
	if node.Spec.PodCIDR == "" {
		klog.Errorf("Spec.PodCIDR is empty for Node %s. Please make sure --allocate-node-cidrs is enabled "+
			"for kube-controller-manager and --cluster-cidr specifies a sufficient CIDR range", nodeName)
		return fmt.Errorf("CIDR string is empty for node %s", nodeName)
	}
	_, localSubnet, err := net.ParseCIDR(node.Spec.PodCIDR)
	if err != nil {
		klog.Errorf("Failed to parse subnet from CIDR string %s: %v", node.Spec.PodCIDR, err)
		return err
	}
	ip, err := noderoute.GetNodeAddr(node)
	if err != nil {
		return fmt.Errorf("failed to obtain local IP address from k8s: %w", err)
	}
	localAddr, _, err := util.GetIPNetDeviceFromIP(ip)
	if err != nil {
		return fmt.Errorf("failed to get local IPNet:  %v", err)
	}

	i.nodeConfig = &config.NodeConfig{Name: nodeName, PodCIDR: localSubnet, NodeIPAddr: localAddr}
	return nil
}

// getNodeName returns the node's name used in Kubernetes, based on the priority:
// - Environment variable NODE_NAME, which should be set by Downward API
// - OS's hostname
func getNodeName() (string, error) {
	nodeName := os.Getenv(nodeNameEnvKey)
	if nodeName != "" {
		return nodeName, nil
	}
	klog.Infof("Environment variable %s not found, using hostname instead", nodeNameEnvKey)
	var err error
	nodeName, err = os.Hostname()
	if err != nil {
		klog.Errorf("Failed to get local hostname: %v", err)
		return "", err
	}
	return nodeName, nil
}

// readIPSecPSK reads the IPSec PSK value from environment variable
// ANTREA_IPSEC_PSK, when enableIPSecTunnel is set to true.
func (i *Initializer) readIPSecPSK() error {
	if !i.networkConfig.EnableIPSecTunnel {
		return nil
	}

	i.networkConfig.IPSecPSK = os.Getenv(ipsecPSKEnvKey)
	if i.networkConfig.IPSecPSK == "" {
		return fmt.Errorf("IPSec PSK environment variable is not set or is empty")
	}

	// Normally we want not to log the secret data.
	klog.V(4).Infof("IPSec PSK value: %s", i.networkConfig.IPSecPSK)
	return nil
}

func getLastRoundNum(bridgeClient ovsconfig.OVSBridgeClient) (uint64, error) {
	extIDs, ovsCfgErr := bridgeClient.GetExternalIDs()
	if ovsCfgErr != nil {
		return 0, fmt.Errorf("error getting external IDs: %w", ovsCfgErr)
	}
	roundNumValue, exists := extIDs[roundNumKey]
	if !exists {
		return 0, fmt.Errorf("no round number found in OVSDB")
	}
	num, err := strconv.ParseUint(roundNumValue, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("error parsing last round number %v: %w", num, err)
	}
	return num, nil
}

func saveRoundNum(num uint64, bridgeClient ovsconfig.OVSBridgeClient) error {
	extIDs, ovsCfgErr := bridgeClient.GetExternalIDs()
	if ovsCfgErr != nil {
		return fmt.Errorf("error getting external IDs: %w", ovsCfgErr)
	}
	updatedExtIDs := make(map[string]interface{})
	for k, v := range extIDs {
		updatedExtIDs[k] = v
	}
	updatedExtIDs[roundNumKey] = fmt.Sprint(num)
	return bridgeClient.SetExternalIDs(updatedExtIDs)
}

func getRoundInfo(bridgeClient ovsconfig.OVSBridgeClient) types.RoundInfo {
	roundInfo := types.RoundInfo{}
	num, err := getLastRoundNum(bridgeClient)
	if err != nil {
		klog.Infof("No round number found in OVSDB, using %v", initialRoundNum)
		// We use a fixed value instead of a randomly-generated value to ensure that stale
		// flows can be properly deleted in case of multiple rapid restarts when the agent
		// is first deployed to a Node.
		num = initialRoundNum
	} else {
		roundInfo.PrevRoundNum = new(uint64)
		*roundInfo.PrevRoundNum = num
		num++
	}

	num %= 1 << cookie.BitwidthRound
	klog.Infof("Using round number %d", num)
	roundInfo.RoundNum = num

	return roundInfo
}
