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
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/containernetworking/plugins/pkg/ip"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apitypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/cniserver"
	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/controller/noderoute"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/openflow/cookie"
	"antrea.io/antrea/pkg/agent/route"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/agent/wireguard"
	"antrea.io/antrea/pkg/features"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/ovs/ovsctl"
	"antrea.io/antrea/pkg/util/env"
	"antrea.io/antrea/pkg/util/k8s"
)

const (
	// Default name of the default tunnel interface on the OVS bridge.
	defaultTunInterfaceName = "antrea-tun0"
	maxRetryForHostLink     = 5
	// ipsecPSKEnvKey is environment variable.
	ipsecPSKEnvKey          = "ANTREA_IPSEC_PSK"
	roundNumKey             = "roundNum" // round number key in externalIDs.
	initialRoundNum         = 1
	maxRetryForRoundNumSave = 5
)

var (
	// getIPNetDeviceFromIP is meant to be overridden for testing.
	getIPNetDeviceFromIP = util.GetIPNetDeviceFromIP

	// getIPNetDeviceByV4CIDR is meant to be overridden for testing.
	getIPNetDeviceByCIDRs = util.GetIPNetDeviceByCIDRs

	// getTransportIPNetDeviceByName is meant to be overridden for testing.
	getTransportIPNetDeviceByName = GetTransportIPNetDeviceByName
)

// Initializer knows how to setup host networking, OpenVSwitch, and Openflow.
type Initializer struct {
	client                clientset.Interface
	ovsBridgeClient       ovsconfig.OVSBridgeClient
	ofClient              openflow.Client
	routeClient           route.Interface
	wireGuardClient       wireguard.Interface
	ifaceStore            interfacestore.InterfaceStore
	ovsBridge             string
	hostGateway           string // name of gateway port on the OVS bridge
	mtu                   int
	serviceCIDR           *net.IPNet // K8s Service ClusterIP CIDR
	serviceCIDRv6         *net.IPNet // K8s Service ClusterIP CIDR in IPv6
	networkConfig         *config.NetworkConfig
	nodeConfig            *config.NodeConfig
	wireGuardConfig       *config.WireGuardConfig
	egressConfig          *config.EgressConfig
	enableProxy           bool
	connectUplinkToBridge bool
	// networkReadyCh should be closed once the Node's network is ready.
	// The CNI server will wait for it before handling any CNI Add requests.
	proxyAll              bool
	nodePortAddressesIPv4 []net.IP
	nodePortAddressesIPv6 []net.IP
	networkReadyCh        chan<- struct{}
	stopCh                <-chan struct{}
}

func NewInitializer(
	k8sClient clientset.Interface,
	ovsBridgeClient ovsconfig.OVSBridgeClient,
	ofClient openflow.Client,
	routeClient route.Interface,
	ifaceStore interfacestore.InterfaceStore,
	ovsBridge string,
	hostGateway string,
	mtu int,
	serviceCIDR *net.IPNet,
	serviceCIDRv6 *net.IPNet,
	networkConfig *config.NetworkConfig,
	wireGuardConfig *config.WireGuardConfig,
	egressConfig *config.EgressConfig,
	networkReadyCh chan<- struct{},
	stopCh <-chan struct{},
	enableProxy bool,
	proxyAll bool,
	nodePortAddressesIPv4 []net.IP,
	nodePortAddressesIPv6 []net.IP,
	connectUplinkToBridge bool,
) *Initializer {
	return &Initializer{
		ovsBridgeClient:       ovsBridgeClient,
		client:                k8sClient,
		ifaceStore:            ifaceStore,
		ofClient:              ofClient,
		routeClient:           routeClient,
		ovsBridge:             ovsBridge,
		hostGateway:           hostGateway,
		mtu:                   mtu,
		serviceCIDR:           serviceCIDR,
		serviceCIDRv6:         serviceCIDRv6,
		networkConfig:         networkConfig,
		wireGuardConfig:       wireGuardConfig,
		egressConfig:          egressConfig,
		networkReadyCh:        networkReadyCh,
		stopCh:                stopCh,
		enableProxy:           enableProxy,
		proxyAll:              proxyAll,
		nodePortAddressesIPv4: nodePortAddressesIPv4,
		nodePortAddressesIPv6: nodePortAddressesIPv6,
		connectUplinkToBridge: connectUplinkToBridge,
	}
}

// GetNodeConfig returns the NodeConfig.
func (i *Initializer) GetNodeConfig() *config.NodeConfig {
	return i.nodeConfig
}

// GetNodeConfig returns the NodeConfig.
func (i *Initializer) GetWireGuardClient() wireguard.Interface {
	return i.wireGuardClient
}

// setupOVSBridge sets up the OVS bridge and create host gateway interface and tunnel port
func (i *Initializer) setupOVSBridge() error {
	if err := i.ovsBridgeClient.Create(); err != nil {
		klog.Error("Failed to create OVS bridge: ", err)
		return err
	}

	if err := i.validateSupportedDPFeatures(); err != nil {
		return err
	}

	if err := i.prepareOVSBridge(); err != nil {
		return err
	}

	// Initialize interface cache
	if err := i.initInterfaceStore(); err != nil {
		return err
	}

	if err := i.setupDefaultTunnelInterface(); err != nil {
		return err
	}
	// Set up host gateway interface
	err := i.setupGatewayInterface()
	if err != nil {
		return err
	}

	return nil
}

func (i *Initializer) validateSupportedDPFeatures() error {
	gotFeatures, err := ovsctl.NewClient(i.ovsBridge).GetDPFeatures()
	if err != nil {
		return err
	}
	// Basic requirements.
	requiredFeatures := []ovsctl.DPFeature{
		ovsctl.CTStateFeature,
		ovsctl.CTZoneFeature,
		ovsctl.CTMarkFeature,
		ovsctl.CTLabelFeature,
	}
	// AntreaProxy requires CTStateNAT feature.
	if features.DefaultFeatureGate.Enabled(features.AntreaProxy) {
		requiredFeatures = append(requiredFeatures, ovsctl.CTStateNATFeature)
	}

	for _, feature := range requiredFeatures {
		supported, found := gotFeatures[feature]
		if !found {
			return fmt.Errorf("the required OVS DP feature '%s' support is unknown", feature)
		}
		if !supported {
			return fmt.Errorf("the required OVS DP feature '%s' is not supported", feature)
		}
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

	parseGatewayInterfaceFunc := func(port *ovsconfig.OVSPortData, ovsPort *interfacestore.OVSPortConfig) *interfacestore.InterfaceConfig {
		intf := &interfacestore.InterfaceConfig{
			Type:          interfacestore.GatewayInterface,
			InterfaceName: port.Name,
			OVSPortConfig: ovsPort}
		if intf.InterfaceName != i.hostGateway {
			klog.Warningf("The discovered gateway interface name %s is different from the configured value: %s",
				intf.InterfaceName, i.hostGateway)
			// Set the gateway interface name to the discovered name.
			i.hostGateway = intf.InterfaceName
		}
		return intf
	}
	parseUplinkInterfaceFunc := func(port *ovsconfig.OVSPortData, ovsPort *interfacestore.OVSPortConfig) *interfacestore.InterfaceConfig {
		return &interfacestore.InterfaceConfig{
			Type:          interfacestore.UplinkInterface,
			InterfaceName: port.Name,
			OVSPortConfig: ovsPort,
		}
	}
	parseTunnelInterfaceFunc := func(port *ovsconfig.OVSPortData, ovsPort *interfacestore.OVSPortConfig) *interfacestore.InterfaceConfig {
		intf := noderoute.ParseTunnelInterfaceConfig(port, ovsPort)
		if intf != nil && port.OFPort == config.DefaultTunOFPort &&
			intf.InterfaceName != i.nodeConfig.DefaultTunName {
			klog.Infof("The discovered default tunnel interface name %s is different from the default value: %s",
				intf.InterfaceName, i.nodeConfig.DefaultTunName)
			// Set the default tunnel interface name to the discovered name.
			i.nodeConfig.DefaultTunName = intf.InterfaceName
		}
		return intf
	}
	ifaceList := make([]*interfacestore.InterfaceConfig, 0, len(ovsPorts))
	for index := range ovsPorts {
		port := &ovsPorts[index]
		ovsPort := &interfacestore.OVSPortConfig{
			PortUUID: port.UUID,
			OFPort:   port.OFPort}
		var intf *interfacestore.InterfaceConfig
		interfaceType, ok := port.ExternalIDs[interfacestore.AntreaInterfaceTypeKey]
		if !ok {
			interfaceType = interfacestore.AntreaUnset
		}
		if interfaceType != interfacestore.AntreaUnset {
			switch interfaceType {
			case interfacestore.AntreaGateway:
				intf = parseGatewayInterfaceFunc(port, ovsPort)
			case interfacestore.AntreaUplink:
				intf = parseUplinkInterfaceFunc(port, ovsPort)
			case interfacestore.AntreaTunnel:
				intf = parseTunnelInterfaceFunc(port, ovsPort)
			case interfacestore.AntreaHost:
				// Not load the host interface, because it is configured on the OVS bridge port, and we don't need a
				// specific interface in the interfaceStore.
				intf = nil
			case interfacestore.AntreaContainer:
				// The port should be for a container interface.
				intf = cniserver.ParseOVSPortInterfaceConfig(port, ovsPort, true)
			default:
				klog.InfoS("Unknown Antrea interface type", "type", interfaceType)
			}
		} else {
			// Antrea Interface type is not saved in OVS port external_ids in earlier Antrea versions, so we use
			// the old way to decide the interface type for the upgrade case.
			uplinkIfName := i.nodeConfig.UplinkNetConfig.Name
			var antreaIFType string
			switch {
			case port.OFPort == config.HostGatewayOFPort:
				intf = parseGatewayInterfaceFunc(port, ovsPort)
				antreaIFType = interfacestore.AntreaGateway
			case port.Name == uplinkIfName:
				intf = parseUplinkInterfaceFunc(port, ovsPort)
				antreaIFType = interfacestore.AntreaUplink
			case port.IFType == ovsconfig.GeneveTunnel:
				fallthrough
			case port.IFType == ovsconfig.VXLANTunnel:
				fallthrough
			case port.IFType == ovsconfig.GRETunnel:
				fallthrough
			case port.IFType == ovsconfig.STTTunnel:
				intf = parseTunnelInterfaceFunc(port, ovsPort)
				antreaIFType = interfacestore.AntreaTunnel
			case port.Name == i.ovsBridge:
				intf = nil
				antreaIFType = interfacestore.AntreaHost
			default:
				// The port should be for a container interface.
				intf = cniserver.ParseOVSPortInterfaceConfig(port, ovsPort, true)
				antreaIFType = interfacestore.AntreaContainer
			}
			updatedExtIDs := make(map[string]interface{})
			for k, v := range port.ExternalIDs {
				updatedExtIDs[k] = v
			}
			updatedExtIDs[interfacestore.AntreaInterfaceTypeKey] = antreaIFType
			if err := i.ovsBridgeClient.SetPortExternalIDs(port.Name, updatedExtIDs); err != nil {
				klog.ErrorS(err, "Failed to set Antrea interface type on OVS port", "port", port.Name)
			}
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
	// wg is used to wait for the asynchronous initialization.
	var wg sync.WaitGroup

	if err := i.initNodeLocalConfig(); err != nil {
		return err
	}

	if err := i.prepareHostNetwork(); err != nil {
		return err
	}

	if err := i.setupOVSBridge(); err != nil {
		return err
	}

	// initializeWireGuard must be executed after setupOVSBridge as it requires gateway addresses on the OVS bridge.
	switch i.networkConfig.TrafficEncryptionMode {
	case config.TrafficEncryptionModeIPSec:
		if err := i.initializeIPSec(); err != nil {
			return err
		}
	case config.TrafficEncryptionModeWireGuard:
		if err := i.initializeWireGuard(); err != nil {
			return err
		}
	}

	wg.Add(1)
	// routeClient.Initialize() should be after i.setupOVSBridge() which
	// creates the host gateway interface.
	if err := i.routeClient.Initialize(i.nodeConfig, wg.Done); err != nil {
		return err
	}

	// Install OpenFlow entries on OVS bridge.
	if err := i.initOpenFlowPipeline(); err != nil {
		return err
	}

	// The Node's network is ready only when both synchronous and asynchronous initialization are done.
	go func() {
		wg.Wait()
		close(i.networkReadyCh)
	}()
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
// Note that at the moment we assume that all OpenFlow groups are deleted every time there is an
// Antrea Agent restart. This allows us to add the necessary groups without having to worry about
// the operation failing because a (stale) group with the same ID already exists in OVS. This
// assumption is currently guaranteed by the ofnet implementation:
// https://github.com/wenyingd/ofnet/blob/14a78b27ef8762e45a0cfc858c4d07a4572a99d5/ofctrl/fgraphSwitch.go#L57-L62
// All previous groups have been deleted by the time the call to i.ofClient.Initialize returns.
func (i *Initializer) initOpenFlowPipeline() error {
	roundInfo := getRoundInfo(i.ovsBridgeClient)

	// Set up all basic flows.
	ofConnCh, err := i.ofClient.Initialize(roundInfo, i.nodeConfig, i.networkConfig)
	if err != nil {
		klog.Errorf("Failed to initialize openflow client: %v", err)
		return err
	}

	// On Windows platform, host network flows are needed for host traffic.
	if err := i.initHostNetworkFlows(); err != nil {
		klog.Errorf("Failed to install openflow entries for host network: %v", err)
		return err
	}

	// Install OpenFlow entries to enable Pod traffic to external IP
	// addresses.
	if err := i.ofClient.InstallExternalFlows(i.egressConfig.ExceptCIDRs); err != nil {
		klog.Errorf("Failed to install openflow entries for external connectivity: %v", err)
		return err
	}

	// Set up flow entries for gateway interface, including classifier, skip spoof guard check,
	// L3 forwarding and L2 forwarding
	if err := i.ofClient.InstallGatewayFlows(); err != nil {
		klog.Errorf("Failed to setup openflow entries for gateway: %v", err)
		return err
	}

	if i.networkConfig.TrafficEncapMode.SupportsEncap() {
		// Set up flow entries for the default tunnel port interface.
		if err := i.ofClient.InstallDefaultTunnelFlows(); err != nil {
			klog.Errorf("Failed to setup openflow entries for tunnel interface: %v", err)
			return err
		}
	}

	if !i.enableProxy {
		// Set up flow entries to enable Service connectivity. Upstream kube-proxy is leveraged to
		// provide load-balancing, and the flows installed by this method ensure that traffic sent
		// from local Pods to any Service address can be forwarded to the host gateway interface
		// correctly. Otherwise packets might be dropped by egress rules before they are DNATed to
		// backend Pods.
		if err := i.ofClient.InstallClusterServiceCIDRFlows([]*net.IPNet{i.serviceCIDR, i.serviceCIDRv6}); err != nil {
			klog.Errorf("Failed to setup OpenFlow entries for Service CIDRs: %v", err)
			return err
		}
	} else {
		// Set up flow entries to enable Service connectivity. The agent proxy handles
		// ClusterIP Services while the upstream kube-proxy is leveraged to handle
		// any other kinds of Services.
		if err := i.ofClient.InstallDefaultServiceFlows(i.nodePortAddressesIPv4, i.nodePortAddressesIPv6); err != nil {
			klog.Errorf("Failed to setup default OpenFlow entries for ClusterIP Services: %v", err)
			return err
		}
	}

	go func() {
		// Delete stale flows from previous round. We need to wait long enough to ensure
		// that all the flow which are still required have received an updated cookie (with
		// the new round number), otherwise we would disrupt the dataplane. Unfortunately,
		// the time required for convergence may be large and there is no simple way to
		// determine when is a right time to perform the cleanup task.
		// TODO: introduce a deterministic mechanism through which the different entities
		//  responsible for installing flows can notify the agent that this deletion
		//  operation can take place. A waitGroup can be created here and notified when
		//  full sync in agent networkpolicy controller is complete. This would signal NP
		//  flows have been synced once. Other mechanisms are still needed for node flows
		//  fullSync check.
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

			if i.ovsBridgeClient.GetOVSDatapathType() == ovsconfig.OVSDatapathNetdev {
				// we don't set flow-restore-wait when using the OVS netdev datapath
				return
			}

			// ofClient and ovsBridgeClient have their own mechanisms to restore connections with OVS, and it could
			// happen that ovsBridgeClient's connection is not ready when ofClient completes flow replay. We retry it
			// with a timeout that is longer time than ovsBridgeClient's maximum connecting retry interval (8 seconds)
			// to ensure the flag can be removed successfully.
			err := wait.PollImmediate(200*time.Millisecond, 10*time.Second, func() (done bool, err error) {
				if err := i.FlowRestoreComplete(); err != nil {
					return false, nil
				}
				return true, nil
			})
			// This shouldn't happen unless OVS is disconnected again after replaying flows. If it happens, we will try
			// to clean up the config again so an error log should be fine.
			if err != nil {
				klog.Errorf("Failed to clean up flow-restore-wait config: %v", err)
			}
		}
	}()

	return nil
}

func (i *Initializer) FlowRestoreComplete() error {
	// Issue #1600: A rare case has been found that the "flow-restore-wait" config was still true even though the delete
	// call below was considered success. At the moment we don't know if it's a race condition caused by "ovs-vsctl set
	// --no-wait" or a problem with OVSDB golang lib or OVSDB itself. To work around it, we check if the config is true
	// before deleting it and if it is false after deleting it, and we will log warnings and retry a few times if
	// anything unexpected happens.
	// If the issue can still happen, it must be that some other code sets the config back after it's deleted.
	getFlowRestoreWait := func() (bool, error) {
		otherConfig, err := i.ovsBridgeClient.GetOVSOtherConfig()
		if err != nil {
			return false, fmt.Errorf("error when getting OVS other config")
		}
		return otherConfig["flow-restore-wait"] == "true", nil
	}

	// "flow-restore-wait" is supposed to be true here.
	err := wait.PollImmediate(200*time.Millisecond, 2*time.Second, func() (done bool, err error) {
		flowRestoreWait, err := getFlowRestoreWait()
		if err != nil {
			return false, err
		}
		if !flowRestoreWait {
			// If the log is seen and the config becomes true later, we should look at why "ovs-vsctl set --no-wait"
			// doesn't take effect on ovsdb immediately.
			klog.Warning("flow-restore-wait was not true before the delete call was made, will retry")
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		if err == wait.ErrWaitTimeout {
			// This could happen if the method is triggered by OVS disconnection event, in which OVS doesn't restart.
			klog.Info("flow-restore-wait was not true, skip cleaning it up")
			return nil
		}
		return err
	}
	for retries := 0; retries < 3; retries++ {
		// ovs-vswitchd is started with flow-restore-wait set to true for the following reasons:
		// 1. It prevents packets from being mishandled by ovs-vswitchd in its default fashion,
		//    which could affect existing connections' conntrack state and cause issues like #625.
		// 2. It prevents ovs-vswitchd from flushing or expiring previously set datapath flows,
		//    so existing connections can achieve 0 downtime during OVS restart.
		// As a result, we remove the config here after restoring necessary flows.
		klog.Info("Cleaning up flow-restore-wait config")
		if err := i.ovsBridgeClient.DeleteOVSOtherConfig(map[string]interface{}{"flow-restore-wait": "true"}); err != nil {
			return fmt.Errorf("error when cleaning up flow-restore-wait config: %v", err)
		}
		flowRestoreWait, err := getFlowRestoreWait()
		if err != nil {
			return err
		}
		if flowRestoreWait {
			// If it is seen, we should look at OVSDB golang lib and OVS.
			klog.Warningf("flow-restore-wait was still true even though the delete call was considered success")
			continue
		}
		klog.Info("Cleaned up flow-restore-wait config")
		return nil
	}
	return fmt.Errorf("error when cleaning up flow-restore-wait config: delete calls failed to take effect")
}

// setupGatewayInterface creates the host gateway interface which is an internal port on OVS. The ofport for host
// gateway interface is predefined, so invoke CreateInternalPort with a specific ofport_request
func (i *Initializer) setupGatewayInterface() error {
	// Create host Gateway port if it does not exist
	gatewayIface, portExists := i.ifaceStore.GetInterface(i.hostGateway)
	if !portExists {
		klog.V(2).Infof("Creating gateway port %s on OVS bridge", i.hostGateway)
		externalIDs := map[string]interface{}{
			interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaGateway,
		}
		gwPortUUID, err := i.ovsBridgeClient.CreateInternalPort(i.hostGateway, config.HostGatewayOFPort, externalIDs)
		if err != nil {
			klog.Errorf("Failed to create gateway port %s on OVS bridge: %v", i.hostGateway, err)
			return err
		}
		gatewayIface = interfacestore.NewGatewayInterface(i.hostGateway)
		gatewayIface.OVSPortConfig = &interfacestore.OVSPortConfig{PortUUID: gwPortUUID, OFPort: config.HostGatewayOFPort}
		i.ifaceStore.AddInterface(gatewayIface)
	} else {
		klog.V(2).Infof("Gateway port %s already exists on OVS bridge", i.hostGateway)
	}

	// Idempotent operation to set the gateway's MTU: we perform this operation regardless of
	// whether or not the gateway interface already exists, as the desired MTU may change across
	// restarts.
	klog.V(4).Infof("Setting gateway interface %s MTU to %d", i.hostGateway, i.nodeConfig.NodeMTU)

	if err := i.configureGatewayInterface(gatewayIface); err != nil {
		return err
	}
	if err := i.ovsBridgeClient.SetInterfaceMTU(i.hostGateway, i.nodeConfig.NodeMTU); err != nil {
		return err
	}

	return nil
}

func (i *Initializer) configureGatewayInterface(gatewayIface *interfacestore.InterfaceConfig) error {
	var gwMAC net.HardwareAddr
	var gwLinkIdx int
	var err error
	// Host link might not be queried at once after creating OVS internal port; retry max 5 times with 1s
	// delay each time to ensure the link is ready.
	for retry := 0; retry < maxRetryForHostLink; retry++ {
		gwMAC, gwLinkIdx, err = util.SetLinkUp(i.hostGateway)
		if err == nil {
			break
		}
		if _, ok := err.(util.LinkNotFound); ok {
			klog.V(2).Infof("Not found host link for gateway %s, retry after 1s", i.hostGateway)
			time.Sleep(1 * time.Second)
			continue
		}
		return err
	}

	if err != nil {
		klog.Errorf("Failed to find host link for gateway %s: %v", i.hostGateway, err)
		return err
	}

	i.nodeConfig.GatewayConfig = &config.GatewayConfig{Name: i.hostGateway, MAC: gwMAC}
	gatewayIface.MAC = gwMAC
	gatewayIface.IPs = []net.IP{}
	if i.networkConfig.TrafficEncapMode.IsNetworkPolicyOnly() {
		// Assign IP to gw as required by SpoofGuard.
		if i.nodeConfig.NodeIPv4Addr != nil {
			i.nodeConfig.GatewayConfig.IPv4 = i.nodeConfig.NodeTransportIPv4Addr.IP
			gatewayIface.IPs = append(gatewayIface.IPs, i.nodeConfig.NodeTransportIPv4Addr.IP)
		}
		if i.nodeConfig.NodeIPv6Addr != nil {
			i.nodeConfig.GatewayConfig.IPv6 = i.nodeConfig.NodeTransportIPv6Addr.IP
			gatewayIface.IPs = append(gatewayIface.IPs, i.nodeConfig.NodeTransportIPv6Addr.IP)
		}
		// No need to assign local CIDR to gw0 because local CIDR is not managed by Antrea
		return nil
	}

	i.nodeConfig.GatewayConfig.LinkIndex = gwLinkIdx
	// Allocate the gateway IP address for each Pod CIDR allocated to the Node. For each CIDR,
	// the first address in the subnet is assigned to the host gateway interface.
	podCIDRs := []*net.IPNet{i.nodeConfig.PodIPv4CIDR, i.nodeConfig.PodIPv6CIDR}
	if err := i.allocateGatewayAddresses(podCIDRs, gatewayIface); err != nil {
		return err
	}

	return nil
}

func (i *Initializer) setupDefaultTunnelInterface() error {
	tunnelPortName := i.nodeConfig.DefaultTunName
	tunnelIface, portExists := i.ifaceStore.GetInterface(tunnelPortName)
	localIP := i.getTunnelPortLocalIP()
	localIPStr := ""
	if localIP != nil {
		localIPStr = localIP.String()
	}

	// Enabling UDP checksum can greatly improve the performance for Geneve and
	// VXLAN tunnels by triggering GRO on the receiver.
	shouldEnableCsum := i.networkConfig.TunnelType == ovsconfig.GeneveTunnel || i.networkConfig.TunnelType == ovsconfig.VXLANTunnel

	// Check the default tunnel port.
	if portExists {
		if i.networkConfig.TrafficEncapMode.SupportsEncap() &&
			tunnelIface.TunnelInterfaceConfig.Type == i.networkConfig.TunnelType &&
			tunnelIface.TunnelInterfaceConfig.LocalIP.Equal(localIP) {
			klog.V(2).Infof("Tunnel port %s already exists on OVS bridge", tunnelPortName)
			// This could happen when upgrading from previous versions that didn't set it.
			if shouldEnableCsum && !tunnelIface.TunnelInterfaceConfig.Csum {
				if err := i.enableTunnelCsum(tunnelPortName); err != nil {
					return fmt.Errorf("failed to enable csum for tunnel port %s: %v", tunnelPortName, err)
				}
				tunnelIface.TunnelInterfaceConfig.Csum = true
			}
			return nil
		}

		if err := i.ovsBridgeClient.DeletePort(tunnelIface.PortUUID); err != nil {
			if i.networkConfig.TrafficEncapMode.SupportsEncap() {
				return fmt.Errorf("failed to remove tunnel port %s with wrong tunnel type: %s", tunnelPortName, err)
			}
			klog.Errorf("Failed to remove tunnel port %s in NoEncapMode: %v", tunnelPortName, err)
		} else {
			klog.Infof("Removed tunnel port %s with tunnel type: %s", tunnelPortName, tunnelIface.TunnelInterfaceConfig.Type)
			i.ifaceStore.DeleteInterface(tunnelIface)
		}
	}

	// Create the default tunnel port and interface.
	if i.networkConfig.TrafficEncapMode.SupportsEncap() {
		if tunnelPortName != defaultTunInterfaceName {
			// Reset the tunnel interface name to the desired name before
			// recreating the tunnel port and interface.
			tunnelPortName = defaultTunInterfaceName
			i.nodeConfig.DefaultTunName = tunnelPortName
		}
		externalIDs := map[string]interface{}{
			interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaTunnel,
		}
		tunnelPortUUID, err := i.ovsBridgeClient.CreateTunnelPortExt(tunnelPortName, i.networkConfig.TunnelType, config.DefaultTunOFPort, shouldEnableCsum, localIPStr, "", "", externalIDs)
		if err != nil {
			klog.Errorf("Failed to create tunnel port %s type %s on OVS bridge: %v", tunnelPortName, i.networkConfig.TunnelType, err)
			return err
		}
		tunnelIface = interfacestore.NewTunnelInterface(tunnelPortName, i.networkConfig.TunnelType, localIP, shouldEnableCsum)
		tunnelIface.OVSPortConfig = &interfacestore.OVSPortConfig{PortUUID: tunnelPortUUID, OFPort: config.DefaultTunOFPort}
		i.ifaceStore.AddInterface(tunnelIface)
	}
	return nil
}

func (i *Initializer) enableTunnelCsum(tunnelPortName string) error {
	options, err := i.ovsBridgeClient.GetInterfaceOptions(tunnelPortName)
	if err != nil {
		return fmt.Errorf("error getting interface options: %w", err)
	}

	updatedOptions := make(map[string]interface{})
	for k, v := range options {
		updatedOptions[k] = v
	}
	updatedOptions["csum"] = "true"
	return i.ovsBridgeClient.SetInterfaceOptions(tunnelPortName, updatedOptions)
}

// initNodeLocalConfig retrieves node's subnet CIDR from node.spec.PodCIDR, which is used for IPAM and setup
// host gateway interface.
func (i *Initializer) initNodeLocalConfig() error {
	nodeName, err := env.GetNodeName()
	if err != nil {
		return err
	}
	node, err := i.client.CoreV1().Nodes().Get(context.TODO(), nodeName, metav1.GetOptions{})
	if err != nil {
		klog.Errorf("Failed to get node from K8s with name %s: %v", nodeName, err)
		return err
	}

	var nodeIPv4Addr, nodeIPv6Addr, transportIPv4Addr, transportIPv6Addr *net.IPNet
	var transportInterfaceName string
	var localIntf *net.Interface
	// Find the interface configured with Node IP and use it for Pod traffic.
	ipAddrs, err := k8s.GetNodeAddrs(node)
	if err != nil {
		return fmt.Errorf("failed to obtain local IP addresses from K8s: %w", err)
	}
	nodeIPv4Addr, nodeIPv6Addr, localIntf, err = getIPNetDeviceFromIP(ipAddrs)
	if err != nil {
		return fmt.Errorf("failed to get local IPNet device with IP %v: %v", ipAddrs, err)
	}
	transportIPv4Addr = nodeIPv4Addr
	transportIPv6Addr = nodeIPv6Addr
	transportInterfaceName = localIntf.Name
	if i.networkConfig.TransportIface != "" {
		// Find the configured transport interface, and update its IP address in Node's annotation.
		transportIPv4Addr, transportIPv6Addr, localIntf, err = getTransportIPNetDeviceByName(i.networkConfig.TransportIface, i.ovsBridge)
		transportInterfaceName = localIntf.Name
		if err != nil {
			return fmt.Errorf("failed to get local IPNet device with transport interface %s: %v", i.networkConfig.TransportIface, err)
		}
		klog.InfoS("Updating Node transport addresses annotation")
		var ips []string
		if transportIPv4Addr != nil {
			ips = append(ips, transportIPv4Addr.IP.String())
		}
		if transportIPv6Addr != nil {
			ips = append(ips, transportIPv6Addr.IP.String())
		}
		if err := i.patchNodeAnnotations(nodeName, types.NodeTransportAddressAnnotationKey, strings.Join(ips, ",")); err != nil {
			return err
		}
	} else if len(i.networkConfig.TransportIfaceCIDRs) > 0 {
		transportIPv4Addr, transportIPv6Addr, localIntf, err = getIPNetDeviceByCIDRs(i.networkConfig.TransportIfaceCIDRs)
		transportInterfaceName = localIntf.Name
		if err != nil {
			return fmt.Errorf("failed to get local IPNet device with transport Address CIDR %s: %v", i.networkConfig.TransportIfaceCIDRs, err)
		}
		var ips []string
		if transportIPv4Addr != nil {
			ips = append(ips, transportIPv4Addr.IP.String())
		}
		if transportIPv6Addr != nil {
			ips = append(ips, transportIPv6Addr.IP.String())
		}
		klog.InfoS("Updating Node transport addresses annotation")
		if err := i.patchNodeAnnotations(nodeName, types.NodeTransportAddressAnnotationKey, strings.Join(ips, ",")); err != nil {
			return err
		}
	} else {
		// Remove the existing annotation "transport-address" if transportInterface is not set in the configuration.
		if node.Annotations[types.NodeTransportAddressAnnotationKey] != "" {
			klog.InfoS("Removing Node transport address annotation")
			i.patchNodeAnnotations(nodeName, types.NodeTransportAddressAnnotationKey, nil)
		}
	}
	i.networkConfig.TransportIface = transportInterfaceName

	// Update the Node's MAC address in the annotations of the Node. The MAC address will be used for direct routing by
	// OVS in noencap case on Windows Nodes. As a mixture of Linux and Windows nodes is possible, Linux Nodes' MAC
	// addresses should be reported too to make them discoverable for Windows Nodes.
	if i.networkConfig.TrafficEncapMode.SupportsNoEncap() {
		klog.Infof("Updating Node MAC annotation")
		if err := i.patchNodeAnnotations(nodeName, types.NodeMACAddressAnnotationKey, localIntf.HardwareAddr.String()); err != nil {
			return err
		}
	}

	i.nodeConfig = &config.NodeConfig{
		Name:                  nodeName,
		OVSBridge:             i.ovsBridge,
		DefaultTunName:        defaultTunInterfaceName,
		NodeIPv4Addr:          nodeIPv4Addr,
		NodeIPv6Addr:          nodeIPv6Addr,
		NodeTransportIPv4Addr: transportIPv4Addr,
		NodeTransportIPv6Addr: transportIPv6Addr,
		UplinkNetConfig:       new(config.AdapterNetConfig),
		NodeLocalInterfaceMTU: localIntf.MTU,
		WireGuardConfig:       i.wireGuardConfig,
	}

	mtu, err := i.getNodeMTU(localIntf)
	if err != nil {
		return err
	}
	i.nodeConfig.NodeMTU = mtu
	klog.Infof("Setting Node MTU=%d", mtu)

	if i.networkConfig.TrafficEncapMode.IsNetworkPolicyOnly() {
		return nil
	}

	// Parse all PodCIDRs first, so that we could support IPv4/IPv6 dual-stack configurations.
	if node.Spec.PodCIDRs != nil {
		for _, podCIDR := range node.Spec.PodCIDRs {
			_, localSubnet, err := net.ParseCIDR(podCIDR)
			if err != nil {
				klog.Errorf("Failed to parse subnet from CIDR string %s: %v", node.Spec.PodCIDR, err)
				return err
			}
			if localSubnet.IP.To4() != nil {
				if i.nodeConfig.PodIPv4CIDR != nil {
					klog.Warningf("One IPv4 PodCIDR is already configured on this Node, ignore the IPv4 Subnet CIDR %s", localSubnet.String())
				} else {
					i.nodeConfig.PodIPv4CIDR = localSubnet
					klog.V(2).Infof("Configure IPv4 Subnet CIDR %s on this Node", localSubnet.String())
				}
				continue
			}
			if i.nodeConfig.PodIPv6CIDR != nil {
				klog.Warningf("One IPv6 PodCIDR is already configured on this Node, ignore the IPv6 subnet CIDR %s", localSubnet.String())
			} else {
				i.nodeConfig.PodIPv6CIDR = localSubnet
				klog.V(2).Infof("Configure IPv6 Subnet CIDR %s on this Node", localSubnet.String())
			}
		}
		return nil
	}
	// Spec.PodCIDR can be empty due to misconfiguration.
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
	if localSubnet.IP.To4() != nil {
		i.nodeConfig.PodIPv4CIDR = localSubnet
	} else {
		i.nodeConfig.PodIPv6CIDR = localSubnet
	}
	return nil
}

// initializeIPSec checks if preconditions are met for using IPsec and reads the IPsec PSK value.
func (i *Initializer) initializeIPSec() error {
	// At the time the agent is initialized and this code is executed, the
	// OVS daemons are already running given that we have successfully
	// connected to OVSDB. Given that the start_ovs script deletes existing
	// PID files before starting the OVS daemons, it is safe to assume that
	// if this file exists, the IPsec monitor is indeed running.
	const ovsMonitorIPSecPID = "/var/run/openvswitch/ovs-monitor-ipsec.pid"
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		if _, err := os.Stat(ovsMonitorIPSecPID); err == nil {
			klog.V(2).Infof("OVS IPsec monitor seems to be present")
			break
		}
		select {
		case <-ticker.C:
			continue
		case <-timer.C:
			return fmt.Errorf("IPsec was requested, but the OVS IPsec monitor does not seem to be running")
		}
	}

	if err := i.readIPSecPSK(); err != nil {
		return err
	}
	return nil
}

// initializeWireguard checks if preconditions are met for using WireGuard and initializes WireGuard client or cleans up.
func (i *Initializer) initializeWireGuard() error {
	i.wireGuardConfig.MTU = i.nodeConfig.NodeLocalInterfaceMTU - config.WireGuardOverhead
	wgClient, err := wireguard.New(i.client, i.nodeConfig, i.wireGuardConfig)
	if err != nil {
		return err
	}

	i.wireGuardClient = wgClient
	return i.wireGuardClient.Init()
}

// readIPSecPSK reads the IPsec PSK value from environment variable ANTREA_IPSEC_PSK
func (i *Initializer) readIPSecPSK() error {
	i.networkConfig.IPSecPSK = os.Getenv(ipsecPSKEnvKey)
	if i.networkConfig.IPSecPSK == "" {
		return fmt.Errorf("IPsec PSK environment variable '%s' is not set or is empty", ipsecPSKEnvKey)
	}

	// Usually one does not want to log the secret data.
	klog.V(4).Infof("IPsec PSK value: %s", i.networkConfig.IPSecPSK)
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

func (i *Initializer) getNodeMTU(localIntf *net.Interface) (int, error) {
	if i.mtu != 0 {
		return i.mtu, nil
	}
	mtu := localIntf.MTU
	// Make sure mtu is set on the interface.
	if mtu <= 0 {
		return 0, fmt.Errorf("Failed to fetch Node MTU : %v", mtu)
	}
	if i.networkConfig.TrafficEncapMode.SupportsEncap() {
		if i.networkConfig.TunnelType == ovsconfig.VXLANTunnel {
			mtu -= config.VXLANOverhead
		} else if i.networkConfig.TunnelType == ovsconfig.GeneveTunnel {
			mtu -= config.GeneveOverhead
		} else if i.networkConfig.TunnelType == ovsconfig.GRETunnel {
			mtu -= config.GREOverhead
		}
		if i.nodeConfig.NodeIPv6Addr != nil {
			mtu -= config.IPv6ExtraOverhead
		}
	}
	if i.networkConfig.TrafficEncryptionMode == config.TrafficEncryptionModeIPSec {
		mtu -= config.IPSecESPOverhead
	}
	return mtu, nil
}

func (i *Initializer) allocateGatewayAddresses(localSubnets []*net.IPNet, gatewayIface *interfacestore.InterfaceConfig) error {
	var gwIPs []*net.IPNet
	for _, localSubnet := range localSubnets {
		if localSubnet == nil {
			continue
		}
		subnetID := localSubnet.IP.Mask(localSubnet.Mask)
		gwIP := &net.IPNet{IP: ip.NextIP(subnetID), Mask: localSubnet.Mask}
		gwIPs = append(gwIPs, gwIP)
	}
	if len(gwIPs) == 0 {
		return nil
	}

	// Check IP address configuration on existing interface first, return if the interface has the desired addresses.
	// We perform this check unconditionally, even if the OVS port does not exist when this function is called
	// (i.e. portExists is false). Indeed, it may be possible for the interface to exist even if the OVS bridge does
	// not exist.
	// Configure any missing IP address on the interface. Remove any extra IP address that may exist.
	if err := util.ConfigureLinkAddresses(i.nodeConfig.GatewayConfig.LinkIndex, gwIPs); err != nil {
		return err
	}
	// Periodically check whether IP configuration of the gateway is correct.
	// Terminate when stopCh is closed.
	go wait.Until(func() {
		if err := util.ConfigureLinkAddresses(i.nodeConfig.GatewayConfig.LinkIndex, gwIPs); err != nil {
			klog.Errorf("Failed to check IP configuration of the gateway: %v", err)
		}
	}, 60*time.Second, i.stopCh)

	for _, gwIP := range gwIPs {
		if gwIP.IP.To4() != nil {
			i.nodeConfig.GatewayConfig.IPv4 = gwIP.IP
		} else {
			i.nodeConfig.GatewayConfig.IPv6 = gwIP.IP
		}

		gatewayIface.IPs = append(gatewayIface.IPs, gwIP.IP)
	}

	return nil
}

func (i *Initializer) patchNodeAnnotations(nodeName, key string, value interface{}) error {
	patch, _ := json.Marshal(map[string]interface{}{
		"metadata": map[string]interface{}{
			"annotations": map[string]interface{}{
				key: value,
			},
		},
	})
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		_, err := i.client.CoreV1().Nodes().Patch(context.TODO(), nodeName, apitypes.MergePatchType, patch, metav1.PatchOptions{})
		return err
	}); err != nil {
		klog.ErrorS(err, "Failed to patch Node annotation", "key", key, "value", value)
		return err
	}
	return nil
}
