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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/spf13/afero"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apitypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"
	clockutils "k8s.io/utils/clock"

	"antrea.io/antrea/pkg/agent/cniserver"
	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/controller/noderoute"
	"antrea.io/antrea/pkg/agent/controller/trafficcontrol"
	"antrea.io/antrea/pkg/agent/externalnode"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/openflow/cookie"
	"antrea.io/antrea/pkg/agent/route"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/agent/wireguard"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/pkg/client/clientset/versioned"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/ovs/ovsctl"
	"antrea.io/antrea/pkg/util/env"
	utilip "antrea.io/antrea/pkg/util/ip"
	"antrea.io/antrea/pkg/util/k8s"
	utilwait "antrea.io/antrea/pkg/util/wait"
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
	// On Linux, OVS configures the MTU for tunnel interfaces to 65000.
	// See https://github.com/openvswitch/ovs/blame/3e666ba000b5eff58da8abb4e8c694ac3f7b08d6/lib/dpif-netlink-rtnl.c#L348-L360
	// There are some edge cases (e.g., Kind clusters) where the transport Node's MTU may be
	// larger than that (e.g., 65535), and packets may be dropped. To account for this, we use
	// 65000 as an upper bound for the MTU calculated in getInterfaceMTU, when encap is
	// supported. For simplicity's sake, we also use this upper bound for Windows, even if it
	// does not apply.
	ovsTunnelMaxMTU = 65000
)

var (
	// getIPNetDeviceFromIP is meant to be overridden for testing.
	getIPNetDeviceFromIP = util.GetIPNetDeviceFromIP

	// getIPNetDeviceByV4CIDR is meant to be overridden for testing.
	getIPNetDeviceByCIDRs = util.GetIPNetDeviceByCIDRs

	// getTransportIPNetDeviceByNameFn is meant to be overridden for testing.
	getTransportIPNetDeviceByNameFn = getTransportIPNetDeviceByName

	// setLinkUp is meant to be overridden for testing
	setLinkUp = util.SetLinkUp

	// configureLinkAddresses is meant to be overridden for testing
	configureLinkAddresses = util.ConfigureLinkAddresses
)

// otherConfigKeysForIPsecCertificates are configurations added to OVS bridge when AuthenticationMode is "cert" and
// need to be deleted when changing to "psk".
var otherConfigKeysForIPsecCertificates = []string{"certificate", "private_key", "ca_cert", "remote_cert", "remote_name"}

var (
	// Declared as variables for testing.
	defaultFs                       = afero.NewOsFs()
	clock     clockutils.WithTicker = &clockutils.RealClock{}

	getNodeTimeout = 30 * time.Second
)

// Initializer knows how to setup host networking, OpenVSwitch, and Openflow.
type Initializer struct {
	client                clientset.Interface
	crdClient             versioned.Interface
	ovsBridgeClient       ovsconfig.OVSBridgeClient
	ovsCtlClient          ovsctl.OVSCtlClient
	ofClient              openflow.Client
	routeClient           route.Interface
	wireGuardClient       wireguard.Interface
	ifaceStore            interfacestore.InterfaceStore
	ovsBridge             string
	hostGateway           string // name of gateway port on the OVS bridge
	mtu                   int
	networkConfig         *config.NetworkConfig
	nodeConfig            *config.NodeConfig
	wireGuardConfig       *config.WireGuardConfig
	egressConfig          *config.EgressConfig
	serviceConfig         *config.ServiceConfig
	l7NetworkPolicyConfig *config.L7NetworkPolicyConfig
	enableL7NetworkPolicy bool
	enableL7FlowExporter  bool
	connectUplinkToBridge bool
	enableAntreaProxy     bool
	// podNetworkWait should be decremented once the Node's network is ready.
	// The CNI server will wait for it before handling any CNI Add requests.
	podNetworkWait        *utilwait.Group
	stopCh                <-chan struct{}
	nodeType              config.NodeType
	externalNodeNamespace string
}

func NewInitializer(
	k8sClient clientset.Interface,
	crdClient versioned.Interface,
	ovsBridgeClient ovsconfig.OVSBridgeClient,
	ovsCtlClient ovsctl.OVSCtlClient,
	ofClient openflow.Client,
	routeClient route.Interface,
	ifaceStore interfacestore.InterfaceStore,
	ovsBridge string,
	hostGateway string,
	mtu int,
	networkConfig *config.NetworkConfig,
	wireGuardConfig *config.WireGuardConfig,
	egressConfig *config.EgressConfig,
	serviceConfig *config.ServiceConfig,
	podNetworkWait *utilwait.Group,
	stopCh <-chan struct{},
	nodeType config.NodeType,
	externalNodeNamespace string,
	connectUplinkToBridge bool,
	enableAntreaProxy bool,
	enableL7NetworkPolicy bool,
	enableL7FlowExporter bool,
) *Initializer {
	return &Initializer{
		ovsBridgeClient:       ovsBridgeClient,
		ovsCtlClient:          ovsCtlClient,
		client:                k8sClient,
		crdClient:             crdClient,
		ifaceStore:            ifaceStore,
		ofClient:              ofClient,
		routeClient:           routeClient,
		ovsBridge:             ovsBridge,
		hostGateway:           hostGateway,
		mtu:                   mtu,
		networkConfig:         networkConfig,
		wireGuardConfig:       wireGuardConfig,
		egressConfig:          egressConfig,
		serviceConfig:         serviceConfig,
		l7NetworkPolicyConfig: &config.L7NetworkPolicyConfig{},
		podNetworkWait:        podNetworkWait,
		stopCh:                stopCh,
		nodeType:              nodeType,
		externalNodeNamespace: externalNodeNamespace,
		connectUplinkToBridge: connectUplinkToBridge,
		enableAntreaProxy:     enableAntreaProxy,
		enableL7NetworkPolicy: enableL7NetworkPolicy,
		enableL7FlowExporter:  enableL7FlowExporter,
	}
}

// GetNodeConfig returns the NodeConfig.
func (i *Initializer) GetNodeConfig() *config.NodeConfig {
	return i.nodeConfig
}

// GetWireGuardClient returns the Wireguard client.
func (i *Initializer) GetWireGuardClient() wireguard.Interface {
	return i.wireGuardClient
}

// setupOVSBridge sets up the OVS bridge and create host gateway interface and tunnel port
func (i *Initializer) setupOVSBridge() error {
	if err := i.ovsBridgeClient.Create(); err != nil {
		klog.ErrorS(err, "Failed to create OVS bridge")
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

	if i.nodeType == config.K8sNode {
		if err := i.setupDefaultTunnelInterface(); err != nil {
			return err
		}
		// Set up host gateway interface
		err := i.setupGatewayInterface()
		if err != nil {
			return err
		}
	}

	return nil
}

func (i *Initializer) validateSupportedDPFeatures() error {
	gotFeatures, err := i.ovsCtlClient.GetDPFeatures()
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
	if i.enableAntreaProxy {
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
			MAC:           port.MAC,
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
				fallthrough
			case interfacestore.AntreaIPsecTunnel:
				intf = parseTunnelInterfaceFunc(port, ovsPort)
			case interfacestore.AntreaHost:
				if port.Name == i.ovsBridge {
					// Need not to load the OVS bridge port to the interfaceStore
					intf = nil
				} else {
					var err error
					intf, err = externalnode.ParseHostInterfaceConfig(i.ovsBridgeClient, port, ovsPort)
					if err != nil {
						return fmt.Errorf("failed to get interfaceConfig by port %s: %v", port.Name, err)
					}
				}
			case interfacestore.AntreaContainer:
				// The port should be for a container interface.
				intf = cniserver.ParseOVSPortInterfaceConfig(port, ovsPort)
			case interfacestore.AntreaTrafficControl:
				intf = trafficcontrol.ParseTrafficControlInterfaceConfig(port, ovsPort)
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
				if intf.Type == interfacestore.IPSecTunnelInterface {
					antreaIFType = interfacestore.AntreaIPsecTunnel
				} else {
					antreaIFType = interfacestore.AntreaTunnel
				}
			case port.Name == i.ovsBridge:
				intf = nil
				antreaIFType = interfacestore.AntreaHost
			default:
				// The port should be for a container interface.
				intf = cniserver.ParseOVSPortInterfaceConfig(port, ovsPort)
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
			klog.V(2).InfoS("Adding interface to cache", "interfaceName", intf.InterfaceName)
			ifaceList = append(ifaceList, intf)
		}
	}

	i.ifaceStore.Initialize(ifaceList)
	return nil
}

func (i *Initializer) restorePortConfigs() error {
	interfaces := i.ifaceStore.ListInterfaces()
	for _, intf := range interfaces {
		switch intf.Type {
		case interfacestore.IPSecTunnelInterface:
			fallthrough
		case interfacestore.TrafficControlInterface:
			if intf.OFPort < 0 {
				klog.InfoS("Skipped setting no-flood for port due to invalid ofPort", "port", intf.InterfaceName, "ofport", intf.OFPort)
				continue
			}
			if err := i.ovsCtlClient.SetPortNoFlood(int(intf.OFPort)); err != nil {
				return fmt.Errorf("failed to set no-flood for port %s: %w", intf.InterfaceName, err)
			}
			klog.InfoS("Set no-flood for port", "port", intf.InterfaceName)
		}
	}
	return nil
}

// Initialize sets up agent initial configurations.
func (i *Initializer) Initialize() error {
	klog.Info("Setting up node network")
	if err := i.initNodeLocalConfig(); err != nil {
		return err
	}

	if err := i.prepareHostNetwork(); err != nil {
		return err
	}

	if err := i.setupOVSBridge(); err != nil {
		return err
	}

	if err := i.restorePortConfigs(); err != nil {
		return err
	}

	if i.enableL7NetworkPolicy || i.enableL7FlowExporter {
		// prepareL7EngineInterfaces must be executed after setupOVSBridge since it requires interfaceStore.
		if err := i.prepareL7EngineInterfaces(); err != nil {
			return err
		}
	}

	// initializeWireGuard must be executed after setupOVSBridge as it requires gateway addresses on the OVS bridge.
	if i.networkConfig.TrafficEncryptionMode == config.TrafficEncryptionModeWireGuard {
		if err := i.initializeWireGuard(); err != nil {
			return err
		}
	}
	// TODO: clean up WireGuard related configurations.

	// Initialize for IPsec PSK mode.
	if i.networkConfig.TrafficEncryptionMode == config.TrafficEncryptionModeIPSec &&
		i.networkConfig.IPsecConfig.AuthenticationMode == config.IPsecAuthenticationModePSK {
		if err := i.waitForIPsecMonitorDaemon(); err != nil {
			return err
		}
		if err := i.readIPSecPSK(); err != nil {
			return err
		}
	}

	// Initialize for IPsec Certificate mode.
	if i.networkConfig.TrafficEncryptionMode == config.TrafficEncryptionModeIPSec &&
		i.networkConfig.IPsecConfig.AuthenticationMode == config.IPsecAuthenticationModeCert {
		if err := i.waitForIPsecMonitorDaemon(); err != nil {
			return err
		}
	} else {
		configs, err := i.ovsBridgeClient.GetOVSOtherConfig()
		if err != nil {
			return fmt.Errorf("failed to get OVS other configs: %w", err)
		}
		// Clean up certificate and private key files.
		if configs["certificate"] != "" {
			if err := os.Remove(configs["certificate"]); err != nil && !os.IsNotExist(err) {
				klog.ErrorS(err, "Failed to delete unused IPsec certificate", "file", configs["certificate"])
			}
		}
		if configs["private_key"] != "" {
			if err := os.Remove(configs["private_key"]); err != nil && !os.IsNotExist(err) {
				klog.ErrorS(err, "Failed to delete unused IPsec private key", "file", configs["private_key"])
			}
		}
		toDelete := make(map[string]interface{})
		for _, key := range otherConfigKeysForIPsecCertificates {
			toDelete[key] = ""
		}
		// Clean up stale configs in OVS database.
		if err := i.ovsBridgeClient.DeleteOVSOtherConfig(toDelete); err != nil {
			return fmt.Errorf("failed to clean up OVS other configs: %w", err)
		}
	}

	if i.nodeType == config.K8sNode {
		i.podNetworkWait.Increment()
		// routeClient.Initialize() should be after i.setupOVSBridge() which
		// creates the host gateway interface.
		if err := i.routeClient.Initialize(i.nodeConfig, i.podNetworkWait.Done); err != nil {
			return err
		}

		// Install OpenFlow entries on OVS bridge.
		if err := i.initOpenFlowPipeline(); err != nil {
			return err
		}
	} else {
		// Install OpenFlow entries on OVS bridge.
		if err := i.initOpenFlowPipeline(); err != nil {
			return err
		}
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
//  1. agent determines the new round number (this is done by incrementing the round number
//     persisted in OVSDB, or if it's not available by picking round 1).
//  2. any existing flow for which the round number matches the round number obtained from step 1
//     is deleted.
//  3. all required flows are installed, using the round number obtained from step 1.
//  4. after convergence, all existing flows for which the round number matches the previous round
//     number (i.e. the round number which was persisted in OVSDB, if any) are deleted.
//  5. the new round number obtained from step 1 is persisted to OVSDB.
//
// The rationale for not persisting the new round number until after all previous flows have been
// deleted is to avoid a situation in which some stale flows are never deleted because of successive
// agent restarts (with the agent crashing before step 4 can be completed). With the sequence
// described above, We guarantee that at most two rounds of flows exist in the switch at any given
// time.
func (i *Initializer) initOpenFlowPipeline() error {
	roundInfo := getRoundInfo(i.ovsBridgeClient)

	// Set up all basic flows.
	ofConnCh, err := i.ofClient.Initialize(roundInfo, i.nodeConfig, i.networkConfig, i.egressConfig, i.serviceConfig, i.l7NetworkPolicyConfig)
	if err != nil {
		klog.Errorf("Failed to initialize openflow client: %v", err)
		return err
	}

	if i.nodeType == config.ExternalNode {
		if err := i.installVMInitialFlows(); err != nil {
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

			klog.InfoS("Restoring OF port configs to OVS bridge")
			if err := i.restorePortConfigs(); err != nil {
				klog.ErrorS(err, "Failed to restore OF port configs")
			} else {
				klog.InfoS("Port configs restoration completed")
			}
			// ofClient and ovsBridgeClient have their own mechanisms to restore connections with OVS, and it could
			// happen that ovsBridgeClient's connection is not ready when ofClient completes flow replay. We retry it
			// with a timeout that is longer time than ovsBridgeClient's maximum connecting retry interval (8 seconds)
			// to ensure the flag can be removed successfully.
			err = wait.PollUntilContextTimeout(context.TODO(), 200*time.Millisecond, 10*time.Second, true,
				func(ctx context.Context) (done bool, err error) {
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
	err := wait.PollUntilContextTimeout(context.TODO(), 200*time.Millisecond, 2*time.Second, true,
		func(ctx context.Context) (done bool, err error) {
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
		if wait.Interrupted(err) {
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
		mac := util.GenerateRandomMAC()
		gwPortUUID, err := i.ovsBridgeClient.CreateInternalPort(i.hostGateway, config.HostGatewayOFPort, mac.String(), externalIDs)
		if err != nil {
			klog.ErrorS(err, "Failed to create gateway port on OVS bridge", "port", i.hostGateway)
			return err
		}
		gwPort, err := i.ovsBridgeClient.GetOFPort(i.hostGateway, false)
		if err != nil {
			klog.ErrorS(err, "Failed to get gateway ofport", "port", i.hostGateway)
			return err
		}
		klog.InfoS("Allocated OpenFlow port for gateway interface", "port", i.hostGateway, "ofPort", gwPort)
		gatewayIface = interfacestore.NewGatewayInterface(i.hostGateway, mac)
		gatewayIface.OVSPortConfig = &interfacestore.OVSPortConfig{PortUUID: gwPortUUID, OFPort: gwPort}
		i.ifaceStore.AddInterface(gatewayIface)
	} else {
		klog.V(2).Infof("Gateway port %s already exists on OVS bridge", i.hostGateway)
	}

	// Idempotent operation to set the gateway's MTU: we perform this operation regardless of
	// whether the gateway interface already exists, as the desired MTU may change across
	// restarts.
	klog.V(4).Infof("Setting gateway interface %s MTU to %d", i.hostGateway, i.networkConfig.InterfaceMTU)

	if err := i.configureGatewayInterface(gatewayIface); err != nil {
		return err
	}
	if err := i.setInterfaceMTU(i.hostGateway, i.networkConfig.InterfaceMTU); err != nil {
		return err
	}
	// Set arp_announce to 1 on Linux platform to make the ARP requests sent on the gateway
	// interface always use the gateway IP as the source IP, otherwise the ARP requests would be
	// dropped by ARP SpoofGuard flow.
	if i.nodeConfig.GatewayConfig.IPv4 != nil {
		if err := setInterfaceARPAnnounce(gatewayIface.InterfaceName, 1); err != nil {
			return err
		}
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
		gwMAC, gwLinkIdx, err = setLinkUp(i.hostGateway)
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
	// Persist the MAC configured in the network interface when the gatewayIface.MAC is not set. This may
	// happen in upgrade case.
	// Note the "mac" field in Windows OVS internal Interface has no impact on the network adapter's actual MAC,
	// set it to the same value just to keep consistency.
	if bytes.Compare(gatewayIface.MAC, gwMAC) != 0 {
		gatewayIface.MAC = gwMAC
		if err := i.ovsBridgeClient.SetInterfaceMAC(gatewayIface.InterfaceName, gwMAC); err != nil {
			klog.ErrorS(err, "Failed to persist interface MAC address", "interface", gatewayIface.InterfaceName, "mac", gwMAC)
		}
	}
	i.nodeConfig.GatewayConfig = &config.GatewayConfig{Name: i.hostGateway, MAC: gwMAC, OFPort: uint32(gatewayIface.OFPort)}
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

	// The correct OVS tunnel type to use GRE with an IPv6 overlay is
	// "ip6gre" and not "gre". While it would be possible to support GRE for
	// an IPv6-only cluster (by simply setting the tunnel type to "ip6gre"),
	// things would be more complicated for a dual-stack cluster. For such a
	// cluster, we have both IPv4 and IPv6 tunnels for inter-Node
	// traffic. We would therefore need to create 2 default tunnel ports:
	// one with type "gre" and one with type "ip6gre". This would introduce
	// some complexity as the code currently assumes that we have a single
	// default tunnel port. So for now, we just reject configurations that
	// request a GRE tunnel when the Node network supports IPv6.
	// See https://github.com/antrea-io/antrea/issues/3150
	if i.networkConfig.TrafficEncapMode.SupportsEncap() &&
		i.networkConfig.TunnelType == ovsconfig.GRETunnel &&
		i.nodeConfig.NodeIPv6Addr != nil {
		return fmt.Errorf("GRE tunnel type is not supported for IPv6 overlay")
	}

	// Enabling UDP checksum can greatly improve the performance for Geneve and
	// VXLAN tunnels by triggering GRO on the receiver for old Linux kernel versions.
	// It's not necessary for new Linux kernel versions with the following patch:
	// https://github.com/torvalds/linux/commit/89e5c58fc1e2857ccdaae506fb8bc5fed57ee063.
	shouldEnableCsum := i.networkConfig.TunnelCsum && (i.networkConfig.TunnelType == ovsconfig.GeneveTunnel || i.networkConfig.TunnelType == ovsconfig.VXLANTunnel)
	createTunnelInterface := i.networkConfig.NeedsTunnelInterface()

	// Check the default tunnel port.
	if portExists {
		if createTunnelInterface &&
			tunnelIface.TunnelInterfaceConfig.Type == i.networkConfig.TunnelType &&
			tunnelIface.TunnelInterfaceConfig.DestinationPort == i.networkConfig.TunnelPort &&
			tunnelIface.TunnelInterfaceConfig.LocalIP.Equal(localIP) {
			klog.V(2).Infof("Tunnel port %s already exists on OVS bridge", tunnelPortName)
			if shouldEnableCsum != tunnelIface.TunnelInterfaceConfig.Csum {
				klog.InfoS("Updating csum for tunnel port", "port", tunnelPortName, "csum", shouldEnableCsum)
				if err := i.setTunnelCsum(tunnelPortName, shouldEnableCsum); err != nil {
					return fmt.Errorf("failed to update csum for tunnel port %s to %v: %v", tunnelPortName, shouldEnableCsum, err)
				}
				tunnelIface.TunnelInterfaceConfig.Csum = shouldEnableCsum
			}
			i.nodeConfig.TunnelOFPort = uint32(tunnelIface.OFPort)
			return nil
		}

		if err := i.ovsBridgeClient.DeletePort(tunnelIface.PortUUID); err != nil {
			if createTunnelInterface {
				return fmt.Errorf("failed to remove tunnel port %s with wrong tunnel type: %s", tunnelPortName, err)
			}
			klog.Errorf("Failed to remove tunnel port %s in NoEncapMode: %v", tunnelPortName, err)
		} else {
			klog.Infof("Removed tunnel port %s with tunnel type: %s", tunnelPortName, tunnelIface.TunnelInterfaceConfig.Type)
			i.ifaceStore.DeleteInterface(tunnelIface)
		}
	}

	// Create the default tunnel port and interface.
	if createTunnelInterface {
		if tunnelPortName != defaultTunInterfaceName {
			// Reset the tunnel interface name to the desired name before
			// recreating the tunnel port and interface.
			tunnelPortName = defaultTunInterfaceName
			i.nodeConfig.DefaultTunName = tunnelPortName
		}
		externalIDs := map[string]interface{}{
			interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaTunnel,
		}
		extraOptions := map[string]interface{}{}
		if i.networkConfig.TunnelPort != 0 {
			extraOptions["dst_port"] = strconv.Itoa(int(i.networkConfig.TunnelPort))
		}
		tunnelPortUUID, err := i.ovsBridgeClient.CreateTunnelPortExt(tunnelPortName,
			i.networkConfig.TunnelType, config.DefaultTunOFPort, shouldEnableCsum, localIPStr, "", "", "", extraOptions, externalIDs)
		if err != nil {
			klog.ErrorS(err, "Failed to create tunnel port on OVS bridge", "port", tunnelPortName, "type", i.networkConfig.TunnelType)
			return err
		}
		tunPort, err := i.ovsBridgeClient.GetOFPort(tunnelPortName, false)
		if err != nil {
			klog.ErrorS(err, "Failed to get tunnel ofport on OVS bridge", "port", tunnelPortName, "type", i.networkConfig.TunnelType)
			return err
		}
		klog.InfoS("Allocated OpenFlow port for tunnel interface", "port", tunnelPortName, "ofPort", tunPort)
		ovsPortConfig := &interfacestore.OVSPortConfig{PortUUID: tunnelPortUUID, OFPort: tunPort}
		tunnelIface = interfacestore.NewTunnelInterface(tunnelPortName, i.networkConfig.TunnelType, i.networkConfig.TunnelPort, localIP, shouldEnableCsum, ovsPortConfig)
		i.ifaceStore.AddInterface(tunnelIface)
		i.nodeConfig.TunnelOFPort = uint32(tunPort)
	}
	return nil
}

func (i *Initializer) setTunnelCsum(tunnelPortName string, enable bool) error {
	options, err := i.ovsBridgeClient.GetInterfaceOptions(tunnelPortName)
	if err != nil {
		return fmt.Errorf("error getting interface options: %w", err)
	}

	updatedOptions := make(map[string]interface{})
	for k, v := range options {
		updatedOptions[k] = v
	}
	updatedOptions["csum"] = strconv.FormatBool(enable)
	return i.ovsBridgeClient.SetInterfaceOptions(tunnelPortName, updatedOptions)
}

// initK8sNodeLocalConfig retrieves node's subnet CIDR from node.spec.PodCIDR, which is used for IPAM and setup
// host gateway interface.
func (i *Initializer) initK8sNodeLocalConfig(nodeName string) error {
	var node *v1.Node
	if err := wait.PollUntilContextTimeout(context.TODO(), 5*time.Second, getNodeTimeout, true,
		func(ctx context.Context) (bool, error) {
			var err error
			node, err = i.client.CoreV1().Nodes().Get(context.TODO(), nodeName, metav1.GetOptions{})
			if err != nil {
				return false, fmt.Errorf("failed to get Node with name %s from K8s: %w", nodeName, err)
			}

			// Except in networkPolicyOnly mode, we need a PodCIDR for the Node.
			if !i.networkConfig.TrafficEncapMode.IsNetworkPolicyOnly() {
				// Validate that PodCIDR has been configured.
				if node.Spec.PodCIDRs == nil && node.Spec.PodCIDR == "" {
					klog.InfoS("Waiting for Node PodCIDR configuration to complete", "nodeName", nodeName)
					return false, nil
				}
			}
			return true, nil
		}); err != nil {
		if wait.Interrupted(err) {
			klog.ErrorS(err, "Spec.PodCIDR is empty for Node. Please make sure --allocate-node-cidrs is enabled "+
				"for kube-controller-manager and --cluster-cidr specifies a sufficient CIDR range, or nodeIPAM is "+
				"enabled for antrea-controller", "nodeName", nodeName)
			return fmt.Errorf("Spec.PodCIDR is empty for Node %s", nodeName)
		}
		return err
	}

	// nodeInterface is the interface that has K8s Node IP. transportInterface is the interface that is used for
	// tunneling or routing the traffic across Nodes. It defaults to nodeInterface and can be overridden by the
	// configuration parameters TransportInterface and TransportInterfaceCIDRs.
	var nodeInterface, transportInterface *net.Interface
	// nodeIPv4Addr and nodeIPv6Addr are the IP addresses of nodeInterface.
	// transportIPv4Addr and transportIPv6Addr are the IP addresses of transportInterface.
	var nodeIPv4Addr, nodeIPv6Addr, transportIPv4Addr, transportIPv6Addr *net.IPNet
	// Find the interface configured with Node IP and use it for Pod traffic.
	ipAddrs, err := k8s.GetNodeAddrs(node)
	if err != nil {
		return fmt.Errorf("failed to obtain local IP addresses from K8s: %w", err)
	}
	nodeIPv4Addr, nodeIPv6Addr, nodeInterface, err = i.getNodeInterfaceFromIP(ipAddrs)
	if err != nil {
		return fmt.Errorf("failed to get local IPNet device with IP %v: %v", ipAddrs, err)
	}
	transportIPv4Addr = nodeIPv4Addr
	transportIPv6Addr = nodeIPv6Addr
	transportInterface = nodeInterface
	if i.networkConfig.TransportIface != "" {
		// Find the configured transport interface, and update its IP address in Node's annotation.
		transportIPv4Addr, transportIPv6Addr, transportInterface, err = getTransportIPNetDeviceByNameFn(i.networkConfig.TransportIface, i.ovsBridge)
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
		transportIPv4Addr, transportIPv6Addr, transportInterface, err = getIPNetDeviceByCIDRs(i.networkConfig.TransportIfaceCIDRs)
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

	// Update the Node's MAC address in the annotations of the Node. The MAC address will be used for direct routing by
	// OVS in noencap case on Windows Nodes. As a mixture of Linux and Windows nodes is possible, Linux Nodes' MAC
	// addresses should be reported too to make them discoverable for Windows Nodes.
	if i.networkConfig.TrafficEncapMode.SupportsNoEncap() {
		klog.InfoS("Updating Node MAC annotation")
		if err := i.patchNodeAnnotations(nodeName, types.NodeMACAddressAnnotationKey, transportInterface.HardwareAddr.String()); err != nil {
			return err
		}
	}

	i.nodeConfig = &config.NodeConfig{
		Name:                       nodeName,
		Type:                       config.K8sNode,
		OVSBridge:                  i.ovsBridge,
		DefaultTunName:             defaultTunInterfaceName,
		NodeIPv4Addr:               nodeIPv4Addr,
		NodeIPv6Addr:               nodeIPv6Addr,
		NodeTransportInterfaceName: transportInterface.Name,
		NodeTransportIPv4Addr:      transportIPv4Addr,
		NodeTransportIPv6Addr:      transportIPv6Addr,
		UplinkNetConfig:            new(config.AdapterNetConfig),
		NodeTransportInterfaceMTU:  transportInterface.MTU,
		WireGuardConfig:            i.wireGuardConfig,
	}

	i.networkConfig.InterfaceMTU, err = i.getInterfaceMTU(transportInterface)
	if err != nil {
		return err
	}
	klog.InfoS("Got Interface MTU", "MTU", i.networkConfig.InterfaceMTU)

	if i.networkConfig.TrafficEncapMode.IsNetworkPolicyOnly() {
		return nil
	}

	// Parse all PodCIDRs first, so that we can support IPv4/IPv6 dual-stack configurations.
	if node.Spec.PodCIDRs != nil {
		for _, podCIDR := range node.Spec.PodCIDRs {
			_, localSubnet, err := net.ParseCIDR(podCIDR)
			if err != nil {
				klog.ErrorS(err, "Failed to parse subnet from Pod CIDR string", "CIDR", podCIDR)
				return err
			}
			if localSubnet.IP.To4() != nil {
				if i.nodeConfig.PodIPv4CIDR != nil {
					klog.InfoS("One IPv4 PodCIDR is already configured on this Node, ignoring the IPv4 Subnet CIDR", "subnet", localSubnet)
				} else {
					i.nodeConfig.PodIPv4CIDR = localSubnet
					klog.V(2).InfoS("Configured IPv4 Subnet CIDR on this Node", "subnet", localSubnet)
				}
				continue
			}
			if i.nodeConfig.PodIPv6CIDR != nil {
				klog.InfoS("One IPv6 PodCIDR is already configured on this Node, ignoring the IPv6 Subnet CIDR", "subnet", localSubnet)
			} else {
				i.nodeConfig.PodIPv6CIDR = localSubnet
				klog.V(2).InfoS("Configured IPv6 Subnet CIDR on this Node", "subnet", localSubnet)
			}
		}
		return nil
	}
	// at this stage, node.Spec.PodCIDR is guaranteed to NOT be empty
	_, localSubnet, err := net.ParseCIDR(node.Spec.PodCIDR)
	if err != nil {
		return fmt.Errorf("failed to parse subnet from CIDR string %s: %w", node.Spec.PodCIDR, err)
	}
	if localSubnet.IP.To4() != nil {
		i.nodeConfig.PodIPv4CIDR = localSubnet
	} else {
		i.nodeConfig.PodIPv6CIDR = localSubnet
	}
	return nil
}

// waitForIPsecMonitorDaemon checks if preconditions are met for using IPsec.
func (i *Initializer) waitForIPsecMonitorDaemon() error {
	// At the time the agent is initialized and this code is executed, the
	// OVS daemons are already running given that we have successfully
	// connected to OVSDB. Given that the start_ovs script deletes existing
	// PID files before starting the OVS daemons, it is safe to assume that
	// if this file exists, the IPsec monitor is indeed running.
	const ovsMonitorIPSecPID = "/var/run/openvswitch/ovs-monitor-ipsec.pid"
	timer := clock.NewTimer(10 * time.Second)
	defer timer.Stop()
	ticker := clock.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		if _, err := defaultFs.Stat(ovsMonitorIPSecPID); err == nil {
			klog.V(2).Infof("OVS IPsec monitor seems to be present")
			break
		}
		select {
		case <-ticker.C():
			continue
		case <-timer.C():
			return fmt.Errorf("IPsec was requested, but the OVS IPsec monitor does not seem to be running")
		}
	}
	return nil
}

// initializeWireguard checks if preconditions are met for using WireGuard and initializes WireGuard client or cleans up.
func (i *Initializer) initializeWireGuard() error {
	i.wireGuardConfig.MTU = i.nodeConfig.NodeTransportInterfaceMTU - i.networkConfig.WireGuardMTUDeduction
	wgClient, err := wireguard.New(i.nodeConfig, i.wireGuardConfig)
	if err != nil {
		return err
	}

	i.wireGuardClient = wgClient
	publicKey, err := i.wireGuardClient.Init(nil, nil)
	if err != nil {
		return err
	}

	patch, _ := json.Marshal(map[string]interface{}{
		"metadata": map[string]interface{}{
			"annotations": map[string]string{
				types.NodeWireGuardPublicAnnotationKey: publicKey,
			},
		},
	})
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		_, err := i.client.CoreV1().Nodes().Patch(context.TODO(), i.nodeConfig.Name, apitypes.MergePatchType, patch, metav1.PatchOptions{}, "status")
		return err
	}); err != nil {
		return fmt.Errorf("error when patching the Node with the '%s' annotation: %w", types.NodeWireGuardPublicAnnotationKey, err)
	}
	return err
}

// readIPSecPSK reads the IPsec PSK value from environment variable ANTREA_IPSEC_PSK
func (i *Initializer) readIPSecPSK() error {
	i.networkConfig.IPsecConfig.PSK = os.Getenv(ipsecPSKEnvKey)
	if i.networkConfig.IPsecConfig.PSK == "" {
		return fmt.Errorf("IPsec PSK environment variable '%s' is not set or is empty", ipsecPSKEnvKey)
	}

	// Usually one does not want to log the secret data.
	klog.V(4).Infof("IPsec PSK value: %s", i.networkConfig.IPsecConfig.PSK)
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

func (i *Initializer) getInterfaceMTU(transportInterface *net.Interface) (int, error) {
	if i.mtu != 0 {
		return i.mtu, nil
	}
	mtu := transportInterface.MTU
	// Make sure MTU is set on the interface.
	if mtu <= 0 {
		return 0, fmt.Errorf("Failed to fetch Node MTU : %v", mtu)
	}

	isIPv6 := i.nodeConfig.NodeIPv6Addr != nil
	mtu -= i.networkConfig.CalculateMTUDeduction(isIPv6)
	if i.networkConfig.TrafficEncapMode.SupportsEncap() {
		// See comment for ovsTunnelMaxMTU constant above.
		mtu = min(mtu, ovsTunnelMaxMTU)
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
	if err := configureLinkAddresses(i.nodeConfig.GatewayConfig.LinkIndex, gwIPs); err != nil {
		return err
	}
	// Periodically check whether IP configuration of the gateway is correct.
	// Terminate when stopCh is closed.
	go wait.Until(func() {
		if err := configureLinkAddresses(i.nodeConfig.GatewayConfig.LinkIndex, gwIPs); err != nil {
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
		_, err := i.client.CoreV1().Nodes().Patch(context.TODO(), nodeName, apitypes.MergePatchType, patch, metav1.PatchOptions{}, "status")
		return err
	}); err != nil {
		klog.ErrorS(err, "Failed to patch Node annotation", "key", key, "value", value)
		return err
	}
	return nil
}

// getNodeInterfaceFromIP returns the IPv4/IPv6 configuration, and the associated interface according the give nodeIPs.
// When searching the Node interface, antrea-gw0 is ignored because it is configured with the same address as Node IP
// with NetworkPolicyOnly mode on public cloud setup, e.g., AKS.
func (i *Initializer) getNodeInterfaceFromIP(nodeIPs *utilip.DualStackIPs) (v4IPNet *net.IPNet, v6IPNet *net.IPNet, iface *net.Interface, err error) {
	return getIPNetDeviceFromIP(nodeIPs, sets.New[string](i.hostGateway))
}

func (i *Initializer) initNodeLocalConfig() error {
	nodeName, err := env.GetNodeName()
	if err != nil {
		return err
	}
	if i.nodeType == config.K8sNode {
		if err := i.initK8sNodeLocalConfig(nodeName); err != nil {
			return err
		}

		i.networkConfig.IPv4Enabled, err = config.IsIPv4Enabled(i.nodeConfig, i.networkConfig.TrafficEncapMode)
		if err != nil {
			return err
		}
		i.networkConfig.IPv6Enabled, err = config.IsIPv6Enabled(i.nodeConfig, i.networkConfig.TrafficEncapMode)
		if err != nil {
			return err
		}

		return nil
	}
	if err := i.initVMLocalConfig(nodeName); err != nil {
		return err
	}
	// Only IPv4 is supported on a VM Node.
	i.networkConfig.IPv4Enabled = true
	return nil
}

func (i *Initializer) initVMLocalConfig(nodeName string) error {
	var en *v1alpha1.ExternalNode
	klog.InfoS("Initializing VM config", "ExternalNode", nodeName)
	if err := wait.PollUntilContextCancel(wait.ContextForChannel(i.stopCh), 10*time.Second, true, func(ctx context.Context) (done bool, err error) {
		en, err = i.crdClient.CrdV1alpha1().ExternalNodes(i.externalNodeNamespace).Get(context.TODO(), nodeName, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		return true, nil
	}); err != nil {
		klog.Info("Stopped waiting for ExternalNode")
		return err
	}

	if err := i.setVMNodeConfig(en, nodeName); err != nil {
		return err
	}
	klog.InfoS("Finished VM config initialization", "ExternalNode", nodeName)
	return nil
}

// prepareOVSBridge operates OVS bridge.
func (i *Initializer) prepareOVSBridge() error {
	if i.nodeType == config.K8sNode {
		return i.prepareOVSBridgeForK8sNode()
	}
	return i.prepareOVSBridgeForVM()
}

// setOVSDatapath generates a static datapath ID for OVS bridge so that the OFSwitch identifier is not
// changed after the physical interface is attached on the switch.
func (i *Initializer) setOVSDatapath() error {
	otherConfig, err := i.ovsBridgeClient.GetOVSOtherConfig()
	if err != nil {
		klog.ErrorS(err, "Failed to read OVS bridge other_config")
		return err
	}
	// Check if "datapath-id" exists in "other_config" on OVS bridge or not, and return directly if yes.
	// Note: function `ovsBridgeClient.GetDatapathID` is not used here, because OVS always has data in "datapath_id"
	// field. If "datapath-id" is not explicitly set in "other_config", the datapath ID in use may change when uplink
	// is attached on OVS.
	if _, exists := otherConfig[ovsconfig.OVSOtherConfigDatapathIDKey]; exists {
		return nil
	}
	datapathID := util.GenerateOVSDatapathID("")
	if err := i.ovsBridgeClient.SetDatapathID(datapathID); err != nil {
		klog.ErrorS(err, "Failed to set OVS bridge datapath_id", "datapathID", datapathID)
		return err
	}
	return nil
}
