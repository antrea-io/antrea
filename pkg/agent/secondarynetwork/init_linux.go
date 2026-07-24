//go:build linux
// +build linux

// Copyright 2023 Antrea Authors
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

package secondarynetwork

import (
	"errors"
	"fmt"
	"net"
	"time"

	netdefclient "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned/typed/k8s.cni.cncf.io/v1"
	"github.com/ovn-kubernetes/libovsdb/client"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	componentbaseconfig "k8s.io/component-base/config"
	"k8s.io/klog/v2"

	"antrea.io/antrea/v2/pkg/agent/antreanodeconfig"
	"antrea.io/antrea/v2/pkg/agent/config"
	"antrea.io/antrea/v2/pkg/agent/interfacestore"
	"antrea.io/antrea/v2/pkg/agent/secondarynetwork/podwatch"
	agenttypes "antrea.io/antrea/v2/pkg/agent/types"
	"antrea.io/antrea/v2/pkg/agent/util"
	crdlisters "antrea.io/antrea/v2/pkg/client/listers/crd/v1beta1"
	agentconfig "antrea.io/antrea/v2/pkg/config/agent"
	"antrea.io/antrea/v2/pkg/ovs/ovsconfig"
	"antrea.io/antrea/v2/pkg/util/channel"
	"antrea.io/antrea/v2/pkg/util/k8s"
)

const (
	// reconcileKey is the single key used in the work queue. Any change that
	// may affect the effective bridge configuration enqueues this key.
	reconcileKey = "reconcile"

	minRetryDelay         = 5 * time.Second
	maxRetryDelay         = 30 * time.Second
	bridgeInUseRetryDelay = 15 * time.Second
)

var (
	errBridgeInUse = errors.New("secondary OVS bridge is in use")

	// Funcs which will be overridden with mock funcs in tests.
	interfaceByNameFn = net.InterfaceByName
	// func(bridge, ifName, ifOFPort, externalIDs, mtu) (bridgedName, alreadyExists, error)
	prepareHostInterfaceConnectionFn = util.PrepareHostInterfaceConnection
	restoreHostInterfaceConfigFn     = util.RestoreHostInterfaceConfiguration // func(brName, ifName string) error
	newOVSBridgeFn                   = ovsconfig.NewOVSBridge
	// findManagedSecondaryBridgeFn queries OVSDB for the Antrea-managed
	// secondary bridge. Overridden in tests.
	findManagedSecondaryBridgeFn = findManagedSecondaryBridge
	// adoptSecondaryBridgeFn adopts a legacy secondary bridge
	// created from static config before bridge-level external_ids existed.
	// Overridden in tests.
	adoptSecondaryBridgeFn = adoptSecondaryBridge
)

type restoredHostConnection struct {
	hostIFName   string
	uplinkIFName string
}

// effectiveOVSBridge returns the desired OVS bridge for this node. When AntreaNodeConfig
// drives the bridge, only snapshots delivered on the notify channel are used.
// When ANC is disabled, only static agent config is consulted.
func (c *Controller) effectiveOVSBridge() *agenttypes.OVSBridgeConfig {
	if c.effectiveBridgeOverride != nil {
		return c.effectiveBridgeOverride()
	}
	if c.dynamicBridgeReconcile {
		return EffectiveSecondaryOVSBridgeFromSnapshot(c.latestANCSnapshot.Load(), c.secNetConfig)
	}
	return ovsBridgeFromStatic(c.secNetConfig)
}

// enqueue adds the single reconciliation key to the work queue.
func (c *Controller) enqueue() {
	c.queue.Add(reconcileKey)
}

func NewController(
	clientConnectionConfig componentbaseconfig.ClientConnectionConfiguration,
	kubeAPIServerOverride string,
	k8sClient clientset.Interface,
	podInformer cache.SharedIndexInformer,
	podUpdateSubscriber channel.Subscriber,
	primaryInterfaceStore interfacestore.InterfaceStore,
	nodeConfig *config.NodeConfig,
	secNetConfig *agentconfig.SecondaryNetworkConfig,
	ovsdbClient client.Client,
	ipPoolLister crdlisters.IPPoolLister,
	ancUpdateSubscriber channel.Subscriber,
) (*Controller, error) {
	c := &Controller{
		secNetConfig:         secNetConfig,
		nodeName:             nodeConfig.Name,
		primaryOVSBridgeName: nodeConfig.OVSBridge,
		ovsdbClient:          ovsdbClient,
	}

	if ancUpdateSubscriber != nil {
		c.dynamicBridgeReconcile = true
		c.ancFirstSnapshotCh = make(chan struct{})
		c.queue = workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.NewTypedItemExponentialFailureRateLimiter[string](minRetryDelay, maxRetryDelay),
			workqueue.TypedRateLimitingQueueConfig[string]{Name: "secondaryNetworkBridge"},
		)
	}

	netAttachDefClient, err := createNetworkAttachDefClient(clientConnectionConfig, kubeAPIServerOverride)
	if err != nil {
		return nil, fmt.Errorf("network attachment definition client creation failed: %w", err)
	}

	podWatchController, err := podwatch.NewPodController(
		k8sClient, netAttachDefClient, podInformer,
		podUpdateSubscriber, primaryInterfaceStore, nodeConfig, nil, ipPoolLister)
	if err != nil {
		return nil, err
	}

	c.podController = podWatchController

	if c.dynamicBridgeReconcile {
		ancUpdateSubscriber.Subscribe(func(p interface{}) {
			snap, ok := p.(*antreanodeconfig.Snapshot)
			if !ok {
				klog.ErrorS(errors.New("unexpected notify payload"), "AntreaNodeConfig notify payload", "type", fmt.Sprintf("%T", p))
				return
			}
			if snap == nil {
				klog.ErrorS(errors.New("nil snapshot from notifier"), "AntreaNodeConfig notify payload")
				return
			}
			c.latestANCSnapshot.Store(snap)
			c.signalFirstANC.Do(func() { close(c.ancFirstSnapshotCh) })
			c.enqueue()
		})
	}

	return c, nil
}

// CreateNetworkAttachDefClient creates net-attach-def client handle from the given config.
func createNetworkAttachDefClient(cfg componentbaseconfig.ClientConnectionConfiguration, kubeAPIServerOverride string) (netdefclient.K8sCniCncfIoV1Interface, error) {
	kubeConfig, err := k8s.CreateRestConfig(cfg, kubeAPIServerOverride)
	if err != nil {
		return nil, err
	}

	netAttachDefClient, err := netdefclient.NewForConfig(kubeConfig)
	if err != nil {
		return nil, err
	}
	return netAttachDefClient, nil
}

// Initialize sets up OVS bridges at agent start-up.
// When AntreaNodeConfig drives the bridge, it first waits for the initial ANC snapshot,
// creates the effective bridge, and then reconciles physical interfaces.
// It reconciles the current OVS bridge state with the effective bridge config:
//   - if the effective bridge has the same name as the previous bridge,
//     keep the bridge and update the physical interfaces (add/remove ports).
//   - if the effective bridge name differs from the previous bridge,
//     delete the old bridge and recreate with the new config.
//   - when allowedVLANs are set on a physical interface, configure the
//     OVS port in trunk mode with the specified VLAN IDs.
func (c *Controller) Initialize(stopCh <-chan struct{}) error {
	if c.dynamicBridgeReconcile {
		select {
		case <-c.ancFirstSnapshotCh:
		case <-stopCh:
			return fmt.Errorf("interrupted while waiting for initial AntreaNodeConfig snapshot")
		}
	}

	err := c.reconcileBridge()
	if !c.dynamicBridgeReconcile {
		return err
	}
	if err != nil {
		if errors.Is(err, errBridgeInUse) {
			c.queue.AddAfter(reconcileKey, bridgeInUseRetryDelay)
			return nil
		}
		// AntreaNodeConfig-driven bridge reconciliation is eventually consistent.
		// Do not make a transient secondary-network failure prevent the Agent from
		// serving the primary network. The worker will retry and install the bridge
		// client in PodController after reconciliation succeeds.
		klog.ErrorS(err, "Failed to reconcile secondary network bridge during initialization, requeuing")
		c.queue.AddRateLimited(reconcileKey)
		return nil
	}
	klog.InfoS("Secondary network bridge reconciled from initial AntreaNodeConfig snapshot")
	return nil
}

// restoreStaleHostConnections detects and tears down Antrea-managed host-connection
// port pairs (e.g. "eth1" internal host port + "eth1~" uplink) that were created
// by a previous single-interface run but are no longer needed in a multi-interface
// setup. It calls RestoreHostInterfaceConfiguration for each such interface, which
// removes both OVS ports and renames "eth1~" back to "eth1" on the host.
func restoreStaleHostConnections(ovsBridgeClient ovsconfig.OVSBridgeClient, bridgeCfg *agenttypes.OVSBridgeConfig) error {
	portList, err := ovsBridgeClient.GetPortList()
	if err != nil {
		return fmt.Errorf("failed to list OVS ports on bridge %s: %v", bridgeCfg.BridgeName, err)
	}

	_, restoreErr := restoreStaleHostConnectionsFromPortList(bridgeCfg.BridgeName, portList, nil)
	return restoreErr
}

func restoreStaleHostConnectionsFromPortList(
	bridgeName string,
	portList []ovsconfig.OVSPortData,
	shouldSkip func(hostIFName string) bool,
) ([]restoredHostConnection, error) {
	portsByName := make(map[string]ovsconfig.OVSPortData, len(portList))
	for _, p := range portList {
		portsByName[p.IFName] = p
	}

	var restored []restoredHostConnection
	for _, p := range portList {
		if p.IFType != "internal" ||
			p.ExternalIDs[interfacestore.AntreaInterfaceTypeKey] != interfacestore.AntreaHost {
			continue
		}
		bridgedName := util.GenerateUplinkInterfaceName(p.IFName)
		sibling, siblingExists := portsByName[bridgedName]
		if !siblingExists ||
			sibling.ExternalIDs[interfacestore.AntreaInterfaceTypeKey] != interfacestore.AntreaUplink ||
			shouldSkip != nil && shouldSkip(p.IFName) {
			continue
		}
		klog.InfoS("Detected stale host-connection setup, restoring interface before re-adding as uplink",
			"interface", p.IFName, "bridge", bridgeName)
		if err := restoreHostInterfaceConfigFn(bridgeName, p.IFName); err != nil {
			return nil, fmt.Errorf("failed to restore stale host-connection interface %s on bridge %s: %w",
				p.IFName, bridgeName, err)
		}
		restored = append(restored, restoredHostConnection{hostIFName: p.IFName, uplinkIFName: bridgedName})
	}
	return restored, nil
}

// clearStaleTrunks reads the actual OVS port state and calls SetPortTrunks(nil) for any
// port that has a non-empty trunk list in OVS but whose desired config carries no
// AllowedVLANs.  This handles the agent-restart scenario where the OVS port was
// previously configured as a trunk but the current desired config no longer requires it.
func clearStaleTrunks(ovsBridgeClient ovsconfig.OVSBridgeClient, phyInterfaces []agenttypes.PhysicalInterfaceConfig) error {
	// Build a set of interfaces that should NOT have trunk VLANs.
	noTrunkDesired := make(map[string]struct{}, len(phyInterfaces))
	for _, pi := range phyInterfaces {
		if len(pi.AllowedVLANs) == 0 {
			noTrunkDesired[pi.Name] = struct{}{}
		}
	}
	if len(noTrunkDesired) == 0 {
		return nil
	}

	portList, err := ovsBridgeClient.GetPortList()
	if err != nil {
		return fmt.Errorf("failed to list OVS ports: %v", err)
	}
	for _, p := range portList {
		// Match by IFName (interface name) against the desired set, but use p.Name
		// (Port name) for SetPortTrunks which filters the Port table by port name.
		// For standard uplink ports the two names are identical; being explicit here
		// avoids any confusion if they ever diverge.
		if _, ok := noTrunkDesired[p.IFName]; !ok {
			continue
		}
		if len(p.Trunks) == 0 {
			continue
		}
		if err := ovsBridgeClient.SetPortTrunks(p.Name, nil); err != nil {
			return fmt.Errorf("failed to clear stale trunk VLANs for OVS port %s: %v", p.Name, err)
		}
		klog.InfoS("Cleared trunk VLAN list on secondary OVS bridge port", "device", p.Name)
	}
	return nil
}

// Restore restores interface configuration from the secondary bridge back to the host interface.
func (c *Controller) Restore() {
	c.mu.RLock()
	bridgeCfg := c.effectiveBridgeCfg
	c.mu.RUnlock()

	if bridgeCfg == nil {
		return
	}
	if len(bridgeCfg.PhysicalInterfaces) == 1 {
		if err := restoreHostInterfaceConfigFn(bridgeCfg.BridgeName, bridgeCfg.PhysicalInterfaces[0].Name); err != nil {
			klog.ErrorS(err, "Failed to restore host interface configuration on shutdown",
				"interface", bridgeCfg.PhysicalInterfaces[0].Name, "bridge", bridgeCfg.BridgeName)
		}
	}
}

// Run starts the secondary network controller. When AntreaNodeConfig is
// enabled, Initialize handles the initial ANC snapshot wait and bridge creation; a bridge
// reconciliation worker then processes items enqueued by the ANC SubscribableChannel.
// When ANC is off, the bridge is static and no worker is started.
func (c *Controller) Run(stopCh <-chan struct{}) {
	klog.InfoS("Starting secondary network controller")
	defer klog.InfoS("Shutting down secondary network controller")

	if c.dynamicBridgeReconcile {
		defer c.queue.ShutDown()
		go wait.Until(func() {
			for c.processNextItem() {
			}
		}, time.Second, stopCh)
	}

	go c.podController.Run(stopCh)

	<-stopCh
}

func (c *Controller) processNextItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	if err := c.reconcileBridge(); err != nil {
		if errors.Is(err, errBridgeInUse) {
			c.queue.Forget(key)
			c.queue.AddAfter(key, bridgeInUseRetryDelay)
		} else {
			c.queue.AddRateLimited(key)
			klog.ErrorS(err, "Failed to reconcile secondary network bridge, requeuing")
		}
	} else {
		c.queue.Forget(key)
	}
	return true
}

// createOVSBridgeClient creates or attaches to an OVS bridge with the given name
// and options. It returns the client for the bridge.
func createOVSBridgeClient(
	bridgeName string,
	ovsdbClient client.Client,
	options ...ovsconfig.OVSBridgeOption,
) (ovsconfig.OVSBridgeClient, error) {
	bridgeClient := newOVSBridgeFn(bridgeName, ovsconfig.OVSDatapathSystem, ovsdbClient, options...)
	if err := bridgeClient.Create(); err != nil {
		return nil, fmt.Errorf("failed to create OVS bridge %s: %v", bridgeName, err)
	}
	klog.InfoS("OVS bridge ready", "bridge", bridgeName)
	return bridgeClient, nil
}

func managedSecondaryBridgeOptions(enableMulticastSnooping bool) []ovsconfig.OVSBridgeOption {
	var options []ovsconfig.OVSBridgeOption
	if enableMulticastSnooping {
		options = append(options, ovsconfig.WithMcastSnooping())
	}
	options = append(options, ovsconfig.WithExternalIDs(map[string]string{
		interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaSecondaryBridge,
	}))
	return options
}

// reconcileBridge is called during initialization and by the work queue worker
// when the AntreaNodeConfig controller signals a change or a retry is required.
// It queries OVSDB for the current Antrea-managed secondary bridge, computes the
// desired configuration, and reconciles:
//
//   - same bridge name as current → keep the bridge, update physical interfaces,
//     and cancel an in-progress drain.
//   - different bridge name → drain Pod-owned resources from the old bridge,
//     delete it, then create the new bridge.
//   - interfaces with allowedVLANs are configured as OVS trunk ports.
//
// State-update discipline: the controller retains the old bridge state while
// Pod-owned resources are draining. It clears that state only after draining
// completes and bridge deletion succeeds. This lets Pod reconciliation continue
// cleaning up Pod-owned interfaces from the old bridge.
func (c *Controller) reconcileBridge() error {
	staticBridge := ovsBridgeFromStatic(c.secNetConfig)
	desired := c.effectiveOVSBridge()
	if desired != nil {
		if err := validateSecondaryBridgeName(desired.BridgeName, c.primaryOVSBridgeName); err != nil {
			return err
		}
	}

	// Discover the existing Antrea-managed secondary bridge from OVSDB.
	currentBrName, err := findManagedSecondaryBridgeFn(c.ovsdbClient)
	if err != nil {
		return fmt.Errorf("failed to find managed secondary bridge: %w", err)
	}
	if currentBrName != "" {
		if err := validateSecondaryBridgeName(currentBrName, c.primaryOVSBridgeName); err != nil {
			return fmt.Errorf("refusing to reconcile managed bridge: %w", err)
		}
	}
	if currentBrName == "" && staticBridge != nil {
		// Do not attempt legacy adoption for an invalid static bridge. If the
		// static bridge is also desired, the desired-name validation above has
		// already returned an error. When an AntreaNodeConfig overrides the invalid
		// static setting, continue without touching the primary bridge.
		if validateSecondaryBridgeName(staticBridge.BridgeName, c.primaryOVSBridgeName) == nil {
			currentBrName, err = adoptSecondaryBridgeFn(staticBridge, c.ovsdbClient)
			if err != nil {
				return fmt.Errorf("failed to adopt secondary OVS bridge from static configuration: %w", err)
			}
		}
	}

	klog.InfoS("Reconciling secondary network bridge configuration",
		"current", currentBrName, "desired", bridgeName(desired))

	if desired != nil && currentBrName == desired.BridgeName {
		// Case: same bridge name - update physical interfaces in-place.
		// effectiveBridgeCfg is updated only after all same-bridge mutations succeed,
		// so a retry does not skip partially-applied host-connection changes.
		klog.InfoS("Secondary OVS bridge name unchanged, updating physical interfaces",
			"bridge", desired.BridgeName)
		c.mu.RLock()
		client := c.ovsBridgeClient
		effectiveBridgeCfg := c.effectiveBridgeCfg
		c.mu.RUnlock()

		// Reuse the installed client for Port-only changes. Creating a client
		// calls OVSBridge.Create, which is needed to attach after an Agent restart
		// or to apply changed bridge-level options.
		needsNewBridgeClient := client == nil
		if !needsNewBridgeClient {
			needsNewBridgeClient = effectiveBridgeCfg.EnableMulticastSnooping != desired.EnableMulticastSnooping
		}
		if needsNewBridgeClient {
			client, err = createOVSBridgeClient(
				desired.BridgeName,
				c.ovsdbClient,
				managedSecondaryBridgeOptions(desired.EnableMulticastSnooping)...,
			)
			if err != nil {
				return err
			}
		}
		if err := c.updatePhysicalInterfaces(client, desired); err != nil {
			return err
		}
		if needsNewBridgeClient {
			if err := c.podController.UpdateOVSBridgeClient(client); err != nil {
				return err
			}
		} else {
			c.podController.CancelOVSBridgeDrain()
		}
		c.mu.Lock()
		c.ovsBridgeClient = client
		c.effectiveBridgeCfg = desired
		c.mu.Unlock()
		klog.InfoS("Secondary OVS bridge reconciliation completed",
			"bridge", desired.BridgeName, "physicalInterfaces", desired.PhysicalInterfaces)
		return nil
	}

	if currentBrName != "" {
		klog.InfoS("Deleting current secondary OVS bridge before applying desired configuration",
			"current", currentBrName, "desired", bridgeName(desired))
		c.mu.RLock()
		currentClient := c.ovsBridgeClient
		c.mu.RUnlock()
		if currentClient == nil {
			currentClient, err = createOVSBridgeClient(currentBrName, c.ovsdbClient)
			if err != nil {
				return err
			}
		}
		bridgeDrained, err := c.podController.DrainOVSBridge(currentClient)
		if err != nil {
			return err
		}
		if !bridgeDrained {
			return errBridgeInUse
		}
		if err := c.deleteBridgeWithClient(currentClient); err != nil {
			return err
		}
		c.podController.CompleteOVSBridgeDrain()
		c.clearBridgeState()
	}
	if desired != nil {
		newClient, err := c.createAndConnectBridge(desired)
		if err != nil {
			return err
		}
		if err := c.podController.UpdateOVSBridgeClient(newClient); err != nil {
			return err
		}
		c.mu.Lock()
		c.ovsBridgeClient = newClient
		c.effectiveBridgeCfg = desired
		c.mu.Unlock()
		klog.InfoS("Secondary OVS bridge transition completed",
			"previousBridge", currentBrName, "currentBridge", desired.BridgeName)
	}
	return nil
}

func bridgeName(bridgeCfg *agenttypes.OVSBridgeConfig) string {
	if bridgeCfg == nil {
		return "<none>"
	}
	return bridgeCfg.BridgeName
}

func validateSecondaryBridgeName(bridgeName, primaryOVSBridgeName string) error {
	if primaryOVSBridgeName != "" && bridgeName == primaryOVSBridgeName {
		return fmt.Errorf("secondary OVS bridge %q conflicts with primary OVS bridge", bridgeName)
	}
	return nil
}

func (c *Controller) clearBridgeState() {
	c.mu.Lock()
	c.effectiveBridgeCfg = nil
	c.ovsBridgeClient = nil
	c.mu.Unlock()
}

// deleteBridgeWithClient refuses deletion while the bridge has container Ports, then tears
// down any host-connection interfaces found on the bridge and deletes it. PodController keeps
// the bridge in draining mode until this function succeeds, preventing new container Ports
// from being added between the OVSDB check and bridge deletion.
func (c *Controller) deleteBridgeWithClient(client ovsconfig.OVSBridgeClient) error {
	brName := client.GetBridgeName()
	// Query OVSDB to find and restore host-connection interfaces before
	// deleting the bridge. These host/uplink ports are not Pod secondary
	// interfaces and are not loaded into PodController's interfaceStore, which
	// tracks antrea-type=container ports only; OVSDB is the source of truth
	// after an agent restart.
	// A host-connection is identified by an internal port with antrea-type=host,
	// which covers the single-interface path where PrepareHostInterfaceConnection
	// renamed the kernel NIC.
	portList, err := client.GetPortList()
	if err != nil {
		return fmt.Errorf("failed to list ports on bridge %s before deletion: %w", brName, err)
	}
	var containerPorts []string
	for _, p := range portList {
		if p.ExternalIDs[interfacestore.AntreaInterfaceTypeKey] == interfacestore.AntreaContainer {
			containerPorts = append(containerPorts, p.Name)
		}
	}
	if len(containerPorts) > 0 {
		klog.InfoS("Waiting for Pod interfaces to be removed before deleting secondary bridge",
			"bridge", brName, "interfaces", containerPorts)
		return errBridgeInUse
	}
	for _, p := range portList {
		if p.IFType == "internal" && p.ExternalIDs[interfacestore.AntreaInterfaceTypeKey] == interfacestore.AntreaHost {
			klog.InfoS("Restoring host interface before bridge deletion",
				"interface", p.IFName, "bridge", brName)
			if err := restoreHostInterfaceConfigFn(brName, p.IFName); err != nil {
				return fmt.Errorf("failed to restore host interface %s before deleting bridge %s: %w",
					p.IFName, brName, err)
			}
		}
	}
	if err := client.Delete(); err != nil {
		return fmt.Errorf("failed to delete OVS bridge %s: %w", brName, err)
	}
	klog.InfoS("OVS bridge deleted", "bridge", brName)
	return nil
}

// createAndConnectBridge creates or attaches to the OVS bridge for the desired config
// and reconciles its physical interfaces.
// Create() reuses an existing bridge with the same name.
func (c *Controller) createAndConnectBridge(desired *agenttypes.OVSBridgeConfig) (ovsconfig.OVSBridgeClient, error) {
	newClient, err := createOVSBridgeClient(
		desired.BridgeName,
		c.ovsdbClient,
		managedSecondaryBridgeOptions(desired.EnableMulticastSnooping)...,
	)
	if err != nil {
		return nil, err
	}
	if err := c.connectBridgePhysicalInterfaces(newClient, desired); err != nil {
		return nil, err
	}
	return newClient, nil
}

// connectBridgePhysicalInterfaces reconciles the physical interfaces when the Controller
// attaches to a bridge for the first time.
func (c *Controller) connectBridgePhysicalInterfaces(
	client ovsconfig.OVSBridgeClient,
	desired *agenttypes.OVSBridgeConfig,
) error {
	physInterfaces := desired.PhysicalInterfaces
	if len(physInterfaces) == 1 {
		interfaceName := physInterfaces[0].Name
		klog.InfoS("Preparing host interface connection for secondary OVS bridge",
			"bridge", desired.BridgeName, "interface", interfaceName,
			"uplink", util.GenerateUplinkInterfaceName(interfaceName))
		bridgedName, alreadyExists, err := prepareHostInterfaceConnectionFn(
			client,
			interfaceName,
			0,
			map[string]string{
				interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaHost,
			},
			0,
		)
		if err != nil {
			return fmt.Errorf("failed to prepare host interface %s for secondary OVS bridge %s: %w",
				interfaceName, desired.BridgeName, err)
		}
		klog.InfoS("Prepared host interface connection for secondary OVS bridge",
			"bridge", desired.BridgeName, "interface", interfaceName,
			"uplink", bridgedName, "alreadyExists", alreadyExists)
		physInterfaces = []agenttypes.PhysicalInterfaceConfig{
			{Name: bridgedName, AllowedVLANs: desired.PhysicalInterfaces[0].AllowedVLANs},
		}
	} else if len(physInterfaces) > 1 {
		// The OVS bridge may already exist (Create is a no-op) with stale host-connection
		// ports from a prior single-interface config.
		if err := restoreStaleHostConnections(client, desired); err != nil {
			return err
		}
	}

	klog.InfoS("Reconciling physical uplinks on secondary OVS bridge",
		"bridge", desired.BridgeName, "interfaces", physInterfaces)
	if err := connectPhyInterfacesToOVSBridge(client, physInterfaces); err != nil {
		return fmt.Errorf("failed to connect physical uplinks to secondary OVS bridge %s: %w",
			desired.BridgeName, err)
	}
	klog.InfoS("Reconciled physical uplinks on secondary OVS bridge",
		"bridge", desired.BridgeName, "interfaces", physInterfaces)
	// Pre-existing ports may still carry trunk VLANs from an old config while the new
	// desired config has no AllowedVLANs; connectPhyInterfacesToOVSBridge skips plain
	// uplinks that are already present (unlike updatePhysicalInterfaces).
	if err := clearStaleTrunks(client, physInterfaces); err != nil {
		return fmt.Errorf("failed to reconcile trunk configuration on secondary OVS bridge %s: %w",
			desired.BridgeName, err)
	}
	return nil
}

// updatePhysicalInterfaces reconciles physical OVS Ports on an existing bridge.
func (c *Controller) updatePhysicalInterfaces(
	client ovsconfig.OVSBridgeClient,
	desired *agenttypes.OVSBridgeConfig,
) error {
	// Build a map of currently present ports on the bridge: interface name → UUID,
	// and a map of IFName → IFType for the host-connection sibling check below.
	portList, err := client.GetPortList()
	if err != nil {
		return fmt.Errorf("failed to list OVS ports on bridge %s: %v", desired.BridgeName, err)
	}
	existingPorts := make(map[string]string, len(portList))   // IFName → UUID
	existingIFTypes := make(map[string]string, len(portList)) // IFName → IFType
	existingAntreaTypes := make(map[string]string, len(portList))
	for _, p := range portList {
		existingPorts[p.IFName] = p.UUID
		existingIFTypes[p.IFName] = p.IFType
		existingAntreaTypes[p.IFName] = p.ExternalIDs[interfacestore.AntreaInterfaceTypeKey]
	}

	if err := c.restoreStaleHostConnections(desired, portList, existingPorts, existingIFTypes); err != nil {
		return err
	}

	bridgePhysInterfaces, prepareErr := c.prepareBridgePhysicalInterfaces(
		client, desired, existingPorts, existingIFTypes, existingAntreaTypes)
	if prepareErr != nil {
		return prepareErr
	}

	desiredBridgeIfaces := make(map[string]struct{}, len(bridgePhysInterfaces))
	for _, pi := range bridgePhysInterfaces {
		desiredBridgeIfaces[pi.Name] = struct{}{}
	}

	// Step 1: remove Antrea-managed uplink ports observed in OVSDB but no longer desired.
	// Host-connection pairs are restored above instead of being deleted as raw OVS ports.
	var toRemoveUUIDs []string
	var toRemoveNames []string
	for _, p := range portList {
		if _, stillExists := existingPorts[p.IFName]; !stillExists {
			continue
		}
		if p.ExternalIDs[interfacestore.AntreaInterfaceTypeKey] != interfacestore.AntreaUplink {
			continue
		}
		if _, desired := desiredBridgeIfaces[p.IFName]; desired {
			continue
		}
		toRemoveUUIDs = append(toRemoveUUIDs, p.UUID)
		toRemoveNames = append(toRemoveNames, p.IFName)
	}
	if len(toRemoveUUIDs) > 0 {
		if err := client.DeletePorts(toRemoveUUIDs); err != nil {
			return fmt.Errorf("failed to remove OVS ports %v from bridge %s: %v",
				toRemoveNames, desired.BridgeName, err)
		}
		for _, name := range toRemoveNames {
			klog.InfoS("Physical interface removed from secondary OVS bridge", "device", name)
			// Keep existingPorts in sync so Step 3 does not skip re-adding an interface
			// that was just removed (remove-then-re-add scenario).
			delete(existingPorts, name)
		}
	}

	// Step 2: clear trunk VLANs on existing ports whose desired config has no AllowedVLANs.
	// clearStaleTrunks reads the actual OVS port state and only calls SetPortTrunks
	// when the port genuinely has trunks set, so it is safe to call unconditionally.
	if err := clearStaleTrunks(client, bridgePhysInterfaces); err != nil {
		return fmt.Errorf("failed to reconcile trunk configuration on secondary OVS bridge %s: %w",
			desired.BridgeName, err)
	}

	// Step 3: add new ports and update the trunk VLAN list on existing ports that
	// have AllowedVLANs.  connectPhyInterfacesToOVSBridge creates the port when it
	// does not yet exist, and calls SetPortTrunks when it does and AllowedVLANs is
	// non-empty.
	var toConnect []agenttypes.PhysicalInterfaceConfig
	for _, pi := range bridgePhysInterfaces {
		if _, alreadyExists := existingPorts[pi.Name]; !alreadyExists || len(pi.AllowedVLANs) > 0 {
			toConnect = append(toConnect, pi)
		}
	}
	if len(toConnect) > 0 {
		klog.InfoS("Reconciling physical uplinks on secondary OVS bridge",
			"bridge", desired.BridgeName, "interfaces", toConnect)
		if err := connectPhyInterfacesToOVSBridge(client, toConnect); err != nil {
			return fmt.Errorf("failed to connect physical uplinks to secondary OVS bridge %s: %w",
				desired.BridgeName, err)
		}
		klog.InfoS("Reconciled physical uplinks on secondary OVS bridge",
			"bridge", desired.BridgeName, "interfaces", toConnect)
	}
	return nil
}

func (c *Controller) restoreStaleHostConnections(
	desired *agenttypes.OVSBridgeConfig,
	portList []ovsconfig.OVSPortData,
	existingPorts map[string]string,
	existingIFTypes map[string]string,
) error {
	desiredIfaces := make(map[string]struct{}, len(desired.PhysicalInterfaces))
	for _, pi := range desired.PhysicalInterfaces {
		desiredIfaces[pi.Name] = struct{}{}
	}
	keepSingleHostConnection := len(desired.PhysicalInterfaces) == 1

	restored, err := restoreStaleHostConnectionsFromPortList(desired.BridgeName, portList, func(hostIFName string) bool {
		if existingIFTypes[hostIFName] != "internal" {
			return true
		}
		_, desiredIface := desiredIfaces[hostIFName]
		return keepSingleHostConnection && desiredIface
	})
	if err != nil {
		return err
	}
	for _, conn := range restored {
		delete(existingPorts, conn.hostIFName)
		delete(existingPorts, conn.uplinkIFName)
		delete(existingIFTypes, conn.hostIFName)
		delete(existingIFTypes, conn.uplinkIFName)
	}
	return nil
}

// prepareBridgePhysicalInterfaces returns the physical OVS port configs that should be used for
// trunk reconciliation and port connection on the bridge.
//
// AntreaNodeConfig records the original host interface name, but a single-uplink bridge does not
// use that original name as the physical uplink port. PrepareHostInterfaceConnection renames the
// host NIC from ethX to ethX~, creates ethX as an internal OVS port for host networking, and uses
// ethX~ as the real physical uplink. Therefore same-bridge updates must apply AllowedVLANs and
// stale-trunk clearing to ethX~, not to the internal ethX port.
//
// This helper normalizes desired.PhysicalInterfaces into the actual bridge-side physical ports.
// For single-uplink configs it prepares or reuses the host-connection setup and returns the
// generated ethX~ uplink. For multi-uplink configs, stale host-connection pairs have already
// been restored from observed OVSDB state, so the original interfaces are returned unchanged.
func (c *Controller) prepareBridgePhysicalInterfaces(
	ovsBridgeClient ovsconfig.OVSBridgeClient,
	desired *agenttypes.OVSBridgeConfig,
	existingPorts map[string]string,
	existingIFTypes map[string]string,
	existingAntreaTypes map[string]string,
) ([]agenttypes.PhysicalInterfaceConfig, error) {
	if len(desired.PhysicalInterfaces) == 1 {
		iface := desired.PhysicalInterfaces[0]
		bridgedName := util.GenerateUplinkInterfaceName(iface.Name)
		if _, exists := existingPorts[bridgedName]; exists {
			return []agenttypes.PhysicalInterfaceConfig{
				{Name: bridgedName, AllowedVLANs: iface.AllowedVLANs},
			}, nil
		}
		// PrepareHostInterfaceConnection creates the internal host Port before the
		// physical uplink Port is added to OVS. A failure between these operations
		// leaves a valid host connection with the renamed kernel uplink but no OVS
		// uplink Port. Resume from that state instead of trying to rename the host
		// interface a second time.
		if existingIFTypes[iface.Name] == "internal" &&
			existingAntreaTypes[iface.Name] == interfacestore.AntreaHost {
			if _, err := interfaceByNameFn(bridgedName); err == nil {
				klog.InfoS("Resuming incomplete host interface connection",
					"bridge", desired.BridgeName, "interface", iface.Name, "uplink", bridgedName,
					"internalPortPresent", true, "kernelUplinkPresent", true, "ovsUplinkPortPresent", false)
				return []agenttypes.PhysicalInterfaceConfig{
					{Name: bridgedName, AllowedVLANs: iface.AllowedVLANs},
				}, nil
			}
		}
		if uuid, exists := existingPorts[iface.Name]; exists && existingIFTypes[iface.Name] != "internal" {
			if err := ovsBridgeClient.DeletePorts([]string{uuid}); err != nil {
				return nil, fmt.Errorf("failed to remove OVS port %s from bridge %s before host connection setup: %v",
					iface.Name, desired.BridgeName, err)
			}
			// Keep the caller's observed-port maps in sync with the OVSDB change so
			// updatePhysicalInterfaces can add the generated uplink port later in
			// the same reconciliation.
			delete(existingPorts, iface.Name)
			delete(existingIFTypes, iface.Name)
			klog.InfoS("Physical interface removed from secondary OVS bridge before host connection setup",
				"device", iface.Name, "bridge", desired.BridgeName)
		}

		klog.InfoS("Preparing host interface connection for secondary OVS bridge",
			"bridge", desired.BridgeName, "interface", iface.Name, "uplink", bridgedName)
		bridgedName, alreadyExists, err := prepareHostInterfaceConnectionFn(
			ovsBridgeClient,
			iface.Name,
			0,
			map[string]string{
				interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaHost,
			},
			0,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to prepare host interface %s for secondary OVS bridge %s: %w",
				iface.Name, desired.BridgeName, err)
		}
		klog.InfoS("Prepared host interface connection for secondary OVS bridge",
			"bridge", desired.BridgeName, "interface", iface.Name,
			"uplink", bridgedName, "alreadyExists", alreadyExists)
		return []agenttypes.PhysicalInterfaceConfig{
			{Name: bridgedName, AllowedVLANs: iface.AllowedVLANs},
		}, nil
	}

	return desired.PhysicalInterfaces, nil
}

// connectPhyInterfacesToOVSBridge adds each physical interface to the OVS bridge
// as an uplink port.  When AllowedVLANs is set the port is created or updated in
// trunk mode with those VLAN IDs; otherwise a plain uplink port is created.
// If the port already exists and AllowedVLANs is non-empty, the trunk VLAN list is
// always updated to match the desired config.
func connectPhyInterfacesToOVSBridge(ovsBridgeClient ovsconfig.OVSBridgeClient, phyInterfaces []agenttypes.PhysicalInterfaceConfig) error {
	for _, pi := range phyInterfaces {
		if _, err := interfaceByNameFn(pi.Name); err != nil {
			return fmt.Errorf("failed to get interface %s: %w", pi.Name, err)
		}
	}

	externalIDs := map[string]string{
		interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaUplink,
	}
	for _, pi := range phyInterfaces {
		_, err := ovsBridgeClient.GetOFPort(pi.Name)
		if err != nil && !errors.Is(err, client.ErrNotFound) {
			return fmt.Errorf("failed to get OFPort for interface %s: %w", pi.Name, err)
		}
		notConnected := errors.Is(err, client.ErrNotFound)

		if len(pi.AllowedVLANs) > 0 {
			if notConnected {
				// Pass ofPortRequest=0 so OVS auto-assign the OF port number.
				// Pinning a number derived from the loop index would collide across
				// reconciliation cycles when the interface list is a filtered subset.
				if _, err := ovsBridgeClient.CreateTrunkPort(pi.Name, 0, pi.AllowedVLANs, externalIDs); err != nil {
					return fmt.Errorf("failed to create OVS trunk port %s: %w", pi.Name, err)
				}
				klog.InfoS("Physical interface added to secondary OVS bridge in trunk mode", "device", pi.Name, "vlanIDs", pi.AllowedVLANs)
			} else {
				if err := ovsBridgeClient.SetPortTrunks(pi.Name, pi.AllowedVLANs); err != nil {
					return fmt.Errorf("failed to update trunk VLANs for OVS port %s: %w", pi.Name, err)
				}
				klog.InfoS("Updated trunk VLAN list on secondary OVS bridge port", "device", pi.Name, "vlanIDs", pi.AllowedVLANs)
			}
			continue
		}

		if notConnected {
			// Pass ofPortRequest=0 so OVS auto-assign the OF port number.
			if _, err := ovsBridgeClient.CreateUplinkPort(pi.Name, 0, externalIDs); err != nil {
				return fmt.Errorf("failed to create OVS uplink port %s: %w", pi.Name, err)
			}
			klog.InfoS("Physical interface added to secondary OVS bridge", "device", pi.Name)
		} else {
			klog.V(2).InfoS("Physical interface already connected to secondary OVS bridge, skipping", "device", pi.Name)
		}
	}
	return nil
}
