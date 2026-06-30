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

	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second
)

var (
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

type secondaryNetworkControllerQueue = workqueue.TypedRateLimitingInterface[string]

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
	return EffectiveSecondaryOVSBridgeFromAgentConfig(c.secNetConfig)
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
		secNetConfig: secNetConfig,
		nodeName:     nodeConfig.Name,
		ovsdbClient:  ovsdbClient,
	}

	if ancUpdateSubscriber != nil {
		c.dynamicBridgeReconcile = true
		c.ancFirstSnapshotCh = make(chan struct{})
		c.queue = workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.NewTypedItemExponentialFailureRateLimiter[string](minRetryDelay, maxRetryDelay),
			workqueue.TypedRateLimitingQueueConfig[string]{Name: "secondaryNetworkBridge"},
		)
	}

	var effectiveBridgeCfg *agenttypes.OVSBridgeConfig
	var ovsBridgeClient ovsconfig.OVSBridgeClient
	var err error

	if !c.dynamicBridgeReconcile {
		effectiveBridgeCfg, ovsBridgeClient, err = resolveAndCreateOVSBridge(c.effectiveOVSBridge, c.ovsdbClient)
		if err != nil {
			return nil, err
		}
	}

	netAttachDefClient, err := createNetworkAttachDefClient(clientConnectionConfig, kubeAPIServerOverride)
	if err != nil {
		return nil, fmt.Errorf("NetworkAttachmentDefinition client creation failed: %v", err)
	}

	podWatchController, err := podwatch.NewPodController(
		k8sClient, netAttachDefClient, podInformer,
		podUpdateSubscriber, primaryInterfaceStore, nodeConfig, ovsBridgeClient, ipPoolLister)
	if err != nil {
		return nil, err
	}

	c.ovsBridgeClient = ovsBridgeClient
	c.effectiveBridgeCfg = effectiveBridgeCfg
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
		if err := c.reconcileBridge(); err != nil {
			return err
		}
		klog.InfoS("Secondary network bridge reconciled from initial AntreaNodeConfig snapshot")
		return nil
	}

	bridgeCfg := c.effectiveBridgeCfg
	if bridgeCfg == nil {
		return nil
	}

	// Only single-interface host-connection migration is supported.
	if len(bridgeCfg.PhysicalInterfaces) == 1 {
		iface := bridgeCfg.PhysicalInterfaces[0]
		bridgedName, _, err := prepareHostInterfaceConnectionFn(
			c.ovsBridgeClient,
			iface.Name,
			0,
			map[string]string{
				interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaHost,
			},
			0,
		)
		if err != nil {
			return err
		}
		phyInterfaces := []agenttypes.PhysicalInterfaceConfig{
			{Name: bridgedName, AllowedVLANs: iface.AllowedVLANs},
		}
		if err := connectPhyInterfacesToOVSBridge(c.ovsBridgeClient, phyInterfaces); err != nil {
			return err
		}
		return clearStaleTrunks(c.ovsBridgeClient, phyInterfaces)
	}

	// Multi-interface path: before connecting ports, tear down any stale
	// host-connection setup left from a previous single-interface run.  A stale
	// setup is identified by finding an OVS port whose interface type is
	// "internal" AND whose kernel-rename sibling (GenerateUplinkInterfaceName)
	// also exists as a port on the bridge.  In that case RestoreHostInterface-
	// Configuration undoes the rename and removes both OVS ports so that the
	// interface can be re-added as a plain uplink below.
	if err := restoreStaleHostConnections(c.ovsBridgeClient, bridgeCfg); err != nil {
		return err
	}

	if err := connectPhyInterfacesToOVSBridge(c.ovsBridgeClient, bridgeCfg.PhysicalInterfaces); err != nil {
		return err
	}
	return clearStaleTrunks(c.ovsBridgeClient, bridgeCfg.PhysicalInterfaces)
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
		go func() {
			for c.processNextItem() {
			}
		}()
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
		c.queue.AddRateLimited(key)
		klog.ErrorS(err, "Failed to reconcile secondary network bridge, requeuing")
	} else {
		c.queue.Forget(key)
	}
	return true
}

// createOVSBridgeClient creates or attaches to an OVS bridge with the given name
// and multicast-snooping setting, and marks it as an Antrea-managed secondary
// bridge via external_ids. It returns the client for the bridge.
func createOVSBridgeClient(bridgeName string, enableMulticastSnooping bool, ovsdbClient client.Client) (ovsconfig.OVSBridgeClient, error) {
	var options []ovsconfig.OVSBridgeOption
	if enableMulticastSnooping {
		options = append(options, ovsconfig.WithMcastSnooping())
	}
	options = append(options, ovsconfig.WithExternalIDs(map[string]string{
		interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaSecondaryBridge,
	}))
	bridgeClient := newOVSBridgeFn(bridgeName, ovsconfig.OVSDatapathSystem, ovsdbClient, options...)
	if err := bridgeClient.Create(); err != nil {
		return nil, fmt.Errorf("failed to create OVS bridge %s: %v", bridgeName, err)
	}
	klog.InfoS("OVS bridge ready", "bridge", bridgeName)
	return bridgeClient, nil
}

// attachOVSBridgeClient returns a client for an existing OVS bridge name. Create
// is idempotent and is used here to look up the bridge UUID before operations
// such as Delete.
func attachOVSBridgeClient(bridgeName string, ovsdbClient client.Client) (ovsconfig.OVSBridgeClient, error) {
	bridgeClient := newOVSBridgeFn(bridgeName, ovsconfig.OVSDatapathSystem, ovsdbClient)
	if err := bridgeClient.Create(); err != nil {
		return nil, fmt.Errorf("failed to attach to OVS bridge %s: %v", bridgeName, err)
	}
	return bridgeClient, nil
}

// resolveAndCreateOVSBridge evaluates effectiveBridge() and creates the OVS bridge.
// Returns the effective OVSBridgeConfig (nil when no bridge is configured), the
// corresponding OVSBridgeClient, and any error.
func resolveAndCreateOVSBridge(
	effectiveBridge func() *agenttypes.OVSBridgeConfig,
	ovsdbClient client.Client,
) (*agenttypes.OVSBridgeConfig, ovsconfig.OVSBridgeClient, error) {
	effectiveBridgeCfg := effectiveBridge()
	if effectiveBridgeCfg == nil {
		return nil, nil, nil
	}
	ovsBridgeClient, err := createOVSBridgeClient(effectiveBridgeCfg.BridgeName, effectiveBridgeCfg.EnableMulticastSnooping, ovsdbClient)
	if err != nil {
		return nil, nil, err
	}
	return effectiveBridgeCfg, ovsBridgeClient, nil
}

// reconcileBridge is called by the work queue worker when the AntreaNodeConfig sync
// controller signals a change (or on retries). It queries OVSDB for the current
// Antrea-managed secondary bridge, computes the desired configuration, and reconciles:
//
//   - same bridge name as current → keep bridge, update physical interfaces.
//   - different bridge name → delete old bridge first, then create the new bridge.
//   - interfaces with allowedVLANs are configured as OVS trunk ports.
//
// State-update discipline: after any destructive operation (bridge deletion) the controller
// state is immediately cleared under the mutex so that a subsequent retry does not attempt to
// delete an already-deleted bridge.
func (c *Controller) reconcileBridge() error {
	staticBridge := EffectiveSecondaryOVSBridgeFromAgentConfig(c.secNetConfig)
	desired := c.effectiveOVSBridge()

	currentBrName, err := findManagedSecondaryBridgeFn(c.ovsdbClient)
	if err != nil {
		return fmt.Errorf("failed to find managed secondary bridge: %w", err)
	}
	if currentBrName == "" {
		currentBrName, err = adoptSecondaryBridgeFn(staticBridge, c.ovsdbClient)
		if err != nil {
			return fmt.Errorf("failed to adopt secondary OVS bridge from static configuration: %w", err)
		}
	}

	if currentBrName == "" && desired == nil {
		return nil
	}
	desiredBrName := ""
	if desired != nil {
		desiredBrName = desired.BridgeName
	}
	klog.InfoS("Reconciling secondary network bridge configuration",
		"current", bridgeName(currentBrName), "desired", bridgeName(desiredBrName))

	// Case: no bridge desired — delete the existing one.
	if desired == nil {
		return c.deleteAndDisconnectBridge(currentBrName)
	}

	// Case: new bridge desired when no managed bridge exists in OVSDB.
	if currentBrName == "" {
		return c.createAndConnectBridge(desired)
	}

	// Case: bridge name changed.
	// The old bridge MUST be deleted before the new one is created.  State is
	// cleared under the mutex immediately after the deletion succeeds so that if
	// createAndConnectBridge subsequently fails the next retry starts from a clean
	// "no bridge" state rather than trying to delete the already-gone old bridge.
	if currentBrName != desired.BridgeName {
		klog.InfoS("Secondary OVS bridge name changed, deleting old bridge before creating new one",
			"old", currentBrName, "new", desired.BridgeName)
		if err := c.deleteAndDisconnectBridge(currentBrName); err != nil {
			return err
		}
		return c.createAndConnectBridge(desired)
	}

	// Case: same bridge name — update physical interfaces in-place.
	// effectiveBridgeCfg is updated only after all same-bridge mutations succeed,
	// so a retry does not skip partially-applied host-connection changes.
	klog.InfoS("Secondary OVS bridge name unchanged, updating physical interfaces",
		"bridge", desired.BridgeName)
	return c.updatePhysicalInterfaces(desired)
}

func (c *Controller) clearBridgeState() {
	c.mu.Lock()
	c.effectiveBridgeCfg = nil
	c.ovsBridgeClient = nil
	c.mu.Unlock()
}

// deleteAndDisconnectBridge deletes the OVS bridge named brName, clears controller state,
// and notifies the pod controller that no secondary bridge is in use. An empty brName is a
// no-op. Controller state is cleared before updating the PodController so that when the
// update fails the next reconcile (which queries OVSDB) correctly sees no bridge and does
// not re-attempt deletion.
func (c *Controller) deleteAndDisconnectBridge(brName string) error {
	if err := c.deleteBridge(brName); err != nil {
		return err
	}
	c.clearBridgeState()
	if err := c.podController.UpdateOVSBridgeClient(nil); err != nil {
		return err
	}
	return nil
}

// deleteBridge tears down any host-connection interfaces found on the bridge (derived from
// OVSDB port state, not from the controller's cached config) and deletes the OVS bridge.
func (c *Controller) deleteBridge(brName string) error {
	if brName == "" {
		return nil
	}
	client, err := attachOVSBridgeClient(brName, c.ovsdbClient)
	if err != nil {
		return err
	}
	// Query OVSDB to find and restore host-connection interfaces before
	// deleting the bridge. A host-connection is identified by an internal
	// port with antrea-type=host — this covers the single-interface path
	// where PrepareHostInterfaceConnection renamed the kernel NIC.
	portList, err := client.GetPortList()
	if err != nil {
		return fmt.Errorf("failed to list ports on bridge %s before deletion: %w", brName, err)
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
		return fmt.Errorf("failed to delete OVS bridge %s: %v", brName, err)
	}
	klog.InfoS("OVS bridge deleted", "bridge", brName)
	return nil
}

// createAndConnectBridge creates or attaches to the OVS bridge for the desired config,
// connects physical interfaces, clears stale trunks, and updates the controller state.
// Create() reuses an existing bridge with the same name, so this path mirrors
// Initialize: multi-interface configs run restoreStaleHostConnections before connect, and
// clearStaleTrunks runs after connect for all interface counts.
func (c *Controller) createAndConnectBridge(desired *agenttypes.OVSBridgeConfig) error {
	newClient, err := createOVSBridgeClient(desired.BridgeName, desired.EnableMulticastSnooping, c.ovsdbClient)
	if err != nil {
		return err
	}

	physInterfaces := desired.PhysicalInterfaces
	if len(physInterfaces) == 1 {
		bridgedName, _, err := prepareHostInterfaceConnectionFn(
			newClient,
			physInterfaces[0].Name,
			0,
			map[string]string{
				interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaHost,
			},
			0,
		)
		if err != nil {
			return err
		}
		physInterfaces = []agenttypes.PhysicalInterfaceConfig{
			{Name: bridgedName, AllowedVLANs: desired.PhysicalInterfaces[0].AllowedVLANs},
		}
	} else if len(physInterfaces) > 1 {
		// The OVS bridge may already exist (Create is a no-op) with stale host-connection
		// ports from a prior single-interface config — same as Initialize.
		if err := restoreStaleHostConnections(newClient, desired); err != nil {
			return err
		}
	}

	if err := connectPhyInterfacesToOVSBridge(newClient, physInterfaces); err != nil {
		return err
	}
	// Pre-existing ports may still carry trunk VLANs from an old config while the new
	// desired config has no AllowedVLANs; connectPhyInterfacesToOVSBridge skips plain
	// uplinks that are already present (unlike Initialize / updatePhysicalInterfaces).
	if err := clearStaleTrunks(newClient, physInterfaces); err != nil {
		return err
	}

	// Notify PodController of the new bridge so it uses the correct OVS client
	// for future Pod interface operations and reloads its interface store.
	if err := c.podController.UpdateOVSBridgeClient(newClient); err != nil {
		return err
	}

	c.mu.Lock()
	c.ovsBridgeClient = newClient
	c.effectiveBridgeCfg = desired
	c.mu.Unlock()
	return nil
}

// updatePhysicalInterfaces reconciles OVS ports on an existing bridge to match the
// desired config. effectiveBridgeCfg is updated under a lock so that concurrent
// podwatch events see a consistent state.
func (c *Controller) updatePhysicalInterfaces(desired *agenttypes.OVSBridgeConfig) error {
	c.mu.RLock()
	updatePodController := c.ovsBridgeClient == nil
	c.mu.RUnlock()

	client, err := createOVSBridgeClient(desired.BridgeName, desired.EnableMulticastSnooping, c.ovsdbClient)
	if err != nil {
		return err
	}

	// Build a map of currently present ports on the bridge: interface name → UUID,
	// and a map of IFName → IFType for the host-connection sibling check below.
	portList, err := client.GetPortList()
	if err != nil {
		return fmt.Errorf("failed to list OVS ports on bridge %s: %v", desired.BridgeName, err)
	}
	existingPorts := make(map[string]string, len(portList))   // IFName → UUID
	existingIFTypes := make(map[string]string, len(portList)) // IFName → IFType
	for _, p := range portList {
		existingPorts[p.IFName] = p.UUID
		existingIFTypes[p.IFName] = p.IFType
	}

	if err := c.restoreStaleHostConnections(desired, portList, existingPorts, existingIFTypes); err != nil {
		return err
	}

	bridgePhysInterfaces, prepareErr := c.prepareBridgePhysicalInterfaces(client, desired, existingPorts, existingIFTypes)
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
		return err
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
		if err := connectPhyInterfacesToOVSBridge(client, toConnect); err != nil {
			return err
		}
	}
	if updatePodController {
		if err := c.podController.UpdateOVSBridgeClient(client); err != nil {
			return err
		}
	}
	// All steps succeeded; record the fully-desired config.
	c.mu.Lock()
	c.ovsBridgeClient = client
	c.effectiveBridgeCfg = desired
	c.mu.Unlock()
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
) ([]agenttypes.PhysicalInterfaceConfig, error) {
	if len(desired.PhysicalInterfaces) == 1 {
		iface := desired.PhysicalInterfaces[0]
		bridgedName := util.GenerateUplinkInterfaceName(iface.Name)
		if _, exists := existingPorts[bridgedName]; exists {
			return []agenttypes.PhysicalInterfaceConfig{
				{Name: bridgedName, AllowedVLANs: iface.AllowedVLANs},
			}, nil
		}
		if uuid, exists := existingPorts[iface.Name]; exists && existingIFTypes[iface.Name] != "internal" {
			if err := ovsBridgeClient.DeletePorts([]string{uuid}); err != nil {
				return nil, fmt.Errorf("failed to remove OVS port %s from bridge %s before host connection setup: %v",
					iface.Name, desired.BridgeName, err)
			}
			delete(existingPorts, iface.Name)
			delete(existingIFTypes, iface.Name)
			klog.InfoS("Physical interface removed from secondary OVS bridge before host connection setup",
				"device", iface.Name, "bridge", desired.BridgeName)
		}

		bridgedName, _, err := prepareHostInterfaceConnectionFn(
			ovsBridgeClient,
			iface.Name,
			0,
			map[string]string{
				interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaHost,
			},
			0,
		)
		if err != nil {
			return nil, err
		}
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
			return fmt.Errorf("failed to get interface %s: %v", pi.Name, err)
		}
	}

	externalIDs := map[string]string{
		interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaUplink,
	}
	for _, pi := range phyInterfaces {
		_, notConnected := ovsBridgeClient.GetOFPort(pi.Name)

		if len(pi.AllowedVLANs) > 0 {
			if notConnected != nil {
				// Pass ofPortRequest=0 so OVS auto-assign the OF port number.
				// Pinning a number derived from the loop index would collide across
				// reconciliation cycles when the interface list is a filtered subset.
				if _, err := ovsBridgeClient.CreateTrunkPort(pi.Name, 0, pi.AllowedVLANs, externalIDs); err != nil {
					return fmt.Errorf("failed to create OVS trunk port %s: %v", pi.Name, err)
				}
				klog.InfoS("Physical interface added to secondary OVS bridge in trunk mode", "device", pi.Name, "vlanIDs", pi.AllowedVLANs)
			} else {
				if err := ovsBridgeClient.SetPortTrunks(pi.Name, pi.AllowedVLANs); err != nil {
					return fmt.Errorf("failed to update trunk VLANs for OVS port %s: %v", pi.Name, err)
				}
				klog.InfoS("Updated trunk VLAN list on secondary OVS bridge port", "device", pi.Name, "vlanIDs", pi.AllowedVLANs)
			}
			continue
		}

		if notConnected != nil {
			// Pass ofPortRequest=0 so OVS auto-assign the OF port number.
			if _, err := ovsBridgeClient.CreateUplinkPort(pi.Name, 0, externalIDs); err != nil {
				return fmt.Errorf("failed to create OVS uplink port %s: %v", pi.Name, err)
			}
			klog.InfoS("Physical interface added to secondary OVS bridge", "device", pi.Name)
		} else {
			klog.V(2).InfoS("Physical interface already connected to secondary OVS bridge, skipping", "device", pi.Name)
		}
	}
	return nil
}

// bridgeName returns the bridge name, or "<none>" for empty.
func bridgeName(name string) string {
	if name == "" {
		return "<none>"
	}
	return name
}
