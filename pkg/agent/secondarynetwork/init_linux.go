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

	minRetryDelay         = 5 * time.Second
	maxRetryDelay         = 30 * time.Second
	bridgeInUseRetryDelay = 10 * time.Second
)

var (
	errStaleBridgeInUse = errors.New("secondary OVS bridge is in use")

	// Funcs which will be overridden with mock funcs in tests.
	interfaceByNameFn = net.InterfaceByName
	renameInterfaceFn = util.RenameInterface
	// func(bridge, ifName, ifOFPort, externalIDs, mtu) (bridgedName, alreadyExists, error)
	prepareHostInterfaceConnectionFn = util.PrepareHostInterfaceConnection
	restoreHostInterfaceConfigFn     = util.RestoreHostInterfaceConfiguration // func(brName, ifName string) error
	newOVSBridgeFn                   = ovsconfig.NewOVSBridge
	// findStartupSecondaryBridgeFn queries OVSDB for an existing managed or
	// legacy desired secondary bridge. Overridden in tests.
	findStartupSecondaryBridgeFn = findStartupSecondaryBridge
)

// effectiveOVSBridge returns the desired OVS bridge for this node. When AntreaNodeConfig
// drives the bridge, only snapshots delivered on the notify channel are used.
// When ANC is disabled, only static agent config is consulted.
func (c *Controller) effectiveOVSBridge() *agenttypes.OVSBridgeConfig {
	if c.dynamicBridgeReconcile {
		return effectiveSecondaryOVSBridgeFromSnapshot(c.latestANCSnapshot.Load(), c.secNetConfig, c.primaryOVSBridgeName)
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
		podUpdateSubscriber, primaryInterfaceStore, nodeConfig, ipPoolLister)
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

	err := c.syncBridge()
	if !c.dynamicBridgeReconcile {
		return err
	}
	if err != nil {
		if errors.Is(err, errStaleBridgeInUse) {
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

// ShutdownAndRestore stops bridge reconciliation, waits for any bridge operation
// already in progress, and restores interface configuration from the secondary
// bridge back to the host interface. It does not wait for PodController workers.
func (c *Controller) ShutdownAndRestore() {
	c.shutdownBridgeQueue()

	c.bridgeSyncMutex.Lock()
	defer c.bridgeSyncMutex.Unlock()

	bridgeCfg := c.effectiveBridgeCfg
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

func (c *Controller) shutdownBridgeQueue() {
	if !c.dynamicBridgeReconcile {
		return
	}
	c.bridgeQueueShutdownOnce.Do(c.queue.ShutDown)
}

// Run starts the secondary network controller. When AntreaNodeConfig is
// enabled, Initialize handles the initial ANC snapshot wait and bridge creation; a bridge
// reconciliation worker then processes items enqueued by the ANC SubscribableChannel.
// When ANC is off, the bridge is static and no worker is started. On shutdown, Run
// stops accepting bridge updates without waiting for in-progress reconciliation
// or PodController workers.
func (c *Controller) Run(stopCh <-chan struct{}) {
	klog.InfoS("Starting secondary network controller")
	defer klog.InfoS("Shutting down secondary network controller")

	if c.dynamicBridgeReconcile {
		go func() {
			for c.processNextItem() {
			}
		}()
	}

	go c.podController.Run(stopCh)

	<-stopCh
	c.shutdownBridgeQueue()
}

func (c *Controller) processNextItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	if err := c.syncBridge(); err != nil {
		if errors.Is(err, errStaleBridgeInUse) {
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

// syncBridge resolves one desired configuration snapshot, initializes the
// current bridge state once after Agent startup, then reconciles that state
// against the same snapshot. Startup initialization is retried as a unit after
// transient failures and committed only after PodController restoration succeeds.
func (c *Controller) syncBridge() error {
	c.bridgeSyncMutex.Lock()
	defer c.bridgeSyncMutex.Unlock()

	// ShutdownAndRestore shuts down the queue before waiting for this operation
	// mutex. Skip items which were already queued so they cannot reconcile the
	// bridge after restoration.
	if c.dynamicBridgeReconcile && c.queue.ShuttingDown() {
		return nil
	}

	// When the AntreaNodeConfig lister returns an error, skip reconciliation
	// instead of deleting the current bridge. A transient error should not tear
	// down a working secondary network. The static config does not depend on the
	// AntreaNodeConfig lister and takes precedence over it, so a static bridge
	// must still be reconciled when the lister is unavailable.
	if c.dynamicBridgeReconcile {
		if snap := c.latestANCSnapshot.Load(); snap != nil && snap.AntreaNodeConfigListError != "" {
			if c.secNetConfig == nil || len(c.secNetConfig.OVSBridges) == 0 {
				klog.ErrorS(errors.New(snap.AntreaNodeConfigListError), "Skipping secondary bridge reconciliation due to AntreaNodeConfig list error")
				return nil
			}
		}
	}

	desired := c.effectiveOVSBridge()
	if err := c.initializeBridgeState(desired); err != nil {
		return err
	}
	return c.reconcileBridge(desired)
}

// initializeBridgeState initializes the current bridge state once after Agent
// startup. It attaches to an existing managed bridge, or adopts an existing
// legacy bridge matching the desired name. A desired bridge which does not
// already exist is left for reconcileBridge to create and configure.
func (c *Controller) initializeBridgeState(desired *agenttypes.OVSBridgeConfig) error {
	if c.bridgeStateInitDone {
		return nil
	}

	desiredBrName := ""
	if desired != nil {
		desiredBrName = desired.BridgeName
	}
	startupBrName, err := findStartupSecondaryBridgeFn(c.ovsdbClient, desiredBrName)
	if err != nil {
		return fmt.Errorf("failed to find startup secondary bridge: %w", err)
	}

	var startupBridgeClient ovsconfig.OVSBridgeClient
	if startupBrName != "" {
		startupBridgeClient, err = createOVSBridge(startupBrName, c.ovsdbClient)
		if err != nil {
			return fmt.Errorf("failed to attach to startup secondary OVS bridge %s: %w", startupBrName, err)
		}
	}
	if err := c.podController.InitializeOVSBridge(startupBridgeClient); err != nil {
		return err
	}

	c.ovsBridgeClient = startupBridgeClient
	c.bridgeStateInitDone = true
	return nil
}

// reconcileBridge uses the cached current bridge client to reconcile the
// desired configuration:
//
//   - same bridge name as current → keep the bridge, update physical interfaces,
//     and cancel an in-progress drain.
//   - different bridge name → drain Pod-owned resources from the old bridge,
//     delete it, then create the new bridge.
//   - interfaces with allowedVLANs are configured as OVS trunk ports.
//
// State-update discipline: Controller retains the old bridge state until bridge
// deletion succeeds. PodController retains its bridge client while Pod-owned
// resources are draining and detaches it as soon as draining completes.
func (c *Controller) reconcileBridge(desired *agenttypes.OVSBridgeConfig) error {
	currentClient := c.ovsBridgeClient
	currentBrName := ""
	if currentClient != nil {
		currentBrName = currentClient.GetBridgeName()
	}

	if desired != nil && currentBrName == desired.BridgeName {
		// Case: same bridge name - update physical interfaces in-place.
		// effectiveBridgeCfg is updated only after all same-bridge mutations succeed,
		// so a retry does not skip partially-applied host-connection changes.
		klog.InfoS("Secondary OVS bridge name unchanged, updating physical interfaces",
			"bridge", desired.BridgeName)

		needsMcastSnoopingUpdate := c.effectiveBridgeCfg == nil ||
			c.effectiveBridgeCfg.EnableMulticastSnooping != desired.EnableMulticastSnooping
		if needsMcastSnoopingUpdate {
			if err := currentClient.SetMcastSnooping(desired.EnableMulticastSnooping); err != nil {
				return fmt.Errorf("failed to update multicast snooping on OVS bridge %s: %w", desired.BridgeName, err)
			}
		}
		if err := updatePhysicalInterfaces(currentClient, desired); err != nil {
			return err
		}
		// The bridge may have been drained and unset in PodController after a
		// failed deletion, so always install the current client again.
		c.podController.SetOVSBridgeClient(currentClient)
		c.effectiveBridgeCfg = desired
		klog.InfoS("Secondary OVS bridge reconciliation completed",
			"bridge", desired.BridgeName, "physicalInterfaces", desired.PhysicalInterfaces)
		return nil
	}

	if currentClient != nil {
		desiredName := "<none>"
		if desired != nil {
			desiredName = desired.BridgeName
		}
		klog.InfoS("Deleting current secondary OVS bridge before applying desired configuration",
			"current", currentBrName, "desired", desiredName)
		if !c.podController.DrainOVSBridge() {
			return errStaleBridgeInUse
		}
		// DrainOVSBridge detaches the bridge client from PodController once all Pod
		// interfaces are removed. If deleteBridge fails, the retry keeps currentClient
		// set while PodController has no bridge client; if the effective bridge then
		// changes back to the current bridge name, the same-name block above
		// re-attaches the detached client via SetOVSBridgeClient.
		if err := deleteBridge(currentClient); err != nil {
			return err
		}
		c.ovsBridgeClient = nil
		c.effectiveBridgeCfg = nil
	}
	if desired != nil {
		newClient, err := c.createAndConfigureBridge(desired)
		if err != nil {
			return err
		}
		c.podController.SetOVSBridgeClient(newClient)
		c.ovsBridgeClient = newClient
		c.effectiveBridgeCfg = desired
		klog.InfoS("Secondary OVS bridge transition completed",
			"previousBridge", currentBrName, "currentBridge", desired.BridgeName)
	}
	return nil
}

// createAndConfigureBridge creates or attaches to the OVS bridge for the desired config
// and reconciles its physical interfaces. The bridge is expected to be newly created
// (or just deleted), but updatePhysicalInterfaces also cleans up any leftover state
// in case it is not: stale host-connection pairs are restored and ports no longer
// desired are removed.
// Create() reuses an existing bridge with the same name. The desired multicast
// snooping setting is applied explicitly: Create() never disables it on an
// existing bridge, so SetMcastSnooping is the single place where the setting is
// both enabled and disabled.
func (c *Controller) createAndConfigureBridge(desired *agenttypes.OVSBridgeConfig) (ovsconfig.OVSBridgeClient, error) {
	newClient, err := createOVSBridge(desired.BridgeName, c.ovsdbClient)
	if err != nil {
		return nil, err
	}
	if err := newClient.SetMcastSnooping(desired.EnableMulticastSnooping); err != nil {
		return nil, fmt.Errorf("failed to set multicast snooping on OVS bridge %s: %w", desired.BridgeName, err)
	}
	if err := updatePhysicalInterfaces(newClient, desired); err != nil {
		return nil, err
	}
	return newClient, nil
}
