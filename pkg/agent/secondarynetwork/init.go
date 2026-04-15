// Copyright 2024 Antrea Authors
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
	"fmt"
	"sync"
	"time"

	"github.com/TomCodeLV/OVSDB-golang-lib/pkg/ovsdb"
	netdefclient "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned/typed/k8s.cni.cncf.io/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	componentbaseconfig "k8s.io/component-base/config"
	"k8s.io/klog/v2"

	"antrea.io/antrea/v2/pkg/agent/config"
	"antrea.io/antrea/v2/pkg/agent/interfacestore"
	"antrea.io/antrea/v2/pkg/agent/secondarynetwork/podwatch"
	agenttypes "antrea.io/antrea/v2/pkg/agent/types"
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
	newOVSBridgeFn = ovsconfig.NewOVSBridge
)

// podControllerInterface is the subset of podwatch.PodController used by Controller.
// Defined as an interface to allow test injection.
type podControllerInterface interface {
	Run(stopCh <-chan struct{})
	AllowCNIDelete(podName, podNamespace string) bool
	UpdateOVSBridge(newClient ovsconfig.OVSBridgeClient) error
}

// Controller manages secondary network resources for a Node.
type Controller struct {
	ovsBridgeClient ovsconfig.OVSBridgeClient
	secNetConfig    *agentconfig.SecondaryNetworkConfig
	podController   podControllerInterface
	nodeName        string
	ovsdbConn       *ovsdb.OVSDB

	// effectiveBridgeFn returns the desired OVS bridge configuration (from static
	// agent config and, when enabled, AntreaNodeConfig via the controller).
	effectiveBridgeFn func() *agenttypes.OVSBridgeConfig

	// mu protects effectiveBridgeCfg for atomic point-in-time reads and writes.
	// It must never be held across blocking OVS calls.
	// Only init_linux.go references mu; Windows uses stub reconcile/Initialize methods.
	mu                 sync.RWMutex //nolint:unused // platform: Linux-only bridge reconciliation in init_linux.go
	effectiveBridgeCfg *agenttypes.OVSBridgeConfig

	// dynamicBridgeReconcile is true when AntreaNodeConfig is enabled: bridge
	// updates are driven by the AntreaNodeConfig channel after the AntreaNodeConfig
	// controller has synced informers and published the first snapshot.
	dynamicBridgeReconcile bool

	queue workqueue.TypedRateLimitingInterface[string]
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
	ovsdbConn *ovsdb.OVSDB,
	ipPoolLister crdlisters.IPPoolLister,
	effectiveBridgeFn func() *agenttypes.OVSBridgeConfig,
	ancUpdateSubscriber channel.Subscriber,
) (*Controller, error) {
	if effectiveBridgeFn == nil {
		return nil, fmt.Errorf("effectiveBridge must not be nil")
	}

	effectiveBridgeCfg, ovsBridgeClient, err := resolveAndCreateOVSBridge(effectiveBridgeFn, ovsdbConn)
	if err != nil {
		return nil, err
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

	dynamicBridgeReconcile := ancUpdateSubscriber != nil
	c := &Controller{
		ovsBridgeClient:        ovsBridgeClient,
		secNetConfig:           secNetConfig,
		effectiveBridgeCfg:     effectiveBridgeCfg,
		podController:          podWatchController,
		nodeName:               nodeConfig.Name,
		effectiveBridgeFn:      effectiveBridgeFn,
		ovsdbConn:              ovsdbConn,
		dynamicBridgeReconcile: dynamicBridgeReconcile,
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.NewTypedItemExponentialFailureRateLimiter[string](minRetryDelay, maxRetryDelay),
			workqueue.TypedRateLimitingQueueConfig[string]{Name: "secondaryNetworkBridge"},
		),
	}

	if dynamicBridgeReconcile {
		// Notify payloads are *antreanodeconfig.Snapshot; this controller
		// reconciles from effectiveBridgeFn() so it only needs the wakeup.
		ancUpdateSubscriber.Subscribe(func(_ interface{}) {
			c.enqueue()
		})
	}

	return c, nil
}

// enqueue adds the single reconciliation key to the work queue.
func (c *Controller) enqueue() {
	c.queue.Add(reconcileKey)
}

// Run starts the secondary network controller. When AntreaNodeConfig is
// enabled, a bridge reconciliation worker processes items enqueued by the ANC
// SubscribableChannel (the AntreaNodeConfig controller only notifies after its
// informers have synced). When ANC is off, the bridge is static and no worker
// is started.
func (c *Controller) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

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

func (c *Controller) AllowCNIDelete(podName, podNamespace string) bool {
	return c.podController.AllowCNIDelete(podName, podNamespace)
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

// createOVSBridgeClient creates a new OVS bridge with the given name and
// multicast-snooping setting, returning the client for the newly created bridge.
func createOVSBridgeClient(bridgeName string, enableMulticastSnooping bool, ovsdbConn *ovsdb.OVSDB) (ovsconfig.OVSBridgeClient, error) {
	var options []ovsconfig.OVSBridgeOption
	if enableMulticastSnooping {
		options = append(options, ovsconfig.WithMcastSnooping())
	}
	client := newOVSBridgeFn(bridgeName, ovsconfig.OVSDatapathSystem, ovsdbConn, options...)
	if err := client.Create(); err != nil {
		return nil, fmt.Errorf("failed to create OVS bridge %s: %v", bridgeName, err)
	}
	klog.InfoS("OVS bridge created", "bridge", bridgeName)
	return client, nil
}

// resolveAndCreateOVSBridge evaluates effectiveBridge() and creates the OVS bridge.
// Returns the effective OVSBridgeConfig (nil when no bridge is configured), the
// corresponding OVSBridgeClient, and any error.
func resolveAndCreateOVSBridge(
	effectiveBridge func() *agenttypes.OVSBridgeConfig,
	ovsdbConn *ovsdb.OVSDB,
) (*agenttypes.OVSBridgeConfig, ovsconfig.OVSBridgeClient, error) {
	effectiveBridgeCfg := effectiveBridge()
	if effectiveBridgeCfg == nil {
		return nil, nil, nil
	}
	ovsBridgeClient, err := createOVSBridgeClient(effectiveBridgeCfg.BridgeName, effectiveBridgeCfg.EnableMulticastSnooping, ovsdbConn)
	if err != nil {
		return nil, nil, err
	}
	return effectiveBridgeCfg, ovsBridgeClient, nil
}
