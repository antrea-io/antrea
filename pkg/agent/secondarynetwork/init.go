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
	"reflect"
	"sync"
	"time"

	"github.com/TomCodeLV/OVSDB-golang-lib/pkg/ovsdb"
	netdefclient "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned/typed/k8s.cni.cncf.io/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	coreinformers "k8s.io/client-go/informers/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	componentbaseconfig "k8s.io/component-base/config"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/antreanodeconfig"
	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/secondarynetwork/podwatch"
	agenttypes "antrea.io/antrea/pkg/agent/types"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha1"
	crdv1alpha1listers "antrea.io/antrea/pkg/client/listers/crd/v1alpha1"
	crdlisters "antrea.io/antrea/pkg/client/listers/crd/v1beta1"
	agentconfig "antrea.io/antrea/pkg/config/agent"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/util/channel"
	"antrea.io/antrea/pkg/util/k8s"
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
	ancLister       crdv1alpha1listers.AntreaNodeConfigLister
	ovsdbConn       *ovsdb.OVSDB

	// mu protects node and effectiveBridgeCfg for atomic point-in-time reads
	// and writes.  It must never be held across blocking OVS calls.
	mu                 sync.RWMutex
	node               *corev1.Node
	effectiveBridgeCfg *agenttypes.OVSBridgeConfig

	nodeListerSynced cache.InformerSynced
	ancListerSynced  cache.InformerSynced

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
	// node and ancInformer are non-nil only when the AntreaNodeConfig feature gate is enabled.
	node *corev1.Node,
	secNetConfig *agentconfig.SecondaryNetworkConfig,
	ovsdbConn *ovsdb.OVSDB,
	ipPoolLister crdlisters.IPPoolLister,
	ancInformer crdinformers.AntreaNodeConfigInformer,
	nodeInformer coreinformers.NodeInformer,
) (*Controller, error) {
	// Resolve the effective bridge configuration. When ancInformer is nil (AntreaNodeConfig
	// feature gate is disabled) the lister is nil and resolveAndCreateOVSBridge falls back to
	// the static agent config.
	var ancLister crdv1alpha1listers.AntreaNodeConfigLister
	if ancInformer != nil {
		ancLister = ancInformer.Lister()
	}
	effectiveBridgeCfg, ovsBridgeClient, err := resolveAndCreateOVSBridge(node, ancLister, secNetConfig, ovsdbConn)
	if err != nil {
		return nil, err
	}

	// Create the NetworkAttachmentDefinition client, which handles access to secondary network object
	// definition from the API Server.
	netAttachDefClient, err := createNetworkAttachDefClient(clientConnectionConfig, kubeAPIServerOverride)
	if err != nil {
		return nil, fmt.Errorf("NetworkAttachmentDefinition client creation failed: %v", err)
	}

	// Create podController to handle secondary network configuration for Pods with
	// k8s.v1.cni.cncf.io/networks Annotation defined.
	podWatchController, err := podwatch.NewPodController(
		k8sClient, netAttachDefClient, podInformer,
		podUpdateSubscriber, primaryInterfaceStore, nodeConfig, ovsBridgeClient, ipPoolLister)
	if err != nil {
		return nil, err
	}

	c := &Controller{
		ovsBridgeClient:    ovsBridgeClient,
		secNetConfig:       secNetConfig,
		effectiveBridgeCfg: effectiveBridgeCfg,
		podController:      podWatchController,
		nodeName:           nodeConfig.Name,
		node:               node,
		ancLister:          ancLister,
		ovsdbConn:          ovsdbConn,
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.NewTypedItemExponentialFailureRateLimiter[string](minRetryDelay, maxRetryDelay),
			workqueue.TypedRateLimitingQueueConfig[string]{Name: "secondaryNetworkBridge"},
		),
	}

	// The following informer event handlers are only registered when the AntreaNodeConfig
	// feature gate is enabled (indicated by ancInformer being non-nil).
	if ancInformer != nil {
		c.nodeListerSynced = nodeInformer.Informer().HasSynced
		c.ancListerSynced = ancInformer.Informer().HasSynced

		// Watch the local Node: a label change may affect which AntreaNodeConfig matches this Node.
		nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
			UpdateFunc: c.onNodeUpdate,
		})

		// Watch AntreaNodeConfig: any add/update/delete may change the effective bridge config.
		ancInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc:    func(_ interface{}) { c.enqueue() },
			UpdateFunc: func(_, _ interface{}) { c.enqueue() },
			DeleteFunc: func(_ interface{}) { c.enqueue() },
		})
	}

	return c, nil
}

// enqueue adds the single reconciliation key to the work queue.
func (c *Controller) enqueue() {
	c.queue.Add(reconcileKey)
}

// onNodeUpdate handles Node UPDATE events. It only reacts to the local Node and only when
// labels (which drive AntreaNodeConfig selector matching) have actually changed.
func (c *Controller) onNodeUpdate(oldObj, newObj interface{}) {
	oldNode, ok := oldObj.(*corev1.Node)
	if !ok {
		return
	}
	newNode, ok := newObj.(*corev1.Node)
	if !ok {
		return
	}
	if newNode.Name != c.nodeName {
		return
	}
	if reflect.DeepEqual(oldNode.Labels, newNode.Labels) {
		return
	}
	// Update the cached node object so reconcileBridge sees the current labels.
	c.mu.Lock()
	c.node = newNode
	c.mu.Unlock()
	klog.V(2).InfoS("Local Node labels changed, enqueuing secondary network bridge reconciliation")
	c.enqueue()
}

// Run starts the secondary network controller. When the AntreaNodeConfig feature gate is
// enabled it first waits for the Node and AntreaNodeConfig caches to sync before starting
// the bridge reconciliation worker; otherwise it skips the cache-sync wait and does not
// start the worker (the bridge config is static and requires no further reconciliation).
func (c *Controller) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	klog.InfoS("Starting secondary network controller")
	defer klog.InfoS("Shutting down secondary network controller")

	// ancListerSynced is non-nil only when the AntreaNodeConfig feature gate is enabled.
	if c.ancListerSynced != nil {
		if !cache.WaitForNamedCacheSync("SecondaryNetworkController", stopCh,
			c.nodeListerSynced, c.ancListerSynced) {
			return
		}

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

// resolveAndCreateOVSBridge determines the effective bridge configuration by consulting
// AntreaNodeConfig CRs (rule 2: CRs override static config) and creates the OVS bridge.
// When no AntreaNodeConfig CR selects the Node the static config from the agent ConfigMap
// is used (rule 1).  Returns the effective OVSBridgeConfig (nil when no bridge is
// configured), the corresponding OVSBridgeClient, and any error.
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

func resolveAndCreateOVSBridge(
	node *corev1.Node,
	ancLister crdv1alpha1listers.AntreaNodeConfigLister,
	staticCfg *agentconfig.SecondaryNetworkConfig,
	ovsdbConn *ovsdb.OVSDB,
) (*agenttypes.OVSBridgeConfig, ovsconfig.OVSBridgeClient, error) {
	effectiveBridgeCfg := resolveEffectiveBridgeConfig(node, ancLister, staticCfg)
	if effectiveBridgeCfg == nil {
		return nil, nil, nil
	}
	ovsBridgeClient, err := createOVSBridgeClient(effectiveBridgeCfg.BridgeName, effectiveBridgeCfg.EnableMulticastSnooping, ovsdbConn)
	if err != nil {
		return nil, nil, err
	}
	return effectiveBridgeCfg, ovsBridgeClient, nil
}

// resolveEffectiveBridgeConfig returns the effective OVSBridgeConfig for this Node.
// It consults the AntreaNodeConfig lister (if available): when a matching AntreaNodeConfig
// that specifies a SecondaryNetwork is found, its bridge config wins entirely (rule 2).
// Otherwise, the static config from the agent ConfigMap is used (rule 1).
// Returns nil when no bridge is configured from either source.
func resolveEffectiveBridgeConfig(
	node *corev1.Node,
	ancLister crdv1alpha1listers.AntreaNodeConfigLister,
	staticCfg *agentconfig.SecondaryNetworkConfig,
) *agenttypes.OVSBridgeConfig {
	if ancLister != nil && node != nil {
		all, err := ancLister.List(labels.Everything())
		if err != nil {
			klog.ErrorS(err, "Failed to list AntreaNodeConfigs, falling back to static config")
		} else {
			effective := antreanodeconfig.SelectAndApply(node, all)
			if effective != nil {
				// A matching AntreaNodeConfig was found – it overrides the static config.
				if effective.OVSBridge != nil {
					klog.InfoS("Using AntreaNodeConfig secondary network config", "bridge", effective.OVSBridge.BridgeName)
				}
				return effective.OVSBridge
			}
		}
	}

	// Fall back to static agent config (rule 1).
	if len(staticCfg.OVSBridges) == 0 {
		return nil
	}
	b := staticCfg.OVSBridges[0]
	bridge := &agenttypes.OVSBridgeConfig{
		BridgeName:              b.BridgeName,
		EnableMulticastSnooping: b.EnableMulticastSnooping,
	}
	for _, iface := range b.PhysicalInterfaces {
		bridge.PhysicalInterfaces = append(bridge.PhysicalInterfaces, agenttypes.PhysicalInterfaceConfig{Name: iface})
	}
	return bridge
}

// createOVSBridge creates a single OVS bridge from the legacy []OVSBridgeConfig slice.
// Kept for internal test use only; production code now goes through resolveAndCreateOVSBridge.
func createOVSBridge(bridges []agentconfig.OVSBridgeConfig, ovsdbConn *ovsdb.OVSDB) (ovsconfig.OVSBridgeClient, error) {
	if len(bridges) == 0 {
		return nil, nil
	}
	bridgeConfig := bridges[0]
	return createOVSBridgeClient(bridgeConfig.BridgeName, bridgeConfig.EnableMulticastSnooping, ovsdbConn)
}
