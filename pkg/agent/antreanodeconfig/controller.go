// Copyright 2026 Antrea Authors
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

package antreanodeconfig

import (
	"reflect"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	coreinformers "k8s.io/client-go/informers/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	agenttypes "antrea.io/antrea/v2/pkg/agent/types"
	crdinformers "antrea.io/antrea/v2/pkg/client/informers/externalversions/crd/v1alpha1"
	crdv1alpha1listers "antrea.io/antrea/v2/pkg/client/listers/crd/v1alpha1"
	agentconfig "antrea.io/antrea/v2/pkg/config/agent"
	"antrea.io/antrea/v2/pkg/util/channel"
)

const (
	// ancInformerResyncPeriod limits how long the agent can rely solely on
	// SubscribableChannel delivery before reconciling AntreaNodeConfig-derived
	// state from the informer cache again.
	ancInformerResyncPeriod = 5 * time.Minute
)

// Controller watches AntreaNodeConfig and the local Node, evaluates derived
// agent settings (see EffectiveSnapshot), and notifies subscribers when that
// aggregate snapshot changes.
type Controller struct {
	nodeName                  string
	staticSecondaryNetworkCfg *agentconfig.SecondaryNetworkConfig
	ancLister                 crdv1alpha1listers.AntreaNodeConfigLister
	nodeLister                corelisters.NodeLister
	notifier                  channel.Notifier

	nodeListerSynced cache.InformerSynced
	ancListerSynced  cache.InformerSynced

	mu           sync.RWMutex
	node         *corev1.Node
	lastNotified *EffectiveSnapshot
}

// NewController constructs a Controller and registers informer handlers.
// The local Node is loaded from nodeInformer after its cache syncs (see Run)
// and kept up to date via Add/Update/Delete callbacks. notifier.Notify
// receives *EffectiveSnapshot payloads (deep-copied).
func NewController(
	ancInformer crdinformers.AntreaNodeConfigInformer,
	nodeInformer coreinformers.NodeInformer,
	nodeName string,
	agentConfig *agentconfig.AgentConfig,
	notifier channel.Notifier,
) *Controller {
	c := &Controller{
		nodeName:                  nodeName,
		staticSecondaryNetworkCfg: &agentConfig.SecondaryNetwork,
		ancLister:                 ancInformer.Lister(),
		nodeLister:                nodeInformer.Lister(),
		notifier:                  notifier,
		nodeListerSynced:          nodeInformer.Informer().HasSynced,
		ancListerSynced:           ancInformer.Informer().HasSynced,
	}

	nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.onNodeAdd,
		UpdateFunc: c.onNodeUpdate,
		DeleteFunc: c.onNodeDelete,
	})

	ancInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    func(_ interface{}) { c.recomputeAndNotifyAsync() },
			UpdateFunc: func(_, _ interface{}) { c.recomputeAndNotifyAsync() },
			DeleteFunc: func(_ interface{}) { c.recomputeAndNotifyAsync() },
		},
		ancInformerResyncPeriod,
	)

	return c
}

// EffectiveSecondaryOVSBridge returns the current effective bridge configuration
// from the informer cache and the latest known Node labels. It is safe to call
// concurrently with Run and informer callbacks.
//
// Before the Node and AntreaNodeConfig informer caches have synced, it returns
// nil so the secondary-network controller does not create a bridge from static
// ConfigMap data while AntreaNodeConfig objects are not yet visible (which would
// later be replaced by CR-driven reconcile).
func (c *Controller) EffectiveSecondaryOVSBridge() *agenttypes.OVSBridgeConfig {
	if !c.nodeListerSynced() || !c.ancListerSynced() {
		return nil
	}
	c.mu.RLock()
	node := c.node
	c.mu.RUnlock()
	all, err := c.ancLister.List(labels.Everything())
	snap := ComputeEffectiveSnapshot(node, all, err, c.staticSecondaryNetworkCfg)
	if snap == nil {
		return nil
	}
	return snap.SecondaryOVSBridge
}

// Run waits for the AntreaNodeConfig and Node informer caches to sync, publishes
// the initial effective configuration, then blocks until stopCh is closed.
func (c *Controller) Run(stopCh <-chan struct{}) {
	klog.InfoS("Starting AntreaNodeConfig controller")
	defer klog.InfoS("Shutting down AntreaNodeConfig controller")

	if !cache.WaitForNamedCacheSync("AntreaNodeConfigController", stopCh,
		c.nodeListerSynced, c.ancListerSynced) {
		return
	}
	c.loadLocalNodeFromLister()
	c.recomputeAndNotify()
	<-stopCh
}

// loadLocalNodeFromLister sets c.node from the shared Node informer cache after
// sync. Event handlers keep it current afterward.
func (c *Controller) loadLocalNodeFromLister() {
	node, err := c.nodeLister.Get(c.nodeName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			klog.InfoS("Local Node not present in informer cache after sync", "node", c.nodeName)
		} else {
			klog.ErrorS(err, "Failed to get local Node from informer lister", "node", c.nodeName)
		}
		c.mu.Lock()
		c.node = nil
		c.mu.Unlock()
		return
	}
	c.mu.Lock()
	c.node = node
	c.mu.Unlock()
}

func (c *Controller) onNodeAdd(obj interface{}) {
	node, ok := obj.(*corev1.Node)
	if !ok {
		return
	}
	if node.Name != c.nodeName {
		return
	}
	c.mu.Lock()
	c.node = node
	c.mu.Unlock()
	c.recomputeAndNotifyAsync()
}

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
	c.mu.Lock()
	c.node = newNode
	c.mu.Unlock()
	if reflect.DeepEqual(oldNode.Labels, newNode.Labels) {
		return
	}
	klog.V(2).InfoS("Local Node labels changed, recomputing AntreaNodeConfig-derived agent settings")
	c.recomputeAndNotifyAsync()
}

func (c *Controller) onNodeDelete(obj interface{}) {
	node, ok := obj.(*corev1.Node)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return
		}
		n, ok := tombstone.Obj.(*corev1.Node)
		if !ok {
			return
		}
		node = n
	}
	if node.Name != c.nodeName {
		return
	}
	c.mu.Lock()
	c.node = nil
	c.mu.Unlock()
	c.recomputeAndNotifyAsync()
}

func (c *Controller) recomputeAndNotifyAsync() {
	go c.recomputeAndNotify()
}

func (c *Controller) recomputeAndNotify() {
	c.mu.RLock()
	node := c.node
	c.mu.RUnlock()
	all, err := c.ancLister.List(labels.Everything())
	next := ComputeEffectiveSnapshot(node, all, err, c.staticSecondaryNetworkCfg)

	// Compare and store using a deep copy so lastNotified is not aliased to
	// memory that callers or the informer cache might reuse, and so future
	// EffectiveSnapshot fields remain safe to extend.
	payload := next.DeepCopy()
	c.mu.Lock()
	if c.lastNotified != nil && reflect.DeepEqual(c.lastNotified, payload) {
		c.mu.Unlock()
		return
	}
	c.lastNotified = payload
	c.mu.Unlock()

	if !c.notifier.Notify(payload) {
		klog.Error("Failed to notify AntreaNodeConfig effective snapshot update; subscribers may be stale until next resync")
	}
}
