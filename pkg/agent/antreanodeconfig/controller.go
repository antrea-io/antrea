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

// Package antreanodeconfig watches AntreaNodeConfig resources and the local Node,
// and publishes immutable snapshots (Node plus the oldest matching AntreaNodeConfig)
// to channel subscribers when relevant state
// changes. Feature packages (for example secondary network) consume those
// snapshots and merge them with their own static configuration.
package antreanodeconfig

import (
	"reflect"
	"sort"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	coreinformers "k8s.io/client-go/informers/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	crdv1alpha1 "antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
	crdinformers "antrea.io/antrea/v2/pkg/client/informers/externalversions/crd/v1alpha1"
	crdv1alpha1listers "antrea.io/antrea/v2/pkg/client/listers/crd/v1alpha1"
	"antrea.io/antrea/v2/pkg/util/channel"
)

const (
	// ancInformerResyncPeriod limits how long the agent can rely solely on
	// SubscribableChannel delivery before reconciling AntreaNodeConfig-derived
	// state from the informer cache again.
	ancInformerResyncPeriod = 5 * time.Minute
)

// Controller watches AntreaNodeConfig and the local Node, builds snapshots of
// the effective AntreaNodeConfig for this Node (plus list errors), and notifies
// subscribers when that snapshot changes.
type Controller struct {
	nodeName   string
	ancLister  crdv1alpha1listers.AntreaNodeConfigLister
	nodeLister corelisters.NodeLister
	notifier   channel.Notifier

	nodeListerSynced cache.InformerSynced
	ancListerSynced  cache.InformerSynced

	mu   sync.RWMutex
	node *corev1.Node
	// lastNotified is the last snapshot successfully passed to notifier.Notify;
	// it is not updated when Notify returns false so the next recompute retries.
	lastNotified *Snapshot
}

// NewController constructs a Controller and registers informer handlers.
// The local Node is loaded from nodeInformer after its cache syncs (see Run)
// and kept up to date via Add/Update/Delete callbacks. notifier.Notify
// receives *Snapshot payloads (deep-copied).
func NewController(
	ancInformer crdinformers.AntreaNodeConfigInformer,
	nodeInformer coreinformers.NodeInformer,
	nodeName string,
	notifier channel.Notifier,
) *Controller {
	c := &Controller{
		nodeName:         nodeName,
		ancLister:        ancInformer.Lister(),
		nodeLister:       nodeInformer.Lister(),
		notifier:         notifier,
		nodeListerSynced: nodeInformer.Informer().HasSynced,
		ancListerSynced:  ancInformer.Informer().HasSynced,
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

// InformersSynced reports whether both the Node and AntreaNodeConfig informer caches
// have completed an initial sync.
func (c *Controller) InformersSynced() bool {
	return c.nodeListerSynced() && c.ancListerSynced()
}

// CurrentSnapshot returns a deep-copied snapshot of the local Node and the
// oldest AntreaNodeConfig that matches this Node's labels. It returns nil if
// informers are not synced yet.
func (c *Controller) CurrentSnapshot() *Snapshot {
	if !c.InformersSynced() {
		return nil
	}
	c.mu.RLock()
	node := c.node
	c.mu.RUnlock()
	all, err := c.ancLister.List(labels.Everything())
	effective := antreaNodeConfigForSnapshot(node, all, err)
	return NewSnapshot(node, effective, err)
}

// Run waits for the AntreaNodeConfig and Node informer caches to sync, publishes
// the initial snapshot, then blocks until stopCh is closed.
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
	klog.V(2).InfoS("Local Node labels changed, recomputing AntreaNodeConfig snapshot")
	c.recomputeAndNotifyAsync()
}

func (c *Controller) onNodeDelete(obj interface{}) {
	node, ok := obj.(*corev1.Node)
	if !ok {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Received unexpected object: %v", obj)
			return
		}
		n, ok := deletedState.Obj.(*corev1.Node)
		if !ok {
			klog.Errorf("DeletedFinalStateUnknown contains non-Node object: %v", deletedState.Obj)
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
	klog.V(2).InfoS("Local Node deleted, recomputing AntreaNodeConfig snapshot")
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
	effective := antreaNodeConfigForSnapshot(node, all, err)
	next := NewSnapshot(node, effective, err)

	payload := next.DeepCopy()
	c.mu.Lock()
	if c.lastNotified != nil && reflect.DeepEqual(c.lastNotified, payload) {
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()

	if !c.notifier.Notify(payload) {
		klog.Error("Failed to notify AntreaNodeConfig snapshot update; subscribers may be stale until next resync")
		return
	}

	c.mu.Lock()
	c.lastNotified = payload
	c.mu.Unlock()
}

// antreaNodeConfigForSnapshot returns the oldest AntreaNodeConfig that applies to
// node when the list succeeded; otherwise nil so subscribers do not act on a
// partial cluster view.
func antreaNodeConfigForSnapshot(node *corev1.Node, all []*crdv1alpha1.AntreaNodeConfig, listErr error) *crdv1alpha1.AntreaNodeConfig {
	if listErr != nil {
		return nil
	}
	return OldestMatchingAntreaNodeConfigForNode(node, all)
}

// OldestMatchingAntreaNodeConfigForNode returns the AntreaNodeConfig whose
// nodeSelector matches the given Node's labels and has the oldest
// creationTimestamp (name breaks ties). It returns nil when node is nil, when no
// config matches, or when every matching config has an invalid nodeSelector.
func OldestMatchingAntreaNodeConfigForNode(node *corev1.Node, configs []*crdv1alpha1.AntreaNodeConfig) *crdv1alpha1.AntreaNodeConfig {
	matched := SelectAntreaNodeConfigsForNode(node, configs)
	if len(matched) == 0 {
		return nil
	}
	return matched[0]
}

// SelectAntreaNodeConfigsForNode returns AntreaNodeConfig objects whose nodeSelector
// matches the given Node's labels, sorted by creationTimestamp ascending (oldest
// first; name is used as a stable tiebreaker when timestamps are equal).
// Configs with an invalid nodeSelector are skipped with a log line.
func SelectAntreaNodeConfigsForNode(node *corev1.Node, configs []*crdv1alpha1.AntreaNodeConfig) []*crdv1alpha1.AntreaNodeConfig {
	if node == nil {
		return nil
	}
	nodeLabels := labels.Set(node.Labels)
	var matching []*crdv1alpha1.AntreaNodeConfig
	for _, cfg := range configs {
		if cfg == nil {
			continue
		}
		sel, err := metav1.LabelSelectorAsSelector(&cfg.Spec.NodeSelector)
		if err != nil {
			klog.ErrorS(err, "Skipping AntreaNodeConfig with invalid nodeSelector", "config", cfg.Name)
			continue
		}
		if sel.Matches(nodeLabels) {
			matching = append(matching, cfg)
		}
	}
	sort.Slice(matching, func(i, j int) bool {
		ti := matching[i].CreationTimestamp
		tj := matching[j].CreationTimestamp
		if ti.Equal(&tj) {
			return matching[i].Name < matching[j].Name
		}
		return ti.Before(&tj)
	})
	return matching
}
