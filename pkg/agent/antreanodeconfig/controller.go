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
	"fmt"
	"reflect"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
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

	// snapshotQueueKey is the sole workqueue item: one worker reconciles the full
	// snapshot from Node + AntreaNodeConfig listers whenever any relevant object changes.
	snapshotQueueKey = "snapshot"

	defaultWorkers = 1

	minRetryDelay = 5 * time.Millisecond
	maxRetryDelay = 30 * time.Second
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

	queue workqueue.TypedRateLimitingInterface[string]

	// lastNotified is only read/written by the snapshot worker goroutine(s).
	lastNotified *Snapshot
}

// NewController constructs a Controller and registers informer handlers.
// The local Node is read from nodeInformer after its cache syncs (see Run).
// notifier.Notify receives *Snapshot payloads (deep-copied).
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
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.NewTypedItemExponentialFailureRateLimiter[string](minRetryDelay, maxRetryDelay),
			workqueue.TypedRateLimitingQueueConfig[string]{
				Name: "AntreaNodeConfig",
			},
		),
	}

	nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.onNodeAdd,
		UpdateFunc: c.onNodeUpdate,
	})

	ancInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    func(_ interface{}) { c.enqueueSnapshot() },
			UpdateFunc: func(_, _ interface{}) { c.enqueueSnapshot() },
			DeleteFunc: func(_ interface{}) { c.enqueueSnapshot() },
		},
		ancInformerResyncPeriod,
	)

	return c
}

func (c *Controller) enqueueSnapshot() {
	c.queue.Add(snapshotQueueKey)
}

// InformersSynced reports whether both the Node and AntreaNodeConfig informer caches
// have completed an initial sync.
func (c *Controller) InformersSynced() bool {
	return c.nodeListerSynced() && c.ancListerSynced()
}

// getLocalNodeFromLister returns the Node for this agent's nodeName from the informer
// cache. If the Node is not present (NotFound), it returns (nil, nil) because an empty
// Node is valid snapshot input. Any other lister error is returned.
func (c *Controller) getLocalNodeFromLister() (*corev1.Node, error) {
	node, err := c.nodeLister.Get(c.nodeName)
	if err == nil {
		return node, nil
	}
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	return nil, err
}

// CurrentSnapshot returns a deep-copied snapshot of the local Node and the
// oldest AntreaNodeConfig that matches this Node's labels. It returns nil if
// informers are not synced yet.
func (c *Controller) CurrentSnapshot() *Snapshot {
	if !c.InformersSynced() {
		return nil
	}
	node, err := c.getLocalNodeFromLister()
	if err != nil {
		klog.ErrorS(err, "Failed to get local Node from lister for snapshot", "node", c.nodeName)
		return nil
	}
	all, err := c.ancLister.List(labels.Everything())
	effective := antreaNodeConfigForSnapshot(node, all, err)
	return NewSnapshot(node, effective, err)
}

// Run waits for the AntreaNodeConfig and Node informer caches to sync, enqueues one
// snapshot reconciliation, then runs workers until stopCh is closed. The first
// successful syncSnapshot publishes a *Snapshot to notifier subscribers (including
// when no AntreaNodeConfig matches this Node: non-nil *Snapshot with nil
// AntreaNodeConfig).
func (c *Controller) Run(stopCh <-chan struct{}) {
	klog.InfoS("Starting AntreaNodeConfig controller")
	defer klog.InfoS("Shutting down AntreaNodeConfig controller")

	defer c.queue.ShutDown()

	if !cache.WaitForNamedCacheSync("AntreaNodeConfigController", stopCh,
		c.nodeListerSynced, c.ancListerSynced) {
		return
	}
	c.enqueueSnapshot()

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(func() {
			for c.processNextWorkItem() {
			}
		}, time.Second, stopCh)
	}
	<-stopCh
}

func (c *Controller) processNextWorkItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	if err := c.syncSnapshot(key); err != nil {
		c.queue.AddRateLimited(key)
		klog.ErrorS(err, "Failed to sync AntreaNodeConfig snapshot", "key", key)
		return true
	}
	c.queue.Forget(key)
	return true
}

// syncSnapshot builds a snapshot from informer listers and notifies subscribers
// when it differs from lastNotified. It is intended to run only from the workqueue worker.
func (c *Controller) syncSnapshot(key string) error {
	_ = key
	node, err := c.getLocalNodeFromLister()
	if err != nil {
		return err
	}

	all, listErr := c.ancLister.List(labels.Everything())
	effective := antreaNodeConfigForSnapshot(node, all, listErr)
	next := NewSnapshot(node, effective, listErr)

	payload := next.DeepCopy()
	if c.lastNotified != nil && reflect.DeepEqual(c.lastNotified, payload) {
		return nil
	}

	if !c.notifier.Notify(payload) {
		return fmt.Errorf("notifier rejected AntreaNodeConfig snapshot update")
	}

	c.lastNotified = payload
	return nil
}

func (c *Controller) onNodeAdd(obj interface{}) {
	node, ok := obj.(*corev1.Node)
	if !ok {
		return
	}
	if node.Name != c.nodeName {
		return
	}
	c.enqueueSnapshot()
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
	if reflect.DeepEqual(oldNode.Labels, newNode.Labels) {
		return
	}
	klog.V(2).InfoS("Local Node labels changed, recomputing AntreaNodeConfig snapshot")
	c.enqueueSnapshot()
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
