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

// Package flowaccesscontrol watches FlowAccessControl CRD objects and Namespaces, and maintains
// an in-memory index used by the flow-aggregator to authorize which Namespaces' flows a given
// Kubernetes user or group is allowed to observe.
package flowaccesscontrol

import (
	"reflect"
	"sync"
	"time"

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	crdv1alpha1 "antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
	crdinformers "antrea.io/antrea/v2/pkg/client/informers/externalversions/crd/v1alpha1"
	crdlisters "antrea.io/antrea/v2/pkg/client/listers/crd/v1alpha1"
)

const (
	controllerName = "FlowAccessControlController"
	// How long to wait before retrying a failed sync.
	minRetryDelay = time.Second
	maxRetryDelay = 30 * time.Second
	// Disable resyncing: all state is derived from informer events, and a periodic full
	// re-evaluation would only add cost.
	resyncPeriod time.Duration = 0
)

// workItem is a workqueue item. Exactly one of its two forms is used:
//   - facResync triggers a full index rebuild from all FlowAccessControl objects and all
//     Namespaces. It is enqueued on FlowAccessControl changes, which are rare.
//   - {namespace: <name>} re-evaluates a single Namespace against the already-parsed selectors
//     cached in the index and patches the index in place. It is enqueued on Namespace changes,
//     which can be frequent, and never lists Namespaces or FlowAccessControls.
//
// The struct is comparable, so the workqueue coalesces duplicates: a burst of updates to the same
// Namespace collapses into a single sync, as does a burst of FlowAccessControl changes. Note that
// this is why the item carries the Namespace's name and not the object itself: the object would be
// a distinct pointer per event, defeating that coalescing, and could also be stale by the time it
// is processed.
type workItem struct {
	isFACResync bool
	namespace   string
}

var facResync = workItem{isFACResync: true}

// subjectState is the cached state for one subject (a username or a group name), aggregated across
// every FlowAccessControl object that names that subject.
type subjectState struct {
	// selectors is the flattened list of parsed Namespace selectors from every FlowAccessControl
	// naming this subject. A Namespace is visible to the subject if any of them matches it, so
	// selectors from different objects can be flattened into a single list: the union across
	// objects and the union within one object's namespaceSelectors are both an OR.
	// Selectors are parsed once per FlowAccessControl change, so Namespace events never re-parse.
	selectors []labels.Selector
	// allowAll indicates cluster-wide visibility, i.e. per-Namespace checks are skipped entirely.
	// When it is true, namespaces is nil and is not maintained.
	allowAll bool
	// namespaces is the materialized set of Namespaces this subject may observe. It is rebuilt on
	// FlowAccessControl changes and patched in place on Namespace changes.
	namespaces sets.Set[string]
}

// matches reports whether a Namespace carrying the given labels is visible to this subject.
func (s *subjectState) matches(nsLabels labels.Set) bool {
	for _, selector := range s.selectors {
		if selector.Matches(nsLabels) {
			return true
		}
	}
	return false
}

// Interface is implemented by Controller and provides read-only, thread-safe access to the
// FlowAccessControl index, for use on the flow authorization path.
type Interface interface {
	// AllowedNamespaces returns the set of Namespaces whose flows the given user (identified by
	// username and the groups it belongs to) is allowed to observe, and whether the user has
	// cluster-wide (allowAll) visibility, in which case namespaces is nil and per-Namespace
	// checks should be skipped.
	AllowedNamespaces(username string, groups []string) (namespaces sets.Set[string], allowAll bool)
}

// Controller watches FlowAccessControl objects and Namespaces, and maintains an in-memory
// "username/group -> allowed Namespace set" index, re-evaluating namespaceSelectors whenever a
// Namespace's labels change.
type Controller struct {
	facInformer     cache.SharedIndexInformer
	facLister       crdlisters.FlowAccessControlLister
	facListerSynced cache.InformerSynced

	namespaceInformer     cache.SharedIndexInformer
	namespaceLister       corelisters.NamespaceLister
	namespaceListerSynced cache.InformerSynced

	queue workqueue.TypedRateLimitingInterface[workItem]

	// mu guards byUser and byGroup, including the subjectState values they point to, which are
	// mutated in place by syncNamespace.
	mu      sync.RWMutex
	byUser  map[string]*subjectState
	byGroup map[string]*subjectState
}

// NewController creates a new Controller.
func NewController(facInformer crdinformers.FlowAccessControlInformer, namespaceInformer coreinformers.NamespaceInformer) *Controller {
	c := &Controller{
		facInformer:           facInformer.Informer(),
		facLister:             facInformer.Lister(),
		facListerSynced:       facInformer.Informer().HasSynced,
		namespaceInformer:     namespaceInformer.Informer(),
		namespaceLister:       namespaceInformer.Lister(),
		namespaceListerSynced: namespaceInformer.Informer().HasSynced,
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.NewTypedItemExponentialFailureRateLimiter[workItem](minRetryDelay, maxRetryDelay),
			workqueue.TypedRateLimitingQueueConfig[workItem]{
				Name: "flowAccessControl",
			},
		),
		byUser:  map[string]*subjectState{},
		byGroup: map[string]*subjectState{},
	}
	c.facInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.addFlowAccessControl,
			UpdateFunc: c.updateFlowAccessControl,
			DeleteFunc: c.deleteFlowAccessControl,
		},
		resyncPeriod,
	)
	c.namespaceInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.addNamespace,
			UpdateFunc: c.updateNamespace,
			DeleteFunc: c.deleteNamespace,
		},
		resyncPeriod,
	)
	return c
}

// AllowedNamespaces implements Interface.
func (c *Controller) AllowedNamespaces(username string, groups []string) (sets.Set[string], bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// The returned set must be a copy, as the cached sets are patched in place by syncNamespace.
	result := sets.New[string]()
	if state, ok := c.byUser[username]; ok {
		if state.allowAll {
			return nil, true
		}
		result = result.Union(state.namespaces)
	}
	for _, group := range groups {
		if state, ok := c.byGroup[group]; ok {
			if state.allowAll {
				return nil, true
			}
			result = result.Union(state.namespaces)
		}
	}
	return result, false
}

func (c *Controller) addFlowAccessControl(obj interface{}) {
	fac := obj.(*crdv1alpha1.FlowAccessControl)
	klog.V(2).InfoS("Processing FlowAccessControl ADD event", "flowAccessControl", klog.KObj(fac))
	c.queue.Add(facResync)
}

func (c *Controller) updateFlowAccessControl(oldObj, obj interface{}) {
	oldFAC := oldObj.(*crdv1alpha1.FlowAccessControl)
	fac := obj.(*crdv1alpha1.FlowAccessControl)
	// Only the spec affects the index, so ignore metadata-only updates.
	if reflect.DeepEqual(oldFAC.Spec, fac.Spec) {
		return
	}
	klog.V(2).InfoS("Processing FlowAccessControl UPDATE event", "flowAccessControl", klog.KObj(fac))
	c.queue.Add(facResync)
}

func (c *Controller) deleteFlowAccessControl(obj interface{}) {
	fac, ok := obj.(*crdv1alpha1.FlowAccessControl)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.V(2).InfoS("Error decoding object when deleting FlowAccessControl, invalid type", "object", obj)
			return
		}
		fac, ok = tombstone.Obj.(*crdv1alpha1.FlowAccessControl)
		if !ok {
			klog.V(2).InfoS("Error decoding object tombstone when deleting FlowAccessControl, invalid type", "object", tombstone.Obj)
			return
		}
	}
	klog.V(2).InfoS("Processing FlowAccessControl DELETE event", "flowAccessControl", klog.KObj(fac))
	c.queue.Add(facResync)
}

func (c *Controller) addNamespace(obj interface{}) {
	ns := obj.(*v1.Namespace)
	klog.V(2).InfoS("Processing Namespace ADD event", "namespace", klog.KObj(ns))
	c.queue.Add(workItem{namespace: ns.Name})
}

func (c *Controller) updateNamespace(oldObj, obj interface{}) {
	oldNS := oldObj.(*v1.Namespace)
	ns := obj.(*v1.Namespace)
	// A Namespace's labels are the only thing that can change which namespaceSelectors match it,
	// so skip updates to any other field. Namespaces are updated far more often than
	// FlowAccessControl objects change, which makes this the most valuable early return here.
	if reflect.DeepEqual(oldNS.GetLabels(), ns.GetLabels()) {
		return
	}
	klog.V(2).InfoS("Processing Namespace UPDATE event", "namespace", klog.KObj(ns))
	c.queue.Add(workItem{namespace: ns.Name})
}

func (c *Controller) deleteNamespace(obj interface{}) {
	ns, ok := obj.(*v1.Namespace)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.V(2).InfoS("Error decoding object when deleting Namespace, invalid type", "object", obj)
			return
		}
		ns, ok = tombstone.Obj.(*v1.Namespace)
		if !ok {
			klog.V(2).InfoS("Error decoding object tombstone when deleting Namespace, invalid type", "object", tombstone.Obj)
			return
		}
	}
	klog.V(2).InfoS("Processing Namespace DELETE event", "namespace", klog.KObj(ns))
	c.queue.Add(workItem{namespace: ns.Name})
}

// Run starts the controller and blocks until stopCh is closed.
func (c *Controller) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	klog.InfoS("Starting", "controller", controllerName)
	defer klog.InfoS("Shutting down", "controller", controllerName)

	if !cache.WaitForNamedCacheSync(controllerName, stopCh, c.facListerSynced, c.namespaceListerSynced) {
		return
	}
	// A single worker keeps index updates serialized, which is what lets syncNamespace patch the
	// index in place without coordinating with a concurrent rebuild.
	go wait.Until(c.worker, time.Second, stopCh)

	<-stopCh
}

func (c *Controller) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *Controller) processNextWorkItem() bool {
	item, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(item)

	if item.isFACResync {
		if err := c.syncFlowAccessControls(); err != nil {
			c.queue.AddRateLimited(item)
			klog.ErrorS(err, "Rebuilding FlowAccessControl index failed, requeue")
			return true
		}
		c.queue.Forget(item)
		return true
	}

	ns, err := c.namespaceLister.Get(item.namespace)
	if err != nil {
		if !apierrors.IsNotFound(err) {
			c.queue.AddRateLimited(item)
			klog.ErrorS(err, "Getting Namespace failed, requeue", "namespace", item.namespace)
			return true
		}
		c.onNamespaceDelete(item.namespace)
	} else {
		c.onNamespaceAdd(ns)
	}
	c.queue.Forget(item)
	return true
}

// syncFlowAccessControls rebuilds the whole index: it re-parses the selectors of every
// FlowAccessControl object and re-evaluates them against every Namespace. This is the expensive
// path, and it only runs when a FlowAccessControl object changes, which is rare since these
// objects are cluster-admin managed.
func (c *Controller) syncFlowAccessControls() error {
	facs, err := c.facLister.List(labels.Everything())
	if err != nil {
		return err
	}
	namespaces, err := c.namespaceLister.List(labels.Everything())
	if err != nil {
		return err
	}

	byUser := map[string]*subjectState{}
	byGroup := map[string]*subjectState{}
	for _, fac := range facs {
		selectors, allowAll := parseNamespaceSelectors(fac)
		for _, subject := range fac.Spec.Subjects {
			var index map[string]*subjectState
			switch subject.Kind {
			case crdv1alpha1.FlowAccessSubjectKindUser:
				index = byUser
			case crdv1alpha1.FlowAccessSubjectKindGroup:
				index = byGroup
			default:
				klog.ErrorS(nil, "Unknown FlowAccessControl subject kind, ignoring", "flowAccessControl", klog.KObj(fac), "kind", subject.Kind)
				continue
			}
			state, ok := index[subject.Name]
			if !ok {
				state = &subjectState{}
				index[subject.Name] = state
			}
			if allowAll {
				// One cluster-wide grant makes every other grant for this subject redundant.
				state.allowAll = true
				state.selectors = nil
			} else if !state.allowAll {
				state.selectors = append(state.selectors, selectors...)
			}
		}
	}

	for _, index := range []map[string]*subjectState{byUser, byGroup} {
		for _, state := range index {
			if state.allowAll {
				continue
			}
			state.namespaces = sets.New[string]()
			for _, ns := range namespaces {
				if state.matches(labels.Set(ns.Labels)) {
					state.namespaces.Insert(ns.Name)
				}
			}
		}
	}

	c.mu.Lock()
	c.byUser = byUser
	c.byGroup = byGroup
	c.mu.Unlock()

	klog.V(4).InfoS("Rebuilt FlowAccessControl index", "flowAccessControls", len(facs), "users", len(byUser), "groups", len(byGroup))
	return nil
}

// onNamespaceAdd re-evaluates a single Namespace against the cached selectors of every subject and
// patches the index in place. It never lists Namespaces or FlowAccessControls, so its cost is
// independent of the number of Namespaces in the cluster. Recomputing this Namespace's membership
// from the subject's cached selectors also means no reference counting is needed when several
// FlowAccessControl objects grant the same Namespace to the same subject: if one of them stops
// matching while another still matches, the Namespace correctly stays visible.
func (c *Controller) onNamespaceAdd(ns *v1.Namespace) {
	nsLabels := labels.Set(ns.Labels)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.forEachTrackedSubject(func(state *subjectState) {
		if state.matches(nsLabels) {
			state.namespaces.Insert(ns.Name)
		} else {
			state.namespaces.Delete(ns.Name)
		}
	})
}

// onNamespaceDelete drops a deleted Namespace from every subject's visible set. No selector
// evaluation is needed: a Namespace that no longer exists is visible to nobody.
func (c *Controller) onNamespaceDelete(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.forEachTrackedSubject(func(state *subjectState) {
		state.namespaces.Delete(name)
	})
}

// forEachTrackedSubject calls fn for every subject whose Namespace set is actually maintained, i.e.
// every subject without cluster-wide visibility. allowAll subjects deliberately keep a nil
// namespaces set, so skipping them avoids pointless work; it also guards against a nil-map insert
// panic. That panic is not reachable today, because syncFlowAccessControls always clears an allowAll
// subject's selectors and so it can never match a Namespace, but the guard keeps an inconsistent
// subject from turning into a crash if that ever changes.
// Callers must hold c.mu for writing.
func (c *Controller) forEachTrackedSubject(fn func(state *subjectState)) {
	for _, index := range []map[string]*subjectState{c.byUser, c.byGroup} {
		for _, state := range index {
			if state.allowAll {
				continue
			}
			fn(state)
		}
	}
}

// parseNamespaceSelectors parses a FlowAccessControl's namespaceSelectors, so that Namespace events
// only ever have to run already-parsed selectors. It reports allowAll when the object grants
// cluster-wide visibility: either it specifies no selectors at all, or one of its selectors is
// empty and therefore matches every Namespace.
func parseNamespaceSelectors(fac *crdv1alpha1.FlowAccessControl) ([]labels.Selector, bool) {
	if len(fac.Spec.NamespaceSelectors) == 0 {
		return nil, true
	}
	selectors := make([]labels.Selector, 0, len(fac.Spec.NamespaceSelectors))
	for i := range fac.Spec.NamespaceSelectors {
		selector, err := metav1.LabelSelectorAsSelector(&fac.Spec.NamespaceSelectors[i])
		if err != nil {
			// Drop only the invalid selector: since selectors are OR-ed, that can only narrow the
			// granted set, which is the fail-closed direction.
			klog.ErrorS(err, "Invalid namespaceSelector in FlowAccessControl, ignoring it", "flowAccessControl", klog.KObj(fac), "index", i)
			continue
		}
		if selector.Empty() {
			return nil, true
		}
		selectors = append(selectors, selector)
	}
	return selectors, false
}
