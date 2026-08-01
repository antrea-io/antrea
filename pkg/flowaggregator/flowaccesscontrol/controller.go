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
	"maps"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
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
	// selectors is the list of parsed Namespace selectors from every FlowAccessControl naming this
	// subject. Each object contributes at most one selector, but several objects may name the same
	// subject, and a Namespace is visible to the subject if any of them matches it. That is why
	// this stays a list even though the API takes a single selector per object.
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
	// HasSynced reports whether the index has been built at least once from a synced cache. Until
	// it returns true, every VisibilityChecker denies everything, which is indistinguishable from a
	// subject that simply has no grant. Callers must therefore check this before serving a stream,
	// and fail the request (e.g. with Unavailable) rather than silently serving no flows while the
	// flow-aggregator is still starting up.
	HasSynced() bool
	// VisibilityCheckerFor returns a VisibilityChecker bound to the given user, identified by its
	// username and the groups it belongs to. It is meant to be called once per flow stream, when the
	// stream's identity has been authenticated.
	VisibilityCheckerFor(username string, groups []string) VisibilityChecker
}

// VisibilityChecker authorizes one user's view of the flow stream. It is obtained once per stream and
// then consulted per flow record.
//
// A VisibilityChecker is a live view of the index, deliberately not a snapshot of it. Every call
// reads the current state, so revoking a grant — by editing or deleting a FlowAccessControl, or by
// relabeling a Namespace so it no longer matches — stops the affected flows from reaching an
// already-established stream.
//
// This is a stricter contract than the one the stream's identity has: identity is authenticated
// once at stream start and not re-validated mid-stream. The two are separate concerns. Identity is
// established at connection time, whereas visibility is administrator policy that is expected to be
// enforceable while a stream is open.
type VisibilityChecker interface {
	// AllowsAll reports whether the user has cluster-wide visibility. Callers need this for flow
	// records that carry no Namespace at all, which only such a user may observe.
	AllowsAll() bool
	// AllowsNamespace reports whether the user may observe flows involving the given Namespace.
	AllowsNamespace(namespace string) bool
}

// checker is the Controller-backed VisibilityChecker. It holds only the user's identity, so that every check
// resolves against the index as it currently stands.
type checker struct {
	c        *Controller
	username string
	// groups is retained, not copied, and must not be mutated by the caller. It comes from the
	// authenticated user info, which is not modified after authentication.
	groups []string
}

// HasSynced implements Interface.
func (c *Controller) HasSynced() bool {
	return c.synced.Load()
}

// VisibilityCheckerFor implements Interface.
func (c *Controller) VisibilityCheckerFor(username string, groups []string) VisibilityChecker {
	return &checker{c: c, username: username, groups: groups}
}

func (ck *checker) AllowsAll() bool {
	ck.c.mu.RLock()
	defer ck.c.mu.RUnlock()

	return ck.c.anySubjectState(ck.username, ck.groups, func(state *subjectState) bool {
		return state.allowAll
	})
}

func (ck *checker) AllowsNamespace(namespace string) bool {
	ck.c.mu.RLock()
	defer ck.c.mu.RUnlock()

	return ck.c.anySubjectState(ck.username, ck.groups, func(state *subjectState) bool {
		return state.allowAll || state.namespaces.Has(namespace)
	})
}

// anySubjectState reports whether pred holds for the cached state of any FlowAccessControl subject
// that applies to the given user. Grants are OR-ed across the user's own subject and its groups'
// subjects, so the first match settles the answer.
//
// This is the per-flow-record hot path: it allocates nothing and only ever does map lookups, since
// the Namespace sets it reads are kept up to date by the Namespace event handlers rather than
// being recomputed here.
//
// Callers must hold c.mu for reading. The cached sets are patched in place by syncNamespace and
// removeNamespace, so pred must not retain anything it is given.
func (c *Controller) anySubjectState(username string, groups []string, pred func(state *subjectState) bool) bool {
	if state, ok := c.byUser[username]; ok && pred(state) {
		return true
	}
	for _, group := range groups {
		if state, ok := c.byGroup[group]; ok && pred(state) {
			return true
		}
	}
	return false
}

// Controller watches FlowAccessControl objects and Namespaces, and maintains an in-memory
// "username/group -> allowed Namespace set" index, re-evaluating their namespaceSelector whenever a
// Namespace's labels change. Keeping the index current is what lets a VisibilityChecker answer from
// it directly, so that an established flow stream sees a grant change without having to reconnect.
type Controller struct {
	facInformer     cache.SharedIndexInformer
	facLister       crdlisters.FlowAccessControlLister
	facListerSynced cache.InformerSynced

	namespaceInformer     cache.SharedIndexInformer
	namespaceLister       corelisters.NamespaceLister
	namespaceListerSynced cache.InformerSynced

	queue workqueue.TypedRateLimitingInterface[workItem]

	// synced is set once Run has built the index from a synced cache, and reported by HasSynced.
	// It is never cleared: the index is only ever replaced by a newer one from that point on.
	synced atomic.Bool

	// mu guards byUser and byGroup, including the subjectState values they point to, which are
	// mutated in place by syncNamespace and removeNamespace. It is taken for reading on the
	// per-flow-record authorization path, so the write side is kept short.
	mu      sync.RWMutex
	byUser  map[string]*subjectState
	byGroup map[string]*subjectState
}

var _ Interface = (*Controller)(nil)

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
	// A Namespace's labels are the only thing that can change which namespaceSelector matches it,
	// so skip updates to any other field. Namespaces are updated far more often than
	// FlowAccessControl objects change, which makes this the most valuable early return here, and
	// the reason it compares the label maps directly instead of reaching for reflection.
	if maps.Equal(oldNS.GetLabels(), ns.GetLabels()) {
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
	// Build the index once, synchronously, before reporting HasSynced. A VisibilityChecker denies
	// everything while the index is empty, which a consumer cannot tell apart from a subject with
	// no grant, so gating on HasSynced is what lets it fail a request outright rather than serve a
	// silently empty flow stream to a client that connects during startup.
	for {
		err := c.syncFlowAccessControls()
		if err == nil {
			break
		}
		klog.ErrorS(err, "Building the initial FlowAccessControl index failed, retrying")
		select {
		case <-stopCh:
			return
		case <-time.After(minRetryDelay):
		}
	}
	c.synced.Store(true)

	// A single worker keeps index updates serialized, which is what lets the Namespace handlers
	// patch the index in place without coordinating with a concurrent rebuild.
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
		c.removeNamespace(item.namespace)
	} else {
		c.syncNamespace(ns)
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
		selector, allowAll := parseNamespaceSelector(fac)
		for _, subject := range fac.Spec.Subjects {
			var index map[string]*subjectState
			key := subject.Name
			switch subject.Kind {
			case crdv1alpha1.FlowAccessSubjectKindUser:
				index = byUser
			case crdv1alpha1.FlowAccessSubjectKindGroup:
				index = byGroup
			case crdv1alpha1.FlowAccessSubjectKindServiceAccount:
				if subject.Namespace == "" {
					// The CRD schema rejects this, but x-kubernetes-validations only became
					// enabled by default in Kubernetes 1.25 and we support 1.23+, so adding
					// a defensive check here.
					klog.ErrorS(nil, "ServiceAccount subject without a Namespace, ignoring", "flowAccessControl", klog.KObj(fac), "name", subject.Name)
					continue
				}
				// A ServiceAccount is authenticated as a user, so it is indexed as one: this is
				// exactly the identity the authenticator produces, which also means a
				// ServiceAccount subject and a User subject spelling out the same identity
				// collapse into one entry and union like any other duplicate grant.
				index = byUser
				key = serviceaccount.MakeUsername(subject.Namespace, subject.Name)
			default:
				klog.ErrorS(nil, "Unknown FlowAccessControl subject kind, ignoring", "flowAccessControl", klog.KObj(fac), "kind", subject.Kind)
				continue
			}
			state, ok := index[key]
			if !ok {
				state = &subjectState{}
				index[key] = state
			}
			if allowAll {
				// One cluster-wide grant makes every other grant for this subject redundant.
				state.allowAll = true
				state.selectors = nil
			} else if !state.allowAll {
				state.selectors = append(state.selectors, selector)
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
				if state.matches(ns.Labels) {
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

// syncNamespace re-evaluates a single Namespace against the cached selectors of every subject and
// patches the index in place, adding the Namespace to the subjects it now matches and removing it
// from those it no longer matches. It never lists Namespaces or FlowAccessControls, so its cost is
// independent of the number of Namespaces in the cluster. Recomputing this Namespace's membership
// from the subject's cached selectors also means no reference counting is needed when several
// FlowAccessControl objects grant the same Namespace to the same subject: if one of them stops
// matching while another still matches, the Namespace correctly stays visible.
func (c *Controller) syncNamespace(ns *v1.Namespace) {
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

// removeNamespace drops a deleted Namespace from every subject's visible set. No selector
// evaluation is needed: a Namespace that no longer exists is visible to nobody.
func (c *Controller) removeNamespace(name string) {
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

// parseNamespaceSelector parses a FlowAccessControl's namespaceSelector once, so that Namespace
// events only ever have to run an already-parsed selector. It reports allowAll when the object
// grants cluster-wide visibility, in which case the returned selector is nil and per-Namespace
// checks are skipped for its subjects.
//
// The null-vs-empty distinction the API documents is exactly what metav1.LabelSelectorAsSelector
// already implements, so the pointer is passed straight through:
//   - a null selector becomes labels.Nothing(), which matches no Namespace and is not Empty(), so
//     the object grants nothing. Admission rejects such an object, so this only comes up for
//     objects created before that validation existed.
//   - an empty selector ({}) becomes labels.Everything(), which is Empty(), so the object grants
//     cluster-wide visibility.
func parseNamespaceSelector(fac *crdv1alpha1.FlowAccessControl) (labels.Selector, bool) {
	selector, err := metav1.LabelSelectorAsSelector(fac.Spec.NamespaceSelector)
	if err != nil {
		// An unparseable selector grants nothing, which is the fail-closed direction. Other
		// FlowAccessControl objects naming the same subjects are unaffected, since grants are
		// OR-ed across objects.
		klog.ErrorS(err, "Invalid namespaceSelector in FlowAccessControl, granting nothing for it", "flowAccessControl", klog.KObj(fac))
		return labels.Nothing(), false
	}
	if selector.Empty() {
		return nil, true
	}
	return selector, false
}
