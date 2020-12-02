// Copyright 2019 Antrea Authors
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

package networkpolicy

import (
	"context"
	"fmt"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent"
	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	"github.com/vmware-tanzu/antrea/pkg/apis/controlplane/v1beta2"
	"github.com/vmware-tanzu/antrea/pkg/querier"
)

const (
	// How long to wait before retrying the processing of a network policy change.
	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second
	// Default number of workers processing a rule change.
	defaultWorkers = 4
)

// Controller is responsible for watching Antrea AddressGroups, AppliedToGroups,
// and NetworkPolicies, feeding them to ruleCache, getting dirty rules from
// ruleCache, invoking reconciler to reconcile them.
//
//          a.Feed AddressGroups,AppliedToGroups
//               and NetworkPolicies
//  |-----------|    <--------    |----------- |  c. Reconcile dirty rules |----------- |
//  | ruleCache |                 | Controller |     ------------>         | reconciler |
//  | ----------|    -------->    |----------- |                           |----------- |
//              b. Notify dirty rules
//
type Controller struct {
	// antreaPolicyEnabled indicates whether Antrea NetworkPolicy and
	// ClusterNetworkPolicy are enabled.
	antreaPolicyEnabled bool
	// antreaClientProvider provides interfaces to get antreaClient, which can be
	// used to watch Antrea AddressGroups, AppliedToGroups, and NetworkPolicies.
	// We need to get antreaClient dynamically because the apiserver cert can be
	// rotated and we need a new client with the updated CA cert.
	// Verifying server certificate only takes place for new requests and existing
	// watches won't be interrupted by rotating cert. The new client will be used
	// after the existing watches expire.
	antreaClientProvider agent.AntreaClientProvider
	// queue maintains the NetworkPolicy ruleIDs that need to be synced.
	queue workqueue.RateLimitingInterface
	// ruleCache maintains the desired state of NetworkPolicy rules.
	ruleCache *ruleCache
	// reconciler provides interfaces to reconcile the desired state of
	// NetworkPolicy rules with the actual state of Openflow entries.
	reconciler Reconciler
	// ofClient registers packetin for Antrea Policy logging.
	ofClient openflow.Client
	// statusManager syncs NetworkPolicy statuses with the antrea-controller.
	// It's only for Antrea NetworkPolicies.
	statusManager         StatusManager
	networkPolicyWatcher  *watcher
	appliedToGroupWatcher *watcher
	addressGroupWatcher   *watcher
	fullSyncGroup         sync.WaitGroup
}

// NewNetworkPolicyController returns a new *Controller.
func NewNetworkPolicyController(antreaClientGetter agent.AntreaClientProvider,
	ofClient openflow.Client,
	ifaceStore interfacestore.InterfaceStore,
	nodeName string,
	podUpdates <-chan v1beta2.PodReference,
	antreaPolicyEnabled bool,
	asyncRuleDeleteInterval time.Duration) (*Controller, error) {
	c := &Controller{
		antreaClientProvider: antreaClientGetter,
		queue:                workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "networkpolicyrule"),
		reconciler:           newReconciler(ofClient, ifaceStore, asyncRuleDeleteInterval),
		ofClient:             ofClient,
		antreaPolicyEnabled:  antreaPolicyEnabled,
	}
	c.ruleCache = newRuleCache(c.enqueueRule, podUpdates)
	if antreaPolicyEnabled {
		c.statusManager = newStatusController(antreaClientGetter, nodeName, c.ruleCache)
	}

	// Create a WaitGroup that is used to block network policy workers from asynchronously processing
	// NP rules until the events preceding bookmark are synced. It can also be used as part of the
	// solution to a deterministic mechanism for when to cleanup flows from previous round.
	// Wait until appliedToGroupWatcher, addressGroupWatcher and networkPolicyWatcher to receive bookmark event.
	c.fullSyncGroup.Add(3)

	if c.ofClient != nil && antreaPolicyEnabled {
		// Register packetInHandler
		c.ofClient.RegisterPacketInHandler(uint8(openflow.PacketInReasonNP), "networkpolicy", c)
		// Initiate logger for Antrea Policy audit logging
		err := initLogger()
		if err != nil {
			return nil, err
		}
	}

	// Use nodeName to filter resources when watching resources.
	options := metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("nodeName", nodeName).String(),
	}

	c.networkPolicyWatcher = &watcher{
		objectType: "NetworkPolicy",
		watchFunc: func() (watch.Interface, error) {
			antreaClient, err := c.antreaClientProvider.GetAntreaClient()
			if err != nil {
				return nil, err
			}
			return antreaClient.ControlplaneV1beta2().NetworkPolicies().Watch(context.TODO(), options)
		},
		AddFunc: func(obj runtime.Object) error {
			policy, ok := obj.(*v1beta2.NetworkPolicy)
			if !ok {
				return fmt.Errorf("cannot convert to *v1beta1.NetworkPolicy: %v", obj)
			}
			if !c.antreaPolicyEnabled && policy.SourceRef.Type != v1beta2.K8sNetworkPolicy {
				klog.Infof("Ignore Antrea NetworkPolicy %s since AntreaPolicy feature gate is not enabled",
					policy.SourceRef.ToString())
				return nil
			}
			c.ruleCache.AddNetworkPolicy(policy)
			klog.Infof("NetworkPolicy %s applied to Pods on this Node", policy.SourceRef.ToString())
			return nil
		},
		UpdateFunc: func(obj runtime.Object) error {
			policy, ok := obj.(*v1beta2.NetworkPolicy)
			if !ok {
				return fmt.Errorf("cannot convert to *v1beta1.NetworkPolicy: %v", obj)
			}
			if !c.antreaPolicyEnabled && policy.SourceRef.Type != v1beta2.K8sNetworkPolicy {
				klog.Infof("Ignore Antrea NetworkPolicy %s since AntreaPolicy feature gate is not enabled",
					policy.SourceRef.ToString())
				return nil
			}
			c.ruleCache.UpdateNetworkPolicy(policy)
			return nil
		},
		DeleteFunc: func(obj runtime.Object) error {
			policy, ok := obj.(*v1beta2.NetworkPolicy)
			if !ok {
				return fmt.Errorf("cannot convert to *v1beta1.NetworkPolicy: %v", obj)
			}
			if !c.antreaPolicyEnabled && policy.SourceRef.Type != v1beta2.K8sNetworkPolicy {
				klog.Infof("Ignore Antrea NetworkPolicy %s since AntreaPolicy feature gate is not enabled",
					policy.SourceRef.ToString())
				return nil
			}
			c.ruleCache.DeleteNetworkPolicy(policy)
			klog.Infof("NetworkPolicy %s no longer applied to Pods on this Node", policy.SourceRef.ToString())
			return nil
		},
		ReplaceFunc: func(objs []runtime.Object) error {
			policies := make([]*v1beta2.NetworkPolicy, len(objs))
			var ok bool
			for i := range objs {
				policies[i], ok = objs[i].(*v1beta2.NetworkPolicy)
				if !ok {
					return fmt.Errorf("cannot convert to *v1beta1.NetworkPolicy: %v", objs[i])
				}
				if !c.antreaPolicyEnabled && policies[i].SourceRef.Type != v1beta2.K8sNetworkPolicy {
					klog.Infof("Ignore Antrea NetworkPolicy %s since AntreaPolicy feature gate is not enabled",
						policies[i].SourceRef.ToString())
					return nil
				}
				klog.Infof("NetworkPolicy %s applied to Pods on this Node", policies[i].SourceRef.ToString())
				// When ReplaceFunc is called, either the controller restarted or this was a regular reconnection.
				// For the former case, agent must resync the statuses as the controller lost the previous statuses.
				// For the latter case, agent doesn't need to do anything. However, we are not able to differentiate the
				// two cases. Anyway there's no harm to do a periodical resync.
				if c.antreaPolicyEnabled && policies[i].SourceRef.Type != v1beta2.K8sNetworkPolicy {
					c.statusManager.Resync(policies[i].UID)
				}
			}
			c.ruleCache.ReplaceNetworkPolicies(policies)
			return nil
		},
		fullSyncWaitGroup: &c.fullSyncGroup,
		fullSynced:        false,
	}

	c.appliedToGroupWatcher = &watcher{
		objectType: "AppliedToGroup",
		watchFunc: func() (watch.Interface, error) {
			antreaClient, err := c.antreaClientProvider.GetAntreaClient()
			if err != nil {
				return nil, err
			}
			return antreaClient.ControlplaneV1beta2().AppliedToGroups().Watch(context.TODO(), options)
		},
		AddFunc: func(obj runtime.Object) error {
			group, ok := obj.(*v1beta2.AppliedToGroup)
			if !ok {
				return fmt.Errorf("cannot convert to *v1beta1.AppliedToGroup: %v", obj)
			}
			c.ruleCache.AddAppliedToGroup(group)
			return nil
		},
		UpdateFunc: func(obj runtime.Object) error {
			group, ok := obj.(*v1beta2.AppliedToGroupPatch)
			if !ok {
				return fmt.Errorf("cannot convert to *v1beta1.AppliedToGroup: %v", obj)
			}
			c.ruleCache.PatchAppliedToGroup(group)
			return nil
		},
		DeleteFunc: func(obj runtime.Object) error {
			group, ok := obj.(*v1beta2.AppliedToGroup)
			if !ok {
				return fmt.Errorf("cannot convert to *v1beta1.AppliedToGroup: %v", obj)
			}
			c.ruleCache.DeleteAppliedToGroup(group)
			return nil
		},
		ReplaceFunc: func(objs []runtime.Object) error {
			groups := make([]*v1beta2.AppliedToGroup, len(objs))
			var ok bool
			for i := range objs {
				groups[i], ok = objs[i].(*v1beta2.AppliedToGroup)
				if !ok {
					return fmt.Errorf("cannot convert to *v1beta1.AppliedToGroup: %v", objs[i])
				}
			}
			c.ruleCache.ReplaceAppliedToGroups(groups)
			return nil
		},
		fullSyncWaitGroup: &c.fullSyncGroup,
		fullSynced:        false,
	}

	c.addressGroupWatcher = &watcher{
		objectType: "AddressGroup",
		watchFunc: func() (watch.Interface, error) {
			antreaClient, err := c.antreaClientProvider.GetAntreaClient()
			if err != nil {
				return nil, err
			}
			return antreaClient.ControlplaneV1beta2().AddressGroups().Watch(context.TODO(), options)
		},
		AddFunc: func(obj runtime.Object) error {
			group, ok := obj.(*v1beta2.AddressGroup)
			if !ok {
				return fmt.Errorf("cannot convert to *v1beta1.AddressGroup: %v", obj)
			}
			c.ruleCache.AddAddressGroup(group)
			return nil
		},
		UpdateFunc: func(obj runtime.Object) error {
			group, ok := obj.(*v1beta2.AddressGroupPatch)
			if !ok {
				return fmt.Errorf("cannot convert to *v1beta1.AddressGroup: %v", obj)
			}
			c.ruleCache.PatchAddressGroup(group)
			return nil
		},
		DeleteFunc: func(obj runtime.Object) error {
			group, ok := obj.(*v1beta2.AddressGroup)
			if !ok {
				return fmt.Errorf("cannot convert to *v1beta1.AddressGroup: %v", obj)
			}
			c.ruleCache.DeleteAddressGroup(group)
			return nil
		},
		ReplaceFunc: func(objs []runtime.Object) error {
			groups := make([]*v1beta2.AddressGroup, len(objs))
			var ok bool
			for i := range objs {
				groups[i], ok = objs[i].(*v1beta2.AddressGroup)
				if !ok {
					return fmt.Errorf("cannot convert to *v1beta1.AddressGroup: %v", objs[i])
				}
			}
			c.ruleCache.ReplaceAddressGroups(groups)
			return nil
		},
		fullSyncWaitGroup: &c.fullSyncGroup,
		fullSynced:        false,
	}
	return c, nil
}

func (c *Controller) GetNetworkPolicyNum() int {
	return c.ruleCache.GetNetworkPolicyNum()
}

func (c *Controller) GetAddressGroupNum() int {
	return c.ruleCache.GetAddressGroupNum()
}

func (c *Controller) GetAppliedToGroupNum() int {
	return c.ruleCache.GetAppliedToGroupNum()
}

// GetNetworkPolicies returns the requested NetworkPolicies.
// This func will return all NetworkPolicies that can match all provided attributes in NetworkPolicyQueryFilter.
// These not provided attributes in NetworkPolicyQueryFilter means match all.
func (c *Controller) GetNetworkPolicies(npFilter *querier.NetworkPolicyQueryFilter) []v1beta2.NetworkPolicy {
	return c.ruleCache.getNetworkPolicies(npFilter)
}

// GetAppliedToNetworkPolicies returns the NetworkPolicies applied to the Pod and match the filter.
func (c *Controller) GetAppliedNetworkPolicies(pod, namespace string, npFilter *querier.NetworkPolicyQueryFilter) []v1beta2.NetworkPolicy {
	return c.ruleCache.getAppliedNetworkPolicies(pod, namespace, npFilter)
}

func (c *Controller) GetAddressGroups() []v1beta2.AddressGroup {
	return c.ruleCache.GetAddressGroups()
}

func (c *Controller) GetAppliedToGroups() []v1beta2.AppliedToGroup {
	return c.ruleCache.GetAppliedToGroups()
}

func (c *Controller) GetNetworkPolicyByRuleFlowID(ruleFlowID uint32) *v1beta2.NetworkPolicyReference {
	rule, exists, err := c.reconciler.GetRuleByFlowID(ruleFlowID)
	if err != nil {
		klog.Errorf("Error when getting network policy by rule flow ID: %v", err)
		return nil
	}
	if !exists {
		return nil
	}
	return rule.PolicyRef
}

func (c *Controller) GetControllerConnectionStatus() bool {
	// When the watchers are connected, controller connection status is true. Otherwise, it is false.
	return c.addressGroupWatcher.isConnected() && c.appliedToGroupWatcher.isConnected() && c.networkPolicyWatcher.isConnected()
}

// Run begins watching and processing Antrea AddressGroups, AppliedToGroups
// and NetworkPolicies, and spawns workers that reconciles NetworkPolicy rules.
// Run will not return until stopCh is closed.
func (c *Controller) Run(stopCh <-chan struct{}) {
	attempts := 0
	if err := wait.PollImmediateUntil(200*time.Millisecond, func() (bool, error) {
		if attempts%10 == 0 {
			klog.Info("Waiting for Antrea client to be ready")
		}
		if _, err := c.antreaClientProvider.GetAntreaClient(); err != nil {
			attempts++
			return false, nil
		}
		return true, nil
	}, stopCh); err != nil {
		klog.Info("Stopped waiting for Antrea client")
		return
	}
	klog.Info("Antrea client is ready")

	// Use NonSlidingUntil so that normal reconnection (disconnected after
	// running a while) can reconnect immediately while abnormal reconnection
	// won't be too aggressive.
	go wait.NonSlidingUntil(c.appliedToGroupWatcher.watch, 5*time.Second, stopCh)
	go wait.NonSlidingUntil(c.addressGroupWatcher.watch, 5*time.Second, stopCh)
	go wait.NonSlidingUntil(c.networkPolicyWatcher.watch, 5*time.Second, stopCh)

	klog.Infof("Waiting for all watchers to complete full sync")
	c.fullSyncGroup.Wait()
	klog.Infof("All watchers have completed full sync, installing flows for init events")
	// Batch install all rules in queue after fullSync is finished.
	c.processAllItemsInQueue()

	klog.Infof("Starting NetworkPolicy workers now")
	defer c.queue.ShutDown()
	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}

	klog.Infof("Starting IDAllocator worker to maintain the async rule cache")
	go c.reconciler.RunIDAllocatorWorker(stopCh)

	if c.antreaPolicyEnabled {
		go c.statusManager.Run(stopCh)
	}

	<-stopCh
}

func (c *Controller) enqueueRule(ruleID string) {
	c.queue.Add(ruleID)
}

// worker runs a worker thread that just dequeues items, processes them, and
// marks them done. You may run as many of these in parallel as you wish; the
// workqueue guarantees that they will not end up processing the same rule at
// the same time.
func (c *Controller) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *Controller) processNextWorkItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	err := c.syncRule(key.(string))
	c.handleErr(err, key)

	return true
}

// processAllItemsInQueue pops all rule keys queued at the moment and calls syncRules to
// reconcile those rules in batch.
func (c *Controller) processAllItemsInQueue() {
	numRules := c.queue.Len()
	batchSyncRuleKeys := make([]string, numRules)
	for i := 0; i < numRules; i++ {
		ruleKey, _ := c.queue.Get()
		batchSyncRuleKeys[i] = ruleKey.(string)
		// set key to done to prevent missing watched updates between here and fullSync finish.
		c.queue.Done(ruleKey)
	}
	// Reconcile all rule keys at once.
	if err := c.syncRules(batchSyncRuleKeys); err != nil {
		klog.Errorf("Error occurred when reconciling all rules for init events: %v", err)
		for _, k := range batchSyncRuleKeys {
			c.queue.AddRateLimited(k)
		}
	}
}

func (c *Controller) syncRule(key string) error {
	startTime := time.Now()
	defer func() {
		klog.V(4).Infof("Finished syncing rule %q. (%v)", key, time.Since(startTime))
	}()

	rule, exists, completed := c.ruleCache.GetCompletedRule(key)
	if !exists {
		klog.V(2).Infof("Rule %v had been deleted, removing its flows", key)
		if err := c.reconciler.Forget(key); err != nil {
			return err
		}
		if c.antreaPolicyEnabled {
			// We don't know whether this is a rule owned by Antrea Policy, but
			// harmless to delete it.
			c.statusManager.DeleteRuleRealization(key)
		}
		return nil
	}
	// If the rule is not complete, we can simply skip it as it will be marked as dirty
	// and queued again when we receive the missing group it missed.
	if !completed {
		klog.V(2).Infof("Rule %v was not complete, skipping", key)
		return nil
	}
	if err := c.reconciler.Reconcile(rule); err != nil {
		return err
	}
	if c.antreaPolicyEnabled && rule.SourceRef.Type != v1beta2.K8sNetworkPolicy {
		c.statusManager.SetRuleRealization(key, rule.PolicyUID)
	}
	return nil
}

// syncRules calls the reconciler to sync all the rules after watchers complete full sync.
// After flows for those init events are installed, subsequent rules will be handled asynchronously
// by the syncRule() function.
func (c *Controller) syncRules(keys []string) error {
	startTime := time.Now()
	defer func() {
		klog.V(4).Infof("Finished syncing all rules before bookmark event (%v)", time.Since(startTime))
	}()

	var allRules []*CompletedRule
	for _, key := range keys {
		rule, exists, completed := c.ruleCache.GetCompletedRule(key)
		if !exists || !completed {
			klog.Errorf("Rule %s is not complete or does not exist in cache", key)
		} else {
			allRules = append(allRules, rule)
		}
	}
	if err := c.reconciler.BatchReconcile(allRules); err != nil {
		return err
	}
	if c.antreaPolicyEnabled {
		for _, rule := range allRules {
			if rule.SourceRef.Type != v1beta2.K8sNetworkPolicy {
				c.statusManager.SetRuleRealization(rule.ID, rule.PolicyUID)
			}
		}
	}
	return nil
}

func (c *Controller) handleErr(err error, key interface{}) {
	if err == nil {
		c.queue.Forget(key)
		return
	}

	klog.Errorf("Error syncing rule %q, retrying. Error: %v", key, err)
	c.queue.AddRateLimited(key)
}

// watcher is responsible for watching a given resource with the provided watchFunc
// and calling the eventHandlers when receiving events.
type watcher struct {
	// objectType is the type of objects being watched, used for logging.
	objectType string
	// watchFunc is the function that starts the watch.
	watchFunc func() (watch.Interface, error)
	// AddFunc is the function that handles added event.
	AddFunc func(obj runtime.Object) error
	// UpdateFunc is the function that handles modified event.
	UpdateFunc func(obj runtime.Object) error
	// DeleteFunc is the function that handles deleted event.
	DeleteFunc func(obj runtime.Object) error
	// ReplaceFunc is the function that handles init events.
	ReplaceFunc func(objs []runtime.Object) error
	// connected represents whether the watch has connected to apiserver successfully.
	connected bool
	// lock protects connected.
	lock sync.RWMutex
	// group to be notified when each watcher receives bookmark event
	fullSyncWaitGroup *sync.WaitGroup
	// fullSynced indicates if the resource has been synced at least once since agent started.
	fullSynced bool
}

func (w *watcher) isConnected() bool {
	w.lock.RLock()
	defer w.lock.RUnlock()
	return w.connected
}

func (w *watcher) setConnected(connected bool) {
	w.lock.Lock()
	defer w.lock.Unlock()
	w.connected = connected
}

func (w *watcher) watch() {
	klog.Infof("Starting watch for %s", w.objectType)
	watcher, err := w.watchFunc()
	if err != nil {
		klog.Warningf("Failed to start watch for %s: %v", w.objectType, err)
		return
	}

	klog.Infof("Started watch for %s", w.objectType)
	w.setConnected(true)
	eventCount := 0
	defer func() {
		klog.Infof("Stopped watch for %s, total items received: %d", w.objectType, eventCount)
		w.setConnected(false)
		watcher.Stop()
	}()

	// First receive init events from the result channel and buffer them until
	// a Bookmark event is received, indicating that all init events have been
	// received.
	var initObjects []runtime.Object
loop:
	for {
		select {
		case event, ok := <-watcher.ResultChan():
			if !ok {
				klog.Warningf("Result channel for %s was closed", w.objectType)
				return
			}
			switch event.Type {
			case watch.Added:
				klog.V(2).Infof("Added %s (%#v)", w.objectType, event.Object)
				initObjects = append(initObjects, event.Object)
			case watch.Bookmark:
				break loop
			}
		}
	}
	klog.Infof("Received %d init events for %s", len(initObjects), w.objectType)

	eventCount += len(initObjects)
	if err := w.ReplaceFunc(initObjects); err != nil {
		klog.Errorf("Failed to handle init events: %v", err)
		return
	}
	if !w.fullSynced {
		w.fullSynced = true
		// Notify fullSyncWaitGroup that all events before bookmark is handled
		w.fullSyncWaitGroup.Done()
	}

	for {
		select {
		case event, ok := <-watcher.ResultChan():
			if !ok {
				return
			}
			switch event.Type {
			case watch.Added:
				if err := w.AddFunc(event.Object); err != nil {
					klog.Errorf("Failed to handle added event: %v", err)
					return
				}
				klog.V(2).Infof("Added %s (%#v)", w.objectType, event.Object)
			case watch.Modified:
				if err := w.UpdateFunc(event.Object); err != nil {
					klog.Errorf("Failed to handle modified event: %v", err)
					return
				}
				klog.V(2).Infof("Updated %s (%#v)", w.objectType, event.Object)
			case watch.Deleted:
				if err := w.DeleteFunc(event.Object); err != nil {
					klog.Errorf("Failed to handle deleted event: %v", err)
					return
				}
				klog.V(2).Infof("Removed %s (%#v)", w.objectType, event.Object)
			default:
				klog.Errorf("Unknown event: %v", event)
				return
			}
			eventCount++
		}
	}
}
