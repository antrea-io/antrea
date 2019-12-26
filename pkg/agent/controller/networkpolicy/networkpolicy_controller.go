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
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	"github.com/vmware-tanzu/antrea/pkg/apis/networking/v1beta1"
	"github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned"
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
	// nodeName is the name of this node, which is used to filter resources
	// when watching resources.
	nodeName string
	// antreaClient provides interfaces to watch Antrea AddressGroups,
	// AppliedToGroups, and NetworkPolicies.
	antreaClient versioned.Interface
	// queue maintains the NetworkPolicy ruleIDs that need to be synced.
	queue workqueue.RateLimitingInterface
	// ruleCache maintains the desired state of NetworkPolicy rules.
	ruleCache *ruleCache
	// reconciler provides interfaces to reconcile the desired state of
	// NetworkPolicy rules with the actual state of Openflow entries.
	reconciler Reconciler
}

// NewNetworkPolicyController returns a new *Controller.
func NewNetworkPolicyController(antreaClient versioned.Interface,
	ofClient openflow.Client,
	ifaceStore interfacestore.InterfaceStore,
	nodeName string,
	podUpdates <-chan v1beta1.PodReference) *Controller {
	c := &Controller{
		antreaClient: antreaClient,
		nodeName:     nodeName,
		queue:        workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "networkpolicyrule"),
		reconciler:   newReconciler(ofClient, ifaceStore),
	}
	c.ruleCache = newRuleCache(c.enqueueRule, podUpdates)
	return c
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

// Run begins watching and processing Antrea AddressGroups, AppliedToGroups
// and NetworkPolicies, and spawns workers that reconciles NetworkPolicy rules.
// Run will not return until stopCh is closed.
func (c *Controller) Run(stopCh <-chan struct{}) error {
	// Use NonSlidingUntil so that normal reconnection (disconnected after
	// running a while) can reconnect immediately while abnormal reconnection
	// won't be too aggressive.
	go wait.NonSlidingUntil(c.watchAppliedToGroups, 5*time.Second, stopCh)
	go wait.NonSlidingUntil(c.watchAddressGroups, 5*time.Second, stopCh)
	go wait.NonSlidingUntil(c.watchNetworkPolicies, 5*time.Second, stopCh)

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}

	<-stopCh
	return nil
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

func (c *Controller) nodeScopedListOptions() metav1.ListOptions {
	options := metav1.ListOptions{}
	options.FieldSelector = fields.OneTermEqualSelector("nodeName", c.nodeName).String()
	return options
}

func (c *Controller) watchAppliedToGroups() {
	// TODO: Cleanup AppliedToGroups that are removed during reconnection.
	klog.Info("Start watching AppliedToGroups")
	options := c.nodeScopedListOptions()
	w, err := c.antreaClient.NetworkingV1beta1().AppliedToGroups().Watch(options)
	if err != nil {
		klog.Errorf("Failed to watch AppliedToGroups: %v", err)
		return
	}

	eventCount := 0
	defer func() {
		klog.Infof("Stop watching AppliedToGroups, total %v items received", eventCount)
		w.Stop()
	}()

	for {
		select {
		case event, ok := <-w.ResultChan():
			if !ok {
				return
			}
			switch event.Type {
			case watch.Added:
				group, ok := event.Object.(*v1beta1.AppliedToGroup)
				if !ok {
					klog.Errorf("Cannot convert to *v1beta1.AppliedToGroup: %v", event.Object)
					return
				}
				klog.V(2).Infof("Added AppliedToGroup (%#v)", event.Object)
				c.ruleCache.AddAppliedToGroup(group)
			case watch.Modified:
				patch, ok := event.Object.(*v1beta1.AppliedToGroupPatch)
				if !ok {
					klog.Errorf("Cannot convert to *v1beta1.AppliedToGroupPatch: %v", event.Object)
					return
				}
				klog.V(2).Infof("Patched AppliedToGroup (%#v)", event.Object)
				c.ruleCache.PatchAppliedToGroup(patch)
			case watch.Deleted:
				group, ok := event.Object.(*v1beta1.AppliedToGroup)
				if !ok {
					klog.Errorf("Cannot convert to *v1beta1.AppliedToGroup: %v", event.Object)
					return
				}
				klog.V(2).Infof("Removed AppliedToGroup (%#v)", event.Object)
				c.ruleCache.DeleteAppliedToGroup(group)
			}
			eventCount++
		}
	}
}

func (c *Controller) watchAddressGroups() {
	// TODO: Cleanup AddressGroups that are removed during reconnection.
	klog.Info("Start watching AddressGroups")
	options := c.nodeScopedListOptions()
	w, err := c.antreaClient.NetworkingV1beta1().AddressGroups().Watch(options)
	if err != nil {
		klog.Errorf("Failed to watch AddressGroups: %v", err)
		return
	}

	eventCount := 0
	defer func() {
		klog.Infof("Stop watching AddressGroups, total %v items received", eventCount)
		w.Stop()
	}()

	for {
		select {
		case event, ok := <-w.ResultChan():
			if !ok {
				return
			}
			switch event.Type {
			case watch.Added:
				group, ok := event.Object.(*v1beta1.AddressGroup)
				if !ok {
					klog.Errorf("Cannot convert to *v1beta1.AddressGroup: %v", event.Object)
					return
				}
				klog.V(2).Infof("Added AddressGroup (%#v)", event.Object)
				c.ruleCache.AddAddressGroup(group)
			case watch.Modified:
				patch, ok := event.Object.(*v1beta1.AddressGroupPatch)
				if !ok {
					klog.Errorf("Cannot convert to *v1beta1.AddressGroupPatch: %v", event.Object)
					return
				}
				klog.V(2).Infof("Patched AddressGroup (%#v)", event.Object)
				c.ruleCache.PatchAddressGroup(patch)
			case watch.Deleted:
				group, ok := event.Object.(*v1beta1.AddressGroup)
				if !ok {
					klog.Errorf("Cannot convert to *v1beta1.AddressGroup: %v", event.Object)
					return
				}
				klog.V(2).Infof("Removed AddressGroup (%#v)", event.Object)
				c.ruleCache.DeleteAddressGroup(group)
			}
			eventCount++
		}
	}
}

func (c *Controller) watchNetworkPolicies() {
	// TODO: Cleanup NetworkPolicies that are removed during reconnection.
	klog.Info("Start watching NetworkPolicies")
	options := c.nodeScopedListOptions()
	w, err := c.antreaClient.NetworkingV1beta1().NetworkPolicies("").Watch(options)
	if err != nil {
		klog.Errorf("Failed to watch NetworkPolicies: %v", err)
		return
	}

	eventCount := 0
	defer func() {
		klog.Infof("Stop watching NetworkPolicies, total %v items received", eventCount)
		w.Stop()
	}()

	for {
		select {
		case event, ok := <-w.ResultChan():
			if !ok {
				return
			}
			switch event.Type {
			case watch.Added:
				policy, ok := event.Object.(*v1beta1.NetworkPolicy)
				if !ok {
					klog.Errorf("Cannot convert to *v1beta1.NetworkPolicy: %v", event.Object)
					return
				}
				klog.V(2).Infof("Added NetworkPolicy (%#v)", event.Object)
				c.ruleCache.AddNetworkPolicy(policy)
			case watch.Modified:
				policy, ok := event.Object.(*v1beta1.NetworkPolicy)
				if !ok {
					klog.Errorf("Cannot convert to *v1beta1.NetworkPolicy: %v", event.Object)
					return
				}
				klog.V(2).Infof("Updated NetworkPolicy (%#v)", event.Object)
				c.ruleCache.UpdateNetworkPolicy(policy)
			case watch.Deleted:
				policy, ok := event.Object.(*v1beta1.NetworkPolicy)
				if !ok {
					klog.Errorf("cannot convert to *v1beta1.NetworkPolicy: %v", event.Object)
					return
				}
				klog.V(2).Infof("Removed NetworkPolicy (%#v)", event.Object)
				c.ruleCache.DeleteNetworkPolicy(policy)
			}
			eventCount++
		}
	}
}
