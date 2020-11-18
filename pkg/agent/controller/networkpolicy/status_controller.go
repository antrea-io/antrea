// Copyright 2020 Antrea Authors
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
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent"
	"github.com/vmware-tanzu/antrea/pkg/apis/controlplane/v1beta2"
)

const (
	realizedRulePolicyIndex = "policy"
)

// StatusManager keeps track of the realized NetworkPolicy rules. It syncs the status of a NetworkPolicy to the
// antrea-controller once it is realized. A policy is considered realized when all of its desired rules have been
// realized and all of its undesired rules have been removed.
// For each new policy, SetRuleRealization is supposed to be called for each of its desired rules while
// DeleteRuleRealization is supposed to be called for the removed rules.
type StatusManager interface {
	// SetRuleRealization updates the actual status for the given NetworkPolicy rule.
	SetRuleRealization(ruleID string, policyID types.UID)
	// DeleteRuleRealization deletes the actual status for the given NetworkPolicy rule.
	DeleteRuleRealization(ruleID string)
	// Resync triggers syncing status with the antrea-controller for the given NetworkPolicy.
	Resync(policyID types.UID)
	// Start the status sync loop.
	Run(stopCh <-chan struct{})
}

// StatusController implements StatusManager.
type StatusController struct {
	nodeName string
	// statusControlInterface knows how to update control plane NetworkPolicy status.
	statusControlInterface networkPolicyStatusControlInterface
	// ruleCache provides the desired state of NetworkPolicy rules.
	ruleCache *ruleCache
	// realizedRules keeps track of the realized NetworkPolicy rules.
	realizedRules cache.Indexer
	// queue maintains the UIDs of the NetworkPolicy that need to be processed.
	queue workqueue.RateLimitingInterface
}

// realizedRule is the struct kept by StatusController for storing a realized rule.
// It has policyID because "ruleCache" only keeps desired state of policies, so if a rule is no longer in a policy it
// will be deleted immediately from "ruleCache" while we need to know these rules are actually uninstalled from
// dataplane before their policies are considered realized.
type realizedRule struct {
	ruleID   string
	policyID types.UID
}

func realizedRuleKeyFunc(obj interface{}) (string, error) {
	return obj.(*realizedRule).ruleID, nil
}

func realizedRulePolicyIndexFunc(obj interface{}) ([]string, error) {
	rule := obj.(*realizedRule)
	return []string{string(rule.policyID)}, nil
}

func newStatusController(antreaClientProvider agent.AntreaClientProvider, nodeName string, ruleCache *ruleCache) *StatusController {
	return &StatusController{
		statusControlInterface: &networkPolicyStatusControl{antreaClientProvider: antreaClientProvider},
		nodeName:               nodeName,
		ruleCache:              ruleCache,
		realizedRules: cache.NewIndexer(realizedRuleKeyFunc, cache.Indexers{
			realizedRulePolicyIndex: realizedRulePolicyIndexFunc,
		}),
		queue: workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "networkpolicystatus"),
	}
}

func (c *StatusController) SetRuleRealization(ruleID string, policyID types.UID) {
	_, exists, _ := c.realizedRules.GetByKey(ruleID)
	// This rule has been realized before. The current call must be triggered by group member updates, which doesn't
	// affect the policy's realization status.
	if exists {
		return
	}
	c.realizedRules.Add(&realizedRule{ruleID: ruleID, policyID: policyID})
	c.queue.Add(policyID)
}

func (c *StatusController) DeleteRuleRealization(ruleID string) {
	obj, exists, _ := c.realizedRules.GetByKey(ruleID)
	// This rule hasn't been realized before, so it doesn't affect the policy's realization status.
	if !exists {
		return
	}
	c.realizedRules.Delete(obj)
	c.queue.Add(obj.(*realizedRule).policyID)
}

func (c *StatusController) Resync(policyID types.UID) {
	klog.V(2).Infof("Resyncing NetworkPolicyStatus for %s", policyID)
	c.queue.Add(policyID)
}

// worker is a long-running function that will continually call the processNextWorkItem function in
// order to read and process a message on the workqueue.
func (c *StatusController) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *StatusController) processNextWorkItem() bool {
	obj, quit := c.queue.Get()
	if quit {
		return false
	}
	// We call Done here so the workqueue knows we have finished processing this item. We also
	// must remember to call Forget if we do not want this work item being re-queued. For
	// example, we do not call Forget if a transient error occurs, instead the item is put back
	// on the workqueue and attempted again after a back-off period.
	defer c.queue.Done(obj)

	// We expect NetworkPolicy UID to come off the workqueue.
	if key, ok := obj.(types.UID); !ok {
		// As the item in the workqueue is actually invalid, we call Forget here else we'd
		// go into a loop of attempting to process a work item that is invalid.
		// This should not happen: enqueueNode only enqueues UIDs.
		c.queue.Forget(obj)
		klog.Errorf("Expected UID in work queue but got %#v", obj)
		return true
	} else if err := c.syncHandler(key); err == nil {
		// If no error occurs we Forget this item so it does not get queued again until
		// another change happens.
		c.queue.Forget(key)
	} else {
		// Put the item back on the workqueue to handle any transient errors.
		c.queue.AddRateLimited(key)
		klog.Errorf("Error syncing NetworkPolicyStatus for %s, requeuing. Error: %v", key, err)
	}
	return true
}

func (c *StatusController) syncHandler(uid types.UID) error {
	policy := c.ruleCache.getNetworkPolicy(string(uid))
	// The policy must have been deleted, no further processing.
	if policy == nil {
		return nil
	}
	desiredRules := c.ruleCache.getRulesByNetworkPolicy(string(uid))
	// The policy must have been deleted, no further processing.
	if len(desiredRules) == 0 {
		return nil
	}
	actualRules, _ := c.realizedRules.ByIndex(realizedRulePolicyIndex, string(uid))
	// desiredRules should match actualRules exactly.
	if len(desiredRules) != len(actualRules) {
		return nil
	}
	desiredRuleSet := sets.NewString()
	for _, r := range desiredRules {
		desiredRuleSet.Insert(r.ID)
	}
	for _, r := range actualRules {
		ruleID := r.(*realizedRule).ruleID
		if !desiredRuleSet.Has(ruleID) {
			return nil
		}
		desiredRuleSet.Delete(ruleID)
	}
	if len(desiredRuleSet) > 0 {
		return nil
	}

	// At this point, all desired rules have been realized and all undesired rules have been removed, report it to the antrea-controller.
	klog.V(2).Infof("Syncing NetworkPolicyStatus for %s, generation: %v", uid, policy.Generation)
	status := &v1beta2.NetworkPolicyStatus{
		ObjectMeta: metav1.ObjectMeta{
			Name: policy.Name,
		},
		Nodes: []v1beta2.NetworkPolicyNodeStatus{
			{
				NodeName:   c.nodeName,
				Generation: policy.Generation,
			},
		},
	}
	return c.statusControlInterface.UpdateNetworkPolicyStatus(status.Name, status)
}

func (c *StatusController) Run(stopCh <-chan struct{}) {
	klog.Info("Starting NetworkPolicy StatusController")
	defer klog.Info("Shutting down NetworkPolicy StatusController")

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}
	<-stopCh
}

// networkPolicyStatusControlInterface is an interface that knows how to get and update control plane NetworkPolicy status.
// It's created as an interface to allow testing.
type networkPolicyStatusControlInterface interface {
	UpdateNetworkPolicyStatus(name string, status *v1beta2.NetworkPolicyStatus) error
}

type networkPolicyStatusControl struct {
	antreaClientProvider agent.AntreaClientProvider
}

func (c *networkPolicyStatusControl) UpdateNetworkPolicyStatus(name string, status *v1beta2.NetworkPolicyStatus) error {
	antreaClient, err := c.antreaClientProvider.GetAntreaClient()
	if err != nil {
		return fmt.Errorf("error getting antrea client: %v", err)
	}
	return antreaClient.ControlplaneV1beta2().NetworkPolicies().UpdateStatus(context.TODO(), name, status)
}
