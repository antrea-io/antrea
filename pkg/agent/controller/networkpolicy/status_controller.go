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
	"sort"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"antrea.io/antrea/v2/pkg/agent/client"
	"antrea.io/antrea/v2/pkg/apis/controlplane/v1beta2"
)

const (
	ruleRealizationPolicyIndex = "policy"
)

// StatusManager keeps track of NetworkPolicy rule realization results. It syncs the status of a NetworkPolicy to the
// antrea-controller when realization fails or completes. A policy is considered realized when all of its desired rules
// have been realized and all of its undesired rules have been removed.
// SetRuleRealization is supposed to be called after each reconciliation of a desired rule, while
// DeleteRuleRealization is supposed to be called for the removed rules.
type StatusManager interface {
	// SetRuleRealization records the reconciliation result for the given NetworkPolicy rule. A nil error indicates success.
	SetRuleRealization(ruleID string, policyID types.UID, realizationErr error)
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
	// ruleRealizations keeps track of successful and failed NetworkPolicy rule reconciliations.
	ruleRealizations cache.Indexer
	// queue maintains the UIDs of the NetworkPolicy that need to be processed.
	queue workqueue.TypedRateLimitingInterface[types.UID]
}

// ruleRealization is the struct kept by StatusController for storing a rule's reconciliation result.
// It has policyID because "ruleCache" only keeps desired state of policies, so if a rule is no longer in a policy it
// will be deleted immediately from "ruleCache" while we need to know these rules are actually uninstalled from
// dataplane before their policies are considered realized.
type ruleRealization struct {
	ruleID             string
	policyID           types.UID
	realizationFailure bool
	message            string
}

func ruleRealizationKeyFunc(obj interface{}) (string, error) {
	return obj.(*ruleRealization).ruleID, nil
}

func ruleRealizationPolicyIndexFunc(obj interface{}) ([]string, error) {
	rule := obj.(*ruleRealization)
	return []string{string(rule.policyID)}, nil
}

func newStatusController(antreaClientProvider client.AntreaClientProvider, nodeName string, ruleCache *ruleCache) *StatusController {
	return &StatusController{
		statusControlInterface: &networkPolicyStatusControl{antreaClientProvider: antreaClientProvider},
		nodeName:               nodeName,
		ruleCache:              ruleCache,
		ruleRealizations: cache.NewIndexer(ruleRealizationKeyFunc, cache.Indexers{
			ruleRealizationPolicyIndex: ruleRealizationPolicyIndexFunc,
		}),
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.NewTypedItemExponentialFailureRateLimiter[types.UID](minRetryDelay, maxRetryDelay),
			workqueue.TypedRateLimitingQueueConfig[types.UID]{
				Name: "networkpolicystatus",
			},
		),
	}
}

func (c *StatusController) SetRuleRealization(ruleID string, policyID types.UID, realizationErr error) {
	result := &ruleRealization{ruleID: ruleID, policyID: policyID, realizationFailure: realizationErr != nil}
	if realizationErr != nil {
		result.message = realizationErr.Error()
	}
	obj, exists, err := c.ruleRealizations.GetByKey(ruleID)
	if err != nil {
		klog.ErrorS(err, "Failed to get rule realization", "ruleID", ruleID)
		return
	}
	// Group member updates and retries only affect policy status if the realization result changes.
	if exists && *obj.(*ruleRealization) == *result {
		return
	}
	if err := c.ruleRealizations.Add(result); err != nil {
		klog.ErrorS(err, "Failed to record rule realization", "ruleID", ruleID)
		return
	}
	c.queue.Add(policyID)
}

func (c *StatusController) DeleteRuleRealization(ruleID string) {
	obj, exists, err := c.ruleRealizations.GetByKey(ruleID)
	if err != nil {
		klog.ErrorS(err, "Failed to get rule realization", "ruleID", ruleID)
		return
	}
	// This rule has no recorded reconciliation result, so it doesn't affect the policy's realization status.
	if !exists {
		return
	}
	if err := c.ruleRealizations.Delete(obj); err != nil {
		klog.ErrorS(err, "Failed to delete rule realization", "ruleID", ruleID)
		return
	}
	c.queue.Add(obj.(*ruleRealization).policyID)
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
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	// We call Done here so the workqueue knows we have finished processing this item. We also
	// must remember to call Forget if we do not want this work item being re-queued. For
	// example, we do not call Forget if a transient error occurs, instead the item is put back
	// on the workqueue and attempted again after a back-off period.
	defer c.queue.Done(key)

	if err := c.syncHandler(key); err == nil {
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
	desiredRules := c.ruleCache.getEffectiveRulesByNetworkPolicy(string(uid))
	// The policy must have been deleted, no further processing.
	if len(desiredRules) == 0 {
		return nil
	}
	actualRules, err := c.ruleRealizations.ByIndex(ruleRealizationPolicyIndex, string(uid))
	if err != nil {
		return err
	}
	desiredRuleSet := sets.New[string]()
	for _, r := range desiredRules {
		desiredRuleSet.Insert(r.ID)
	}
	var failures []string
	for _, obj := range actualRules {
		r := obj.(*ruleRealization)
		if !desiredRuleSet.Has(r.ruleID) {
			continue
		}
		if r.realizationFailure {
			failures = append(failures, fmt.Sprintf("rule %s: %s", r.ruleID, r.message))
		}
		desiredRuleSet.Delete(r.ruleID)
	}
	// Report failures even if other rules are still pending. Success requires all desired rules to be
	// realized and all undesired rules to be removed, including rules whose last reconciliation failed.
	if len(failures) == 0 && (len(desiredRuleSet) > 0 || len(desiredRules) != len(actualRules)) {
		return nil
	}
	sort.Strings(failures)

	klog.V(2).Infof("Syncing NetworkPolicyStatus for %s, generation: %v", uid, policy.Generation)
	status := &v1beta2.NetworkPolicyStatus{
		ObjectMeta: metav1.ObjectMeta{
			Name: policy.Name,
		},
		Nodes: []v1beta2.NetworkPolicyNodeStatus{
			{
				NodeName:           c.nodeName,
				Generation:         policy.Generation,
				RealizationFailure: len(failures) > 0,
				Message:            strings.Join(failures, "; "),
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
	antreaClientProvider client.AntreaClientProvider
}

func (c *networkPolicyStatusControl) UpdateNetworkPolicyStatus(name string, status *v1beta2.NetworkPolicyStatus) error {
	antreaClient, err := c.antreaClientProvider.GetAntreaClient()
	if err != nil {
		return fmt.Errorf("error getting antrea client: %v", err)
	}
	return antreaClient.ControlplaneV1beta2().NetworkPolicies().UpdateStatus(context.TODO(), name, status)
}
