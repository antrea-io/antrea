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
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/apis/networking/v1beta1"
)

const (
	RuleIDLength        = 16
	appliedToGroupIndex = "appliedToGroup"
	addressGroupIndex   = "addressGroup"
	policyIndex         = "policy"
)

// rule is the struct stored in ruleCache, it contains necessary information
// to construct a complete rule that can be used by reconciler to enforce.
// The K8s NetworkPolicy object doesn't provide ID for its rule, here we
// calculate an ID based on the rule's fields. That means:
// 1. If a rule's selector/services/direction changes, it becomes "another" rule.
// 2. If inserting rules before a rule or shuffling rules in a NetworkPolicy, we
//    can know the existing rules don't change and skip processing them.
type rule struct {
	// ID is calculated from the hash value of all other fields.
	ID string
	// Direction of this rule.
	Direction v1beta1.Direction
	// Source Address of this rule, can't coexist with To.
	From v1beta1.NetworkPolicyPeer
	// Destination Address of this rule, can't coexist with From.
	To v1beta1.NetworkPolicyPeer
	// Protocols and Ports of this rule.
	Services []v1beta1.Service
	// Targets of this rule.
	AppliedToGroups []string
	// The parent Policy ID. Used to identify rules belong to a specified
	// policy for deletion.
	PolicyUID types.UID
}

// hashRule calculates a string based on the rule's content.
func hashRule(r *rule) string {
	hash := sha1.New()
	b, _ := json.Marshal(r)
	hash.Write(b)
	hashValue := hex.EncodeToString(hash.Sum(nil))
	return hashValue[:RuleIDLength]
}

// CompletedRule contains IPAddresses and Pods flattened from AddressGroups and AppliedToGroups.
// It's the struct used by reconciler.
type CompletedRule struct {
	*rule
	// Source Pods of this rule, can't coexist with ToAddresses.
	FromAddresses v1beta1.GroupMemberPodSet
	// Destination Pods of this rule, can't coexist with FromAddresses.
	ToAddresses v1beta1.GroupMemberPodSet
	// Target Pods of this rule.
	Pods v1beta1.GroupMemberPodSet
}

// String returns the string representation of the CompletedRule.
func (r *CompletedRule) String() string {
	var addressString string
	if r.Direction == v1beta1.DirectionIn {
		addressString = fmt.Sprintf("FromAddressGroups: %d, FromIPBlocks: %d, FromAddresses: %d", len(r.From.AddressGroups), len(r.From.IPBlocks), len(r.FromAddresses))
	} else {
		addressString = fmt.Sprintf("ToAddressGroups: %d, ToIPBlocks: %d, ToAddresses: %d", len(r.To.AddressGroups), len(r.To.IPBlocks), len(r.ToAddresses))
	}
	return fmt.Sprintf("%s (Direction: %v, Pods: %d, %s, Services: %d)", r.ID, r.Direction, len(r.Pods), addressString, len(r.Services))
}

// ruleCache caches Antrea AddressGroups, AppliedToGroups and NetworkPolicies,
// can construct complete rules that can be used by reconciler to enforce.
type ruleCache struct {
	podSetLock sync.RWMutex
	// podSetByGroup stores the AppliedToGroup members.
	// It is a mapping from group name to a set of Pods.
	podSetByGroup map[string]v1beta1.GroupMemberPodSet

	addressSetLock sync.RWMutex
	// addressSetByGroup stores the AddressGroup members.
	// It is a mapping from group name to a set of Pods.
	addressSetByGroup map[string]v1beta1.GroupMemberPodSet

	policySetLock sync.RWMutex
	// policySet is a set to store NetworkPolicy UID strings.
	policySet sets.String

	// rules is a storage that supports listing rules using multiple indexing functions.
	// rules is thread-safe.
	rules cache.Indexer
	// dirtyRuleHandler is a callback that is run upon finding a rule out-of-sync.
	dirtyRuleHandler func(string)

	// podUpdates is a channel for receiving Pod updates from CNIServer.
	podUpdates <-chan v1beta1.PodReference
}

// ruleKeyFunc knows how to get key of a *rule.
func ruleKeyFunc(obj interface{}) (string, error) {
	rule := obj.(*rule)
	return rule.ID, nil
}

// addressGroupIndexFunc knows how to get addressGroups of a *rule.
// It's provided to cache.Indexer to build an index of addressGroups.
func addressGroupIndexFunc(obj interface{}) ([]string, error) {
	rule := obj.(*rule)
	addressGroups := make([]string, 0, len(rule.From.AddressGroups)+len(rule.To.AddressGroups))
	addressGroups = append(addressGroups, rule.From.AddressGroups...)
	addressGroups = append(addressGroups, rule.To.AddressGroups...)
	return addressGroups, nil
}

// appliedToGroupIndexFunc knows how to get appliedToGroups of a *rule.
// It's provided to cache.Indexer to build an index of appliedToGroups.
func appliedToGroupIndexFunc(obj interface{}) ([]string, error) {
	rule := obj.(*rule)
	return rule.AppliedToGroups, nil
}

// policyIndexFunc knows how to get NetworkPolicy UID of a *rule.
// It's provided to cache.Indexer to build an index of NetworkPolicy.
func policyIndexFunc(obj interface{}) ([]string, error) {
	rule := obj.(*rule)
	return []string{string(rule.PolicyUID)}, nil
}

// newRuleCache returns a new *ruleCache.
func newRuleCache(dirtyRuleHandler func(string), podUpdate <-chan v1beta1.PodReference) *ruleCache {
	rules := cache.NewIndexer(
		ruleKeyFunc,
		cache.Indexers{addressGroupIndex: addressGroupIndexFunc, appliedToGroupIndex: appliedToGroupIndexFunc, policyIndex: policyIndexFunc},
	)
	cache := &ruleCache{
		podSetByGroup:     make(map[string]v1beta1.GroupMemberPodSet),
		addressSetByGroup: make(map[string]v1beta1.GroupMemberPodSet),
		policySet:         sets.NewString(),
		rules:             rules,
		dirtyRuleHandler:  dirtyRuleHandler,
		podUpdates:        podUpdate,
	}
	go cache.processPodUpdates()
	return cache
}

// processPodUpdates is an infinite loop that takes Pod update events from the
// channel, finds out AppliedToGroups that contains this Pod and trigger
// reconciling of related rules.
// It can enforce NetworkPolicies to newly added Pods right after CNI ADD is
// done if antrea-controller has computed the Pods' policies and propagated
// them to this Node by their labels and NodeName, instead of waiting for their
// IPs are reported to kube-apiserver and processed by antrea-controller.
func (c *ruleCache) processPodUpdates() {
	for {
		select {
		case pod := <-c.podUpdates:
			func() {
				memberPod := &v1beta1.GroupMemberPod{Pod: &pod}
				c.podSetLock.RLock()
				defer c.podSetLock.RUnlock()
				for group, podSet := range c.podSetByGroup {
					if podSet.Has(memberPod) {
						c.onAppliedToGroupUpdate(group)
					}
				}
			}()
		}
	}
}

// GetAddressGroupNum gets the number of AddressGroup.
func (c *ruleCache) GetAddressGroupNum() int {
	c.addressSetLock.RLock()
	defer c.addressSetLock.RUnlock()

	return len(c.addressSetByGroup)
}

// AddAddressGroup adds a new *v1beta1.AddressGroup to the cache. The rules
// referencing it will be regarded as dirty.
// It's safe to add an AddressGroup multiple times as it only overrides the
// map, this could happen when the watcher reconnects to the Apiserver.
func (c *ruleCache) AddAddressGroup(group *v1beta1.AddressGroup) error {
	c.addressSetLock.Lock()
	defer c.addressSetLock.Unlock()

	podSet := v1beta1.GroupMemberPodSet{}
	for _, pod := range group.Pods {
		podSet.Insert(&pod)
	}
	c.addressSetByGroup[group.Name] = podSet
	c.onAddressGroupUpdate(group.Name)
	return nil
}

// PatchAddressGroup updates a cached *v1beta1.AddressGroup.
// The rules referencing it will be regarded as dirty.
func (c *ruleCache) PatchAddressGroup(patch *v1beta1.AddressGroupPatch) error {
	c.addressSetLock.Lock()
	defer c.addressSetLock.Unlock()

	podSet, exists := c.addressSetByGroup[patch.Name]
	if !exists {
		return fmt.Errorf("AddressGroup %v doesn't exist in cache, can't be patched", patch.Name)
	}
	for _, pod := range patch.AddedPods {
		podSet.Insert(&pod)
	}
	for _, pod := range patch.RemovedPods {
		podSet.Delete(&pod)
	}
	c.onAddressGroupUpdate(patch.Name)
	return nil
}

// DeleteAddressGroup deletes a cached *v1beta1.AddressGroup.
// It should only happen when a group is no longer referenced by any rule, so
// no need to mark dirty rules.
func (c *ruleCache) DeleteAddressGroup(group *v1beta1.AddressGroup) error {
	c.addressSetLock.Lock()
	defer c.addressSetLock.Unlock()

	delete(c.addressSetByGroup, group.Name)
	return nil
}

// GetAppliedToGroupNum gets the number of AppliedToGroup.
func (c *ruleCache) GetAppliedToGroupNum() int {
	c.podSetLock.RLock()
	defer c.podSetLock.RUnlock()

	return len(c.podSetByGroup)
}

// AddAppliedToGroup adds a new *v1beta1.AppliedToGroup to the cache. The rules
// referencing it will be regarded as dirty.
// It's safe to add an AppliedToGroup multiple times as it only overrides the
// map, this could happen when the watcher reconnects to the Apiserver.
func (c *ruleCache) AddAppliedToGroup(group *v1beta1.AppliedToGroup) error {
	c.podSetLock.Lock()
	defer c.podSetLock.Unlock()

	podSet := v1beta1.GroupMemberPodSet{}
	for _, pod := range group.Pods {
		podSet.Insert(&pod)
	}
	c.podSetByGroup[group.Name] = podSet
	c.onAppliedToGroupUpdate(group.Name)
	return nil
}

// PatchAppliedToGroup updates a cached *v1beta1.AppliedToGroupPatch.
// The rules referencing it will be regarded as dirty.
func (c *ruleCache) PatchAppliedToGroup(patch *v1beta1.AppliedToGroupPatch) error {
	c.podSetLock.Lock()
	defer c.podSetLock.Unlock()

	podSet, exists := c.podSetByGroup[patch.Name]
	if !exists {
		return fmt.Errorf("AppliedToGroup %v doesn't exist in cache, can't be patched", patch.Name)
	}
	for _, added := range patch.AddedPods {
		podSet.Insert(&added)
	}
	for _, removed := range patch.RemovedPods {
		podSet.Delete(&removed)
	}
	c.onAppliedToGroupUpdate(patch.Name)
	return nil
}

// DeleteAppliedToGroup deletes a cached *v1beta1.AppliedToGroup.
// It should only happen when a group is no longer referenced by any rule, so
// no need to mark dirty rules.
func (c *ruleCache) DeleteAppliedToGroup(group *v1beta1.AppliedToGroup) error {
	c.podSetLock.Lock()
	defer c.podSetLock.Unlock()

	delete(c.podSetByGroup, group.Name)
	return nil
}

// toRule converts v1beta1.NetworkPolicyRule to *rule.
func toRule(r *v1beta1.NetworkPolicyRule, policy *v1beta1.NetworkPolicy) *rule {
	rule := &rule{
		Direction:       r.Direction,
		From:            r.From,
		To:              r.To,
		Services:        r.Services,
		AppliedToGroups: policy.AppliedToGroups,
		PolicyUID:       policy.UID,
	}
	rule.ID = hashRule(rule)
	return rule
}

// GetNetworkPolicyNum gets the number of NetworkPolicy.
func (c *ruleCache) GetNetworkPolicyNum() int {
	c.policySetLock.RLock()
	defer c.policySetLock.RUnlock()

	return c.policySet.Len()
}

// AddNetworkPolicy adds a new *v1beta1.NetworkPolicy to the cache.
// It could happen that an existing NetworkPolicy is "added" again when the
// watcher reconnects to the Apiserver, we use the same processing as
// UpdateNetworkPolicy to ensure orphan rules are removed.
func (c *ruleCache) AddNetworkPolicy(policy *v1beta1.NetworkPolicy) error {
	c.policySetLock.Lock()
	defer c.policySetLock.Unlock()

	c.policySet.Insert(string(policy.UID))
	return c.UpdateNetworkPolicy(policy)
}

// UpdateNetworkPolicy updates a cached *v1beta1.NetworkPolicy.
// The added rules and removed rules will be regarded as dirty.
func (c *ruleCache) UpdateNetworkPolicy(policy *v1beta1.NetworkPolicy) error {
	existingRules, _ := c.rules.ByIndex(policyIndex, string(policy.UID))
	ruleByID := map[string]interface{}{}
	for _, r := range existingRules {
		ruleByID[r.(*rule).ID] = r
	}

	for _, r := range policy.Rules {
		rule := toRule(&r, policy)
		if _, exists := ruleByID[rule.ID]; exists {
			// If rule already exists, remove it from the map so the ones left finally are orphaned.
			klog.V(2).Infof("Rule %v was not changed", rule.ID)
			delete(ruleByID, rule.ID)
		} else {
			// If rule doesn't exist, add it to cache, mark it as dirty.
			c.rules.Add(rule)
			c.dirtyRuleHandler(rule.ID)
		}
	}

	// At this moment, the remaining rules are orphaned, remove them from store and mark them as dirty.
	for ruleID, rule := range ruleByID {
		c.rules.Delete(rule)
		c.dirtyRuleHandler(ruleID)
	}
	return nil
}

// DeleteNetworkPolicy deletes a cached *v1beta1.NetworkPolicy.
// All its rules will be regarded as dirty.
func (c *ruleCache) DeleteNetworkPolicy(policy *v1beta1.NetworkPolicy) error {
	c.policySetLock.Lock()
	defer c.policySetLock.Unlock()

	c.policySet.Delete(string(policy.UID))
	existingRules, _ := c.rules.ByIndex(policyIndex, string(policy.UID))
	for _, r := range existingRules {
		ruleID := r.(*rule).ID
		c.rules.Delete(r)
		c.dirtyRuleHandler(ruleID)
	}
	return nil
}

// GetCompletedRule constructs a *CompletedRule for the provided ruleID.
// If the rule is not found or not completed due to missing group data,
// the return value will indicate it.
func (c *ruleCache) GetCompletedRule(ruleID string) (completedRule *CompletedRule, exists bool, completed bool) {
	obj, exists, _ := c.rules.GetByKey(ruleID)
	if !exists {
		return nil, false, false
	}

	r := obj.(*rule)
	var fromAddresses, toAddresses v1beta1.GroupMemberPodSet
	if r.Direction == v1beta1.DirectionIn {
		fromAddresses, completed = c.unionAddressGroups(r.From.AddressGroups)
	} else {
		toAddresses, completed = c.unionAddressGroups(r.To.AddressGroups)
	}
	if !completed {
		return nil, true, false
	}

	pods, completed := c.unionAppliedToGroups(r.AppliedToGroups)
	if !completed {
		return nil, true, false
	}

	completedRule = &CompletedRule{
		rule:          r,
		FromAddresses: fromAddresses,
		ToAddresses:   toAddresses,
		Pods:          pods,
	}
	return completedRule, true, true
}

// onAppliedToGroupUpdate gets rules referencing to the provided AppliedToGroup
// and mark them as dirty.
func (c *ruleCache) onAppliedToGroupUpdate(groupName string) {
	ruleIDs, _ := c.rules.IndexKeys(appliedToGroupIndex, groupName)
	for _, ruleID := range ruleIDs {
		c.dirtyRuleHandler(ruleID)
	}
}

// onAddressGroupUpdate gets rules referencing to the provided AddressGroup
// and mark them as dirty.
func (c *ruleCache) onAddressGroupUpdate(groupName string) {
	ruleIDs, _ := c.rules.IndexKeys(addressGroupIndex, groupName)
	for _, ruleID := range ruleIDs {
		c.dirtyRuleHandler(ruleID)
	}
}

// unionAddressGroups gets the union of addresses of the provided address groups.
// If any group is not found, nil and false will be returned to indicate the
// set is not complete yet.
func (c *ruleCache) unionAddressGroups(groupNames []string) (v1beta1.GroupMemberPodSet, bool) {
	c.addressSetLock.RLock()
	defer c.addressSetLock.RUnlock()

	set := v1beta1.NewGroupMemberPodSet()
	for _, groupName := range groupNames {
		curSet, exists := c.addressSetByGroup[groupName]
		if !exists {
			klog.V(2).Infof("AddressGroup %v was not found", groupName)
			return nil, false
		}
		set = set.Union(curSet)
	}
	return set, true
}

// unionAppliedToGroups gets the union of pods of the provided appliedTo groups.
// If any group is not found, nil and false will be returned to indicate the
// set is not complete yet.
func (c *ruleCache) unionAppliedToGroups(groupNames []string) (v1beta1.GroupMemberPodSet, bool) {
	c.podSetLock.RLock()
	defer c.podSetLock.RUnlock()

	set := v1beta1.NewGroupMemberPodSet()
	for _, groupName := range groupNames {
		curSet, exists := c.podSetByGroup[groupName]
		if !exists {
			klog.V(2).Infof("AppliedToGroup %v was not found", groupName)
			return nil, false
		}
		set = set.Union(curSet)
	}
	return set, true
}
