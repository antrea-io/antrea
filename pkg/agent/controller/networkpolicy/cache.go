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
	"crypto/sha1" // #nosec G505: not used for security purposes
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/metrics"
	"github.com/vmware-tanzu/antrea/pkg/apis/controlplane/v1beta1"
	secv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/security/v1alpha1"
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
//    can know the existing rules don't change and skip processing them. Note that
//    if a CNP/ANP rule's position (from top down) within a networkpolicy changes, it
//    affects the Priority of the rule.
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
	// Action of this rule. nil for k8s NetworkPolicy.
	Action *secv1alpha1.RuleAction
	// Priority of this rule within the NetworkPolicy. Defaults to -1 for K8s NetworkPolicy.
	Priority int32
	// Priority of the NetworkPolicy to which this rule belong. nil for K8s NetworkPolicy.
	PolicyPriority *float64
	// Priority of the tier that the NetworkPolicy belongs to. nil for K8s NetworkPolicy.
	TierPriority *v1beta1.TierPriority
	// Targets of this rule.
	AppliedToGroups []string
	// The parent Policy ID. Used to identify rules belong to a specified
	// policy for deletion.
	PolicyUID types.UID
	// The metadata of parent Policy. Used to associate the rule with Policy
	// for troubleshooting purpose (logging and CLI).
	PolicyName string
	// PolicyNamespace is empty for ClusterNetworkPolicy.
	PolicyNamespace string
}

// hashRule calculates a string based on the rule's content.
func hashRule(r *rule) string {
	hash := sha1.New() // #nosec G401: not used for security purposes
	b, _ := json.Marshal(r)
	hash.Write(b)
	hashValue := hex.EncodeToString(hash.Sum(nil))
	return hashValue[:RuleIDLength]
}

// CompletedRule contains IPAddresses and Pods flattened from AddressGroups and AppliedToGroups.
// It's the struct used by reconciler.
type CompletedRule struct {
	*rule
	// Source GroupMembers of this rule, can't coexist with ToAddresses.
	FromAddresses v1beta1.GroupMemberSet
	// Destination GroupMembers of this rule, can't coexist with FromAddresses.
	ToAddresses v1beta1.GroupMemberSet
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
	return fmt.Sprintf("%s (Direction: %v, Pods: %d, %s, Services: %d, PolicyPriority: %v, RulePriority: %v)",
		r.ID, r.Direction, len(r.Pods), addressString, len(r.Services), r.PolicyPriority, r.Priority)
}

// isAntreaNetworkPolicyRule returns true if the rule is part of a ClusterNetworkPolicy.
func (r *CompletedRule) isAntreaNetworkPolicyRule() bool {
	return r.PolicyPriority != nil
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
	// It is a mapping from group name to a set of GroupMembers.
	addressSetByGroup map[string]v1beta1.GroupMemberSet

	policyMapLock sync.RWMutex
	// policyMap is a map using NetworkPolicy UID as the key.
	policyMap map[string]*types.NamespacedName

	// rules is a storage that supports listing rules using multiple indexing functions.
	// rules is thread-safe.
	rules cache.Indexer
	// dirtyRuleHandler is a callback that is run upon finding a rule out-of-sync.
	dirtyRuleHandler func(string)

	// podUpdates is a channel for receiving Pod updates from CNIServer.
	podUpdates <-chan v1beta1.PodReference
}

func (c *ruleCache) getNetworkPolicies(namespace string) []v1beta1.NetworkPolicy {
	ret := []v1beta1.NetworkPolicy{}
	c.policyMapLock.RLock()
	defer c.policyMapLock.RUnlock()
	for uid, np := range c.policyMap {
		if namespace == "" || np.Namespace == namespace {
			ret = append(ret, *c.buildNetworkPolicyFromRules(uid))
		}
	}
	return ret
}

// getNetworkPolicy looks up and returns the cached NetworkPolicy.
// nil is returned if the specified NetworkPolicy is not found.
func (c *ruleCache) getNetworkPolicy(npName, npNamespace string) *v1beta1.NetworkPolicy {
	var npUID string
	c.policyMapLock.Lock()
	defer c.policyMapLock.Unlock()
	for uid, np := range c.policyMap {
		if np.Name == npName && np.Namespace == npNamespace {
			npUID = uid
			break
		}
	}

	if npUID == "" {
		// NetworkPolicy not found.
		return nil
	}
	return c.buildNetworkPolicyFromRules(npUID)
}

func (c *ruleCache) buildNetworkPolicyFromRules(uid string) *v1beta1.NetworkPolicy {
	var np *v1beta1.NetworkPolicy
	rules, _ := c.rules.ByIndex(policyIndex, uid)
	// Sort the rules by priority
	sort.Slice(rules, func(i, j int) bool {
		r1 := rules[i].(*rule)
		r2 := rules[j].(*rule)
		return r1.Priority < r2.Priority
	})
	for _, ruleObj := range rules {
		np = addRuleToNetworkPolicy(np, ruleObj.(*rule))
	}
	return np
}

// addRuleToNetworkPolicy adds a cached rule to the passed NetworkPolicy struct
// and returns it. If np is nil, a new NetworkPolicy struct will be created.
func addRuleToNetworkPolicy(np *v1beta1.NetworkPolicy, rule *rule) *v1beta1.NetworkPolicy {
	if np == nil {
		np = &v1beta1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{UID: rule.PolicyUID,
				Name:      rule.PolicyName,
				Namespace: rule.PolicyNamespace},
			AppliedToGroups: rule.AppliedToGroups,
			Priority:        rule.PolicyPriority,
			TierPriority:    rule.TierPriority,
		}
	}
	np.Rules = append(np.Rules, v1beta1.NetworkPolicyRule{
		Direction: rule.Direction,
		From:      rule.From,
		To:        rule.To,
		Services:  rule.Services,
		Action:    rule.Action,
		Priority:  rule.Priority})
	return np

}

func (c *ruleCache) getAppliedNetworkPolicies(pod, namespace string) []v1beta1.NetworkPolicy {
	var groups []string
	memberPod := &v1beta1.GroupMemberPod{Pod: &v1beta1.PodReference{Name: pod, Namespace: namespace}}
	c.podSetLock.RLock()
	for group, podSet := range c.podSetByGroup {
		if podSet.Has(memberPod) {
			groups = append(groups, group)
		}
	}
	c.podSetLock.RUnlock()

	npMap := make(map[string]*v1beta1.NetworkPolicy)
	for _, group := range groups {
		rules, _ := c.rules.ByIndex(appliedToGroupIndex, group)
		for _, ruleObj := range rules {
			rule := ruleObj.(*rule)
			np, ok := npMap[string(rule.PolicyUID)]
			np = addRuleToNetworkPolicy(np, rule)
			if !ok {
				// First rule for this NetworkPolicy
				npMap[string(rule.PolicyUID)] = np
			}
		}
	}

	ret := make([]v1beta1.NetworkPolicy, 0, len(npMap))
	for _, np := range npMap {
		ret = append(ret, *np)
	}
	return ret
}

func (c *ruleCache) GetAddressGroups() []v1beta1.AddressGroup {
	var ret []v1beta1.AddressGroup
	c.addressSetLock.RLock()
	defer c.addressSetLock.RUnlock()

	for k, v := range c.addressSetByGroup {
		var pods []v1beta1.GroupMemberPod
		var groupMembers []v1beta1.GroupMember
		for _, member := range v {
			if member.Pod != nil {
				pods = append(pods, *member.ToGroupMemberPod())
			} else if member.ExternalEntity != nil {
				groupMembers = append(groupMembers, *member)
			}
		}
		ret = append(ret, v1beta1.AddressGroup{
			ObjectMeta:   metav1.ObjectMeta{Name: k},
			Pods:         pods,
			GroupMembers: groupMembers,
		})
	}
	return ret
}

func (c *ruleCache) GetAppliedToGroups() []v1beta1.AppliedToGroup {
	var ret []v1beta1.AppliedToGroup
	c.podSetLock.RLock()
	defer c.podSetLock.RUnlock()
	for k, v := range c.podSetByGroup {
		var pods []v1beta1.GroupMemberPod
		for _, pod := range v.Items() {
			pods = append(pods, *pod)
		}
		ret = append(ret, v1beta1.AppliedToGroup{
			ObjectMeta: metav1.ObjectMeta{Name: k},
			Pods:       pods,
		})
	}
	return ret
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
		addressSetByGroup: make(map[string]v1beta1.GroupMemberSet),
		policyMap:         make(map[string]*types.NamespacedName),
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

// ReplaceAddressGroups atomically adds the given groups to the cache and deletes
// the pre-existing groups that are not in the given groups from the cache.
// It makes the cache in sync with the apiserver when restarting a watch.
func (c *ruleCache) ReplaceAddressGroups(groups []*v1beta1.AddressGroup) {
	c.addressSetLock.Lock()
	defer c.addressSetLock.Unlock()

	oldGroupKeys := make(sets.String, len(c.addressSetByGroup))
	for key := range c.addressSetByGroup {
		oldGroupKeys.Insert(key)
	}

	for _, group := range groups {
		oldGroupKeys.Delete(group.Name)
		c.addAddressGroupLocked(group)
	}

	for key := range oldGroupKeys {
		delete(c.addressSetByGroup, key)
	}
	return
}

// AddAddressGroup adds a new *v1beta1.AddressGroup to the cache. The rules
// referencing it will be regarded as dirty.
// It's safe to add an AddressGroup multiple times as it only overrides the
// map, this could happen when the watcher reconnects to the Apiserver.
func (c *ruleCache) AddAddressGroup(group *v1beta1.AddressGroup) error {
	c.addressSetLock.Lock()
	defer c.addressSetLock.Unlock()

	return c.addAddressGroupLocked(group)
}

func (c *ruleCache) addAddressGroupLocked(group *v1beta1.AddressGroup) error {
	groupMemberSet := v1beta1.GroupMemberSet{}
	for i := range group.Pods {
		// Must not store address of loop iterator variable as it's the same
		// address taking different values in each loop iteration, otherwise
		// groupMemberSet would eventually contain only the last value.
		// https://github.com/golang/go/wiki/CommonMistakes#using-reference-to-loop-iterator-variable
		groupMemberSet.Insert(group.Pods[i].ToGroupMember())
	}
	for i := range group.GroupMembers {
		groupMemberSet.Insert(&group.GroupMembers[i])
	}

	oldGroupMemberSet, exists := c.addressSetByGroup[group.Name]
	if exists && oldGroupMemberSet.Equal(groupMemberSet) {
		return nil
	}
	c.addressSetByGroup[group.Name] = groupMemberSet
	c.onAddressGroupUpdate(group.Name)
	return nil
}

// PatchAddressGroup updates a cached *v1beta1.AddressGroup.
// The rules referencing it will be regarded as dirty.
func (c *ruleCache) PatchAddressGroup(patch *v1beta1.AddressGroupPatch) error {
	c.addressSetLock.Lock()
	defer c.addressSetLock.Unlock()

	groupMemberSet, exists := c.addressSetByGroup[patch.Name]
	if !exists {
		return fmt.Errorf("AddressGroup %v doesn't exist in cache, can't be patched", patch.Name)
	}
	for i := range patch.AddedPods {
		groupMemberSet.Insert(patch.AddedPods[i].ToGroupMember())
	}
	for i := range patch.RemovedPods {
		groupMemberSet.Delete(patch.RemovedPods[i].ToGroupMember())
	}
	for i := range patch.AddedGroupMembers {
		groupMemberSet.Insert(&patch.AddedGroupMembers[i])
	}
	for i := range patch.RemovedGroupMembers {
		groupMemberSet.Delete(&patch.RemovedGroupMembers[i])
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

// ReplaceAppliedToGroups atomically adds the given groups to the cache and deletes
// the pre-existing groups that are not in the given groups from the cache.
// It makes the cache in sync with the apiserver when restarting a watch.
func (c *ruleCache) ReplaceAppliedToGroups(groups []*v1beta1.AppliedToGroup) {
	c.podSetLock.Lock()
	defer c.podSetLock.Unlock()

	oldGroupKeys := make(sets.String, len(c.podSetByGroup))
	for key := range c.podSetByGroup {
		oldGroupKeys.Insert(key)
	}

	for _, group := range groups {
		oldGroupKeys.Delete(group.Name)
		c.addAppliedToGroupLocked(group)
	}

	for key := range oldGroupKeys {
		delete(c.podSetByGroup, key)
	}
	return
}

// AddAppliedToGroup adds a new *v1beta1.AppliedToGroup to the cache. The rules
// referencing it will be regarded as dirty.
// It's safe to add an AppliedToGroup multiple times as it only overrides the
// map, this could happen when the watcher reconnects to the Apiserver.
func (c *ruleCache) AddAppliedToGroup(group *v1beta1.AppliedToGroup) error {
	c.podSetLock.Lock()
	defer c.podSetLock.Unlock()

	return c.addAppliedToGroupLocked(group)
}

func (c *ruleCache) addAppliedToGroupLocked(group *v1beta1.AppliedToGroup) error {
	podSet := v1beta1.GroupMemberPodSet{}
	for i := range group.Pods {
		podSet.Insert(&group.Pods[i])
	}
	oldPodSet, exists := c.podSetByGroup[group.Name]
	if exists && oldPodSet.Equal(podSet) {
		return nil
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
	for i := range patch.AddedPods {
		podSet.Insert(&patch.AddedPods[i])
	}
	for i := range patch.RemovedPods {
		podSet.Delete(&patch.RemovedPods[i])
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
		Action:          r.Action,
		Priority:        r.Priority,
		PolicyPriority:  policy.Priority,
		TierPriority:    policy.TierPriority,
		AppliedToGroups: policy.AppliedToGroups,
		PolicyUID:       policy.UID,
	}
	rule.ID = hashRule(rule)
	rule.PolicyNamespace = policy.Namespace
	rule.PolicyName = policy.Name
	return rule
}

// GetNetworkPolicyNum gets the number of NetworkPolicy.
func (c *ruleCache) GetNetworkPolicyNum() int {
	c.policyMapLock.RLock()
	defer c.policyMapLock.RUnlock()

	return len(c.policyMap)
}

// ReplaceNetworkPolicies atomically adds the given policies to the cache and deletes
// the pre-existing policies that are not in the given policies from the cache.
// It makes the cache in sync with the apiserver when restarting a watch.
func (c *ruleCache) ReplaceNetworkPolicies(policies []*v1beta1.NetworkPolicy) {
	c.policyMapLock.Lock()
	defer c.policyMapLock.Unlock()

	oldKeys := make(sets.String, len(c.policyMap))
	for key := range c.policyMap {
		oldKeys.Insert(key)
	}

	for i := range policies {
		oldKeys.Delete(string(policies[i].UID))
		c.addNetworkPolicyLocked(policies[i])
	}

	for key := range oldKeys {
		c.deleteNetworkPolicyLocked(key)
	}
	return
}

// AddNetworkPolicy adds a new *v1beta1.NetworkPolicy to the cache.
// It could happen that an existing NetworkPolicy is "added" again when the
// watcher reconnects to the Apiserver, we use the same processing as
// UpdateNetworkPolicy to ensure orphan rules are removed.
func (c *ruleCache) AddNetworkPolicy(policy *v1beta1.NetworkPolicy) error {
	c.policyMapLock.Lock()
	defer c.policyMapLock.Unlock()

	return c.addNetworkPolicyLocked(policy)
}

func (c *ruleCache) addNetworkPolicyLocked(policy *v1beta1.NetworkPolicy) error {
	c.policyMap[string(policy.UID)] = &types.NamespacedName{Namespace: policy.Namespace, Name: policy.Name}
	metrics.NetworkPolicyCount.Inc()
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

	for i := range policy.Rules {
		r := toRule(&policy.Rules[i], policy)
		if _, exists := ruleByID[r.ID]; exists {
			// If rule already exists, remove it from the map so the ones left finally are orphaned.
			klog.V(2).Infof("Rule %v was not changed", r.ID)
			delete(ruleByID, r.ID)
		} else {
			// If rule doesn't exist, add it to cache, mark it as dirty.
			c.rules.Add(r)
			// Count up antrea_agent_ingress_networkpolicy_rule_count or antrea_agent_egress_networkpolicy_rule_count
			if r.Direction == v1beta1.DirectionIn {
				metrics.IngressNetworkPolicyRuleCount.Inc()
			} else {
				metrics.EgressNetworkPolicyRuleCount.Inc()
			}
			c.dirtyRuleHandler(r.ID)
		}
	}

	// At this moment, the remaining rules are orphaned, remove them from store and mark them as dirty.
	for ruleID, r := range ruleByID {
		c.rules.Delete(r)
		// Count down antrea_agent_ingress_networkpolicy_rule_count or antrea_agent_egress_networkpolicy_rule_count
		if r.(*rule).Direction == v1beta1.DirectionIn {
			metrics.IngressNetworkPolicyRuleCount.Dec()
		} else {
			metrics.EgressNetworkPolicyRuleCount.Dec()
		}
		c.dirtyRuleHandler(ruleID)
	}
	return nil
}

// DeleteNetworkPolicy deletes a cached *v1beta1.NetworkPolicy.
// All its rules will be regarded as dirty.
func (c *ruleCache) DeleteNetworkPolicy(policy *v1beta1.NetworkPolicy) error {
	c.policyMapLock.Lock()
	defer c.policyMapLock.Unlock()

	return c.deleteNetworkPolicyLocked(string(policy.UID))
}

func (c *ruleCache) deleteNetworkPolicyLocked(uid string) error {
	delete(c.policyMap, uid)
	existingRules, _ := c.rules.ByIndex(policyIndex, uid)
	for _, r := range existingRules {
		ruleID := r.(*rule).ID
		// Count down antrea_agent_ingress_networkpolicy_rule_count or antrea_agent_egress_networkpolicy_rule_count
		if r.(*rule).Direction == v1beta1.DirectionIn {
			metrics.IngressNetworkPolicyRuleCount.Dec()
		} else {
			metrics.EgressNetworkPolicyRuleCount.Dec()
		}
		c.rules.Delete(r)
		c.dirtyRuleHandler(ruleID)
	}
	metrics.NetworkPolicyCount.Dec()
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
	var fromAddresses, toAddresses v1beta1.GroupMemberSet
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
func (c *ruleCache) unionAddressGroups(groupNames []string) (v1beta1.GroupMemberSet, bool) {
	c.addressSetLock.RLock()
	defer c.addressSetLock.RUnlock()

	set := v1beta1.NewGroupMemberSet()
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
