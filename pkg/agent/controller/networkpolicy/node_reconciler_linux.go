//go:build linux
// +build linux

// Copyright 2024 Antrea Authors
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
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/route"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/agent/util/iptables"
	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	secv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/pkg/util/ip"
)

const (
	ipv4Any = "0.0.0.0/0"
	ipv6Any = "::/0"
)

/*
Tips:
In the following, service describes a port to allow traffic on which is defined in pkg/apis/controlplane/v1beta2/types.go

NodeNetworkPolicy data path implementation using iptables/ip6tables involves four components:
1. Core iptables rule:
   - Added to ANTREA-POL-INGRESS-RULES (ingress) or ANTREA-POL-EGRESS-RULES (egress).
   - Matches an ipset created for the NodeNetworkPolicy rule as source (ingress) or destination (egress) when there are
     multiple IP addresses; if there is only one address, matches the address directly.
   - Targets an action (the rule with a single service) or a service chain created for the NodeNetworkPolicy rule (the
     rule with multiple services).
2. Service iptables chain:
   - Created for the NodeNetworkPolicy rule to integrate service iptables rules if a rule has multiple services.
3. Service iptables rules:
   - Added to the service chain created for the NodeNetworkPolicy rule.
   - Constructed from the services of the NodeNetworkPolicy rule.
4. From/To ipset:
   - Created for the NodeNetworkPolicy rule, containing all source IP addresses (ingress) or destination IP addresses (egress).

Assuming four ingress NodeNetworkPolicy rules with IDs RULE1, RULE2, RULE3 and RULE4 prioritized in descending order.
Core iptables rules organized by priorities in ANTREA-POL-INGRESS-RULES like the following.

If the rule has multiple source IP addresses to match, then an ipset will be created for it. The name of the ipset consists
of prefix "ANTREA-POL", rule ID and IP protocol version.

If the rule has multiple services, an iptables chain and related rules will be created for it. The name the chain consists
of prefix "ANTREA-POL" and rule ID.

```
:ANTREA-POL-INGRESS-RULES
-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-RULE1-4 src -j ANTREA-POL-RULE1 -m comment --comment "Antrea: for rule RULE1, policy AntreaClusterNetworkPolicy:name1"
-A ANTREA-POL-INGRESS-RULES -m set --match-set ANTREA-POL-RULE2-4 src -p tcp --dport 8080 -j ACCEPT -m comment --comment "Antrea: for rule RULE2, policy AntreaClusterNetworkPolicy:name2"
-A ANTREA-POL-INGRESS-RULES -s 3.3.3.3/32 src -j ANTREA-POL-RULE3 -m comment --comment "Antrea: for rule RULE3, policy AntreaClusterNetworkPolicy:name3"
-A ANTREA-POL-INGRESS-RULES -s 4.4.4.4/32 -p tcp --dport 80 -j ACCEPT -m comment --comment "Antrea: for rule RULE4, policy AntreaClusterNetworkPolicy:name4"
```

For the first rule, it has multiple services and multiple source IP addresses to match, so there will be service iptables chain
and service iptables rules and ipset created for it.

The iptables chain is like the following:

```
:ANTREA-POL-RULE1
-A ANTREA-POL-RULE1 -j ACCEPT -p tcp --dport 80
-A ANTREA-POL-RULE1 -j ACCEPT -p tcp --dport 443
```

The ipset is like the following:

```
Name: ANTREA-POL-RULE1-4
Type: hash:net
Revision: 6
Header: family inet hashsize 1024 maxelem 65536
Size in memory: 472
References: 1
Number of entries: 2
Members:
1.1.1.1
1.1.1.2
```

For the second rule, it has only one service, so there will be no service iptables chain and service iptables rules created
for it. The core rule will match the service and target the action directly. The rule has multiple source IP addresses to
match, so there will be an ipset `ANTREA-POL-RULE2-4` created for it.

For the third rule, it has multiple services to match, so there will be service iptables chain and service iptables rules
created for it. The rule has only one source IP address to match, so there will be no ipset created for it and just match
the source IP address directly.

For the fourth rule, it has only one service and one source IP address to match, so there will be no service iptables chain
and service iptables rules created for it. The core rule will match the service and source IP address and target the action
directly.
*/

// coreIPTRule is a struct to store the information of a core iptables rule.
type coreIPTRule struct {
	ruleID   string
	priority *types.Priority
	ruleStr  string
}

type chainKey struct {
	name   string
	isIPv6 bool
}

func newChainKey(name string, isIPv6 bool) chainKey {
	return chainKey{
		name:   name,
		isIPv6: isIPv6,
	}
}

// coreIPTChain caches the sorted iptables rules for a chain where core iptables rules are installed.
type coreIPTChain struct {
	rules []*coreIPTRule
	sync.Mutex
}

func newCoreIPTChain() *coreIPTChain {
	return &coreIPTChain{}
}

// nodePolicyLastRealized is the struct cached by nodeReconciler. It's used to track the actual state of iptables rules
// and chains we have enforced, so that we can know how to reconcile a rule when it's updated/removed.
type nodePolicyLastRealized struct {
	// ipsets tracks the last realized ipset names used in core iptables rules. It cannot coexist with ipnets.
	ipsets map[iptables.Protocol]string
	// ipnets tracks the last realized ip nets used in core iptables rules. It cannot coexist with ipsets.
	ipnets map[iptables.Protocol]string
	// serviceIPTChain tracks the last realized service iptables chain if a rule has multiple services.
	serviceIPTChain string
	// coreIPTChain tracks the last realized iptables chain where the core iptables rule is installed.
	coreIPTChain string
}

func newNodePolicyLastRealized() *nodePolicyLastRealized {
	return &nodePolicyLastRealized{
		ipsets: make(map[iptables.Protocol]string),
		ipnets: make(map[iptables.Protocol]string),
	}
}

type nodeReconciler struct {
	ipProtocols   []iptables.Protocol
	routeClient   route.Interface
	coreIPTChains map[chainKey]*coreIPTChain
	// lastRealizeds caches the last realized rules. It's a mapping from ruleID to *nodePolicyLastRealized.
	lastRealizeds sync.Map
}

func newNodeReconciler(routeClient route.Interface, ipv4Enabled, ipv6Enabled bool) *nodeReconciler {
	var ipProtocols []iptables.Protocol
	coreIPTChains := make(map[chainKey]*coreIPTChain)

	if ipv4Enabled {
		ipProtocols = append(ipProtocols, iptables.ProtocolIPv4)
		coreIPTChains[newChainKey(config.NodeNetworkPolicyIngressRulesChain, false)] = newCoreIPTChain()
		coreIPTChains[newChainKey(config.NodeNetworkPolicyEgressRulesChain, false)] = newCoreIPTChain()
	}
	if ipv6Enabled {
		ipProtocols = append(ipProtocols, iptables.ProtocolIPv6)
		coreIPTChains[newChainKey(config.NodeNetworkPolicyIngressRulesChain, true)] = newCoreIPTChain()
		coreIPTChains[newChainKey(config.NodeNetworkPolicyEgressRulesChain, true)] = newCoreIPTChain()
	}

	return &nodeReconciler{
		ipProtocols:   ipProtocols,
		routeClient:   routeClient,
		coreIPTChains: coreIPTChains,
	}
}

// Reconcile checks whether the provided rule has been enforced or not, and invoke the add or update method accordingly.
func (r *nodeReconciler) Reconcile(rule *CompletedRule) error {
	klog.InfoS("Reconciling Node NetworkPolicy rule", "rule", rule.ID, "policy", rule.SourceRef.ToString())

	value, exists := r.lastRealizeds.Load(rule.ID)
	var err error
	if !exists {
		err = r.add(rule)
	} else {
		err = r.update(value.(*nodePolicyLastRealized), rule)
	}
	return err
}

func (r *nodeReconciler) RunIDAllocatorWorker(stopCh <-chan struct{}) {

}

func (r *nodeReconciler) BatchReconcile(rules []*CompletedRule) error {
	var rulesToInstall []*CompletedRule
	for _, rule := range rules {
		if _, exists := r.lastRealizeds.Load(rule.ID); exists {
			klog.ErrorS(nil, "Rule should not have been realized yet: initialization phase", "rule", rule.ID)
		} else {
			rulesToInstall = append(rulesToInstall, rule)
		}
	}
	if err := r.batchAdd(rulesToInstall); err != nil {
		return err
	}
	return nil
}

func (r *nodeReconciler) batchAdd(rules []*CompletedRule) error {
	lastRealizeds := make(map[string]*nodePolicyLastRealized)
	serviceIPTChains := make(map[iptables.Protocol][]string)
	serviceIPTRules := make(map[iptables.Protocol][][]string)
	ingressCoreIPTRules := make(map[iptables.Protocol][]*coreIPTRule)
	egressCoreIPTRules := make(map[iptables.Protocol][]*coreIPTRule)

	for _, rule := range rules {
		iptRules, lastRealized := r.computeIPTRules(rule)
		ruleID := rule.ID
		for ipProtocol, iptRule := range iptRules {
			// Sync all ipsets.
			if iptRule.IPSet != "" {
				if err := r.routeClient.AddOrUpdateNodeNetworkPolicyIPSet(iptRule.IPSet, iptRule.IPSetMembers, iptRule.IsIPv6); err != nil {
					return err
				}
			}
			// Collect all service iptables rules and chains.
			if iptRule.ServiceIPTChain != "" {
				serviceIPTChains[ipProtocol] = append(serviceIPTChains[ipProtocol], iptRule.ServiceIPTChain)
				serviceIPTRules[ipProtocol] = append(serviceIPTRules[ipProtocol], iptRule.ServiceIPTRules)
			}

			// Collect all core iptables rules.
			coreIPTRule := &coreIPTRule{ruleID, iptRule.Priority, iptRule.CoreIPTRule}
			if rule.Direction == v1beta2.DirectionIn {
				ingressCoreIPTRules[ipProtocol] = append(ingressCoreIPTRules[ipProtocol], coreIPTRule)
			} else {
				egressCoreIPTRules[ipProtocol] = append(egressCoreIPTRules[ipProtocol], coreIPTRule)
			}
		}
		lastRealizeds[ruleID] = lastRealized
	}
	for _, ipProtocol := range r.ipProtocols {
		isIPv6 := iptables.IsIPv6Protocol(ipProtocol)
		if err := r.routeClient.AddOrUpdateNodeNetworkPolicyIPTables(serviceIPTChains[ipProtocol], serviceIPTRules[ipProtocol], isIPv6); err != nil {
			return err
		}
		if err := r.addOrUpdateCoreIPTRules(config.NodeNetworkPolicyIngressRulesChain, isIPv6, false, ingressCoreIPTRules[ipProtocol]...); err != nil {
			return err
		}
		if err := r.addOrUpdateCoreIPTRules(config.NodeNetworkPolicyEgressRulesChain, isIPv6, false, egressCoreIPTRules[ipProtocol]...); err != nil {
			return err
		}
	}

	for ruleID, lastRealized := range lastRealizeds {
		r.lastRealizeds.Store(ruleID, lastRealized)
	}
	return nil
}

func (r *nodeReconciler) Forget(ruleID string) error {
	klog.InfoS("Forgetting rule", "rule", ruleID)

	value, exists := r.lastRealizeds.Load(ruleID)
	if !exists {
		return nil
	}

	lastRealized := value.(*nodePolicyLastRealized)
	coreIPTChain := lastRealized.coreIPTChain

	for _, ipProtocol := range r.ipProtocols {
		isIPv6 := iptables.IsIPv6Protocol(ipProtocol)
		if err := r.deleteCoreIPTRule(ruleID, coreIPTChain, isIPv6); err != nil {
			return err
		}
		if lastRealized.ipsets[ipProtocol] != "" {
			if err := r.routeClient.DeleteNodeNetworkPolicyIPSet(lastRealized.ipsets[ipProtocol], isIPv6); err != nil {
				return err
			}
		}
		if lastRealized.serviceIPTChain != "" {
			if err := r.routeClient.DeleteNodeNetworkPolicyIPTables([]string{lastRealized.serviceIPTChain}, isIPv6); err != nil {
				return err
			}
		}
	}

	r.lastRealizeds.Delete(ruleID)
	return nil
}

func (r *nodeReconciler) GetRuleByFlowID(ruleFlowID uint32) (*types.PolicyRule, bool, error) {
	return nil, false, nil
}

func (r *nodeReconciler) computeIPTRules(rule *CompletedRule) (map[iptables.Protocol]*types.NodePolicyRule, *nodePolicyLastRealized) {
	ruleID := rule.ID
	lastRealized := newNodePolicyLastRealized()
	priority := &types.Priority{
		TierPriority:   *rule.TierPriority,
		PolicyPriority: *rule.PolicyPriority,
		RulePriority:   rule.Priority,
	}

	var serviceIPTChain, serviceIPTRuleTarget, coreIPTRuleTarget string
	var service *v1beta2.Service
	if len(rule.Services) > 1 {
		// If a rule has multiple services, create a chain to install iptables rules for these services, with the target
		// of the services determined by the rule's action. The core iptables rule should target the chain.
		serviceIPTChain = fmt.Sprintf("%s-%s", config.NodeNetworkPolicyPrefix, strings.ToUpper(ruleID))
		serviceIPTRuleTarget = ruleActionToIPTTarget(rule.Action)
		coreIPTRuleTarget = serviceIPTChain
		lastRealized.serviceIPTChain = serviceIPTChain
	} else {
		// If a rule has no service or a single service, the target is determined by the rule's action, as there is no
		// need to create a chain for a single-service iptables rule.
		coreIPTRuleTarget = ruleActionToIPTTarget(rule.Action)
		// If a rule has a single service, the core iptables rule directly incorporates the service.
		if len(rule.Services) == 1 {
			service = &rule.Services[0]
		}
	}
	var coreIPTChain string
	if rule.Direction == v1beta2.DirectionIn {
		coreIPTChain = config.NodeNetworkPolicyIngressRulesChain
	} else {
		coreIPTChain = config.NodeNetworkPolicyEgressRulesChain
	}
	coreIPTRuleComment := fmt.Sprintf("Antrea: for rule %s, policy %s", ruleID, rule.SourceRef.ToString())
	lastRealized.coreIPTChain = coreIPTChain

	nodePolicyRules := make(map[iptables.Protocol]*types.NodePolicyRule)
	for _, ipProtocol := range r.ipProtocols {
		isIPv6 := iptables.IsIPv6Protocol(ipProtocol)

		var serviceIPTRules []string
		if serviceIPTChain != "" {
			serviceIPTRules = buildServiceIPTRules(ipProtocol, rule.Services, serviceIPTChain, serviceIPTRuleTarget)
		}

		ipnets := getIPNetsFromRule(rule, isIPv6)
		var ipnet string
		var ipset string
		if ipnets.Len() > 1 {
			// If a rule matches multiple source or destination ipnets, create an ipset which contains these ipnets and
			// use the ipset in core iptables rule.
			suffix := "4"
			if isIPv6 {
				suffix = "6"
			}
			ipset = fmt.Sprintf("%s-%s-%s", config.NodeNetworkPolicyPrefix, strings.ToUpper(ruleID), suffix)
			lastRealized.ipsets[ipProtocol] = ipset
		} else if ipnets.Len() == 1 {
			// If a rule matches single source or destination, use it in core iptables rule directly.
			ipnet, _ = ipnets.PopAny()
			lastRealized.ipnets[ipProtocol] = ipnet
		}

		coreIPTRule := buildCoreIPTRule(ipProtocol,
			coreIPTChain,
			ipset,
			ipnet,
			coreIPTRuleTarget,
			coreIPTRuleComment,
			service,
			rule.Direction == v1beta2.DirectionIn)

		nodePolicyRules[ipProtocol] = &types.NodePolicyRule{
			IPSet:           ipset,
			IPSetMembers:    ipnets,
			Priority:        priority,
			ServiceIPTChain: serviceIPTChain,
			ServiceIPTRules: serviceIPTRules,
			CoreIPTChain:    coreIPTChain,
			CoreIPTRule:     coreIPTRule,
			IsIPv6:          isIPv6,
		}
	}

	return nodePolicyRules, lastRealized
}

func (r *nodeReconciler) add(rule *CompletedRule) error {
	klog.V(2).InfoS("Adding new rule", "rule", rule)
	ruleID := rule.ID
	iptRules, lastRealized := r.computeIPTRules(rule)
	for _, iptRule := range iptRules {
		if iptRule.IPSet != "" {
			if err := r.routeClient.AddOrUpdateNodeNetworkPolicyIPSet(iptRule.IPSet, iptRule.IPSetMembers, iptRule.IsIPv6); err != nil {
				return err
			}
		}
		if iptRule.ServiceIPTChain != "" {
			if err := r.routeClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{iptRule.ServiceIPTChain}, [][]string{iptRule.ServiceIPTRules}, iptRule.IsIPv6); err != nil {
				return err
			}
		}
		if err := r.addOrUpdateCoreIPTRules(iptRule.CoreIPTChain, iptRule.IsIPv6, false, &coreIPTRule{ruleID, iptRule.Priority, iptRule.CoreIPTRule}); err != nil {
			return err
		}
	}
	r.lastRealizeds.Store(ruleID, lastRealized)
	return nil
}

func (r *nodeReconciler) update(lastRealized *nodePolicyLastRealized, newRule *CompletedRule) error {
	klog.V(2).InfoS("Updating existing rule", "rule", newRule)
	ruleID := newRule.ID
	newIPTRules, newLastRealized := r.computeIPTRules(newRule)

	for _, ipProtocol := range r.ipProtocols {
		iptRule := newIPTRules[ipProtocol]

		prevIPNet := lastRealized.ipnets[ipProtocol]
		ipnet := newLastRealized.ipnets[ipProtocol]
		prevIPSet := lastRealized.ipsets[ipProtocol]
		ipset := newLastRealized.ipsets[ipProtocol]

		if ipset != "" {
			if err := r.routeClient.AddOrUpdateNodeNetworkPolicyIPSet(iptRule.IPSet, iptRule.IPSetMembers, iptRule.IsIPv6); err != nil {
				return err
			}
		} else if prevIPSet != "" {
			if err := r.routeClient.DeleteNodeNetworkPolicyIPSet(lastRealized.ipsets[ipProtocol], iptRule.IsIPv6); err != nil {
				return err
			}
		}
		if prevIPSet != ipset || prevIPNet != ipnet {
			if err := r.addOrUpdateCoreIPTRules(iptRule.CoreIPTChain, iptRule.IsIPv6, true, &coreIPTRule{ruleID, iptRule.Priority, iptRule.CoreIPTRule}); err != nil {
				return err
			}
		}
	}

	r.lastRealizeds.Store(ruleID, newLastRealized)
	return nil
}

func (r *nodeReconciler) addOrUpdateCoreIPTRules(chain string, isIPv6 bool, isUpdate bool, newRules ...*coreIPTRule) error {
	if len(newRules) == 0 {
		return nil
	}

	iptChain := r.getCoreIPTChain(chain, isIPv6)
	iptChain.Lock()
	defer iptChain.Unlock()

	rules := iptChain.rules
	if isUpdate {
		// Build a map to store the mapping of rule ID to rule for the rules to update.
		rulesToUpdate := make(map[string]*coreIPTRule)
		for _, rule := range newRules {
			rulesToUpdate[rule.ruleID] = rule
		}
		// Iterate each existing rule. If an existing rule exists in rulesToUpdate, replace it with the new rule.
		for index, rule := range rules {
			if _, exists := rulesToUpdate[rule.ruleID]; exists {
				rules[index] = rulesToUpdate[rule.ruleID]
			}
		}
	} else {
		// If these are new rules, append the new rules then sort all rules.
		rules = append(rules, newRules...)
		sort.Slice(rules, func(i, j int) bool {
			return !rules[i].priority.Less(*rules[j].priority)
		})
	}

	// Get all iptables rules and synchronize them.
	var ruleStrs []string
	for _, rule := range rules {
		if rule.ruleStr != "" {
			ruleStrs = append(ruleStrs, rule.ruleStr)
		}
	}
	if err := r.routeClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{chain}, [][]string{ruleStrs}, isIPv6); err != nil {
		return err
	}

	// cache the updated rules.
	iptChain.rules = rules
	return nil
}

func (r *nodeReconciler) deleteCoreIPTRule(ruleID string, iptChain string, isIPv6 bool) error {
	chain := r.getCoreIPTChain(iptChain, isIPv6)
	chain.Lock()
	defer chain.Unlock()

	// Get all the cached rules, then delete the rule with the given rule ID.
	rules := chain.rules
	indexToDelete := -1
	for i := 0; i < len(rules); i++ {
		if rules[i].ruleID == ruleID {
			indexToDelete = i
			break
		}
	}
	// If the rule is not found, return directly.
	if indexToDelete == -1 {
		return nil
	}
	// If the rule is found, delete it from the slice.
	rules = append(rules[:indexToDelete], rules[indexToDelete+1:]...)

	// Get all the iptables rules and synchronize them.
	var ruleStrs []string
	for _, r := range rules {
		ruleStrs = append(ruleStrs, r.ruleStr)
	}
	if err := r.routeClient.AddOrUpdateNodeNetworkPolicyIPTables([]string{iptChain}, [][]string{ruleStrs}, isIPv6); err != nil {
		return err
	}

	// cache the updated rules.
	chain.rules = rules
	return nil
}

func (r *nodeReconciler) getCoreIPTChain(iptChain string, isIPv6 bool) *coreIPTChain {
	// - For IPv4 ingress rules, iptables rules are installed in chain ANTREA-INGRESS-RULES.
	// - For IPv6 ingress rules, ip6tables rules are installed in chain ANTREA-INGRESS-RULES.
	// - For IPv4 egress rules, iptables rules are installed in chain ANTREA-EGRESS-RULES.
	// - For IPv6 egress rules, ip6tables rules are installed in chain ANTREA-EGRESS-RULES.
	return r.coreIPTChains[newChainKey(iptChain, isIPv6)]
}

func groupMembersToIPNets(groups v1beta2.GroupMemberSet, isIPv6 bool) sets.Set[string] {
	ipnets := sets.New[string]()
	suffix := "/32"
	if isIPv6 {
		suffix = "/128"
	}
	for _, member := range groups {
		for _, ip := range member.IPs {
			ipAddr := net.IP(ip)
			if isIPv6 == utilnet.IsIPv6(ipAddr) {
				ipnets.Insert(ipAddr.String() + suffix)
			}
		}
	}
	return ipnets
}

func ipBlocksToIPNets(ipBlocks []v1beta2.IPBlock, isIPv6 bool) []string {
	var ipnets []string
	for _, b := range ipBlocks {
		blockCIDR := ip.IPNetToNetIPNet(&b.CIDR)
		if isIPv6 != utilnet.IsIPv6CIDR(blockCIDR) {
			continue
		}
		exceptIPNets := make([]*net.IPNet, 0, len(b.Except))
		for i := range b.Except {
			c := b.Except[i]
			except := ip.IPNetToNetIPNet(&c)
			exceptIPNets = append(exceptIPNets, except)
		}
		diffCIDRs, err := ip.DiffFromCIDRs(blockCIDR, exceptIPNets)
		if err != nil {
			klog.ErrorS(err, "Error when computing effective CIDRs by removing except IPNets from IPBlock")
			continue
		}
		for _, d := range diffCIDRs {
			ipnets = append(ipnets, d.String())
		}
	}
	return ipnets
}

func getIPNetsFromRule(rule *CompletedRule, isIPv6 bool) sets.Set[string] {
	var set sets.Set[string]
	if rule.Direction == v1beta2.DirectionIn {
		set = groupMembersToIPNets(rule.FromAddresses, isIPv6)
		set.Insert(ipBlocksToIPNets(rule.From.IPBlocks, isIPv6)...)
	} else {
		set = groupMembersToIPNets(rule.ToAddresses, isIPv6)
		set.Insert(ipBlocksToIPNets(rule.To.IPBlocks, isIPv6)...)
	}
	// If the set contains "0.0.0.0/0" or "::/0", it means the rule matches any source or destination IP address, just
	// return a new set only containing "0.0.0.0/0" or "::/0".
	if isIPv6 && set.Has(ipv6Any) {
		return sets.New[string](ipv6Any)
	}
	if !isIPv6 && set.Has(ipv4Any) {
		return sets.New[string](ipv4Any)
	}
	return set
}

func buildCoreIPTRule(ipProtocol iptables.Protocol,
	iptChain string,
	ipset string,
	ipnet string,
	iptRuleTarget string,
	iptRuleComment string,
	service *v1beta2.Service,
	isIngress bool) string {
	builder := iptables.NewRuleBuilder(iptChain)
	if isIngress {
		if ipset != "" {
			builder = builder.MatchIPSetSrc(ipset)
		} else if ipnet != "" {
			builder = builder.MatchCIDRSrc(ipnet)
		} else {
			// If no source IP address is matched, return an empty string since the core iptables will never be matched.
			return ""
		}
	} else {
		if ipset != "" {
			builder = builder.MatchIPSetDst(ipset)
		} else if ipnet != "" {
			builder = builder.MatchCIDRDst(ipnet)
		} else {
			// If no destination IP address is matched, return an empty string since the core iptables will never be matched.
			return ""
		}
	}
	if service != nil {
		transProtocol := getServiceTransProtocol(service.Protocol)
		switch transProtocol {
		case "tcp":
			fallthrough
		case "udp":
			fallthrough
		case "sctp":
			builder = builder.MatchTransProtocol(transProtocol).
				MatchSrcPort(service.SrcPort, service.SrcEndPort).
				MatchDstPort(service.Port, service.EndPort)
		case "icmp":
			builder = builder.MatchICMP(service.ICMPType, service.ICMPCode, ipProtocol)
		}
	}
	return builder.SetTarget(iptRuleTarget).
		SetComment(iptRuleComment).
		Done().
		GetRule()
}

func buildServiceIPTRules(ipProtocol iptables.Protocol, services []v1beta2.Service, chain string, ruleTarget string) []string {
	var rules []string
	builder := iptables.NewRuleBuilder(chain)
	for _, svc := range services {
		copiedBuilder := builder.CopyBuilder()
		transProtocol := getServiceTransProtocol(svc.Protocol)
		switch transProtocol {
		case "tcp":
			fallthrough
		case "udp":
			fallthrough
		case "sctp":
			copiedBuilder = copiedBuilder.MatchTransProtocol(transProtocol).
				MatchSrcPort(svc.SrcPort, svc.SrcEndPort).
				MatchDstPort(svc.Port, svc.EndPort)
		case "icmp":
			copiedBuilder = copiedBuilder.MatchICMP(svc.ICMPType, svc.ICMPCode, ipProtocol)
		}
		rules = append(rules, copiedBuilder.SetTarget(ruleTarget).
			Done().
			GetRule())
	}
	return rules
}

func ruleActionToIPTTarget(ruleAction *secv1beta1.RuleAction) string {
	var target string
	switch *ruleAction {
	case secv1beta1.RuleActionDrop:
		target = iptables.DropTarget
	case secv1beta1.RuleActionReject:
		target = iptables.RejectTarget
	case secv1beta1.RuleActionAllow:
		target = iptables.AcceptTarget
	}
	return target
}

func getServiceTransProtocol(protocol *v1beta2.Protocol) string {
	if protocol == nil {
		return "tcp"
	}
	return strings.ToLower(string(*protocol))
}
