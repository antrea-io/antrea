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

// Package networkpolicy provides NetworkPolicyController implementation to manage
// and synchronize the Pods and Namespaces affected by Network Policies and enforce
// their rules.
package networkpolicy

import (
	"errors"
	"math"
	"sort"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"

	"antrea.io/antrea/pkg/apis/controlplane"
	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/pkg/controller/networkpolicy/store"
	antreatypes "antrea.io/antrea/pkg/controller/types"
)

// EndpointQuerier handles requests for querying NetworkPolicies of the endpoint.
type EndpointQuerier interface {
	// QueryNetworkPolicyRules returns the list of NetworkPolicies which apply to the provided Pod,
	// along with the list of NetworkPolicy ingress/egress rules which select the provided Pod.
	QueryNetworkPolicyRules(namespace, podName string) (*antreatypes.EndpointNetworkPolicyRules, error)
}

// EndpointQuerierImpl implements the EndpointQuerier interface
type EndpointQuerierImpl struct {
	networkPolicyController *NetworkPolicyController
}

// NewEndpointQuerier returns a new *EndpointQuerierImpl.
func NewEndpointQuerier(networkPolicyController *NetworkPolicyController) *EndpointQuerierImpl {
	return &EndpointQuerierImpl{
		networkPolicyController: networkPolicyController,
	}
}

// PolicyRuleQuerier handles requests for querying effective policy rule on entities.
type PolicyRuleQuerier interface {
	QueryNetworkPolicyEvaluation(entities *controlplane.NetworkPolicyEvaluationRequest) (*controlplane.NetworkPolicyEvaluationResponse, error)
}

// policyRuleQuerier implements the PolicyRuleQuerier interface
type policyRuleQuerier struct {
	endpointQuerier EndpointQuerier
}

// NewPolicyRuleQuerier returns a new *policyRuleQuerier
func NewPolicyRuleQuerier(endpointQuerier EndpointQuerier) *policyRuleQuerier {
	return &policyRuleQuerier{
		endpointQuerier: endpointQuerier,
	}
}

type lessFunc func(p1, p2 *antreatypes.RuleInfo) int

// ByRulePriority implements the Sort interface, sorting the rules within.
// Comparators should be ordered by their importance in terms of determining rule priority.
type ByRulePriority struct {
	rules       []*antreatypes.RuleInfo
	comparators []lessFunc
}

func (s ByRulePriority) Len() int { return len(s.rules) }

func (s ByRulePriority) Swap(i, j int) { s.rules[i], s.rules[j] = s.rules[j], s.rules[i] }

func (s ByRulePriority) Less(i, j int) bool {
	p, q := s.rules[i], s.rules[j]
	for k := 0; k < len(s.comparators); k++ {
		less := s.comparators[k]
		switch less(p, q) {
		case 1: // p < q
			return true
		case -1: // p > q
			return false
		}
		// p == q; try the next comparison.
	}
	return false
}

// QueryNetworkPolicyRules returns network policies and rules relevant to the selected
// network endpoint. Relevant network policies fall into three categories: applied policies
// are policies which directly apply to an endpoint, egress/ingress rules are rules which
// reference the endpoint respectively.
func (eq *EndpointQuerierImpl) QueryNetworkPolicyRules(namespace, podName string) (*antreatypes.EndpointNetworkPolicyRules, error) {
	if namespace == "" {
		namespace = "default"
	}
	groups, exists := eq.networkPolicyController.groupingInterface.GetGroupsForPod(namespace, podName)
	if !exists {
		return nil, nil
	}

	// create network policies categories
	var applied []*antreatypes.NetworkPolicy
	var ingress, egress []*antreatypes.RuleInfo
	// get all appliedToGroups using filter, then get applied policies using appliedToGroup
	appliedToGroupKeys := groups[appliedToGroupType]
	// We iterate over all AppliedToGroups (same for AddressGroups below). This is acceptable
	// since this implementation only supports user queries (in particular through antctl) and
	// should resturn within a reasonable amount of time. We experimented with adding Pod
	// Indexers to the AppliedToGroup and AddressGroup stores, but we felt that this use case
	// did not justify the memory overhead. If we can find another use for the Indexers as part
	// of the NetworkPolicy Controller implementation, we may consider adding them back.
	for _, appliedToGroupKey := range appliedToGroupKeys {
		policies, err := eq.networkPolicyController.internalNetworkPolicyStore.GetByIndex(
			store.AppliedToGroupIndex,
			appliedToGroupKey,
		)
		if err != nil {
			return nil, err
		}
		for _, policy := range policies {
			applied = append(applied, policy.(*antreatypes.NetworkPolicy))
		}
	}
	// get all addressGroups using filter, then get ingress and egress policies using addressGroup
	addressGroupKeys := groups[addressGroupType]
	for _, addressGroupKey := range addressGroupKeys {
		addressGroup, found, _ := eq.networkPolicyController.addressGroupStore.Get(addressGroupKey)
		if !found {
			continue
		}
		policies, err := eq.networkPolicyController.internalNetworkPolicyStore.GetByIndex(
			store.AddressGroupIndex,
			addressGroupKey,
		)
		if err != nil {
			return nil, err
		}
		for _, policy := range policies {
			egressIndex, ingressIndex := 0, 0
			for _, rule := range policy.(*antreatypes.NetworkPolicy).Rules {
				for _, addressGroupTrial := range rule.To.AddressGroups {
					if addressGroupTrial == string(addressGroup.(*antreatypes.AddressGroup).UID) {
						egress = append(egress, &antreatypes.RuleInfo{Policy: policy.(*antreatypes.NetworkPolicy), Index: egressIndex,
							Rule: &controlplane.NetworkPolicyRule{Direction: rule.Direction, Name: rule.Name, Action: rule.Action}})
						// an AddressGroup can only be referenced in a rule once
						break
					}
				}
				for _, addressGroupTrial := range rule.From.AddressGroups {
					if addressGroupTrial == string(addressGroup.(*antreatypes.AddressGroup).UID) {
						ingress = append(ingress, &antreatypes.RuleInfo{Policy: policy.(*antreatypes.NetworkPolicy), Index: ingressIndex,
							Rule: &controlplane.NetworkPolicyRule{Direction: rule.Direction, Name: rule.Name, Action: rule.Action}})
						// an AddressGroup can only be referenced in a rule once
						break
					}
				}
				// IngressIndex/egressIndex indicates the current rule's index among this policy's original ingress/egress
				// rules. The calculation accounts for policy rules not referencing this pod, and guarantees that
				// users can reference the rules from configuration without accessing the internal policies.
				if rule.Direction == controlplane.DirectionIn {
					ingressIndex++
				} else {
					egressIndex++
				}
			}
		}
	}
	return &antreatypes.EndpointNetworkPolicyRules{Namespace: namespace, Name: podName, AppliedPolicies: applied, EndpointAsIngressSrcRules: ingress, EndpointAsEgressDstRules: egress}, nil
}

// processEndpointAppliedRules processes NetworkPolicy rules applied to an endpoint,
// returns a set of the corresponding policy UIDs, and manually generates Kubernetes
// NetworkPolicy default isolation rules if they exist. The default isolation rule's
// direction depends on isSourceEndpoint, and has the lowest precedence.
func processEndpointAppliedRules(appliedPolicies []*antreatypes.NetworkPolicy, isSourceEndpoint bool) (sets.Set[types.UID], []*antreatypes.RuleInfo) {
	policyUIDs := sets.New[types.UID]()
	isolationRules := make([]*antreatypes.RuleInfo, 0)
	for _, internalPolicy := range appliedPolicies {
		policyUIDs.Insert(internalPolicy.SourceRef.UID)
		if internalPolicy.SourceRef.Type == controlplane.K8sNetworkPolicy {
			// check if the Kubernetes NetworkPolicy creates ingress or egress isolationRules
			for _, rule := range internalPolicy.Rules {
				if rule.Direction == controlplane.DirectionIn && !isSourceEndpoint {
					isolationRules = append(isolationRules, &antreatypes.RuleInfo{Policy: internalPolicy, Index: math.MaxInt,
						Rule: &controlplane.NetworkPolicyRule{Direction: rule.Direction, Name: rule.Name, Action: rule.Action}})
				} else if rule.Direction == controlplane.DirectionOut && isSourceEndpoint {
					isolationRules = append(isolationRules, &antreatypes.RuleInfo{Policy: internalPolicy, Index: math.MaxInt,
						Rule: &controlplane.NetworkPolicyRule{Direction: rule.Direction, Name: rule.Name, Action: rule.Action}})
				}
			}
		}
	}
	return policyUIDs, isolationRules
}

// predictEndpointsRules returns the predicted rules effective from srcEndpoints to dstEndpoints.
// Rules returned satisfy a. in source applied policies and destination egress rules,
// or b. in source ingress rules and destination applied policies or c. applied to KNP default isolation.
func predictEndpointsRules(srcEndpointRules, dstEndpointRules *antreatypes.EndpointNetworkPolicyRules) (commonRule *antreatypes.RuleInfo) {
	commonRules := make([]*antreatypes.RuleInfo, 0)
	if srcEndpointRules != nil && dstEndpointRules != nil {
		srcPolicies, srcIsolated := processEndpointAppliedRules(srcEndpointRules.AppliedPolicies, true)
		dstPolicies, dstIsolated := processEndpointAppliedRules(dstEndpointRules.AppliedPolicies, false)
		for _, rule := range dstEndpointRules.EndpointAsEgressDstRules {
			if srcPolicies.Has(rule.Policy.SourceRef.UID) {
				commonRules = append(commonRules, rule)
			}
		}
		for _, rule := range srcEndpointRules.EndpointAsIngressSrcRules {
			if dstPolicies.Has(rule.Policy.SourceRef.UID) {
				commonRules = append(commonRules, rule)
			}
		}
		for _, defaultDropRule := range srcIsolated {
			commonRules = append(commonRules, defaultDropRule)
		}
		for _, defaultDropRule := range dstIsolated {
			commonRules = append(commonRules, defaultDropRule)
		}
	}

	// sort the common rules based on multiple closures, the top rule has the highest precedence
	tierPriority := func(r1, r2 *antreatypes.RuleInfo) int {
		effectiveTierPriorityK8sNP := (crdv1beta1.DefaultTierPriority + crdv1beta1.BaselineTierPriority) / 2
		r1Priority, r2Priority := effectiveTierPriorityK8sNP, effectiveTierPriorityK8sNP
		if r1.Policy.TierPriority != nil {
			r1Priority = *r1.Policy.TierPriority
		}
		if r2.Policy.TierPriority != nil {
			r2Priority = *r2.Policy.TierPriority
		}
		if r1Priority < r2Priority {
			return 1
		} else if r1Priority > r2Priority {
			return -1
		}
		return 0
	}
	policyPriority := func(r1, r2 *antreatypes.RuleInfo) int {
		if r1.Policy.Priority != nil && r2.Policy.Priority != nil {
			if *r1.Policy.Priority < *r2.Policy.Priority {
				return 1
			} else if *r1.Policy.Priority > *r2.Policy.Priority {
				return -1
			}
		}
		return 0
	}
	rulePriority := func(r1, r2 *antreatypes.RuleInfo) int {
		if r1.Index < r2.Index {
			return 1
		} else if r1.Index > r2.Index {
			return -1
		}
		return 0
	}
	defaultOrder := func(r1, r2 *antreatypes.RuleInfo) int {
		if r1.Policy.Name < r2.Policy.Name {
			return 1
		}
		return 0
	}
	sort.Sort(ByRulePriority{rules: commonRules, comparators: []lessFunc{tierPriority, policyPriority, rulePriority, defaultOrder}})
	if len(commonRules) > 0 {
		commonRule = commonRules[0]
		// filter Antrea-native policy rules with Pass action
		// if pass rule currently has the highest precedence, skip the remaining rules
		// until the next K8s rule or Baseline rule, or return the pass rule otherwise
		isPass := func(ruleInfo *controlplane.NetworkPolicyRule) bool {
			return ruleInfo.Action != nil && *ruleInfo.Action == crdv1beta1.RuleActionPass
		}
		if isPass(commonRule.Rule) {
			for _, rule := range commonRules[1:] {
				if rule.Policy.SourceRef.Type == controlplane.K8sNetworkPolicy ||
					(rule.Policy.TierPriority != nil && *rule.Policy.TierPriority == crdv1beta1.BaselineTierPriority && !isPass(rule.Rule)) {
					commonRule = rule
					break
				}
			}
		}
	}
	return
}

// QueryNetworkPolicyEvaluation returns the effective NetworkPolicy rule on given
// source and destination entities.
func (eq *policyRuleQuerier) QueryNetworkPolicyEvaluation(entities *controlplane.NetworkPolicyEvaluationRequest) (*controlplane.NetworkPolicyEvaluationResponse, error) {
	if entities.Source.Pod == nil || entities.Destination.Pod == nil || entities.Source.Pod.Name == "" || entities.Destination.Pod.Name == "" {
		return nil, errors.New("invalid NetworkPolicyEvaluation request entities")
	}
	// query endpoints and handle response errors
	endpointAnalysisSource, err := eq.endpointQuerier.QueryNetworkPolicyRules(entities.Source.Pod.Namespace, entities.Source.Pod.Name)
	if err != nil {
		return nil, err
	}
	endpointAnalysisDestination, err := eq.endpointQuerier.QueryNetworkPolicyRules(entities.Destination.Pod.Namespace, entities.Destination.Pod.Name)
	if err != nil {
		return nil, err
	}
	endpointAnalysisRule := predictEndpointsRules(endpointAnalysisSource, endpointAnalysisDestination)
	if endpointAnalysisRule == nil {
		return nil, nil
	}
	return &controlplane.NetworkPolicyEvaluationResponse{
		NetworkPolicy: *endpointAnalysisRule.Policy.SourceRef,
		RuleIndex:     int32(endpointAnalysisRule.Index),
		Rule: controlplane.RuleRef{
			Direction: endpointAnalysisRule.Rule.Direction,
			Name:      endpointAnalysisRule.Rule.Name,
			Action:    endpointAnalysisRule.Rule.Action,
		},
	}, nil
}
