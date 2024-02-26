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
	"antrea.io/antrea/pkg/apis/controlplane"
	"antrea.io/antrea/pkg/controller/networkpolicy/store"
	antreatypes "antrea.io/antrea/pkg/controller/types"
)

// EndpointQuerier handles requests for querying NetworkPolicies of the endpoint.
type EndpointQuerier interface {
	// QueryNetworkPolicyRules returns the list of NetworkPolicies which apply to the provided Pod,
	// along with the list of NetworkPolicy ingress/egress rules which select the provided Pod.
	QueryNetworkPolicyRules(namespace, podName string) (*antreatypes.EndpointNetworkPolicyRules, error)
}

// endpointQuerier implements the EndpointQuerier interface
type endpointQuerier struct {
	networkPolicyController *NetworkPolicyController
}

// NewEndpointQuerier returns a new *endpointQuerier.
func NewEndpointQuerier(networkPolicyController *NetworkPolicyController) *endpointQuerier {
	n := &endpointQuerier{
		networkPolicyController: networkPolicyController,
	}
	return n
}

// QueryNetworkPolicyRules returns network policies and rules relevant to the selected
// network endpoint. Relevant network policies fall into three categories: applied policies
// are policies which directly apply to an endpoint, egress/ingress rules are rules which
// reference the endpoint respectively.
func (eq *endpointQuerier) QueryNetworkPolicyRules(namespace, podName string) (*antreatypes.EndpointNetworkPolicyRules, error) {
	if namespace == "" {
		namespace = "default"
	}
	groups, exists := eq.networkPolicyController.groupingInterface.GetGroupsForPod(namespace, podName)
	if !exists {
		return nil, nil
	}

	// create network policies categories
	var applied []*controlplane.NetworkPolicyReference
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
			applied = append(applied, policy.(*antreatypes.NetworkPolicy).SourceRef)
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
						egress = append(egress, &antreatypes.RuleInfo{Policy: policy.(*antreatypes.NetworkPolicy).SourceRef, Index: egressIndex,
							Rule: &controlplane.NetworkPolicyRule{Direction: rule.Direction, Name: rule.Name, Action: rule.Action}})
						// an AddressGroup can only be referenced in a rule once
						break
					}
				}
				for _, addressGroupTrial := range rule.From.AddressGroups {
					if addressGroupTrial == string(addressGroup.(*antreatypes.AddressGroup).UID) {
						ingress = append(ingress, &antreatypes.RuleInfo{Policy: policy.(*antreatypes.NetworkPolicy).SourceRef, Index: ingressIndex,
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
