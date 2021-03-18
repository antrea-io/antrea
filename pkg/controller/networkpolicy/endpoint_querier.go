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
	"k8s.io/apimachinery/pkg/types"

	cpv1beta "github.com/vmware-tanzu/antrea/pkg/apis/controlplane/v1beta2"
	"github.com/vmware-tanzu/antrea/pkg/controller/networkpolicy/store"
	antreatypes "github.com/vmware-tanzu/antrea/pkg/controller/types"
)

// EndpointQuerier handles requests for antctl query
type EndpointQuerier interface {
	// QueryNetworkPolicies returns the list of NetworkPolicies which apply to the provided Pod,
	// along with the list NetworkPolicies which select the provided Pod in one of their policy
	// rules (ingress or egress).
	QueryNetworkPolicies(namespace string, podName string) (*EndpointQueryResponse, error)
}

// endpointQuerier implements the EndpointQuerier interface
type endpointQuerier struct {
	networkPolicyController *NetworkPolicyController
}

// EndpointQueryResponse is the reply struct for anctl endpoint queries
type EndpointQueryResponse struct {
	Endpoints []Endpoint `json:"endpoints,omitempty"`
}

type Endpoint struct {
	Namespace string   `json:"namespace,omitempty"`
	Name      string   `json:"name,omitempty"`
	Policies  []Policy `json:"policies,omitempty"`
	Rules     []Rule   `json:"rules,omitempty"`
}

type PolicyRef struct {
	Namespace string    `json:"namespace,omitempty"`
	Name      string    `json:"name,omitempty"`
	UID       types.UID `json:"uid,omitempty"`
}

type Policy struct {
	PolicyRef
}

type Rule struct {
	PolicyRef
	Direction cpv1beta.Direction `json:"direction,omitempty"`
	RuleIndex int                `json:"ruleindex,omitempty"`
}

// NewEndpointQuerier returns a new *endpointQuerier.
func NewEndpointQuerier(networkPolicyController *NetworkPolicyController) *endpointQuerier {
	n := &endpointQuerier{
		networkPolicyController: networkPolicyController,
	}
	return n
}

// QueryNetworkPolicies returns kubernetes network policy references relevant to the selected
// network endpoint. Relevant policies fall into three categories: applied policies (Policies in
// Endpoint type) are policies which directly apply to an endpoint, egress and ingress rules (Rules
// in Endpoint type) are policies which reference the endpoint in an ingress/egress rule
// respectively.
func (eq *endpointQuerier) QueryNetworkPolicies(namespace string, podName string) (*EndpointQueryResponse, error) {
	groups, exists := eq.networkPolicyController.groupingInterface.GetGroupsForPod(namespace, podName)
	if !exists {
		return nil, nil
	}
	type ruleTemp struct {
		policy *antreatypes.NetworkPolicy
		index  int
	}
	// create network policies categories
	applied := make([]*antreatypes.NetworkPolicy, 0)
	ingress := make([]*ruleTemp, 0)
	egress := make([]*ruleTemp, 0)
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
			egressIndex := 0
			ingressIndex := 0
			for _, rule := range policy.(*antreatypes.NetworkPolicy).Rules {
				for _, addressGroupTrial := range rule.To.AddressGroups {
					if addressGroupTrial == string(addressGroup.(*antreatypes.AddressGroup).UID) {
						egress = append(egress, &ruleTemp{policy: policy.(*antreatypes.NetworkPolicy), index: egressIndex})
						egressIndex++
						// an AddressGroup can only be referenced in a rule once
						break
					}
				}
				for _, addressGroupTrial := range rule.From.AddressGroups {
					if addressGroupTrial == string(addressGroup.(*antreatypes.AddressGroup).UID) {
						ingress = append(ingress, &ruleTemp{policy: policy.(*antreatypes.NetworkPolicy), index: ingressIndex})
						ingressIndex++
						// an AddressGroup can only be referenced in a rule once
						break
					}
				}
			}
		}
	}
	// make response policies
	responsePolicies := make([]Policy, 0)
	for _, internalPolicy := range applied {
		responsePolicy := Policy{
			PolicyRef: PolicyRef{
				Namespace: internalPolicy.SourceRef.Namespace,
				Name:      internalPolicy.SourceRef.Name,
				UID:       internalPolicy.SourceRef.UID,
			},
		}
		responsePolicies = append(responsePolicies, responsePolicy)
	}
	responseRules := make([]Rule, 0)
	// create rules based on egress and ingress policies
	for _, internalPolicy := range egress {
		newRule := Rule{
			PolicyRef: PolicyRef{
				Namespace: internalPolicy.policy.SourceRef.Namespace,
				Name:      internalPolicy.policy.SourceRef.Name,
				UID:       internalPolicy.policy.SourceRef.UID,
			},
			Direction: cpv1beta.DirectionOut,
			RuleIndex: internalPolicy.index,
		}
		responseRules = append(responseRules, newRule)
	}
	for _, internalPolicy := range ingress {
		newRule := Rule{
			PolicyRef: PolicyRef{
				Namespace: internalPolicy.policy.SourceRef.Namespace,
				Name:      internalPolicy.policy.SourceRef.Name,
				UID:       internalPolicy.policy.SourceRef.UID,
			},
			Direction: cpv1beta.DirectionIn,
			RuleIndex: internalPolicy.index,
		}
		responseRules = append(responseRules, newRule)
	}
	// for now, selector only selects a single endpoint (pod, namespace)
	endpoint := Endpoint{
		Namespace: namespace,
		Name:      podName,
		Policies:  responsePolicies,
		Rules:     responseRules,
	}
	return &EndpointQueryResponse{[]Endpoint{endpoint}}, nil
}
