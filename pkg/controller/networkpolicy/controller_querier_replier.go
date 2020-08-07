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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	networkingv1beta1 "github.com/vmware-tanzu/antrea/pkg/apis/networking/v1beta1"
	"github.com/vmware-tanzu/antrea/pkg/controller/networkpolicy/store"
	antreatypes "github.com/vmware-tanzu/antrea/pkg/controller/types"
)

type EndpointQuerier interface {
	QueryNetworkPolicies(namespace string, podName string) (*EndpointQueryResponse, error)
}

// EndpointQueryReplier is responsible for handling query requests from antctl query
type EndpointQueryReplier struct {
	networkPolicyController *NetworkPolicyController
}

// EndpointQueryResponse is the reply struct for QueryNetworkPolicies
type EndpointQueryResponse struct {
	Endpoints []Endpoint `json:"endpoints,omitempty"`
}

// Endpoint holds response information for an endpoint following a query
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

// Policy holds network policy information to be relayed to client following query endpoint
type Policy struct {
	PolicyRef
	selector metav1.LabelSelector `json:"selector,omitempty"`
}

type Rule struct {
	PolicyRef
	Direction networkingv1beta1.Direction `json:"direction,omitempty"`
	RuleIndex int                         `json:"ruleindex,omitempty"`
}

// NewEndpointQueryReplier returns a new *NewEndpointQueryReplier.
func NewEndpointQueryReplier(networkPolicyController *NetworkPolicyController) *EndpointQueryReplier {
	n := &EndpointQueryReplier{
		networkPolicyController: networkPolicyController,
	}
	return n
}

// QueryNetworkPolicies returns kubernetes network policy references relevant to the selected network endpoint. Relevant
// policies fall into three categories: applied policies (Policies in Endpoint type) are policies which directly apply to
// an endpoint, egress and ingress rules (Rules in Endpoint type) are policies which reference the endpoint in an ingress/
// egress rule respectively.
func (eq EndpointQueryReplier) QueryNetworkPolicies(namespace string, podName string) (*EndpointQueryResponse, error) {
	// check if namespace and podName select an existing pod
	pod, err := eq.networkPolicyController.podInformer.Lister().Pods(namespace).Get(podName)
	if err != nil {
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
	appliedToGroupKeys := eq.networkPolicyController.filterAppliedToGroupsForPod(pod)
	if err != nil {
		return nil, err
	}
	for appliedToGroupKey := range appliedToGroupKeys {
		policies, err := eq.networkPolicyController.internalNetworkPolicyStore.GetByIndex(store.AppliedToGroupIndex,
			appliedToGroupKey)
		if err != nil {
			return nil, err
		}
		for _, policy := range policies {
			applied = append(applied, policy.(*antreatypes.NetworkPolicy))
		}
	}
	// get all addressGroups using filter, then get ingress and egress policies using addressGroup
	addressGroupKeys := eq.networkPolicyController.filterAddressGroupsForPod(pod)
	if err != nil {
		return nil, err
	}
	for addressGroupKey := range addressGroupKeys {
		addressGroup, found, err := eq.networkPolicyController.addressGroupStore.Get(addressGroupKey)
		if !found {
			continue
		}
		policies, err := eq.networkPolicyController.internalNetworkPolicyStore.GetByIndex(store.AddressGroupIndex,
			addressGroupKey)
		if err != nil {
			return nil, err
		}
		for _, policy := range policies {
			for i, rule := range policy.(*antreatypes.NetworkPolicy).Rules {
				for _, addressGroupTrial := range rule.To.AddressGroups {
					if addressGroupTrial == string(addressGroup.(*antreatypes.AddressGroup).UID) {
						egress = append(egress, &ruleTemp{policy: policy.(*antreatypes.NetworkPolicy), index: i})
					}
				}
				for _, addressGroupTrial := range rule.From.AddressGroups {
					if addressGroupTrial == string(addressGroup.(*antreatypes.AddressGroup).UID) {
						ingress = append(ingress, &ruleTemp{policy: policy.(*antreatypes.NetworkPolicy), index: i})
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
				Namespace: internalPolicy.Namespace,
				Name:      internalPolicy.Name,
				UID:       internalPolicy.UID,
			},
		}
		responsePolicies = append(responsePolicies, responsePolicy)
	}
	responseRules := make([]Rule, 0)
	// create rules based on egress and ingress policies
	for _, internalPolicy := range egress {
		newRule := Rule{
			PolicyRef: PolicyRef{
				Namespace: internalPolicy.policy.Namespace,
				Name:      internalPolicy.policy.Name,
				UID:       internalPolicy.policy.UID,
			},
			Direction: networkingv1beta1.DirectionOut,
			RuleIndex: internalPolicy.index,
		}
		responseRules = append(responseRules, newRule)
	}
	for _, internalPolicy := range ingress {
		newRule := Rule{
			PolicyRef: PolicyRef{
				Namespace: internalPolicy.policy.Namespace,
				Name:      internalPolicy.policy.Name,
				UID:       internalPolicy.policy.UID,
			},
			Direction: networkingv1beta1.DirectionIn,
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
