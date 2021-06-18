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

package querier

import (
	v1 "k8s.io/api/core/v1"

	"antrea.io/antrea/pkg/agent/types"
	cpv1beta "antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	"antrea.io/antrea/pkg/util/env"
	"antrea.io/antrea/pkg/version"
)

type NetworkPolicyInfoQuerier interface {
	GetNetworkPolicyNum() int
	GetAddressGroupNum() int
	GetAppliedToGroupNum() int
}

type AgentNetworkPolicyInfoQuerier interface {
	NetworkPolicyInfoQuerier
	GetControllerConnectionStatus() bool
	GetNetworkPolicies(npFilter *NetworkPolicyQueryFilter) []cpv1beta.NetworkPolicy
	GetAddressGroups() []cpv1beta.AddressGroup
	GetAppliedToGroups() []cpv1beta.AppliedToGroup
	GetAppliedNetworkPolicies(pod, namespace string, npFilter *NetworkPolicyQueryFilter) []cpv1beta.NetworkPolicy
	GetNetworkPolicyByRuleFlowID(ruleFlowID uint32) *cpv1beta.NetworkPolicyReference
	GetRuleByFlowID(ruleFlowID uint32) *types.PolicyRule
}

type ControllerNetworkPolicyInfoQuerier interface {
	NetworkPolicyInfoQuerier
	GetConnectedAgentNum() int
}

// GetSelfPod gets current pod.
func GetSelfPod() v1.ObjectReference {
	podName := env.GetPodName()
	podNamespace := env.GetPodNamespace()
	if podName == "" || podNamespace == "" {
		return v1.ObjectReference{}
	}
	return v1.ObjectReference{Kind: "Pod", Name: podName, Namespace: podNamespace}
}

// GetSelfNode gets current node.
func GetSelfNode(isAgent bool, node string) v1.ObjectReference {
	if isAgent {
		if node == "" {
			return v1.ObjectReference{}
		}
		return v1.ObjectReference{Kind: "Node", Name: node}
	}
	nodeName, _ := env.GetNodeName()
	if nodeName == "" {
		return v1.ObjectReference{}
	}
	return v1.ObjectReference{Kind: "Node", Name: nodeName}
}

// GetVersion gets current version.
func GetVersion() string {
	return version.GetFullVersion()
}

// NetworkPolicyQueryFilter is used to filter the result while retrieve network policy
// An empty attribute, which won't be used as a condition, means match all.
// e.g SourceType = "" means all type network policy will be retrieved
// Can have more attributes in future if more args are required
type NetworkPolicyQueryFilter struct {
	// The Name of the controlplane network policy. If this field is set then
	// none of the other fields can be.
	Name string
	// The Name of the original network policy.
	SourceName string
	// The namespace of the original Namespace that the internal NetworkPolicy is created for.
	Namespace string
	// Name of the pod that the network policy is applied on.
	Pod string
	// The type of the original NetworkPolicy that the internal NetworkPolicy is created for.(K8sNP, CNP, ANP)
	SourceType cpv1beta.NetworkPolicyType
}
