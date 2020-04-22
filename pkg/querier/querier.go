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
	"os"

	v1 "k8s.io/api/core/v1"

	networkingv1beta1 "github.com/vmware-tanzu/antrea/pkg/apis/networking/v1beta1"
	"github.com/vmware-tanzu/antrea/pkg/version"
)

const (
	podName      = "POD_NAME"
	podNamespace = "POD_NAMESPACE"
	nodeName     = "NODE_NAME"
)

type NetworkPolicyInfoQuerier interface {
	GetNetworkPolicyNum() int
	GetAddressGroupNum() int
	GetAppliedToGroupNum() int
}

type AgentNetworkPolicyInfoQuerier interface {
	NetworkPolicyInfoQuerier
	GetControllerConnectionStatus() bool
	GetNetworkPolicies() []networkingv1beta1.NetworkPolicy
	GetAddressGroups() []networkingv1beta1.AddressGroup
	GetAppliedToGroups() []networkingv1beta1.AppliedToGroup
	GetNetworkPolicy(npName, npNamespace string) *networkingv1beta1.NetworkPolicy
}

type ControllerNetworkPolicyInfoQuerier interface {
	NetworkPolicyInfoQuerier
	GetConnectedAgentNum() int
}

// GetSelfPod gets current pod.
func GetSelfPod() v1.ObjectReference {
	if os.Getenv(podName) == "" || os.Getenv(podNamespace) == "" {
		return v1.ObjectReference{}
	}
	return v1.ObjectReference{Kind: "Pod", Name: os.Getenv(podName), Namespace: os.Getenv(podNamespace)}
}

// GetSelfNode gets current node.
func GetSelfNode(isAgent bool, node string) v1.ObjectReference {
	if isAgent {
		if node == "" {
			return v1.ObjectReference{}
		}
		return v1.ObjectReference{Kind: "Node", Name: node}
	}
	if os.Getenv(nodeName) == "" {
		return v1.ObjectReference{}
	}
	return v1.ObjectReference{Kind: "Node", Name: os.Getenv(nodeName)}
}

// GetVersion gets current version.
func GetVersion() string {
	return version.GetFullVersion()
}
