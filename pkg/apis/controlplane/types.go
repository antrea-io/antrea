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

package controlplane

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"

	secv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/security/v1alpha1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// AppliedToGroup is the message format of antrea/pkg/controller/types.AppliedToGroup in an API response.
type AppliedToGroup struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	// Pods is a list of Pods selected by this group.
	Pods []GroupMemberPod
	// GroupMembers is a list of resources selected by this group.
	GroupMembers []GroupMember
}

// PodReference represents a Pod Reference.
type PodReference struct {
	// The name of this pod.
	Name string
	// The namespace of this pod.
	Namespace string
}

// NamedPort represents a Port with a name on Pod.
type NamedPort struct {
	// Port represents the Port number.
	Port int32
	// Name represents the associated name with this Port number.
	Name string
	// Protocol for port. Must be UDP, TCP, or SCTP.
	Protocol Protocol
}

// GroupMemberPod represents a Pod related member to be populated in Groups.
type GroupMemberPod struct {
	// Pod maintains the reference to the Pod.
	Pod *PodReference
	// IP maintains the IPAddress of the Pod.
	IP IPAddress
	// Ports maintain the list of named port associated with this Pod member.
	Ports []NamedPort
}

// ExternalEntityReference represents a ExternalEntity Reference.
type ExternalEntityReference struct {
	// The name of this ExternalEntity.
	Name string
	// The namespace of this ExternalEntity.
	Namespace string
}

// Endpoint represents an external endpoint.
type Endpoint struct {
	// IP is the IP address of the Endpoint.
	IP IPAddress
	// Ports is the list NamedPort of the Endpoint.
	Ports []NamedPort
}

// GroupMember represents an resource member to be populated in Groups.
type GroupMember struct {
	// Pod maintains the reference to the Pod.
	Pod *PodReference

	// ExternalEntity maintains the reference to the ExternalEntity.
	ExternalEntity *ExternalEntityReference

	// Endpoints maintains a list of EndPoints associated with this GroupMember.
	Endpoints []Endpoint
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// AppliedToGroupPatch describes the incremental update of an AppliedToGroup.
type AppliedToGroupPatch struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	AddedPods           []GroupMemberPod
	RemovedPods         []GroupMemberPod
	AddedGroupMembers   []GroupMember
	RemovedGroupMembers []GroupMember
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// AppliedToGroupList is a list of AppliedToGroup objects.
type AppliedToGroupList struct {
	metav1.TypeMeta
	metav1.ListMeta
	Items []AppliedToGroup
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// AddressGroup is the message format of antrea/pkg/controller/types.AddressGroup in an API response.
type AddressGroup struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	// Pods is a list of Pods selected by this group.
	Pods []GroupMemberPod
	// GroupMembers is a list of GroupMember selected by this group.
	GroupMembers []GroupMember
}

// IPAddress describes a single IP address. Either an IPv4 or IPv6 address must be set.
type IPAddress []byte

// IPNet describes an IP network.
type IPNet struct {
	IP           IPAddress
	PrefixLength int32
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// AddressGroupPatch describes the incremental update of an AddressGroup.
type AddressGroupPatch struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	AddedPods           []GroupMemberPod
	RemovedPods         []GroupMemberPod
	AddedGroupMembers   []GroupMember
	RemovedGroupMembers []GroupMember
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// AddressGroupList is a list of AddressGroup objects.
type AddressGroupList struct {
	metav1.TypeMeta
	metav1.ListMeta
	Items []AddressGroup
}

// TierPriority specifies the relative ordering among Tiers. A lower
// TierPriority indicates higher precedence.
type TierPriority uint32

type NetworkPolicyType string

const (
	K8sNetworkPolicy           NetworkPolicyType = "K8sNetworkPolicy"
	AntreaClusterNetworkPolicy NetworkPolicyType = "AntreaClusterNetworkPolicy"
	AntreaNetworkPolicy        NetworkPolicyType = "AntreaNetworkPolicy"
)

type NetworkPolicyReference struct {
	// Type of the NetworkPolicy.
	Type NetworkPolicyType
	// Namespace of the NetworkPolicy. It's empty for Antrea ClusterNetworkPolicy.
	Namespace string
	// Name of the NetworkPolicy.
	Name string
	// UID of the NetworkPolicy.
	UID types.UID
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// NetworkPolicy is the message format of antrea/pkg/controller/types.NetworkPolicy in an API response.
type NetworkPolicy struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	// Rules is a list of rules to be applied to the selected Pods.
	Rules []NetworkPolicyRule
	// AppliedToGroups is a list of names of AppliedToGroups to which this policy applies.
	AppliedToGroups []string
	// Priority represents the relative priority of this NetworkPolicy as compared to
	// other NetworkPolicies. Priority will be unset (nil) for K8s NetworkPolicy.
	Priority *float64
	// TierPriority represents the priority of the Tier associated with this NetworkPolicy.
	// The TierPriority will remain nil for K8s NetworkPolicy.
	TierPriority *TierPriority
	// Reference to the original NetworkPolicy that the internal NetworkPolicy is created for.
	SourceRef *NetworkPolicyReference
}

// Direction defines traffic direction of NetworkPolicyRule.
type Direction string

const (
	DirectionIn  Direction = "In"
	DirectionOut Direction = "Out"
)

// NetworkPolicyRule describes a particular set of traffic that is allowed.
type NetworkPolicyRule struct {
	// The direction of this rule.
	// If it's set to In, From must be set and To must not be set.
	// If it's set to Out, To must be set and From must not be set.
	Direction Direction
	// From represents sources which should be able to access the pods selected by the policy.
	From NetworkPolicyPeer
	// To represents destinations which should be able to be accessed by the pods selected by the policy.
	To NetworkPolicyPeer
	// Services is a list of services which should be matched.
	Services []Service
	// Priority defines the priority of the Rule as compared to other rules in the
	// NetworkPolicy.
	Priority int32
	// Action specifies the action to be applied on the rule. i.e. Allow/Drop. An empty
	// action “nil” defaults to Allow action, which would be the case for rules created for
	// K8s NetworkPolicy.
	Action *secv1alpha1.RuleAction
}

// Protocol defines network protocols supported for things like container ports.
type Protocol string

const (
	// ProtocolTCP is the TCP protocol.
	ProtocolTCP Protocol = "TCP"
	// ProtocolUDP is the UDP protocol.
	ProtocolUDP Protocol = "UDP"
	// ProtocolSCTP is the SCTP protocol.
	ProtocolSCTP Protocol = "SCTP"
)

// Service describes a port to allow traffic on.
type Service struct {
	// The protocol (TCP, UDP, or SCTP) which traffic must match. If not specified, this
	// field defaults to TCP.
	// +optional
	Protocol *Protocol
	// The port name or number on the given protocol. If not specified, this matches all port numbers.
	// +optional
	Port *intstr.IntOrString
}

// NetworkPolicyPeer describes a peer of NetworkPolicyRules.
// It could be a list of names of AddressGroups and/or a list of IPBlock.
type NetworkPolicyPeer struct {
	// A list of names of AddressGroups.
	AddressGroups []string
	// A list of IPBlock.
	IPBlocks []IPBlock
}

// IPBlock describes a particular CIDR (Ex. "192.168.1.1/24"). The except entry describes CIDRs that should
// not be included within this rule.
type IPBlock struct {
	// CIDR is an IPNet represents the IP Block.
	CIDR IPNet
	// Except is a slice of IPNets that should not be included within an IP Block.
	// Except values will be rejected if they are outside the CIDR range.
	// +optional
	Except []IPNet
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// NetworkPolicyList is a list of NetworkPolicy objects.
type NetworkPolicyList struct {
	metav1.TypeMeta
	metav1.ListMeta
	Items []NetworkPolicy
}
