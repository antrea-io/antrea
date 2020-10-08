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

package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"

	secv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/security/v1alpha1"
	statsv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/stats/v1alpha1"
)

// +genclient
// +genclient:nonNamespaced
// +genclient:onlyVerbs=list,get,watch
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// AppliedToGroup is the message format of antrea/pkg/controller/types.AppliedToGroup in an API response.
type AppliedToGroup struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	// Pods is a list of Pods selected by this group.
	Pods []GroupMemberPod `json:"pods,omitempty" protobuf:"bytes,2,rep,name=pods"`
	// GroupMembers is list of resources selected by this group. This eventually will replace Pods
	GroupMembers []GroupMember `json:"groupMembers,omitempty" protobuf:"bytes,3,rep,name=groupMembers"`
}

// PodReference represents a Pod Reference.
type PodReference struct {
	// The name of this pod.
	Name string `json:"name,omitempty" protobuf:"bytes,1,opt,name=name"`
	// The namespace of this pod.
	Namespace string `json:"namespace,omitempty" protobuf:"bytes,2,opt,name=namespace"`
}

// NamedPort represents a Port with a name on Pod.
type NamedPort struct {
	// Port represents the Port number.
	Port int32 `json:"port,omitempty" protobuf:"varint,1,opt,name=port"`
	// Name represents the associated name with this Port number.
	Name string `json:"name,omitempty" protobuf:"bytes,2,opt,name=name"`
	// Protocol for port. Must be UDP, TCP, or SCTP.
	Protocol Protocol `json:"protocol,omitempty" protobuf:"bytes,3,opt,name=protocol"`
}

// GroupMemberPod represents a GroupMember related to Pods.
type GroupMemberPod struct {
	// Pod maintains the reference to the Pod.
	Pod *PodReference `json:"pod,omitempty" protobuf:"bytes,1,opt,name=pod"`
	// IP maintains the IPAddress associated with the Pod.
	IP IPAddress `json:"ip,omitempty" protobuf:"bytes,2,opt,name=ip"`
	// Ports maintain the named port mapping of this Pod.
	Ports []NamedPort `json:"ports,omitempty" protobuf:"bytes,3,rep,name=ports"`
}

// ExternalEntityReference represents a ExternalEntity Reference.
type ExternalEntityReference struct {
	// The name of this ExternalEntity.
	Name string `json:"name,omitempty" protobuf:"bytes,1,opt,name=name"`
	// The namespace of this ExternalEntity.
	Namespace string `json:"namespace,omitempty" protobuf:"bytes,2,opt,name=namespace"`
}

// Endpoint represents an external endpoint.
type Endpoint struct {
	// IP is the IP address of the Endpoint.
	IP IPAddress `json:"ip,omitempty" protobuf:"bytes,1,opt,name=ip"`
	// Ports is the list NamedPort of the Endpoint.
	Ports []NamedPort `json:"ports,omitempty" protobuf:"bytes,2,rep,name=ports"`
}

// GroupMember represents resource member to be populated in Groups.
// This supersedes GroupMemberPod, and will eventually replace it.
type GroupMember struct {
	// Pod maintains the reference to the Pod.
	Pod *PodReference `json:"pod,omitempty" protobuf:"bytes,1,opt,name=pod"`

	// ExternalEntity maintains the reference to the ExternalEntity.
	ExternalEntity *ExternalEntityReference `json:"externalEntity,omitempty" protobuf:"bytes,2,opt,name=externalEntity"`

	// Endpoints maintains a list of EndPoints associated with this groupMember.
	Endpoints []Endpoint `json:"endpoints,omitempty" protobuf:"bytes,3,rep,name=endpoints"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// AppliedToGroupPatch describes the incremental update of an AppliedToGroup.
type AppliedToGroupPatch struct {
	metav1.TypeMeta     `json:",inline"`
	metav1.ObjectMeta   `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	AddedPods           []GroupMemberPod `json:"addedPods,omitempty" protobuf:"bytes,2,rep,name=addedPods"`
	RemovedPods         []GroupMemberPod `json:"removedPods,omitempty" protobuf:"bytes,3,rep,name=removedPods"`
	AddedGroupMembers   []GroupMember    `json:"addedGroupMembers,omitempty" protobuf:"bytes,4,rep,name=addedGroupMembers"`
	RemovedGroupMembers []GroupMember    `json:"removedGroupMembers,omitempty" protobuf:"bytes,5,rep,name=removedGroupMembers"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// AppliedToGroupList is a list of AppliedToGroup objects.
type AppliedToGroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	Items           []AppliedToGroup `json:"items" protobuf:"bytes,2,rep,name=items"`
}

// +genclient
// +genclient:nonNamespaced
// +genclient:onlyVerbs=list,get,watch
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// AddressGroup is the message format of antrea/pkg/controller/types.AddressGroup in an API response.
type AddressGroup struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	Pods              []GroupMemberPod `json:"pods,omitempty" protobuf:"bytes,2,rep,name=pods"`
	GroupMembers      []GroupMember    `json:"groupMembers,omitempty" protobuf:"bytes,3,rep,name=groupMembers"`
}

// IPAddress describes a single IP address. Either an IPv4 or IPv6 address must be set.
type IPAddress []byte

// IPNet describes an IP network.
type IPNet struct {
	IP           IPAddress `json:"ip,omitempty" protobuf:"bytes,1,opt,name=ip"`
	PrefixLength int32     `json:"prefixLength,omitempty" protobuf:"varint,2,opt,name=prefixLength"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// AddressGroupPatch describes the incremental update of an AddressGroup.
type AddressGroupPatch struct {
	metav1.TypeMeta     `json:",inline"`
	metav1.ObjectMeta   `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	AddedPods           []GroupMemberPod `json:"addedPods,omitempty" protobuf:"bytes,2,rep,name=addedPods"`
	RemovedPods         []GroupMemberPod `json:"removedPods,omitempty" protobuf:"bytes,3,rep,name=removedPods"`
	AddedGroupMembers   []GroupMember    `json:"addedGroupMembers,omitempty" protobuf:"bytes,4,rep,name=addedGroupMembers"`
	RemovedGroupMembers []GroupMember    `json:"removedGroupMembers,omitempty" protobuf:"bytes,5,rep,name=removedGroupMembers"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// AddressGroupList is a list of AddressGroup objects.
type AddressGroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	Items           []AddressGroup `json:"items" protobuf:"bytes,2,rep,name=items"`
}

type NetworkPolicyType string

const (
	K8sNetworkPolicy           NetworkPolicyType = "K8sNetworkPolicy"
	AntreaClusterNetworkPolicy NetworkPolicyType = "AntreaClusterNetworkPolicy"
	AntreaNetworkPolicy        NetworkPolicyType = "AntreaNetworkPolicy"
)

type NetworkPolicyReference struct {
	// Type of the NetworkPolicy.
	Type NetworkPolicyType `json:"type,omitempty" protobuf:"bytes,1,opt,name=type,casttype=NetworkPolicyType"`
	// Namespace of the NetworkPolicy. It's empty for Antrea ClusterNetworkPolicy.
	Namespace string `json:"namespace,omitempty" protobuf:"bytes,2,opt,name=namespace"`
	// Name of the NetworkPolicy.
	Name string `json:"name,omitempty" protobuf:"bytes,3,opt,name=name"`
	// UID of the NetworkPolicy.
	UID types.UID `json:"uid,omitempty" protobuf:"bytes,4,opt,name=uid,casttype=k8s.io/apimachinery/pkg/types.UID"`
}

// +genclient
// +genclient:onlyVerbs=list,get,watch
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// NetworkPolicy is the message format of antrea/pkg/controller/types.NetworkPolicy in an API response.
type NetworkPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	// Rules is a list of rules to be applied to the selected Pods.
	Rules []NetworkPolicyRule `json:"rules,omitempty" protobuf:"bytes,2,rep,name=rules"`
	// AppliedToGroups is a list of names of AppliedToGroups to which this policy applies.
	AppliedToGroups []string `json:"appliedToGroups,omitempty" protobuf:"bytes,3,rep,name=appliedToGroups"`
	// Priority represents the relative priority of this Network Policy as compared to
	// other Network Policies. Priority will be unset (nil) for K8s NetworkPolicy.
	Priority *float64 `json:"priority,omitempty" protobuf:"fixed64,4,opt,name=priority"`
	// TierPriority represents the priority of the Tier associated with this Network
	// Policy. The TierPriority will remain nil for K8s NetworkPolicy.
	TierPriority *int32 `json:"tierPriority,omitempty" protobuf:"varint,5,opt,name=tierPriority"`
	// Reference to the original NetworkPolicy that the internal NetworkPolicy is created for.
	SourceRef *NetworkPolicyReference `json:"sourceRef,omitempty" protobuf:"bytes,6,opt,name=sourceRef"`
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
	Direction Direction `json:"direction,omitempty" protobuf:"bytes,1,opt,name=direction"`
	// From represents sources which should be able to access the pods selected by the policy.
	From NetworkPolicyPeer `json:"from,omitempty" protobuf:"bytes,2,opt,name=from"`
	// To represents destinations which should be able to be accessed by the pods selected by the policy.
	To NetworkPolicyPeer `json:"to,omitempty" protobuf:"bytes,3,opt,name=to"`
	// Services is a list of services which should be matched.
	Services []Service `json:"services,omitempty" protobuf:"bytes,4,rep,name=services"`
	// Priority defines the priority of the Rule as compared to other rules in the
	// NetworkPolicy.
	Priority int32 `json:"priority,omitempty" protobuf:"varint,5,opt,name=priority"`
	// Action specifies the action to be applied on the rule. i.e. Allow/Drop. An empty
	// action “nil” defaults to Allow action, which would be the case for rules created for
	// K8s Network Policy.
	Action *secv1alpha1.RuleAction `json:"action,omitempty" protobuf:"bytes,6,opt,name=action,casttype=github.com/vmware-tanzu/antrea/pkg/apis/security/v1alpha1.RuleAction"`
	// EnableLogging indicates whether or not to generate logs when rules are matched. Default to false.
	EnableLogging bool `json:"enableLogging" protobuf:"varint,7,opt,name=enableLogging"`
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
	Protocol *Protocol `json:"protocol,omitempty" protobuf:"bytes,1,opt,name=protocol"`
	// The port name or number on the given protocol. If not specified, this matches all port numbers.
	// +optional
	Port *intstr.IntOrString `json:"port,omitempty" protobuf:"bytes,2,opt,name=port"`
}

// NetworkPolicyPeer describes a peer of NetworkPolicyRules.
// It could be a list of names of AddressGroups and/or a list of IPBlock.
type NetworkPolicyPeer struct {
	// A list of names of AddressGroups.
	AddressGroups []string `json:"addressGroups,omitempty" protobuf:"bytes,1,rep,name=addressGroups"`
	// A list of IPBlock.
	IPBlocks []IPBlock `json:"ipBlocks,omitempty" protobuf:"bytes,2,rep,name=ipBlocks"`
}

// IPBlock describes a particular CIDR (Ex. "192.168.1.1/24"). The except entry describes CIDRs that should
// not be included within this rule.
type IPBlock struct {
	// CIDR is an IPNet represents the IP Block.
	CIDR IPNet `json:"cidr" protobuf:"bytes,1,name=cidr"`
	// Except is a slice of IPNets that should not be included within an IP Block.
	// Except values will be rejected if they are outside the CIDR range.
	// +optional
	Except []IPNet `json:"except,omitempty" protobuf:"bytes,2,rep,name=except"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// NetworkPolicyList is a list of NetworkPolicy objects.
type NetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	Items           []NetworkPolicy `json:"items" protobuf:"bytes,2,rep,name=items"`
}

// +genclient
// +genclient:nonNamespaced
// +genclient:onlyVerbs=create
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NodeStatsSummary contains stats produced on a Node. It's used by the antrea-agents to report stats to the antrea-controller.
type NodeStatsSummary struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// The TrafficStats of K8s NetworkPolicies collected from the Node.
	NetworkPolicies []NetworkPolicyStats `json:"networkPolicies,omitempty" protobuf:"bytes,2,rep,name=networkPolicies"`
	// The TrafficStats of Antrea ClusterNetworkPolicies collected from the Node.
	AntreaClusterNetworkPolicies []NetworkPolicyStats `json:"antreaClusterNetworkPolicies,omitempty" protobuf:"bytes,3,rep,name=antreaClusterNetworkPolicies"`
	// The TrafficStats of Antrea NetworkPolicies collected from the Node.
	AntreaNetworkPolicies []NetworkPolicyStats `json:"antreaNetworkPolicies,omitempty" protobuf:"bytes,4,rep,name=antreaNetworkPolicies"`
}

// NetworkPolicyStats contains the information and traffic stats of a NetworkPolicy.
type NetworkPolicyStats struct {
	// The reference of the NetworkPolicy.
	NetworkPolicy NetworkPolicyReference `json:"networkPolicy,omitempty" protobuf:"bytes,1,opt,name=networkPolicy"`
	// The stats of the NetworkPolicy.
	TrafficStats statsv1alpha1.TrafficStats `json:"trafficStats,omitempty" protobuf:"bytes,2,opt,name=trafficStats"`
}
