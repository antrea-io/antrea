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
	"k8s.io/apimachinery/pkg/util/intstr"
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
}

// PodReference represents a Pod Reference.
type PodReference struct {
	// The name of this pod.
	Name string `json:"name,omitempty" protobuf:"bytes,1,opt,name=name"`
	// The namespace of this pod.
	Namespace string `json:"namespace,omitempty" protobuf:"bytes,2,opt,name=namespace"`
}

// ContainerPort represents a NamedPort on Pod.
type ContainerPort struct {
	// Port represents the Port number.
	Port int32 `json:"port,omitempty" protobuf:"varint,1,opt,name=port"`
	// Name represents the associated name with this Port number.
	Name string `json:"name,omitempty" protobuf:"bytes,2,opt,name=name"`
}

// GroupMemberPod represents a GroupMember related to Pods.
type GroupMemberPod struct {
	// Pod maintains the reference to the Pod.
	Pod PodReference `json:"pod,omitempty" protobuf:"bytes,1,opt,name=pod"`
	// IP maintains the IPAddress associated with the Pod.
	IP IPAddress `json:"ip,omitempty" protobuf:"bytes,2,opt,name=ip"`
	// Ports maintain the named port mapping of this Pod.
	Ports []ContainerPort `json:"ports,omitempty" protobuf:"bytes,3,rep,name=ports"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// AppliedToGroupPatch describes the incremental update of an AppliedToGroup.
type AppliedToGroupPatch struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	AddedPods         []GroupMemberPod `json:"addedPods,omitempty" protobuf:"bytes,2,rep,name=addedPods"`
	RemovedPods       []GroupMemberPod `json:"removedPods,omitempty" protobuf:"bytes,3,rep,name=removedPods"`
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
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	AddedPods         []GroupMemberPod `json:"addedPods,omitempty" protobuf:"bytes,2,rep,name=addedPods"`
	RemovedPods       []GroupMemberPod `json:"removedPods,omitempty" protobuf:"bytes,3,rep,name=removedPods"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// AddressGroupList is a list of AddressGroup objects.
type AddressGroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	Items           []AddressGroup `json:"items" protobuf:"bytes,2,rep,name=items"`
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
