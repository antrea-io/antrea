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

package v1beta2

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	statsv1alpha1 "antrea.io/antrea/pkg/apis/stats/v1alpha1"
)

// +genclient
// +genclient:nonNamespaced
// +genclient:onlyVerbs=list,get,watch
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AppliedToGroup is the message format of antrea/pkg/controller/types.AppliedToGroup in an API response.
type AppliedToGroup struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	// GroupMembers is list of resources selected by this group.
	GroupMembers []GroupMember `json:"groupMembers,omitempty" protobuf:"bytes,2,rep,name=groupMembers"`
}

// PodReference represents a Pod Reference.
type PodReference struct {
	// The name of this Pod.
	Name string `json:"name,omitempty" protobuf:"bytes,1,opt,name=name"`
	// The Namespace of this Pod.
	Namespace string `json:"namespace,omitempty" protobuf:"bytes,2,opt,name=namespace"`
}

// ServiceReference represents reference to a v1.Service.
type ServiceReference struct {
	// The name of this Service.
	Name string `json:"name,omitempty" protobuf:"bytes,1,opt,name=name"`
	// The Namespace of this Service.
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

// ExternalEntityReference represents a ExternalEntity Reference.
type ExternalEntityReference struct {
	// The name of this ExternalEntity.
	Name string `json:"name,omitempty" protobuf:"bytes,1,opt,name=name"`
	// The Namespace of this ExternalEntity.
	Namespace string `json:"namespace,omitempty" protobuf:"bytes,2,opt,name=namespace"`
}

// GroupMember represents resource member to be populated in Groups.
type GroupMember struct {
	// Pod maintains the reference to the Pod.
	Pod *PodReference `json:"pod,omitempty" protobuf:"bytes,1,opt,name=pod"`
	// ExternalEntity maintains the reference to the ExternalEntity.
	ExternalEntity *ExternalEntityReference `json:"externalEntity,omitempty" protobuf:"bytes,2,opt,name=externalEntity"`
	// IP is the IP address of the Endpoints associated with the GroupMember.
	IPs []IPAddress `json:"ips,omitempty" protobuf:"bytes,3,rep,name=ips"`
	// Ports is the list NamedPort of the GroupMember.
	Ports []NamedPort `json:"ports,omitempty" protobuf:"bytes,4,rep,name=ports"`
}

// +genclient
// +genclient:nonNamespaced
// +genclient:onlyVerbs=get
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ClusterGroupMembers is a list of GroupMember objects or ipBlocks that are currently selected by a ClusterGroup.
type ClusterGroupMembers struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	EffectiveMembers  []GroupMember `json:"effectiveMembers" protobuf:"bytes,2,rep,name=effectiveMembers"`
	EffectiveIPBlocks []IPNet       `json:"effectiveIPBlocks" protobuf:"bytes,3,rep,name=effectiveIPBlocks"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AppliedToGroupPatch describes the incremental update of an AppliedToGroup.
type AppliedToGroupPatch struct {
	metav1.TypeMeta     `json:",inline"`
	metav1.ObjectMeta   `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	AddedGroupMembers   []GroupMember `json:"addedGroupMembers,omitempty" protobuf:"bytes,2,rep,name=addedGroupMembers"`
	RemovedGroupMembers []GroupMember `json:"removedGroupMembers,omitempty" protobuf:"bytes,3,rep,name=removedGroupMembers"`
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
	GroupMembers      []GroupMember `json:"groupMembers,omitempty" protobuf:"bytes,2,rep,name=groupMembers"`
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
	AddedGroupMembers   []GroupMember `json:"addedGroupMembers,omitempty" protobuf:"bytes,2,rep,name=addedGroupMembers"`
	RemovedGroupMembers []GroupMember `json:"removedGroupMembers,omitempty" protobuf:"bytes,3,rep,name=removedGroupMembers"`
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
// +genclient:nonNamespaced
// +genclient:onlyVerbs=list,get,watch
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NetworkPolicy is the message format of antrea/pkg/controller/types.NetworkPolicy in an API response.
type NetworkPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	// Rules is a list of rules to be applied to the selected GroupMembers.
	Rules []NetworkPolicyRule `json:"rules,omitempty" protobuf:"bytes,2,rep,name=rules"`
	// AppliedToGroups is a list of names of AppliedToGroups to which this policy applies.
	// Cannot be set in conjunction with any NetworkPolicyRule.AppliedToGroups in Rules.
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
	// From represents sources which should be able to access the GroupMembers selected by the policy.
	From NetworkPolicyPeer `json:"from,omitempty" protobuf:"bytes,2,opt,name=from"`
	// To represents destinations which should be able to be accessed by the GroupMembers selected by the policy.
	To NetworkPolicyPeer `json:"to,omitempty" protobuf:"bytes,3,opt,name=to"`
	// Services is a list of services which should be matched.
	Services []Service `json:"services,omitempty" protobuf:"bytes,4,rep,name=services"`
	// Priority defines the priority of the Rule as compared to other rules in the
	// NetworkPolicy.
	Priority int32 `json:"priority,omitempty" protobuf:"varint,5,opt,name=priority"`
	// Action specifies the action to be applied on the rule. i.e. Allow/Drop. An empty
	// action “nil” defaults to Allow action, which would be the case for rules created for
	// K8s Network Policy.
	Action *crdv1alpha1.RuleAction `json:"action,omitempty" protobuf:"bytes,6,opt,name=action,casttype=antrea.io/antrea/pkg/apis/security/v1alpha1.RuleAction"`
	// EnableLogging indicates whether or not to generate logs when rules are matched. Default to false.
	EnableLogging bool `json:"enableLogging" protobuf:"varint,7,opt,name=enableLogging"`
	// AppliedToGroups is a list of names of AppliedToGroups to which this rule applies.
	// Cannot be set in conjunction with NetworkPolicy.AppliedToGroups of the NetworkPolicy
	// that this Rule is referred to.
	AppliedToGroups []string `json:"appliedToGroups,omitempty" protobuf:"bytes,8,opt,name=appliedToGroups"`
	// Name describes the intention of this rule.
	// Name should be unique within the policy.
	Name string `json:"name,omitempty" protobuf:"bytes,9,opt,name=name"`
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
	// ProtocolICMP is the ICMP protocol.
	ProtocolICMP Protocol = "ICMP"
)

// Service describes a port to allow traffic on.
type Service struct {
	// The protocol (TCP, UDP, SCTP, or ICMP) which traffic must match. If not specified, this
	// field defaults to TCP.
	// +optional
	Protocol *Protocol `json:"protocol,omitempty" protobuf:"bytes,1,opt,name=protocol"`
	// Port and EndPort can only be specified, when the Protocol is TCP, UDP, or SCTP.
	// Port defines the port name or number on the given protocol. If not specified
	// and the Protocol is TCP, UDP, or SCTP, this matches all port numbers.
	// +optional
	Port *intstr.IntOrString `json:"port,omitempty" protobuf:"bytes,2,opt,name=port"`
	// EndPort defines the end of the port range, being the end included within the range.
	// It can only be specified when a numerical `port` is specified.
	// +optional
	EndPort *int32 `json:"endPort,omitempty" protobuf:"bytes,3,opt,name=endPort"`
	// ICMPType and ICMPCode can only be specified, when the Protocol is ICMP. If they
	// both are not specified and the Protocol is ICMP, this matches all ICMP traffic.
	// +optional
	ICMPType *int32 `json:"icmpType,omitempty" protobuf:"bytes,4,opt,name=icmpType"`
	ICMPCode *int32 `json:"icmpCode,omitempty" protobuf:"bytes,5,opt,name=icmpCode"`
}

// NetworkPolicyPeer describes a peer of NetworkPolicyRules.
// It could be a list of names of AddressGroups and/or a list of IPBlock.
type NetworkPolicyPeer struct {
	// A list of names of AddressGroups.
	AddressGroups []string `json:"addressGroups,omitempty" protobuf:"bytes,1,rep,name=addressGroups"`
	// A list of IPBlock.
	IPBlocks []IPBlock `json:"ipBlocks,omitempty" protobuf:"bytes,2,rep,name=ipBlocks"`
	// A list of exact FQDN names or FQDN wildcard expressions.
	// This field can only be possibly set for NetworkPolicyPeer of egress rules.
	FQDNs []string `json:"fqdns,omitempty" protobuf:"bytes,3,rep,name=fqdns"`
	// A list of ServiceReference.
	// This field can only be possibly set for NetworkPolicyPeer of egress rules.
	ToServices []ServiceReference `json:"toServices,omitempty" protobuf:"bytes,4,rep,name=toServices"`
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
	// The stats of the NetworkPolicy rules. It's empty for K8s NetworkPolicies as they don't have rule name to identify a rule.
	RuleTrafficStats []statsv1alpha1.RuleTrafficStats `json:"ruleTrafficStats,omitempty" protobuf:"bytes,3,rep,name=ruleTrafficStats"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NetworkPolicyStatus is the status of a NetworkPolicy.
type NetworkPolicyStatus struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	// Nodes contains statuses produced on a list of Nodes.
	Nodes []NetworkPolicyNodeStatus `json:"nodes,omitempty" protobuf:"bytes,2,rep,name=nodes"`
}

// NetworkPolicyNodeStatus is the status of a NetworkPolicy on a Node.
type NetworkPolicyNodeStatus struct {
	// The name of the Node that produces the status.
	NodeName string `json:"nodeName,omitempty" protobuf:"bytes,1,opt,name=nodeName"`
	// The generation realized by the Node.
	Generation int64 `json:"generation,omitempty" protobuf:"varint,2,opt,name=generation"`
}

type GroupReference struct {
	// Namespace of the Group. Empty for ClusterGroup.
	Namespace string `json:"namespace,omitempty" protobuf:"bytes,1,opt,name=namespace"`
	// Name of the Group.
	Name string `json:"name,omitempty" protobuf:"bytes,2,opt,name=name"`
	// UID of the Group.
	UID types.UID `json:"uid,omitempty" protobuf:"bytes,3,opt,name=uid,casttype=k8s.io/apimachinery/pkg/types.UID"`
}

// +genclient
// +genclient:onlyVerbs=get
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// GroupAssociation is the message format in an API response for groupassociation queries.
type GroupAssociation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	// AssociatedGroups is a list of GroupReferences that is associated with the
	// Pod/ExternalEntity being queried.
	AssociatedGroups []GroupReference `json:"associatedGroups" protobuf:"bytes,2,rep,name=associatedGroups"`
}

// +genclient
// +genclient:nonNamespaced
// +genclient:onlyVerbs=list,get,watch
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type EgressGroup struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	// GroupMembers is list of resources selected by this group.
	GroupMembers []GroupMember `json:"groupMembers,omitempty" protobuf:"bytes,2,rep,name=groupMembers"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// EgressGroupPatch describes the incremental update of an EgressGroup.
type EgressGroupPatch struct {
	metav1.TypeMeta
	metav1.ObjectMeta   `protobuf:"bytes,1,opt,name=objectMeta"`
	AddedGroupMembers   []GroupMember `protobuf:"bytes,2,rep,name=addedGroupMembers"`
	RemovedGroupMembers []GroupMember `protobuf:"bytes,3,rep,name=removedGroupMembers"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// EgressGroupList is a list of EgressGroup objects.
type EgressGroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	Items           []EgressGroup `json:"items" protobuf:"bytes,2,rep,name=items"`
}
