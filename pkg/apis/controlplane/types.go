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
	"fmt"
	"net"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	statsv1alpha1 "antrea.io/antrea/pkg/apis/stats/v1alpha1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AppliedToGroup is the message format of antrea/pkg/controller/types.AppliedToGroup in an API response.
type AppliedToGroup struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	// GroupMembers is a list of resources selected by this group.
	GroupMembers []GroupMember
}

// PodReference represents a Pod Reference.
type PodReference struct {
	// The name of this Pod.
	Name string
	// The Namespace of this Pod.
	Namespace string
}

// NodeReference represents a Node Reference.
type NodeReference struct {
	// The name of this Node.
	Name string
}

// ServiceReference represents reference to a v1.Service.
type ServiceReference struct {
	// The name of this Service.
	Name string
	// The Namespace of this Service.
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

// ExternalEntityReference represents a ExternalEntity Reference.
type ExternalEntityReference struct {
	// The name of this ExternalEntity.
	Name string
	// The Namespace of this ExternalEntity.
	Namespace string
}

// GroupMember represents a resource member to be populated in Groups.
type GroupMember struct {
	// Pod maintains the reference to the Pod.
	Pod *PodReference
	// ExternalEntity maintains the reference to the ExternalEntity.
	ExternalEntity *ExternalEntityReference
	// Node maintains the reference to the Node.
	Node *NodeReference
	// IP is the IP address of the Endpoints associated with the GroupMember.
	IPs []IPAddress
	// Ports is the list NamedPort of the GroupMember.
	Ports []NamedPort
	// Service is the reference to the Service. It can only be used in an AppliedTo
	// Group and only a NodePort type Service can be referred by this field.
	Service *ServiceReference
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ClusterGroupMembers is a list of GroupMember objects or ipBlocks that are currently selected by a ClusterGroup.
type ClusterGroupMembers struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	EffectiveMembers  []GroupMember
	EffectiveIPBlocks []IPNet
	TotalMembers      int64
	TotalPages        int64
	CurrentPage       int64
}

// +k8s:conversion-gen:explicit-from=net/url.Values
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// PaginationGetOptions is used to retrieve page number and page limit info from the request.
type PaginationGetOptions struct {
	metav1.TypeMeta
	Page  int64
	Limit int64
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AppliedToGroupPatch describes the incremental update of an AppliedToGroup.
type AppliedToGroupPatch struct {
	metav1.TypeMeta
	metav1.ObjectMeta
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
	// GroupMembers is a list of GroupMember selected by this group.
	GroupMembers []GroupMember
}

// IPAddress describes a single IP address. Either an IPv4 or IPv6 address must be set.
type IPAddress []byte

func (ip IPAddress) String() string {
	return net.IP(ip).String()
}

// IPNet describes an IP network.
type IPNet struct {
	IP           IPAddress
	PrefixLength int32
}

func (ipn IPNet) String() string {
	return fmt.Sprintf("%s/%d", ipn.IP.String(), ipn.PrefixLength)
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AddressGroupPatch describes the incremental update of an AddressGroup.
type AddressGroupPatch struct {
	metav1.TypeMeta
	metav1.ObjectMeta
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
	// Rules is a list of rules to be applied to the selected GroupMembers.
	Rules []NetworkPolicyRule
	// AppliedToGroups is a list of names of AppliedToGroups to which this policy applies.
	// Cannot be set in conjunction with any NetworkPolicyRule.AppliedToGroups in Rules.
	AppliedToGroups []string
	// Priority represents the relative priority of this NetworkPolicy as compared to
	// other NetworkPolicies. Priority will be unset (nil) for K8s NetworkPolicy.
	Priority *float64
	// TierPriority represents the priority of the Tier associated with this NetworkPolicy.
	// The TierPriority will remain nil for K8s NetworkPolicy.
	TierPriority *int32
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
	// From represents sources which should be able to access the GroupMembers selected by the policy.
	From NetworkPolicyPeer
	// To represents destinations which should be able to be accessed by the GroupMembers selected by the policy.
	To NetworkPolicyPeer
	// Services is a list of services which should be matched.
	Services []Service
	// Name describes the intention of this rule.
	// Name should be unique within the policy.
	Name string
	// Priority defines the priority of the Rule as compared to other rules in the
	// NetworkPolicy.
	Priority int32
	// Action specifies the action to be applied on the rule. i.e. Allow/Drop. An empty
	// action “nil” defaults to Allow action, which would be the case for rules created for
	// K8s NetworkPolicy.
	Action *crdv1alpha1.RuleAction
	// EnableLogging is used to indicate if agent should generate logs
	// when rules are matched. Should be default to false.
	EnableLogging bool
	// AppliedToGroups is a list of names of AppliedToGroups to which this rule applies.
	// Cannot be set in conjunction with NetworkPolicy.AppliedToGroups of the NetworkPolicy
	// that this Rule is referred to.
	AppliedToGroups []string
	// L7Protocols is a list of application layer protocols which should be matched.
	L7Protocols []L7Protocol
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

	ProtocolIGMP Protocol = "IGMP"
)

// Service describes a port to allow traffic on.
type Service struct {
	// The protocol (TCP, UDP, SCTP, or ICMP) which traffic must match. If not specified, this
	// field defaults to TCP.
	// +optional
	Protocol *Protocol
	// Port and EndPort can only be specified, when the Protocol is TCP, UDP, or SCTP.
	// Port defines the port name or number on the given protocol. If not specified
	// and the Protocol is TCP, UDP, or SCTP, this matches all port numbers.
	// +optional
	Port *intstr.IntOrString
	// EndPort defines the end of the port range, being the end included within the range.
	// It can only be specified when a numerical `port` is specified.
	// +optional
	EndPort *int32
	// ICMPType and ICMPCode can only be specified, when the Protocol is ICMP. If they
	// both are not specified and the Protocol is ICMP, this matches all ICMP traffic.
	ICMPType *int32
	ICMPCode *int32

	// IGMPType and GroupAddress can only be specified when the Protocol is IGMP.
	IGMPType     *int32
	GroupAddress string
}

// L7Protocol defines application layer protocol to match.
type L7Protocol struct {
	HTTP *HTTPProtocol
}

// HTTPProtocol matches HTTP requests with specific host, method, and path. All
// fields could be used alone or together. If all fields are not provided, this
// matches all HTTP requests.
type HTTPProtocol struct {
	// Host represents the hostname present in the URI or the HTTP Host header to match.
	// It does not contain the port associated with the host.
	Host string
	// Method represents the HTTP method to match.
	// It could be GET, POST, PUT, HEAD, DELETE, TRACE, OPTIONS, CONNECT and PATCH.
	Method string
	// Path represents the URI path to match (Ex. "/index.html", "/admin").
	Path string
}

// NetworkPolicyPeer describes a peer of NetworkPolicyRules.
// It could be a list of names of AddressGroups and/or a list of IPBlock.
type NetworkPolicyPeer struct {
	// A list of names of AddressGroups.
	AddressGroups []string
	// A list of IPBlock.
	IPBlocks []IPBlock
	// A list of exact FQDN names or FQDN wildcard expressions.
	// This field can only be possibly set for NetworkPolicyPeer of egress rules.
	FQDNs []string
	// A list of ServiceReference.
	// This field can only be possibly set for NetworkPolicyPeer of egress rules.
	ToServices []ServiceReference
	// A list of labelIdentities selected as ingress peers for stretched policy.
	// This field can only be possibly set for NetworkPolicyPeer of ingress rules.
	LabelIdentities []uint32
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

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NodeStatsSummary contains stats produced on a Node. It's used by the antrea-agents to report stats to the antrea-controller.
type NodeStatsSummary struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	// The TrafficStats of K8s NetworkPolicies collected from the Node.
	NetworkPolicies []NetworkPolicyStats
	// The TrafficStats of Antrea ClusterNetworkPolicies collected from the Node.
	AntreaClusterNetworkPolicies []NetworkPolicyStats
	// The TrafficStats of Antrea NetworkPolicies collected from the Node.
	AntreaNetworkPolicies []NetworkPolicyStats
	// Multicast group information from the Node.
	Multicast []MulticastGroupInfo
}

// MulticastGroupInfo contains the list of Pods that have joined a multicast group, for a given Node.
type MulticastGroupInfo struct {
	// Group is the IP of the multicast group.
	Group string
	// Pods is the list of Pods that have joined the multicast group.
	Pods []PodReference
}

// NetworkPolicyStats contains the information and traffic stats of a NetworkPolicy.
type NetworkPolicyStats struct {
	// The reference of the NetworkPolicy.
	NetworkPolicy NetworkPolicyReference
	// The stats of the NetworkPolicy.
	TrafficStats statsv1alpha1.TrafficStats
	// The stats of the NetworkPolicy rules. It's empty for K8s NetworkPolicies as they don't have rule name to identify a rule.
	RuleTrafficStats []statsv1alpha1.RuleTrafficStats
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NetworkPolicyStatus is the status of a NetworkPolicy.
type NetworkPolicyStatus struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	// Nodes contains statuses produced on a list of Nodes.
	Nodes []NetworkPolicyNodeStatus
}

// NetworkPolicyNodeStatus is the status of a NetworkPolicy on a Node.
type NetworkPolicyNodeStatus struct {
	// The name of the Node that produces the status.
	NodeName string
	// The generation realized by the Node.
	Generation int64
	// The flag to mark the NetworkPolicy realization is failed on the Node or not.
	RealizationFailure bool
	// The error message to describe why the NetworkPolicy realization is failed on the Node.
	Message string
}

type GroupReference struct {
	// Namespace of the Group. Empty for ClusterGroup.
	Namespace string
	// Name of the Group.
	Name string
	// UID of the Group.
	UID types.UID
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// GroupAssociation is a list of GroupReferences for responses to groupassociation queries.
type GroupAssociation struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	// AssociatedGroups is a list of GroupReferences that is associated with the
	// Pod/ExternalEntity being queried.
	AssociatedGroups []GroupReference
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type EgressGroup struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	// GroupMembers is a list of GroupMember selected by this group.
	GroupMembers []GroupMember
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// EgressGroupPatch describes the incremental update of an EgressGroup.
type EgressGroupPatch struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	AddedGroupMembers   []GroupMember
	RemovedGroupMembers []GroupMember
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// EgressGroupList is a list of EgressGroup objects.
type EgressGroupList struct {
	metav1.TypeMeta
	metav1.ListMeta
	Items []EgressGroup
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type SupportBundleCollection struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	ExpiredAt      metav1.Time
	SinceTime      string
	FileServer     BundleFileServer
	Authentication BundleServerAuthConfiguration
}

// BundleFileServer specifies the bundle file server information.
type BundleFileServer struct {
	// The URL of the bundle file server. It is set with format: scheme://host[:port][/path],
	// e.g, https://api.example.com:8443/v1/supportbundles/. If scheme is not set, https is used by default.
	URL string
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SupportBundleCollectionList is a list of SupportBundleCollection objects.
type SupportBundleCollectionList struct {
	metav1.TypeMeta
	metav1.ListMeta
	Items []SupportBundleCollection
}

type BasicAuthentication struct {
	Username string
	Password string
}

type BundleServerAuthConfiguration struct {
	BearerToken         string
	APIKey              string
	BasicAuthentication *BasicAuthentication
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SupportBundleCollectionStatus is the status of a SupportBundleCollection.
type SupportBundleCollectionStatus struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	// Nodes contains statuses produced on a list of Nodes.
	Nodes []SupportBundleCollectionNodeStatus
}

type SupportBundleCollectionNodeType string

const (
	SupportBundleCollectionNodeTypeNode         SupportBundleCollectionNodeType = "Node"
	SupportBundleCollectionNodeTypeExternalNode SupportBundleCollectionNodeType = "ExternalNode"
)

// SupportBundleCollectionNodeStatus is the status of a SupportBundleCollection on a Node.
type SupportBundleCollectionNodeStatus struct {
	// The name of the Node that produces the status.
	NodeName string
	// The Namespace of the Node produces the status. It is set only when NodeType is externalNode
	NodeNamespace string
	// The type of the Node that produces the status. The supported values are "Node" and "ExternalNode".
	NodeType SupportBundleCollectionNodeType
	// Completed shows if the SupportBundleCollection is successfully processed on the Node or ExternalNode or not.
	Completed bool
	// Error is the reason for which the SupportBundleCollection is failed on the Node.
	Error string
}
