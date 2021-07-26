// Copyright 2021 Antrea Authors
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

package v1alpha1

import (
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"net"
)

type TraceflowPhase string

const (
	Pending   TraceflowPhase = "Pending"
	Running   TraceflowPhase = "Running"
	Succeeded TraceflowPhase = "Succeeded"
	Failed    TraceflowPhase = "Failed"
)

type TraceflowComponent string

const (
	ComponentSpoofGuard    TraceflowComponent = "SpoofGuard"
	ComponentLB            TraceflowComponent = "LB"
	ComponentRouting       TraceflowComponent = "Routing"
	ComponentNetworkPolicy TraceflowComponent = "NetworkPolicy"
	ComponentForwarding    TraceflowComponent = "Forwarding"
)

type TraceflowAction string

const (
	ActionDelivered TraceflowAction = "Delivered"
	ActionReceived  TraceflowAction = "Received"
	ActionForwarded TraceflowAction = "Forwarded"
	ActionDropped   TraceflowAction = "Dropped"
	ActionRejected  TraceflowAction = "Rejected"
	// ActionForwardedOutOfOverlay indicates that the packet has been forwarded out of the network
	// managed by Antrea. This indicates that the Traceflow request can be considered complete.
	ActionForwardedOutOfOverlay TraceflowAction = "ForwardedOutOfOverlay"
)

// List the supported protocols and their codes in traceflow.
// According to code in Antrea agent and controller, default protocol is ICMP if protocol is not inputted by users.
const (
	ICMPProtocol int32 = 1
	TCPProtocol  int32 = 6
	UDPProtocol  int32 = 17
	SCTPProtocol int32 = 132
)

var SupportedProtocols = map[string]int32{
	"TCP":  TCPProtocol,
	"UDP":  UDPProtocol,
	"ICMP": ICMPProtocol,
}

var ProtocolsToString = map[int32]string{
	TCPProtocol:  "TCP",
	UDPProtocol:  "UDP",
	ICMPProtocol: "ICMP",
	SCTPProtocol: "SCTP",
}

// List the supported destination types in traceflow.
const (
	DstTypePod     = "Pod"
	DstTypeService = "Service"
	DstTypeIPv4    = "IPv4"
)

var SupportedDestinationTypes = []string{
	DstTypePod,
	DstTypeService,
	DstTypeIPv4,
}

// List the ethernet types.
const (
	EtherTypeIPv4 uint16 = 0x0800
	EtherTypeIPv6 uint16 = 0x86DD
)

// Default timeout in seconds.
const DefaultTraceflowTimeout uint16 = 20

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type Traceflow struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TraceflowSpec   `json:"spec,omitempty"`
	Status TraceflowStatus `json:"status,omitempty"`
}

// TraceflowSpec describes the spec of the traceflow.
type TraceflowSpec struct {
	Source      Source      `json:"source,omitempty"`
	Destination Destination `json:"destination,omitempty"`
	Packet      Packet      `json:"packet,omitempty"`
	// LiveTraffic indicates the Traceflow is to trace the live traffic
	// rather than an injected packet, when set to true. The first packet of
	// the first connection that matches the packet spec will be traced.
	LiveTraffic bool `json:"liveTraffic,omitempty"`
	// DroppedOnly indicates only the dropped packet should be captured in a
	// live-traffic Traceflow.
	DroppedOnly bool `json:"droppedOnly,omitempty"`
	// Timeout specifies the timeout of the Traceflow in seconds. Defaults
	// to 20 seconds if not set.
	Timeout uint16 `json:"timeout,omitempty"`
}

// Source describes the source spec of the traceflow.
type Source struct {
	// Namespace is the source namespace.
	Namespace string `json:"namespace,omitempty"`
	// Pod is the source pod.
	Pod string `json:"pod,omitempty"`
	// IP is the source IPv4 or IPv6 address. IP as the source is supported
	// only for live-traffic Traceflow.
	IP string `json:"ip,omitempty"`
}

// Destination describes the destination spec of the traceflow.
type Destination struct {
	// Namespace is the destination namespace.
	Namespace string `json:"namespace,omitempty"`
	// Pod is the destination pod, exclusive with destination service.
	Pod string `json:"pod,omitempty"`
	// Service is the destination service, exclusive with destination pod.
	Service string `json:"service,omitempty"`
	// IP is the destination IPv4 or IPv6 address.
	IP string `json:"ip,omitempty"`
}

// IPHeader describes spec of an IPv4 header.
type IPHeader struct {
	// SrcIP is the source IP.
	SrcIP string `json:"srcIP,omitempty" yaml:"srcIP,omitempty"`
	// Protocol is the IP protocol.
	Protocol int32 `json:"protocol,omitempty" yaml:"protocol,omitempty"`
	// TTL is the IP TTL.
	TTL int32 `json:"ttl,omitempty" yaml:"ttl,omitempty"`
	// Flags is the flags for IP.
	Flags int32 `json:"flags,omitempty" yaml:"flags,omitempty"`
}

// IPv6Header describes spec of an IPv6 header.
type IPv6Header struct {
	// SrcIP is the source IPv6.
	SrcIP string `json:"srcIP,omitempty" yaml:"srcIP,omitempty"`
	// NextHeader is the IPv6 protocol.
	NextHeader *int32 `json:"nextHeader,omitempty" yaml:"nextHeader,omitempty"`
	// HopLimit is the IPv6 Hop Limit.
	HopLimit int32 `json:"hopLimit,omitempty" yaml:"hopLimit,omitempty"`
}

// TransportHeader describes spec of a TransportHeader.
type TransportHeader struct {
	ICMP *ICMPEchoRequestHeader `json:"icmp,omitempty" yaml:"icmp,omitempty"`
	UDP  *UDPHeader             `json:"udp,omitempty" yaml:"udp,omitempty"`
	TCP  *TCPHeader             `json:"tcp,omitempty" yaml:"tcp,omitempty"`
}

// ICMPEchoRequestHeader describes spec of an ICMP echo request header.
type ICMPEchoRequestHeader struct {
	// ID is the ICMPEchoRequestHeader ID.
	ID int32 `json:"id,omitempty"`
	// Sequence is the ICMPEchoRequestHeader sequence.
	Sequence int32 `json:"sequence,omitempty"`
}

// UDPHeader describes spec of a UDP header.
type UDPHeader struct {
	// SrcPort is the source port.
	SrcPort int32 `json:"srcPort,omitempty"`
	// DstPort is the destination port.
	DstPort int32 `json:"dstPort,omitempty"`
}

// TCPHeader describes spec of a TCP header.
type TCPHeader struct {
	// SrcPort is the source port.
	SrcPort int32 `json:"srcPort,omitempty"`
	// DstPort is the destination port.
	DstPort int32 `json:"dstPort,omitempty"`
	// Flags are flags in the header.
	Flags int32 `json:"flags,omitempty"`
}

// Packet includes header info.
type Packet struct {
	SrcIP string `json:"srcIP,omitempty"`
	DstIP string `json:"dstIP,omitempty"`
	// Length is the IP packet length (includes the IPv4 or IPv6 header length).
	Length uint16 `json:"length,omitempty"`
	// TODO: change type IPHeader to *IPHeader and correct all internal references
	IPHeader        IPHeader        `json:"ipHeader,omitempty"`
	IPv6Header      *IPv6Header     `json:"ipv6Header,omitempty"`
	TransportHeader TransportHeader `json:"transportHeader,omitempty"`
}

// TraceflowStatus describes current status of the traceflow.
type TraceflowStatus struct {
	// Phase is the Traceflow phase.
	Phase TraceflowPhase `json:"phase,omitempty"`
	// Reason is a message indicating the reason of the traceflow's current phase.
	Reason string `json:"reason,omitempty"`
	// DataplaneTag is a tag to identify a traceflow session across Nodes.
	DataplaneTag uint8 `json:"dataplaneTag,omitempty"`
	// Results is the collection of all observations on different nodes.
	Results []NodeResult `json:"results,omitempty"`
	// CapturedPacket is the captured packet in live-traffic Traceflow.
	CapturedPacket *Packet `json:"capturedPacket,omitempty"`
}

type NodeResult struct {
	// Node is the node of the observation.
	Node string `json:"node,omitempty" yaml:"node,omitempty"`
	// Role of the node like sender, receiver, etc.
	Role string `json:"role,omitempty" yaml:"role,omitempty"`
	// Timestamp is the timestamp of the observations on the node.
	Timestamp int64 `json:"timestamp,omitempty" yaml:"timestamp,omitempty"`
	// Observations includes all observations from sender nodes, receiver ones, etc.
	Observations []Observation `json:"observations,omitempty" yaml:"observations,omitempty"`
}

// Observation describes those from sender nodes or receiver nodes.
type Observation struct {
	// Component is the observation component.
	Component TraceflowComponent `json:"component,omitempty" yaml:"component,omitempty"`
	// ComponentInfo is the extension of Component field.
	ComponentInfo string `json:"componentInfo,omitempty" yaml:"componentInfo,omitempty"`
	// Action is the action to the observation.
	Action TraceflowAction `json:"action,omitempty" yaml:"action,omitempty"`
	// Pod is the combination of Pod name and Pod Namespace.
	Pod string `json:"pod,omitempty" yaml:"pod,omitempty"`
	// DstMAC is the destination MAC.
	DstMAC string `json:"dstMAC,omitempty" yaml:"dstMAC,omitempty"`
	// NetworkPolicy is the combination of Namespace and NetworkPolicyName.
	NetworkPolicy string `json:"networkPolicy,omitempty" yaml:"networkPolicy,omitempty"`
	// TTL is the observation TTL.
	TTL int32 `json:"ttl,omitempty" yaml:"ttl,omitempty"`
	// TranslatedSrcIP is the translated source IP.
	TranslatedSrcIP string `json:"translatedSrcIP,omitempty" yaml:"translatedSrcIP,omitempty"`
	// TranslatedDstIP is the translated destination IP.
	TranslatedDstIP string `json:"translatedDstIP,omitempty" yaml:"translatedDstIP,omitempty"`
	// TunnelDstIP is the tunnel destination IP.
	TunnelDstIP string `json:"tunnelDstIP,omitempty" yaml:"tunnelDstIP,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type TraceflowList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []Traceflow `json:"items"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type NetworkPolicy struct {
	metav1.TypeMeta `json:",inline"`
	// Standard metadata of the object.
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired behavior of NetworkPolicy.
	Spec NetworkPolicySpec `json:"spec"`
	// Most recently observed status of the NetworkPolicy.
	Status NetworkPolicyStatus `json:"status"`
}

// NetworkPolicySpec defines the desired state for NetworkPolicy.
type NetworkPolicySpec struct {
	// Tier specifies the tier to which this NetworkPolicy belongs to.
	// The NetworkPolicy order will be determined based on the combination of the
	// Tier's Priority and the NetworkPolicy's own Priority. If not specified,
	// this policy will be created in the Application Tier right above the K8s
	// NetworkPolicy which resides at the bottom.
	Tier string `json:"tier,omitempty"`
	// Priority specfies the order of the NetworkPolicy relative to other
	// NetworkPolicies.
	Priority float64 `json:"priority"`
	// Select workloads on which the rules will be applied to. Cannot be set in
	// conjunction with AppliedTo in each rule.
	// +optional
	AppliedTo []NetworkPolicyPeer `json:"appliedTo,omitempty"`
	// Set of ingress rules evaluated based on the order in which they are set.
	// Currently Ingress rule supports setting the `From` field but not the `To`
	// field within a Rule.
	// +optional
	Ingress []Rule `json:"ingress"`
	// Set of egress rules evaluated based on the order in which they are set.
	// Currently Egress rule supports setting the `To` field but not the `From`
	// field within a Rule.
	// +optional
	Egress []Rule `json:"egress"`
}

// NetworkPolicyPhase defines the phase in which a NetworkPolicy is.
type NetworkPolicyPhase string

// These are the valid values for NetworkPolicyPhase.
const (
	// NetworkPolicyPending means the NetworkPolicy has been accepted by the system, but it has not been processed by Antrea.
	NetworkPolicyPending NetworkPolicyPhase = "Pending"
	// NetworkPolicyRealizing means the NetworkPolicy has been observed by Antrea and is being realized.
	NetworkPolicyRealizing NetworkPolicyPhase = "Realizing"
	// NetworkPolicyRealized means the NetworkPolicy has been enforced to all Pods on all Nodes it applies to.
	NetworkPolicyRealized NetworkPolicyPhase = "Realized"
)

// NetworkPolicyStatus represents information about the status of a NetworkPolicy.
type NetworkPolicyStatus struct {
	// The phase of a NetworkPolicy is a simple, high-level summary of the NetworkPolicy's status.
	Phase NetworkPolicyPhase `json:"phase"`
	// The generation observed by Antrea.
	ObservedGeneration int64 `json:"observedGeneration"`
	// The number of nodes that have realized the NetworkPolicy.
	CurrentNodesRealized int32 `json:"currentNodesRealized"`
	// The total number of nodes that should realize the NetworkPolicy.
	DesiredNodesRealized int32 `json:"desiredNodesRealized"`
}

// Rule describes the traffic allowed to/from the workloads selected by
// Spec.AppliedTo. Based on the action specified in the rule, traffic is either
// allowed or denied which exactly match the specified ports and protocol.
type Rule struct {
	// Action specifies the action to be applied on the rule.
	Action *RuleAction `json:"action"`
	// Set of port and protocol allowed/denied by the rule. If this field is unset
	// or empty, this rule matches all ports.
	// +optional
	Ports []NetworkPolicyPort `json:"ports,omitempty"`
	// Rule is matched if traffic originates from workloads selected by
	// this field. If this field is empty, this rule matches all sources.
	// +optional
	From []NetworkPolicyPeer `json:"from"`
	// Rule is matched if traffic is intended for workloads selected by
	// this field. If this field is empty or missing, this rule matches all
	// destinations.
	// +optional
	To []NetworkPolicyPeer `json:"to"`
	// Name describes the intention of this rule.
	// Name should be unique within the policy.
	// +optional
	Name string `json:"name"`
	// EnableLogging is used to indicate if agent should generate logs
	// when rules are matched. Should be default to false.
	EnableLogging bool `json:"enableLogging"`
	// Select workloads on which this rule will be applied to. Cannot be set in
	// conjunction with NetworkPolicySpec/ClusterNetworkPolicySpec.AppliedTo.
	// +optional
	AppliedTo []NetworkPolicyPeer `json:"appliedTo,omitempty"`
}

// NetworkPolicyPeer describes the grouping selector of workloads.
type NetworkPolicyPeer struct {
	// IPBlock describes the IPAddresses/IPBlocks that is matched in to/from.
	// IPBlock cannot be set as part of the AppliedTo field.
	// Cannot be set with any other selector.
	// +optional
	IPBlock *IPBlock `json:"ipBlock,omitempty"`
	// Select Pods from NetworkPolicy's Namespace as workloads in
	// AppliedTo/To/From fields. If set with NamespaceSelector, Pods are
	// matched from Namespaces matched by the NamespaceSelector.
	// Cannot be set with any other selector except NamespaceSelector.
	// +optional
	PodSelector *metav1.LabelSelector `json:"podSelector,omitempty"`
	// Select all Pods from Namespaces matched by this selector, as
	// workloads in To/From fields. If set with PodSelector,
	// Pods are matched from Namespaces matched by the NamespaceSelector.
	// Cannot be set with any other selector except PodSelector or
	// ExternalEntitySelector. Cannot be set with Namespaces.
	// +optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
	// Select Pod/ExternalEntity from Namespaces matched by specifc criteria.
	// Current supported criteria is match: Self, which selects from the same
	// Namespace of the appliedTo workloads.
	// Cannot be set with any other selector except PodSelector or
	// ExternalEntitySelector. This field can only be set when NetworkPolicyPeer
	// is created for ClusterNetworkPolicy ingress/egress rules.
	// Cannot be set with NamespaceSelector.
	// +optional
	Namespaces *PeerNamespaces `json:"namespaces,omitempty"`
	// Select ExternalEntities from NetworkPolicy's Namespace as workloads
	// in AppliedTo/To/From fields. If set with NamespaceSelector,
	// ExternalEntities are matched from Namespaces matched by the
	// NamespaceSelector.
	// Cannot be set with any other selector except NamespaceSelector.
	// +optional
	ExternalEntitySelector *metav1.LabelSelector `json:"externalEntitySelector,omitempty"`
	// Group is the name of the ClusterGroup which can be set as an
	// AppliedTo or within an Ingress or Egress rule in place of
	// a stand-alone selector. A Group cannot be set with any other
	// selector.
	Group string `json:"group,omitempty"`
}

type PeerNamespaces struct {
	Match NamespaceMatchType `json:"match,omitempty"`
}

// NamespaceMatchType describes Namespace matching strategy.
type NamespaceMatchType string

const (
	NamespaceMatchSelf NamespaceMatchType = "Self"
)

// IPBlock describes a particular CIDR (Ex. "192.168.1.1/24") that is allowed
// or denied to/from the workloads matched by a Spec.AppliedTo.
type IPBlock struct {
	// CIDR is a string representing the IP Block
	// Valid examples are "192.168.1.1/24".
	CIDR string `json:"cidr"`
}

// NetworkPolicyPort describes the port and protocol to match in a rule.
type NetworkPolicyPort struct {
	// The protocol (TCP, UDP, or SCTP) which traffic must match.
	// If not specified, this field defaults to TCP.
	// +optional
	Protocol *v1.Protocol `json:"protocol,omitempty"`
	// The port on the given protocol. This can be either a numerical
	// or named port on a Pod. If this field is not provided, this
	// matches all port names and numbers.
	// +optional
	Port *intstr.IntOrString `json:"port,omitempty"`
	// EndPort defines the end of the port range, being the end included within the range.
	// It can only be specified when a numerical `port` is specified.
	// +optional
	EndPort *int32 `json:"endPort,omitempty"`
}

// RuleAction describes the action to be applied on traffic matching a rule.
type RuleAction string

const (
	// RuleActionAllow describes that the traffic matching the rule must be allowed.
	RuleActionAllow RuleAction = "Allow"
	// RuleActionDrop describes that the traffic matching the rule must be dropped.
	RuleActionDrop RuleAction = "Drop"
	// RuleActionReject indicates that the traffic matching the rule must be rejected and the
	// client will receive a response.
	RuleActionReject RuleAction = "Reject"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type NetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []NetworkPolicy `json:"items"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type ClusterNetworkPolicy struct {
	metav1.TypeMeta `json:",inline"`
	// Standard metadata of the object.
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired behavior of ClusterNetworkPolicy.
	Spec ClusterNetworkPolicySpec `json:"spec"`
	// Most recently observed status of the NetworkPolicy.
	Status NetworkPolicyStatus `json:"status"`
}

// ClusterNetworkPolicySpec defines the desired state for ClusterNetworkPolicy.
type ClusterNetworkPolicySpec struct {
	// Tier specifies the tier to which this ClusterNetworkPolicy belongs to.
	// The ClusterNetworkPolicy order will be determined based on the
	// combination of the Tier's Priority and the ClusterNetworkPolicy's own
	// Priority. If not specified, this policy will be created in the Application
	// Tier right above the K8s NetworkPolicy which resides at the bottom.
	Tier string `json:"tier,omitempty"`
	// Priority specfies the order of the ClusterNetworkPolicy relative to
	// other AntreaClusterNetworkPolicies.
	Priority float64 `json:"priority"`
	// Select workloads on which the rules will be applied to. Cannot be set in
	// conjunction with AppliedTo in each rule.
	// +optional
	AppliedTo []NetworkPolicyPeer `json:"appliedTo,omitempty"`
	// Set of ingress rules evaluated based on the order in which they are set.
	// Currently Ingress rule supports setting the `From` field but not the `To`
	// field within a Rule.
	// +optional
	Ingress []Rule `json:"ingress"`
	// Set of egress rules evaluated based on the order in which they are set.
	// Currently Egress rule supports setting the `To` field but not the `From`
	// field within a Rule.
	// +optional
	Egress []Rule `json:"egress"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type ClusterNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []ClusterNetworkPolicy `json:"items"`
}

// +genclient
// +genclient:nonNamespaced
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type Tier struct {
	metav1.TypeMeta `json:",inline"`
	// Standard metadata of the object.
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired behavior of Tier.
	Spec TierSpec `json:"spec"`
}

// TierSpec defines the desired state for Tier.
type TierSpec struct {
	// Priority specfies the order of the Tier relative to other Tiers.
	Priority int32 `json:"priority"`
	// Description is an optional field to add more information regarding
	// the purpose of this Tier.
	Description string `json:"description,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type TierList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []Tier `json:"items"`
}

type Multicast struct {
	metav1.TypeMeta `json:",inline"`
	// Standard metadata of the object.
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired behavior of Tier.
	Spec MulticastSpec `json:"spec"`
}

type MulticastSpec struct {
	// Specify the Multicast group Pods and external addresses need to join in.
	Mgroup net.IP
	// Select Pods to join the Multicast group.
	PodSelector *metav1.LabelSelector `json:"podSelector,omitempty"`
	// Specify the interfaces on which the Multicast traffic is forwarded to/from with external addresses.
	ExternalInterfaces string
	// Specify if Pod's source address is shown or translated. The default value is false.
	Local bool
}

type MulticastList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []Multicast `json:"items"`
}
