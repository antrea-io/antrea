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
)

type TraceflowPhase string

const (
	// Pending is not used anymore
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
	ComponentEgress        TraceflowComponent = "Egress"
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
	ActionMarkedForSNAT         TraceflowAction = "MarkedForSNAT"
	ActionForwardedToEgressNode TraceflowAction = "ForwardedToEgressNode"
)

// List the supported protocols and their codes in traceflow.
// According to code in Antrea agent and controller, default protocol is ICMP if protocol is not provided by users.
const (
	ICMPProtocolNumber int32 = 1
	IGMPProtocolNumber int32 = 2
	TCPProtocolNumber  int32 = 6
	UDPProtocolNumber  int32 = 17
	SCTPProtocolNumber int32 = 132
)

var SupportedProtocols = map[string]int32{
	"TCP":  TCPProtocolNumber,
	"UDP":  UDPProtocolNumber,
	"ICMP": ICMPProtocolNumber,
}

var ProtocolsToString = map[int32]string{
	TCPProtocolNumber:  "TCP",
	UDPProtocolNumber:  "UDP",
	ICMPProtocolNumber: "ICMP",
	IGMPProtocolNumber: "IGMP",
	SCTPProtocolNumber: "SCTP",
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
	// StartTime is the time at which the Traceflow as started by the Antrea Controller.
	// Before K8s v1.20, null values (field not set) are not pruned, and a CR where a
	// metav1.Time field is not set would fail OpenAPI validation (type string). The
	// recommendation seems to be to use a pointer instead, and the field will be omitted when
	// serializing.
	// See https://github.com/kubernetes/kubernetes/issues/86811
	StartTime *metav1.Time `json:"startTime,omitempty"`
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
	// Egress is the name of the Egress.
	Egress string `json:"egress,omitempty" yaml:"egress,omitempty"`
	// TTL is the observation TTL.
	TTL int32 `json:"ttl,omitempty" yaml:"ttl,omitempty"`
	// TranslatedSrcIP is the translated source IP.
	TranslatedSrcIP string `json:"translatedSrcIP,omitempty" yaml:"translatedSrcIP,omitempty"`
	// TranslatedDstIP is the translated destination IP.
	TranslatedDstIP string `json:"translatedDstIP,omitempty" yaml:"translatedDstIP,omitempty"`
	// TunnelDstIP is the tunnel destination IP.
	TunnelDstIP string `json:"tunnelDstIP,omitempty" yaml:"tunnelDstIP,omitempty"`
	EgressIP    string `json:"egressIP,omitempty" yaml:"egressIP,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type TraceflowList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []Traceflow `json:"items"`
}

// IPBlock describes a particular CIDR (Ex. "192.168.1.1/24") that is allowed
// or denied to/from the workloads matched by a Spec.AppliedTo.
type IPBlock struct {
	// CIDR is a string representing the IP Block
	// Valid examples are "192.168.1.1/24".
	CIDR string `json:"cidr"`
}

// NamespacedName refers to a Namespace scoped resource.
// All fields must be used together.
type NamespacedName struct {
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ExternalNode refers to a virtual machine or a bare-metal server
// which is not a K8s node, but has Antrea agent running on it.
type ExternalNode struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ExternalNodeSpec `json:"spec,omitempty"`
}

// ExternalNodeSpec defines the desired state for ExternalNode.
type ExternalNodeSpec struct {
	// Only one network interface is supported now.
	// Other interfaces except interfaces[0] will be ignored if there are more than one interfaces.
	Interfaces []NetworkInterface `json:"interfaces,omitempty"`
}

type NetworkInterface struct {
	Name string `json:"name,omitempty"`

	IPs []string `json:"ips,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type ExternalNodeList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []ExternalNode `json:"items,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type SupportBundleCollectionList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []SupportBundleCollection `json:"items"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type SupportBundleCollection struct {
	metav1.TypeMeta `json:",inline"`
	// Standard metadata of the object.
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired behavior of SupportBundleCollection.
	Spec SupportBundleCollectionSpec `json:"spec"`
	// Most recently observed status of the SupportBundleCollection.
	Status SupportBundleCollectionStatus `json:"status"`
}

type SupportBundleCollectionSpec struct {
	Nodes         *BundleNodes         `json:"nodes,omitempty"`
	ExternalNodes *BundleExternalNodes `json:"externalNodes,omitempty"`
	// ExpirationMinutes is the requested duration of validity of the SupportBundleCollection.
	// A SupportBundleCollection will be marked as Failed if it does not finish before expiration.
	// Default is 60.
	ExpirationMinutes int32 `json:"expirationMinutes"`
	// SinceTime specifies a relative time before the current time from which to collect logs
	// A valid value is like: 1d, 2h, 30m.
	SinceTime      string                        `json:"sinceTime,omitempty"`
	FileServer     BundleFileServer              `json:"fileServer"`
	Authentication BundleServerAuthConfiguration `json:"authentication"`
}

type SupportBundleCollectionStatus struct {
	// The number of Nodes and ExternalNodes that have completed the SupportBundleCollection.
	CollectedNodes int32 `json:"collectedNodes"`
	// The total number of Nodes and ExternalNodes that should process the SupportBundleCollection.
	DesiredNodes int32 `json:"desiredNodes"`
	// Represents the latest available observations of a SupportBundleCollection current state.
	Conditions []SupportBundleCollectionCondition `json:"conditions"`
}

type SupportBundleCollectionConditionType string

const (
	// CollectionStarted is added in a SupportBundleCollection when Antrea Controller has started to handle the request.
	CollectionStarted SupportBundleCollectionConditionType = "Started"
	// CollectionCompleted is added in a SupportBundleCollection when Antrea has finished processing the collection.
	CollectionCompleted SupportBundleCollectionConditionType = "Completed"
	// CollectionFailure is added in a SupportBundleCollection when one of its required Nodes/ExternalNodes fails
	// to process the request.
	CollectionFailure SupportBundleCollectionConditionType = "CollectionFailure"
	// BundleCollected is added in a SupportBundleCollection when at least one of its required Nodes/ExternalNodes
	// successfully uploaded files to the file server.
	BundleCollected SupportBundleCollectionConditionType = "BundleCollected"
)

// SupportBundleCollectionCondition describes the state of a SupportBundleCollection at a certain point.
type SupportBundleCollectionCondition struct {
	// Type of StatefulSet condition.
	Type SupportBundleCollectionConditionType `json:"type"`
	// Status of the condition, one of True, False, Unknown.
	Status metav1.ConditionStatus `json:"status"`
	// Last time the condition transitioned from one status to another.
	// +optional
	LastTransitionTime metav1.Time `json:"lastTransitionTime,omitempty"`
	// The reason for the condition's last transition.
	// +optional
	Reason string `json:"reason,omitempty"`
	// A human-readable message indicating details about the transition.
	// +optional
	Message string `json:"message,omitempty"`
}

type BundleNodes struct {
	// List the names of certain Nodes which are expected to collect and upload
	// bundle files.
	// +optional
	NodeNames []string `json:"nodeNames,omitempty"`
	// Select certain Nodes which match the label selector.
	// +optional
	NodeSelector *metav1.LabelSelector `json:"nodeSelector,omitempty"`
}

type BundleExternalNodes struct {
	Namespace string `json:"namespace"`
	// List the names of certain ExternalNodes which are expected to collect and upload
	// bundle files.
	// +optional
	NodeNames []string `json:"nodeNames,omitempty"`
	// Select certain ExternalNodes which match the label selector.
	// +optional
	NodeSelector *metav1.LabelSelector `json:"nodeSelector,omitempty"`
}

// BundleFileServer specifies the bundle file server information.
type BundleFileServer struct {
	// The URL of the bundle file server. It is set with format: scheme://host[:port][/path],
	// e.g, https://api.example.com:8443/v1/supportbundles/. If scheme is not set, https is used by default.
	URL string `json:"url"`
}

// BundleServerAuthType defines the authentication type to access the BundleFileServer.
type BundleServerAuthType string

const (
	APIKey              BundleServerAuthType = "APIKey"
	BearerToken         BundleServerAuthType = "BearerToken"
	BasicAuthentication BundleServerAuthType = "BasicAuthentication"
)

// BundleServerAuthConfiguration defines the authentication parameters that Antrea uses to access
// the BundleFileServer.
type BundleServerAuthConfiguration struct {
	AuthType BundleServerAuthType `json:"authType"`
	// AuthSecret is a Secret reference which stores the authentication value.
	AuthSecret *v1.SecretReference `json:"authSecret"`
}

type L7Protocol struct {
	HTTP *HTTPProtocol `json:"http,omitempty"`
	TLS  *TLSProtocol  `json:"tls,omitempty"`
}

// HTTPProtocol matches HTTP requests with specific host, method, and path. All fields could be used alone or together.
// If all fields are not provided, it matches all HTTP requests.
type HTTPProtocol struct {
	// Host represents the hostname present in the URI or the HTTP Host header to match.
	// It does not contain the port associated with the host.
	Host string `json:"host,omitempty"`
	// Method represents the HTTP method to match.
	// It could be GET, POST, PUT, HEAD, DELETE, TRACE, OPTIONS, CONNECT and PATCH.
	Method string `json:"method,omitempty"`
	// Path represents the URI path to match (Ex. "/index.html", "/admin").
	Path string `json:"path,omitempty"`
}

// TLSProtocol matches TLS handshake packets with specific SNI. If the field is not provided, this
// matches all TLS handshake packets.
type TLSProtocol struct {
	// SNI (Server Name Indication) indicates the server domain name in the TLS/SSL hello message.
	SNI string `json:"sni,omitempty"`
}
