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

// +genclient
// +genclient:nonNamespaced
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NodeLatencyMonitor is used to monitor the latency between nodes in a Kubernetes cluster. It is a singleton resource,
// meaning only one instance of it can exist in the cluster.
type NodeLatencyMonitor struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec NodeLatencyMonitorSpec `json:"spec"`
}

type NodeLatencyMonitorSpec struct {
	// PingInterval specifies the interval between ping requests.
	// Ping interval should be greater than or equal to 1s(one second).
	// Defaults to "60". Valid time units are "s".
	PingIntervalSeconds int32 `json:"pingIntervalSeconds"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NodeLatencyMonitor is only a singleton resource, so it does not use a list type.
// But current k8s client-gen does not support generating client for singleton informer resource,
// so we have to define a list type for CRD Informer.
// Maybe we will remove it in the future.
type NodeLatencyMonitorList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []NodeLatencyMonitor `json:"items"`
}
