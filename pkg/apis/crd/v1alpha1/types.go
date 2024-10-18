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
)

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
	// PingInterval specifies the interval in seconds between ping requests.
	// Ping interval should be greater than or equal to 1s.
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

// +genclient
// +genclient:nonNamespaced
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// BGPPolicy defines BGP configuration applied to Nodes.
type BGPPolicy struct {
	metav1.TypeMeta `json:",inline"`
	// Standard metadata of the object.
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec BGPPolicySpec `json:"spec"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type BGPPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []BGPPolicy `json:"items"`
}

// BGPPolicySpec defines the specification for a BGPPolicy.
type BGPPolicySpec struct {
	// NodeSelector selects Nodes to which the BGPPolicy is applied. If multiple BGPPolicies select a Node, only one
	// will be effective and enforced; others serve as alternatives.
	NodeSelector metav1.LabelSelector `json:"nodeSelector"`

	// LocalASN is the AS number used by the BGP process. The available private AS number range is 64512-65535.
	LocalASN int32 `json:"localASN"`

	// ListenPort is the port on which the BGP process listens, and the default value is 179.
	ListenPort *int32 `json:"listenPort,omitempty"`

	// Advertisements configures IPs or CIDRs to be advertised to BGP peers.
	Advertisements Advertisements `json:"advertisements,omitempty"`

	// BGPPeers is the list of BGP peers.
	BGPPeers []BGPPeer `json:"bgpPeers,omitempty"`
}

type Advertisements struct {
	// Service specifies how to advertise Service IPs.
	Service *ServiceAdvertisement `json:"service,omitempty"`

	// Pod specifies how to advertise Pod IPs. Currently, if this is set, NodeIPAM Pod CIDR instead of specific Pods IPs
	// will be advertised since pod selector is not added yet.
	Pod *PodAdvertisement `json:"pod,omitempty"`

	// Egress specifies how to advertise Egress IPs. Currently, if this is set, all Egress IPs will be advertised since
	// Egress selector is not added yet.
	Egress *EgressAdvertisement `json:"egress,omitempty"`
}

type ServiceIPType string

const (
	ServiceIPTypeClusterIP      ServiceIPType = "ClusterIP"
	ServiceIPTypeLoadBalancerIP ServiceIPType = "LoadBalancerIP"
	ServiceIPTypeExternalIP     ServiceIPType = "ExternalIP"
)

type ServiceAdvertisement struct {
	// IPTypes specifies the types of Service IPs from the selected Services to be advertised. Currently, all Services
	// will be selected since Service selector is not added yet.
	IPTypes []ServiceIPType `json:"ipTypes,omitempty"`

	// Empty now, selectors to be added later, which are used to select specific Services.
	// Selectors []Selector `json:"selectors,omitempty"`
}

type PodAdvertisement struct {
	// Empty now, selectors to be added later, which are used to select specific Pods.
	// Selectors []Selector `json:"selectors,omitempty"`
}

type EgressAdvertisement struct {
	// Empty now, selectors to be added later, which are used to select specific Egresses.
	// Selectors []Selector `json:"selectors,omitempty"`
}

type BGPPeer struct {
	// The IP address on which the BGP peer listens.
	Address string `json:"address"`

	// The port number on which the BGP peer listens. The default value is 179, the well-known port of BGP protocol.
	Port *int32 `json:"port,omitempty"`

	// The AS number of the BGP peer.
	ASN int32 `json:"asn"`

	// The Time To Live (TTL) value used in BGP packets sent to the BGP peer. The range of the value is from 1 to 255,
	// and the default value is 1.
	MultihopTTL *int32 `json:"multihopTTL,omitempty"`

	// GracefulRestartTimeSeconds specifies how long the BGP peer would wait for the BGP session to re-establish after
	// a restart before deleting stale routes. The range of the value is from 1 to 3600, and the default value is 120.
	GracefulRestartTimeSeconds *int32 `json:"gracefulRestartTimeSeconds,omitempty"`
}

type PodReference struct {
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name,omitempty"`
}

type ServiceReference struct {
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name,omitempty"`
}

// Source describes the source spec of the packetcapture.
type Source struct {
	// Pod is the source pod,
	Pod *PodReference `json:"pod,omitempty"`
	// IP is the source IPv4 or IPv6 address.
	IP *string `json:"ip,omitempty"`
}

// Destination describes the destination spec of the PacketCapture.
type Destination struct {
	// Pod is the destination Pod, exclusive with destination Service.
	Pod *PodReference `json:"pod,omitempty"`
	// Service is the destination Service, exclusive with destination Pod.
	Service *ServiceReference `json:"service,omitempty"`
	// IP is the destination IPv4 or IPv6 address.
	IP *string `json:"ip,omitempty"`
}

// TransportHeader describes spec of a TransportHeader.
type TransportHeader struct {
	UDP *UDPHeader `json:"udp,omitempty"`
	TCP *TCPHeader `json:"tcp,omitempty"`
}

// UDPHeader describes spec of a UDP header.
type UDPHeader struct {
	// SrcPort is the source port.
	SrcPort *int32 `json:"srcPort,omitempty"`
	// DstPort is the destination port.
	DstPort *int32 `json:"dstPort,omitempty"`
}

// TCPHeader describes spec of a TCP header.
type TCPHeader struct {
	// SrcPort is the source port.
	SrcPort *int32 `json:"srcPort,omitempty"`
	// DstPort is the destination port.
	DstPort *int32 `json:"dstPort,omitempty"`
	// Flags are tcp flags filter in BPF format. eg: 'tcp[13] & 16!=0' or 'tcp[tcpflags] == tcp-ack'
	Flags *string `json:"flags,omitempty"`
}

// Packet includes header info.
type Packet struct {
	// IPFamily is the filter's IP family. Default to `IPv4`.
	IPFamily v1.IPFamily `json:"ipFamily,omitempty"`
	// Protocol represents the transport protocol. Default is to not filter on protocol.
	Protocol        *intstr.IntOrString `json:"protocol,omitempty"`
	TransportHeader TransportHeader     `json:"transportHeader"`
}

// PacketCaptureFirstNConfig contains the config for the FirstN type capture. The only supported parameter is
// `Number` at the moment, meaning capturing the first specified number of packets in a flow.
type PacketCaptureFirstNConfig struct {
	Number int32 `json:"number"`
}

const DefaultPacketCaptureTimeout uint16 = 60

type PacketCapturePhase string

const (
	PacketCaptureRunning   PacketCapturePhase = "Running"
	PacketCaptureSucceeded PacketCapturePhase = "Succeeded"
	PacketCaptureFailed    PacketCapturePhase = "Failed"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type PacketCaptureList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []PacketCapture `json:"items"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type PacketCapture struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              PacketCaptureSpec   `json:"spec"`
	Status            PacketCaptureStatus `json:"status"`
}

type CaptureConfig struct {
	FirstN *PacketCaptureFirstNConfig `json:"firstN,omitempty"`
}

type PacketCaptureSpec struct {
	Timeout       *uint16       `json:"timeout,omitempty"`
	CaptureConfig CaptureConfig `json:"captureConfig"`
	Source        Source        `json:"source"`
	Destination   Destination   `json:"destination"`
	Packet        *Packet       `json:"packet,omitempty"`
	// FileServer specifies the sftp url config for the fileServer. Captured packets will be uploaded to this server.
	FileServer *BundleFileServer `json:"fileServer,omitempty"`
}

type PacketCaptureStatus struct {
	Phase PacketCapturePhase `json:"phase"`
	// Reason records the failure reason when the capture fails.
	Reason string `json:"reason"`
	// NumCapturedPackets records how many packets have been captured. If it reaches the target number, the capture
	// can be considered as finished.
	NumCapturedPackets int32 `json:"numCapturedPackets,omitempty"`
	// PacketsFilePath is the file path where the captured packets are stored. The format is: "<antrea-agent-pod-name>:<path>".
	// If `.spec.FileServer` is present, this file will also be uploaded to the targeted location.
	PacketsFilePath string `json:"packetsFilePath"`
	// StartTime is the time when this capture sessions starts.
	StartTime *metav1.Time `json:"startTime,omitempty"`
}
