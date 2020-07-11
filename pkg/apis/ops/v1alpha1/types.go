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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	SpoofGuard    TraceflowComponent = "SpoofGuard"
	LB            TraceflowComponent = "LB"
	Routing       TraceflowComponent = "Routing"
	NetworkPolicy TraceflowComponent = "NetworkPolicy"
	Forwarding    TraceflowComponent = "Forwarding"
)

type TraceflowAction string

const (
	Delivered TraceflowAction = "Delivered"
	Received  TraceflowAction = "Received"
	Forwarded TraceflowAction = "Forwarded"
	Dropped   TraceflowAction = "Dropped"
)

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
}

// Source describes the source spec of the traceflow.
type Source struct {
	// Namespace is the source namespace.
	Namespace string `json:"namespace,omitempty"`
	// Pod is the source pod.
	Pod string `json:"pod,omitempty"`
}

// Destination describes the destination spec of the traceflow.
type Destination struct {
	// Namespace is the destination namespace.
	Namespace string `json:"namespace,omitempty"`
	// Pod is the destination pod, exclusive with destination service.
	Pod string `json:"pod,omitempty"`
	// Service is the destination service, exclusive with destination pod.
	Service string `json:"service,omitempty"`
	// IP is the destination IP.
	IP string `json:"ip,omitempty"`
}

// IPHeader describes spec of an IPv4 header. IPv6 not supported yet.
type IPHeader struct {
	// SrcIP is the source IP.
	SrcIP string `json:"srcIP,omitempty"`
	// Protocol is the IP protocol.
	Protocol int32 `json:"protocol,omitempty"`
	// TTL is the IP TTL.
	TTL int32 `json:"ttl,omitempty"`
	// Flags is the flags for IP.
	Flags int32 `json:"flags,omitempty"`
}

// TransportHeader describes spec of a TransportHeader.
type TransportHeader struct {
	ICMP *ICMPEchoRequestHeader `json:"icmp,omitempty"`
	UDP  *UDPHeader             `json:"udp,omitempty"`
	TCP  *TCPHeader             `json:"tcp,omitempty"`
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
	IPHeader        IPHeader        `json:"ipHeader,omitempty"`
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
}

type NodeResult struct {
	// Node is the node of the observation.
	Node string `json:"node,omitempty"`
	// Role of the node like sender, receiver, etc.
	Role string `json:"role,omitempty"`
	// Timestamp is the timestamp of the observations on the node.
	Timestamp int64 `json:"timestamp,omitempty"`
	// Observations includes all observations from sender nodes, receiver ones, etc.
	Observations []Observation `json:"observations,omitempty"`
}

// Observation describes those from sender nodes or receiver nodes.
type Observation struct {
	// Component is the observation component.
	Component TraceflowComponent `json:"component,omitempty"`
	// ComponentInfo is the extension of Component field.
	ComponentInfo string `json:"componentInfo,omitempty"`
	// Action is the action to the observation.
	Action TraceflowAction `json:"action,omitempty"`
	// Pod is the combination of Pod name and Pod Namespace.
	Pod string `json:"pod,omitempty"`
	// DstMAC is the destination MAC.
	DstMAC string `json:"dstMAC,omitempty"`
	// NetworkPolicy is the combination of Namespace and NetworkPolicyName.
	NetworkPolicy string `json:"networkPolicy,omitempty"`
	// TTL is the observation TTL.
	TTL int32 `json:"ttl,omitempty"`
	// TranslatedSrcIP is the translated source IP.
	TranslatedSrcIP string `json:"translatedSrcIP,omitempty"`
	// TranslatedSrcIP is the translated destination IP.
	TranslatedDstIP string `json:"translatedDstIP,omitempty"`
	// TunnelDstIP is the tunnel destination IP.
	TunnelDstIP string `json:"tunnelDstIP,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type TraceflowList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []Traceflow `json:"items"`
}
