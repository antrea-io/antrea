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

// +genclient
// +resourceName=antreaclusternetworkpolicystats
// +genclient:readonly
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AntreaClusterNetworkPolicyStats is the statistics of a Antrea ClusterNetworkPolicy.
type AntreaClusterNetworkPolicyStats struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	// The traffic stats of the Antrea ClusterNetworkPolicy.
	TrafficStats TrafficStats `json:"trafficStats,omitempty" protobuf:"bytes,2,opt,name=trafficStats"`
	// The traffic stats of the Antrea ClusterNetworkPolicy, from rule perspective.
	RuleTrafficStats []RuleTrafficStats `json:"ruleTrafficStats,omitempty" protobuf:"bytes,3,rep,name=ruleTrafficStats"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AntreaClusterNetworkPolicyStatsList is a list of AntreaClusterNetworkPolicyStats.
type AntreaClusterNetworkPolicyStatsList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// List of AntreaClusterNetworkPolicyStats.
	Items []AntreaClusterNetworkPolicyStats `json:"items" protobuf:"bytes,2,rep,name=items"`
}

// +genclient
// +resourceName=antreanetworkpolicystats
// +genclient:readonly
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AntreaNetworkPolicyStats is the statistics of a Antrea NetworkPolicy.
type AntreaNetworkPolicyStats struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	// The traffic stats of the Antrea NetworkPolicy.
	TrafficStats TrafficStats `json:"trafficStats,omitempty" protobuf:"bytes,2,opt,name=trafficStats"`
	// The traffic stats of the Antrea NetworkPolicy, from rule perspective.
	RuleTrafficStats []RuleTrafficStats `json:"ruleTrafficStats,omitempty" protobuf:"bytes,3,rep,name=ruleTrafficStats"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AntreaNetworkPolicyStatsList is a list of AntreaNetworkPolicyStats.
type AntreaNetworkPolicyStatsList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// List of AntreaNetworkPolicyStats.
	Items []AntreaNetworkPolicyStats `json:"items" protobuf:"bytes,2,rep,name=items"`
}

// +genclient
// +resourceName=networkpolicystats
// +genclient:readonly
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NetworkPolicyStats is the statistics of a K8s NetworkPolicy.
type NetworkPolicyStats struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// The traffic stats of the K8s NetworkPolicy.
	TrafficStats TrafficStats `json:"trafficStats,omitempty" protobuf:"bytes,2,opt,name=trafficStats"`
}

// +genclient
// +genclient:readonly
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// MulticastGroup contains the mapping between multicast group and Pods.
type MulticastGroup struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// Group is the IP of the multicast group.
	Group string `json:"group,omitempty" protobuf:"bytes,2,opt,name=group"`
	// Pods is the list of Pods that have joined the multicast group.
	Pods []PodReference `json:"pods" protobuf:"bytes,3,rep,name=pods"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// MulticastGroupList is a list of MulticastGroup.
type MulticastGroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// List of MulticastGroup.
	Items []MulticastGroup `json:"items" protobuf:"bytes,2,rep,name=items"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NetworkPolicyStatsList is a list of NetworkPolicyStats.
type NetworkPolicyStatsList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// List of NetworkPolicyStats.
	Items []NetworkPolicyStats `json:"items" protobuf:"bytes,2,rep,name=items"`
}

// PodReference represents a Pod Reference.
type PodReference struct {
	// The name of this Pod.
	Name string `json:"name,omitempty" protobuf:"bytes,1,opt,name=name"`
	// The namespace of this Pod.
	Namespace string `json:"namespace,omitempty" protobuf:"bytes,2,opt,name=namespace"`
}

// TrafficStats contains the traffic stats of a NetworkPolicy.
type TrafficStats struct {
	// Packets is the packets count hit by the NetworkPolicy.
	Packets int64 `json:"packets,omitempty" protobuf:"varint,1,opt,name=packets"`
	// Bytes is the bytes count hit by the NetworkPolicy.
	Bytes int64 `json:"bytes,omitempty" protobuf:"varint,2,opt,name=bytes"`
	// Sessions is the sessions count hit by the NetworkPolicy.
	Sessions int64 `json:"sessions,omitempty" protobuf:"varint,3,opt,name=sessions"`
}

// RuleTrafficStats contains TrafficStats of single rule inside a NetworkPolicy.
type RuleTrafficStats struct {
	Name         string       `json:"name,omitempty" protobuf:"bytes,1,opt,name=name"`
	TrafficStats TrafficStats `json:"trafficStats,omitempty" protobuf:"bytes,2,opt,name=trafficStats"`
}

// +genclient
// +genclient:nonNamespaced
// +resourceName=nodelatencystats
// +genclient:onlyVerbs=create,delete,get,list
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NodeLatencyStats contains all the latency measurements collected by the Agent from a specific Node.
type NodeLatencyStats struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// The list of PeerNodeLatencyStats.
	PeerNodeLatencyStats []PeerNodeLatencyStats `json:"peerNodeLatencyStats,omitempty" protobuf:"bytes,2,rep,name=peerNodeLatencyStats"`
}

// PeerNodeLatencyStats contains the latency stats of a Peer Node.
type PeerNodeLatencyStats struct {
	// The Node's name.
	NodeName string `json:"nodeName,omitempty" protobuf:"bytes,1,opt,name=nodeName"`
	// The list of target IP latency stats.
	TargetIPLatencyStats []TargetIPLatencyStats `json:"targetIPLatencyStats,omitempty" protobuf:"bytes,2,rep,name=targetIPLatencyStats"`
}

// TargetIPLatencyStats contains the latency stats of a target IP.
type TargetIPLatencyStats struct {
	// The target IP address.
	TargetIP string `json:"targetIP,omitempty" protobuf:"bytes,1,opt,name=targetIP"`
	// The timestamp of the last sent packet.
	LastSendTime metav1.Time `json:"lastSendTime,omitempty" protobuf:"bytes,2,opt,name=lastSendTime"`
	// The timestamp of the last received packet.
	LastRecvTime metav1.Time `json:"lastRecvTime,omitempty" protobuf:"bytes,3,opt,name=lastRecvTime"`
	// The last measured RTT for this target IP, in nanoseconds.
	LastMeasuredRTTNanoseconds int64 `json:"lastMeasuredRTTNanoseconds,omitempty" protobuf:"varint,4,opt,name=lastMeasuredRTTNanoseconds"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NodeLatencyStatsList is a list of NodeLatencyStats objects.
type NodeLatencyStatsList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// The list of NodeLatencyStats.
	Items []NodeLatencyStats `json:"items" protobuf:"bytes,2,rep,name=items"`
}
