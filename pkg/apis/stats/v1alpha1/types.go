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

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NetworkPolicyStatsList is a list of NetworkPolicyStats.
type NetworkPolicyStatsList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// List of NetworkPolicyStats.
	Items []NetworkPolicyStats `json:"items" protobuf:"bytes,2,rep,name=items"`
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
