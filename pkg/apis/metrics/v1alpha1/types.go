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
// +resourceName=antreaclusternetworkpolicymetrics
// +genclient:readonly
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AntreaClusterNetworkPolicyMetrics is the metrics of a Antrea ClusterNetworkPolicy.
type AntreaClusterNetworkPolicyMetrics struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// The traffic stats of the Antrea ClusterNetworkPolicy.
	TrafficStats TrafficStats `json:"trafficStats,omitempty" protobuf:"bytes,2,opt,name=trafficStats"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AntreaClusterNetworkPolicyMetricsList is a list of AntreaClusterNetworkPolicyMetrics.
type AntreaClusterNetworkPolicyMetricsList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// List of AntreaClusterNetworkPolicyMetrics.
	Items []AntreaClusterNetworkPolicyMetrics `json:"items" protobuf:"bytes,2,rep,name=items"`
}

// +genclient
// +resourceName=antreanetworkpolicymetrics
// +genclient:readonly
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AntreaNetworkPolicyMetrics is the metrics of a Antrea NetworkPolicy.
type AntreaNetworkPolicyMetrics struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// The traffic stats of the Antrea NetworkPolicy.
	TrafficStats TrafficStats `json:"trafficStats,omitempty" protobuf:"bytes,2,opt,name=trafficStats"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AntreaNetworkPolicyMetricsList is a list of AntreaNetworkPolicyMetrics.
type AntreaNetworkPolicyMetricsList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// List of AntreaNetworkPolicyMetrics.
	Items []AntreaNetworkPolicyMetrics `json:"items" protobuf:"bytes,2,rep,name=items"`
}

// +genclient
// +resourceName=networkpolicymetrics
// +genclient:readonly
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NetworkPolicyMetrics is the metrics of a K8s NetworkPolicy.
type NetworkPolicyMetrics struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// The traffic stats of the K8s NetworkPolicy.
	TrafficStats TrafficStats `json:"trafficStats,omitempty" protobuf:"bytes,2,opt,name=trafficStats"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NetworkPolicyMetricsList is a list of NetworkPolicyMetrics.
type NetworkPolicyMetricsList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// List of NetworkPolicyMetrics.
	Items []NetworkPolicyMetrics `json:"items" protobuf:"bytes,2,rep,name=items"`
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
