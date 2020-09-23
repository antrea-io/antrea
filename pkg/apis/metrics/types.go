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

package metrics

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AntreaClusterNetworkPolicyMetrics is the metrics of a Antrea ClusterNetworkPolicy.
type AntreaClusterNetworkPolicyMetrics struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	// The traffic stats of the Antrea ClusterNetworkPolicy.
	TrafficStats TrafficStats
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AntreaClusterNetworkPolicyMetricsList is a list of AntreaClusterNetworkPolicyMetrics.
type AntreaClusterNetworkPolicyMetricsList struct {
	metav1.TypeMeta
	metav1.ListMeta

	// List of AntreaClusterNetworkPolicyMetrics.
	Items []AntreaClusterNetworkPolicyMetrics
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AntreaNetworkPolicyMetrics is the metrics of a Antrea NetworkPolicy.
type AntreaNetworkPolicyMetrics struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	// The traffic stats of the Antrea NetworkPolicy.
	TrafficStats TrafficStats
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AntreaNetworkPolicyMetricsList is a list of AntreaNetworkPolicyMetrics.
type AntreaNetworkPolicyMetricsList struct {
	metav1.TypeMeta
	metav1.ListMeta

	// List of AntreaNetworkPolicyMetrics.
	Items []AntreaNetworkPolicyMetrics
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NetworkPolicyMetrics is the metrics of a K8s NetworkPolicy.
type NetworkPolicyMetrics struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	// The traffic stats of the K8s NetworkPolicy.
	TrafficStats TrafficStats
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NetworkPolicyMetricsList is a list of NetworkPolicyMetrics.
type NetworkPolicyMetricsList struct {
	metav1.TypeMeta
	metav1.ListMeta

	// List of NetworkPolicyMetrics.
	Items []NetworkPolicyMetrics
}

// TrafficStats contains the traffic stats of a NetworkPolicy.
type TrafficStats struct {
	// Packets is the packets count hit by the NetworkPolicy.
	Packets int64
	// Bytes is the bytes count hit by the NetworkPolicy.
	Bytes int64
	// Sessions is the sessions count hit by the NetworkPolicy.
	Sessions int64
}
