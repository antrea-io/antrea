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

package stats

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AntreaClusterNetworkPolicyStats is the statistics of a Antrea ClusterNetworkPolicy.
type AntreaClusterNetworkPolicyStats struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	// The traffic stats of the Antrea ClusterNetworkPolicy.
	TrafficStats TrafficStats
	// The traffic stats of the Antrea ClusterNetworkPolicy rules.
	RuleTrafficStats []RuleTrafficStats
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AntreaClusterNetworkPolicyStatsList is a list of AntreaClusterNetworkPolicyStats.
type AntreaClusterNetworkPolicyStatsList struct {
	metav1.TypeMeta
	metav1.ListMeta

	// List of AntreaClusterNetworkPolicyStats.
	Items []AntreaClusterNetworkPolicyStats
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AntreaNetworkPolicyStats is the statistics of a Antrea NetworkPolicy.
type AntreaNetworkPolicyStats struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	// The traffic stats of the Antrea NetworkPolicy.
	TrafficStats TrafficStats
	// The traffic stats of the Antrea NetworkPolicy, from rule perspective.
	RuleTrafficStats []RuleTrafficStats
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AntreaNetworkPolicyStatsList is a list of AntreaNetworkPolicyStats.
type AntreaNetworkPolicyStatsList struct {
	metav1.TypeMeta
	metav1.ListMeta

	// List of AntreaNetworkPolicyStats.
	Items []AntreaNetworkPolicyStats
}

// PodReference represents a Pod Reference.
type PodReference struct {
	// The name of this Pod.
	Name string
	// The namespace of this Pod.
	Namespace string
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// MulticastGroup contains the mapping between multicast group and Pods.
type MulticastGroup struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	// Group is the IP of the multicast group.
	Group string
	// Pods is the list of Pods that have joined the multicast group.
	Pods []PodReference
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// MulticastGroupList is a list of MulticastGroup.
type MulticastGroupList struct {
	metav1.TypeMeta
	metav1.ListMeta

	// List of MulticastGroup.
	Items []MulticastGroup
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NetworkPolicyStats is the statistics of a K8s NetworkPolicy.
type NetworkPolicyStats struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	// The traffic stats of the K8s NetworkPolicy.
	TrafficStats TrafficStats
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NetworkPolicyStatsList is a list of NetworkPolicyStats.
type NetworkPolicyStatsList struct {
	metav1.TypeMeta
	metav1.ListMeta

	// List of NetworkPolicyStats.
	Items []NetworkPolicyStats
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

// RuleTrafficStats contains TrafficStats of single rule inside a NetworkPolicy.
type RuleTrafficStats struct {
	Name         string
	TrafficStats TrafficStats
}
