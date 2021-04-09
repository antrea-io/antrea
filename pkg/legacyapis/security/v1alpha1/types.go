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

	"github.com/vmware-tanzu/antrea/pkg/apis/crd/v1alpha1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type NetworkPolicy struct {
	metav1.TypeMeta `json:",inline"`
	// Standard metadata of the object.
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired behavior of NetworkPolicy.
	Spec v1alpha1.NetworkPolicySpec `json:"spec"`
	// Most recently observed status of the NetworkPolicy.
	Status v1alpha1.NetworkPolicyStatus `json:"status"`
}

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
	Spec v1alpha1.ClusterNetworkPolicySpec `json:"spec"`
	// Most recently observed status of the NetworkPolicy.
	Status v1alpha1.NetworkPolicyStatus `json:"status"`
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
	Spec v1alpha1.TierSpec `json:"spec"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type TierList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []Tier `json:"items"`
}
