/*
Copyright 2021 Antrea Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha2

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// Identify this cluster.
	WellKnownClusterClaimID = "id.k8s.io"
	// Identify a ClusterSet that this cluster is a member of.
	WellKnownClusterClaimClusterSet = "clusterset.k8s.io"
)

// +genclient
//+kubebuilder:object:root=true

// +kubebuilder:printcolumn:name="Value",type=string,JSONPath=`.value`,description="Value of the ClusterClaim"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=`.metadata.creationTimestamp`
// ClusterClaim is the Schema for the clusterclaims API.
type ClusterClaim struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// Value of the ClusterClaim.
	// +kubebuilder:validation:Required
	Value string `json:"value"`
}

//+kubebuilder:object:root=true

// ClusterClaimList contains a list of ClusterClaim
type ClusterClaimList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterClaim `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ClusterClaim{}, &ClusterClaimList{})
}
