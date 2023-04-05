/*
Copyright 2023 Antrea Authors.

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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// Identify this cluster.
	WellKnownClusterPropertyID = "cluster.clusterset.k8s.io"
	// Identify a ClusterSet that this cluster is a member of.
	WellKnownClusterPropertyClusterSet = "clusterset.k8s.io"
)

// +genclient
//+kubebuilder:object:root=true

// +kubebuilder:printcolumn:name="Value",type=string,JSONPath=`.value`,description="Value of the ClusterProperty"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=`.metadata.creationTimestamp`
// ClusterProperty is the Schema for the clusterproperties API
type ClusterProperty struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// Value of the ClusterProperty.
	// +kubebuilder:validation:Required
	Value string `json:"value"`
}

//+kubebuilder:object:root=true

// ClusterPropertyList contains a list of ClusterProperty
type ClusterPropertyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterProperty `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ClusterProperty{}, &ClusterPropertyList{})
}
