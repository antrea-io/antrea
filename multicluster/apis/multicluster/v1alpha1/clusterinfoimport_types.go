/*
Copyright 2022 Antrea Authors.

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

// ClusterInfoImportStatus defines the observed state of ClusterInfoImport.
type ClusterInfoImportStatus struct {
	Conditions []ResourceCondition `json:"conditions,omitempty"`
}

// +genclient
//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// +kubebuilder:printcolumn:name="Cluster ID",type=string,JSONPath=`.spec.clusterID`,description="Member Cluster ID"
// +kubebuilder:printcolumn:name="Service CIDR",type=string,JSONPath=`.spec.serviceCIDR`,description="Service CIDR of the cluster"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=`.metadata.creationTimestamp`
type ClusterInfoImport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ClusterInfo             `json:"spec,omitempty"`
	Status ClusterInfoImportStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

type ClusterInfoImportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterInfoImport `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ClusterInfoImport{}, &ClusterInfoImportList{})
}
