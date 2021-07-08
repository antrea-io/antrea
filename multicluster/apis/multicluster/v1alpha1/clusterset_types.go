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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// MemberCluster defines member cluster information.
type MemberCluster struct {
	// Identify member cluster in ClusterSet.
	ClusterID string `json:"clusterID,omitempty"`
	// API server of the destination cluster.
	Server string `json:"server,omitempty"`
	// Secret name to access API server of the member from the leader cluster.
	Secret string `json:"secret,omitempty"`
	// ServiceAccount used by the member cluster to access into leader cluster.
	ServiceAccount string `json:"serviceAccount,omitempty"`
}

// ClusterSetSpec defines the desired state of ClusterSet
type ClusterSetSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Members include member clusters known to the leader clusters.
	// Used in leader cluster.
	Members []MemberCluster `json:"members,omitempty"`
	// Leaders include leader clusters known to the member clusters.
	Leaders []MemberCluster `json:"leaders,omitempty"`
	// Namespace to connect to in leader clusters.
	// Used in member cluster.
	Namespace string `json:"namespace,omitempty"`
}

// ClusterSetStatus defines the observed state of ClusterSet
type ClusterSetStatus struct {
	// Important: Run "make" to regenerate code after modifying this file
	// TBD
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// ClusterSet is the Schema for the clustersets API
type ClusterSet struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ClusterSetSpec   `json:"spec,omitempty"`
	Status ClusterSetStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// ClusterSetList contains a list of ClusterSet
type ClusterSetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterSet `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ClusterSet{}, &ClusterSetList{})
}
