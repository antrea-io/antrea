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

// +genclient
//+kubebuilder:object:root=true

// +kubebuilder:printcolumn:name="Cluster ID",type=string,JSONPath=`.clusterID`,description="Cluster ID of the member cluster"
// +kubebuilder:printcolumn:name="ClusterSet ID",type=string,JSONPath=`.clusterSetID`,description="ClusterSet ID"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=`.metadata.creationTimestamp`
// MemberClusterAnnounce is the Schema for the memberclusterannounces API
type MemberClusterAnnounce struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Cluster ID of the member cluster.
	ClusterID string `json:"clusterID,omitempty"`
	// ClusterSet this member belongs to.
	ClusterSetID string `json:"clusterSetID,omitempty"`
	// Leader cluster this member has selected.
	LeaderClusterID string `json:"leaderClusterID,omitempty"`
}

//+kubebuilder:object:root=true

// MemberClusterAnnounceList contains a list of MemberClusterAnnounce
type MemberClusterAnnounceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []MemberClusterAnnounce `json:"items"`
}

func init() {
	SchemeBuilder.Register(&MemberClusterAnnounce{}, &MemberClusterAnnounceList{})
}
