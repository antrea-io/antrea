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
	v1 "k8s.io/api/core/v1"
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

// ClusterSetSpec defines the desired state of ClusterSet.
type ClusterSetSpec struct {
	// Members include member clusters known to the leader clusters.
	// Used in leader cluster.
	Members []MemberCluster `json:"members,omitempty"`
	// Leaders include leader clusters known to the member clusters.
	Leaders []MemberCluster `json:"leaders,omitempty"`
	// Namespace to connect to in leader clusters.
	// Used in member cluster.
	Namespace string `json:"namespace,omitempty"`
}

type ClusterSetConditionType string

const (
	// ClusterSetReady indicates whether ClusterSet is ready.
	ClusterSetReady ClusterSetConditionType = "ClusterSetReady"
)

// ClusterSetCondition indicates the readiness condition of the clusterSet.
type ClusterSetCondition struct {
	Type ClusterSetConditionType `json:"type,omitempty"`
	// Status of the condition, one of True, False, Unknown.
	Status v1.ConditionStatus `json:"status,omitempty"`
	// +optional
	// Last time the condition transit from one status to another.
	LastTransitionTime metav1.Time `json:"lastTransitionTime,omitempty"`
	// +optional
	// A human readable message indicating details about the transition.
	Message string `json:"message,omitempty"`
	// +optional
	// Unique, one-word, CamelCase reason for the condition's last transition.
	Reason string `json:"reason,omitempty"`
}

type ClusterConditionType string

const (
	// ClusterReady indicates whether Cluster is ready and connected.
	ClusterReady ClusterConditionType = "ClusterReady"
	// ClusterIsLeader indicates whether Cluster is leader.
	ClusterIsLeader ClusterConditionType = "ClusterIsLeader"
)

// ClusterCondition indicates the readiness condition of a cluster.
type ClusterCondition struct {
	Type ClusterConditionType `json:"type,omitempty"`
	// Status of the condition, one of True, False, Unknown.
	Status v1.ConditionStatus `json:"status,omitempty"`
	// ClusterID is the unique identifier of this cluster.
	ClusterID string `json:"clusterID,omitempty"`

	// +optional
	// Last time the condition transit from one status to another.
	LastTransitionTime metav1.Time `json:"lastTransitionTime,omitempty"`
	// +optional
	// A human readable message indicating details about the transition.
	Message string `json:"message,omitempty"`
	// +optional
	// Unique, one-word, CamelCase reason for the condition's last transition.
	Reason string `json:"reason,omitempty"`
}

type ClusterStatus struct {
	Conditions []ClusterCondition `json:"conditions,omitempty"`
}

// ClusterSetStatus defines the observed state of ClusterSet.
type ClusterSetStatus struct {
	// Total number of member clusters configured in the set.
	TotalClusters int32 `json:"totalClusters,omitempty"`
	// Total number of clusters ready and connected.
	ReadyClusters int32 `json:"readyClusters,omitempty"`
	// The overall condition of the cluster set.
	Conditions []ClusterSetCondition `json:"conditions,omitempty"`
	// The status of individual member clusters.
	ClusterStatuses []ClusterStatus `json:"clusterStatuses,omitempty"`
	// The generation observed by the controller.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
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
