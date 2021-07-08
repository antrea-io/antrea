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
	mcs "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
)

// EndpointsImport imports Endpoints.
type EndpointsImport struct {
	Subsets []v1.EndpointSubset `json:"subsets,omitempty"`
}

// ExternalEntityImport imports ExternalEntity.
type ExternalEntityImport struct {
	ExternalEntitySpec *v1alpha2.ExternalEntitySpec `json:"externalentityspec,omitempty"`
}

// RawResourceImport imports opaque resources.
type RawResourceImport struct {
	Data []byte `json:"data,omitempty"`
}

// ResourceImportSpec defines the desired state of ResourceImport
type ResourceImportSpec struct {
	// ClusterIDs specifies the member clusters this resource to import to.
	// When not specified, import to all member clusters.
	ClusterIDs []string `json:"clusterID,omitempty"`
	// Name of imported resource.
	Name string `json:"name,omitempty"`
	// Namespace of imported resource.
	Namespace string `json:"namespace,omitempty"`
	// Kind of imported resource.
	Kind string `json:"kind,omitempty"`

	// If imported resource is ServiceImport.
	ServiceImport *mcs.ServiceImport `json:"serviceImport,omitempty"`
	// If imported resource is EndPoints.
	Endpoints *EndpointsImport `json:"endpoints,omitempty"`
	// If imported resource is ExternalEntity.
	ExternalEntity *ExternalEntityImport `json:"externalentity,omitempty"`
	// If imported resource is ANP.
	// TODO:
	// ANP uses float64 as priority.  Type float64 is discouraged by k8s, and is not supported by controller-gen tools.
	// NetworkPolicy *v1alpha1.NetworkPolicySpec `json:"networkpolicy,omitempty"`
	// If imported resource Kind is unknown.
	Raw *RawResourceImport `json:"raw,omitempty"`
}

type ResourceImportConditionType string

const (
	ResourceImportSucceeded ResourceImportConditionType = "ResourceImportSucceeded"
)

// ResourceImportClusterCondition indicates the condition of the ResourceImport in a cluster
type ResourceImportClusterCondition struct {
	Type ResourceImportConditionType `json:"type,omitempty"`
	// Status of the condition, one of True, False, Unknown
	Status    v1.ConditionStatus `json:"status,omitempty"`
	ClusterID string             `json:"clusterID,omitempty"`
	// +optional
	// Last time the condition transit from one status to another
	LastTransitionTime metav1.Time `json:"lastTransitionTime,omitempty"`
	// +optional
	// A human readable message indicating details about the transition
	Message string `json:"message,omitempty"`
	// +optional
	// Unique, one-word, CamelCase reason for the condition's last transition.
	Reason string `json:"reason,omitempty"`
}

// ResourceImportClusterStatus indicates the readiness status of the ResourceImport in clusters
type ResourceImportClusterStatus struct {
	Conditions []ResourceImportClusterCondition `json:"conditions,omitempty"`
}

// ResourceImportStatus defines the observed state of ResourceImport
type ResourceImportStatus struct {
	ClusterStatuses []ResourceImportClusterStatus `json:"clusterStatuses,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// ResourceImport is the Schema for the resourceimports API
type ResourceImport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ResourceImportSpec   `json:"spec,omitempty"`
	Status ResourceImportStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// ResourceImportList contains a list of ResourceImport
type ResourceImportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ResourceImport `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ResourceImport{}, &ResourceImportList{})
}
