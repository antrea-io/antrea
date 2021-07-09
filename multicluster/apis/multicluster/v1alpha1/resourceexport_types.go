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

	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
)

// ServiceExport exports Service.
type ServiceExport struct {
	ServiceSpec v1.ServiceSpec `json:"serviceSpec,omitempty"`
}

// EndpointsExport exports Endpoints.
type EndpointsExport struct {
	Subsets []v1.EndpointSubset `json:"subsets,omitempty"`
}

// ExternalEntityExport exports ExternalEntity.
type ExternalEntityExport struct {
	ExternalEntitySpec v1alpha2.ExternalEntitySpec `json:"externalentityspec,omitempty"`
}

// RawResourceExport exports opaque resources.
type RawResourceExport struct {
	Data []byte `json:"data,omitempty"`
}

// ResourceExportSpec defines the desired state of ResourceExport
type ResourceExportSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// ClusterID specifies the member cluster this resource exported from.
	ClusterID string `json:"clusterID,omitempty"`
	// Name of exported resource.
	Name string `json:"name,omitempty"`
	// Namespace of exported resource.
	Namespace string `json:"namespace,omitempty"`
	// Kind of exported resource.
	Kind string `json:"kind,omitempty"`

	// If exported resource is Service.
	Service *ServiceExport `json:"service,omitempty"`
	// If exported resource is EndPoints.
	Endpoints *EndpointsExport `json:"endpoints,omitempty"`
	// If exported resource is ExternalEntity.
	ExternalEntity *ExternalEntityExport `json:"externalentity,omitempty"`
	// If exported resource Kind is unknown.
	Raw RawResourceExport `json:"raw,omitempty"`
}

type ResourceExportConditionType string

const (
	ResourceExportSucceeded ResourceExportConditionType = "Succeeded"
)

// ResourceExportCondition indicates the readiness condition of the ResourceExport
type ResourceExportCondition struct {
	Type ResourceExportConditionType `json:"type,omitempty"`
	// Status of the condition, one of True, False, Unknown
	Status v1.ConditionStatus `json:"status,omitempty"`
	// +optional
	// Last time the condition transited from one status to another
	LastTransitionTime metav1.Time `json:"lastTransitionTime,omitempty"`
	// +optional
	// A human readable message indicating details about the transition
	Message string `json:"message,omitempty"`
	// +optional
	// Unique, one-word, CamelCase reason for the condition's last transition.
	Reason string `json:"reason,omitempty"`
}

// ResourceExportStatus defines the observed state of ResourceExport
type ResourceExportStatus struct {
	Conditions []ResourceExportCondition `json:"conditions,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// ResourceExport is the Schema for the resourceexports API
type ResourceExport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ResourceExportSpec   `json:"spec,omitempty"`
	Status ResourceExportStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// ResourceExportList contains a list of ResourceExport
type ResourceExportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ResourceExport `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ResourceExport{}, &ResourceExportList{})
}
