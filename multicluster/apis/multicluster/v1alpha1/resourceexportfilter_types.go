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

// ResourceExportFilterSpec defines the desired state of ResourceExportFilter
type ResourceExportFilterSpec struct {
	// TBD.
}

// ResourceExportFilterStatus defines the observed state of ResourceExportFilter
type ResourceExportFilterStatus struct {
	// TBD
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// ResourceExportFilter is the Schema for the ResourceExportFilters API
type ResourceExportFilter struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ResourceExportFilterSpec   `json:"spec,omitempty"`
	Status ResourceExportFilterStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// ResourceExportFilterList contains a list of ResourceExportFilter
type ResourceExportFilterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ResourceExportFilter `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ResourceExportFilter{}, &ResourceExportFilterList{})
}
