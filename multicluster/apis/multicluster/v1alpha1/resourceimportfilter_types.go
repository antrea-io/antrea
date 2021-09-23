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

// ResourceImportFilterSpec defines the desired state of ResourceImportFilter
type ResourceImportFilterSpec struct {
	// TBD.
}

// ResourceImportFilterStatus defines the observed state of ResourceImportFilter
type ResourceImportFilterStatus struct {
	// TBD.
}

// +genclient
//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// ResourceImportFilter is the Schema for the ResourceImportFilters API
type ResourceImportFilter struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ResourceImportFilterSpec   `json:"spec,omitempty"`
	Status ResourceImportFilterStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// ResourceImportFilterList contains a list of ResourceImportFilter
type ResourceImportFilterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ResourceImportFilter `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ResourceImportFilter{}, &ResourceImportFilterList{})
}
