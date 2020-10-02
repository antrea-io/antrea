// Copyright 2021 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	antreacore "github.com/vmware-tanzu/antrea/pkg/apis/core/v1alpha2"
)

// +genclient
// +genclient:nonNamespaced
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Egress defines which egress (SNAT) IP the traffic from the selected Pods to
// the external network should use.
type Egress struct {
	metav1.TypeMeta `json:",inline"`
	// Standard metadata of the object.
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired behavior of Egress.
	Spec EgressSpec `json:"spec"`
}

// EgressSpec defines the desired state for Egress.
type EgressSpec struct {
	// AppliedTo selects Pods to which the Egress will be applied.
	AppliedTo antreacore.AppliedTo `json:"appliedTo"`
	// EgressIP specifies the SNAT IP address for the selected workloads.
	EgressIP string `json:"egressIP"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type EgressList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []Egress `json:"items"`
}
