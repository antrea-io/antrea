// Copyright 2020 Antrea Authors
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
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type ExternalEntity struct {
	metav1.TypeMeta `json:",inline"`
	// Standard metadata of the object.
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// Desired state of the external entity.
	Spec ExternalEntitySpec `json:"spec"`
}

// ExternalEntitySpec defines the desired state for ExternalEntity.
type ExternalEntitySpec struct {
	// Endpoints is a list of external endpoints associated with this entity.
	Endpoints []ExternalEndpoint `json:"endpoints"`
	// ExternalNode is the opaque identifier of the agent/controller responsible
	// for additional computation of this external entity.
	ExternalNode string `json:"externalNode"`
}

// ExternalEndpoint refers to an endpoint associated with the ExternalEntity.
type ExternalEndpoint struct {
	// IP associated with this endpoint.
	IP IPAddress `json:"ip"`
	// Name identifies this endpoint. Could be the interface name in case of VMs.
	// +optional
	Name string `json:"name"`
	// Ports maintain the list of named ports.
	Ports []NamedPort `json:"ports"`
}

// NamedPort describes the port and protocol to match in a rule.
type NamedPort struct {
	// The protocol (TCP, UDP, or SCTP) which traffic must match.
	// If not specified, this field defaults to TCP.
	// +optional
	Protocol *v1.Protocol `json:"protocol"`
	// The port on the given protocol.
	// +optional
	Port int32 `json:"port"`
	// Name associated with the Port.
	// +optional
	Name string `json:"name"`
}

// IPAddress describes a single IP address. Either an IPv4 or IPv6 address must be set.
type IPAddress []byte

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type ExternalEntityList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []ExternalEntity `json:"items"`
}
