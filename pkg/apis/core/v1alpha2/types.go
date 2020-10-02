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

package v1alpha2

import (
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	secv1a1 "github.com/vmware-tanzu/antrea/pkg/apis/security/v1alpha1"
)

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type ExternalEntity struct {
	metav1.TypeMeta `json:",inline"`
	// Standard metadata of the object.
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// Desired state of the external entity.
	Spec ExternalEntitySpec `json:"spec,omitempty"`
}

// ExternalEntitySpec defines the desired state for ExternalEntity.
type ExternalEntitySpec struct {
	// Endpoints is a list of external endpoints associated with this entity.
	Endpoints []Endpoint `json:"endpoints,omitempty"`
	// Ports maintain the list of named ports.
	Ports []NamedPort `json:"ports,omitempty"`
	// ExternalNode is the opaque identifier of the agent/controller responsible
	// for additional processing or handling of this external entity.
	ExternalNode string `json:"externalNode,omitempty"`
}

// Endpoint refers to an endpoint associated with the ExternalEntity.
type Endpoint struct {
	// IP associated with this endpoint.
	IP string `json:"ip,omitempty"`
	// Name identifies this endpoint. Could be the network interface name in case of VMs.
	// +optional
	Name string `json:"name,omitempty"`
}

// NamedPort describes the port and protocol to match in a rule.
type NamedPort struct {
	// The protocol (TCP, UDP, or SCTP) which traffic must match.
	// If not specified, this field defaults to TCP.
	// +optional
	Protocol v1.Protocol `json:"protocol,omitempty"`
	// The port on the given protocol.
	// +optional
	Port int32 `json:"port,omitempty"`
	// Name associated with the Port.
	// +optional
	Name string `json:"name,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type ExternalEntityList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []ExternalEntity `json:"items,omitempty"`
}

// ServiceReference represent reference to a v1.Service.
type ServiceReference struct {
	// Name of the Service
	Name string `json:"name,omitempty"`
	// Namespace of the Service
	Namespace string `json:"namespace,omitempty"`
}

// ClusterGroupReference represent reference to a ClusterGroup.
type ClusterGroupReference string

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type ClusterGroup struct {
	metav1.TypeMeta `json:",inline"`
	// Standard metadata of the object.
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Desired state of the group.
	Spec GroupSpec `json:"spec"`
	// Most recently observed status of the group.
	Status GroupStatus `json:"status"`
}

type GroupSpec struct {
	// Select Pods matching the labels set in the PodSelector in
	// AppliedTo/To/From fields. If set with NamespaceSelector, Pods are
	// matched from Namespaces matched by the NamespaceSelector.
	// Cannot be set with any other selector except NamespaceSelector.
	// +optional
	PodSelector *metav1.LabelSelector `json:"podSelector,omitempty"`
	// Select all Pods from Namespaces matched by this selector, as
	// workloads in AppliedTo/To/From fields. If set with PodSelector,
	// Pods are matched from Namespaces matched by the NamespaceSelector.
	// Cannot be set with any other selector except PodSelector.
	// +optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
	// IPBlock describes the IPAddresses/IPBlocks that is matched in to/from.
	// IPBlock cannot be set as part of the AppliedTo field.
	// Cannot be set with any other selector or ServiceReference.
	// +optional
	IPBlock *secv1a1.IPBlock `json:"ipBlock,omitempty"`
	// Select backend Pods of the referred Service.
	// Cannot be set with any other selector or ipBlock.
	// +optional
	ServiceReference *ServiceReference `json:"serviceReference,omitempty"`
	// Select ExternalEntities from all Namespaces as workloads
	// in AppliedTo/To/From fields. If set with NamespaceSelector,
	// ExternalEntities are matched from Namespaces matched by the
	// NamespaceSelector.
	// Cannot be set with any other selector except NamespaceSelector.
	// +optional
	ExternalEntitySelector *metav1.LabelSelector `json:"externalEntitySelector,omitempty"`
	// Select other ClusterGroups by name. The ClusterGroups must already
	// exist and must not contain ChildGroups themselves.
	// Cannot be set with any selector/IPBlock/ServiceReference.
	// +optional
	ChildGroups []ClusterGroupReference `json:"childGroups,omitempty"`
}

type GroupConditionType string

const GroupMembersComputed GroupConditionType = "GroupMembersComputed"

type GroupCondition struct {
	Type               GroupConditionType `json:"type"`
	Status             v1.ConditionStatus `json:"status"`
	LastTransitionTime metav1.Time        `json:"lastTransitionTime,omitempty"`
}

// GroupStatus represents information about the status of a Group.
type GroupStatus struct {
	Conditions []GroupCondition `json:"conditions,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type ClusterGroupList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []ClusterGroup `json:"items,omitempty"`
}

// AppliedTo selects the entities to which a policy is applied.
type AppliedTo struct {
	// Select Pods matched by this selector. If set with NamespaceSelector,
	// Pods are matched from Namespaces matched by the NamespaceSelector;
	// otherwise, Pods are matched from all Namespaces.
	// +optional
	PodSelector *metav1.LabelSelector `json:"podSelector,omitempty"`
	// Select all Pods from Namespaces matched by this selector. If set with
	// PodSelector, Pods are matched from Namespaces matched by the
	// NamespaceSelector.
	// +optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
	// Groups is the set of ClusterGroup names.
	// +optional
	Groups []string `json:"groups,omitempty"`
}
