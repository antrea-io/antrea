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

package v1alpha2

import (
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
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
	// Cannot be set with IPBlocks.
	// +optional
	IPBlock *v1alpha1.IPBlock `json:"ipBlock,omitempty"`
	// IPBlocks is a list of IPAddresses/IPBlocks that is matched in to/from.
	// IPBlock cannot be set as part of the AppliedTo field.
	// Cannot be set with any other selector or ServiceReference.
	// Cannot be set with IPBlock.
	// +optional
	IPBlocks []v1alpha1.IPBlock `json:"ipBlocks,omitempty"`
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

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Egress defines which egress (SNAT) IP the traffic from the selected Pods to
// the external network should use.
type Egress struct {
	metav1.TypeMeta `json:",inline"`
	// Standard metadata of the object.
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired behavior of Egress.
	Spec EgressSpec `json:"spec"`

	// EgressStatus represents the current status of an Egress.
	Status EgressStatus `json:"status"`
}

// EgressStatus represents the current status of an Egress.
type EgressStatus struct {
	// The name of the Node that holds the Egress IP.
	EgressNode string `json:"egressNode"`
}

// EgressSpec defines the desired state for Egress.
type EgressSpec struct {
	// AppliedTo selects Pods to which the Egress will be applied.
	AppliedTo AppliedTo `json:"appliedTo"`
	// EgressIP specifies the SNAT IP address for the selected workloads.
	// If ExternalIPPool is empty, it must be specified manually.
	// If ExternalIPPool is non-empty, it can be empty and will be assigned by Antrea automatically.
	// If both ExternalIPPool and EgressIP are non-empty, the IP must be in the pool.
	EgressIP string `json:"egressIP,omitempty"`
	// ExternalIPPool specifies the IP Pool that the EgressIP should be allocated from.
	// If it is empty, the specified EgressIP must be assigned to a Node manually.
	// If it is non-empty, the EgressIP will be assigned to a Node specified by the pool automatically and will failover
	// to a different Node when the Node becomes unreachable.
	ExternalIPPool string `json:"externalIPPool"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type EgressList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []Egress `json:"items"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ExternalIPPool defines one or multiple IP sets that can be used in the external network. For instance, the IPs can be
// allocated to the Egress resources as the Egress IPs.
type ExternalIPPool struct {
	metav1.TypeMeta `json:",inline"`
	// Standard metadata of the object.
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the ExternalIPPool.
	Spec ExternalIPPoolSpec `json:"spec"`

	// The current status of the ExternalIPPool.
	Status ExternalIPPoolStatus `json:"status"`
}

type ExternalIPPoolSpec struct {
	// The IP ranges of this IP pool, e.g. 10.10.0.0/24, 10.10.10.2-10.10.10.20, 10.10.10.30-10.10.10.30.
	IPRanges []IPRange `json:"ipRanges"`
	// The Nodes that the external IPs can be assigned to. If empty, it means all Nodes.
	NodeSelector metav1.LabelSelector `json:"nodeSelector"`
}

// IPRange is a set of contiguous IP addresses, represented by a CIDR or a pair of start and end IPs.
type IPRange struct {
	// The CIDR of this range, e.g. 10.10.10.0/24.
	CIDR string `json:"cidr,omitempty"`
	// The start IP of the range, e.g. 10.10.20.5, inclusive.
	Start string `json:"start,omitempty"`
	// The end IP of the range, e.g. 10.10.20.20, inclusive.
	End string `json:"end,omitempty"`
}

type ExternalIPPoolStatus struct {
	Usage ExternalIPPoolUsage `json:"usage,omitempty"`
}

type ExternalIPPoolUsage struct {
	// Total number of IPs.
	Total int `json:"total"`
	// Number of allocated IPs.
	Used int `json:"used"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type ExternalIPPoolList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []ExternalIPPool `json:"items"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// IPPool defines one or multiple IP sets that can be used for flexible IPAM feature. For instance, the IPs can be
// allocated to Pods according to IP pool specified in Deployment annotation.
type IPPool struct {
	metav1.TypeMeta `json:",inline"`
	// Standard metadata of the object.
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the IPPool.
	Spec IPPoolSpec `json:"spec"`

	// Most recently observed status of the pool.
	Status IPPoolStatus `json:"status"`
}

type IPPoolSpec struct {
	// IP Version for this IP pool - either 4 or 6
	IPVersion int `json:"ipVersion"`
	// List IP ranges, along with subnet definition.
	IPRanges []SubnetIPRange `json:"ipRanges"`
}

// SubnetIPRange is a set of contiguous IP addresses, represented by a CIDR or a pair of start and end IPs,
// along with subnet definition.
type SubnetIPRange struct {
	IPRange `json:",inline"`
	// Gateway IP for this subnet, eg. 10.10.1.1
	Gateway string `json:"gateway"`
	// Prefix length for the subnet, eg. 24
	PrefixLen string `json:"prefixLen"`
	// VLAN ID for this subnet. Default is 0. String-typed for sake of potential autoselect option.
	VLAN string `json:"vlan,omitempty"`
}

type IPPoolStatus struct {
	Usage []IPPoolUsage `json:"usage,omitempty"`
	// TODO: add usage statistics
}

type IPPoolUsage struct {
	// IP Address this entry is tracking
	IPAddress string `json:"ipAddress"`
	// Allocation state - either Allocated or Preallocated
	State string `json:"state"`
	// Resource this IP Address is allocated to
	Resource string `json:"resource"`
	// TODO: add usage statistics (consistent with ExternalIPPool status)
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type IPPoolList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []IPPool `json:"items"`
}
