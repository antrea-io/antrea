// Copyright 2026 Antrea Authors
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

package v1beta2

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Egress defines which egress (SNAT) IPs traffic from the selected Pods to the external network should use.
type Egress struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec EgressSpec `json:"spec"`
	// +optional
	Status EgressStatus `json:"status,omitzero"`
}

// EgressSpec defines the desired state for Egress.
type EgressSpec struct {
	// AppliedTo selects Pods to which the Egress will be applied.
	// +required
	AppliedTo AppliedTo `json:"appliedTo"`
	// EgressIPs specifies the SNAT IP addresses for the selected workloads. One address represents a single-stack
	// Egress. Two addresses, one per IP family in either order, represent a dual-stack Egress. When IPFamilies is also
	// specified, EgressIPs[i] must have the family IPFamilies[i]. When EgressIPs is not set, ExternalIPPool must be
	// provided and the addresses will be allocated from the pool automatically.
	// +optional
	// +listType=atomic
	EgressIPs []string `json:"egressIPs,omitempty"`
	// ExternalIPPool specifies the IP Pool from which EgressIPs are allocated. If it is not set, EgressIPs must be
	// specified and the addresses need to be manually assigned to a Node.
	// +optional
	ExternalIPPool string `json:"externalIPPool,omitempty"`
	// IPFamilies specifies the IP families when allocating EgressIPs, in either order. One family requests a single-stack
	// Egress; two families request a dual-stack Egress. When both EgressIPs and IPFamilies are specified, they must have
	// the same length and EgressIPs[i] must have the family IPFamilies[i]. When both fields are omitted, one IP is
	// allocated from ExternalIPPool without a family preference.
	// +optional
	// +listType=atomic
	IPFamilies []corev1.IPFamily `json:"ipFamilies,omitempty"`
	// Bandwidth specifies the rate limit of north-south egress traffic of this Egress.
	// +optional
	Bandwidth *Bandwidth `json:"bandwidth,omitempty"`
}

// EgressStatus represents the current status of an Egress.
type EgressStatus struct {
	// EgressNode is the Node which hosts the effective Egress IPs.
	// For a dual-stack Egress, the IPv4 and IPv6 addresses must be scheduled together on the same Node.
	// +optional
	EgressNode string `json:"egressNode,omitempty"`
	// EgressIPs are the effective Egress IPs for the selected workloads, in the same order as spec.egressIPs.
	// It may be empty when no IP has been allocated or assigned yet.
	// +optional
	// +listType=atomic
	EgressIPs []string `json:"egressIPs,omitempty"`
	// Conditions describe the current state of the Egress. Each condition type may appear at most once.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

const (
	// IPAllocated means at least one IP has been allocated to the Egress from ExternalIPPool.
	// It is not applicable for Egresses with empty ExternalIPPool.
	IPAllocated = "IPAllocated"
	// IPAssigned means the Egress has been assigned to a Node.
	// It is not applicable for Egresses with empty ExternalIPPool.
	IPAssigned = "IPAssigned"
)

// Bandwidth defines the traffic rate and burst limits for an Egress.
type Bandwidth struct {
	// Rate specifies the maximum traffic rate, e.g. 300k, 10M.
	// +required
	Rate string `json:"rate"`
	// Burst specifies the maximum burst size when traffic exceeds the rate, e.g. 300k, 10M.
	// +required
	Burst string `json:"burst"`
}

// AppliedTo describes the grouping selector of workloads in the AppliedTo field.
// When both selectors are specified, a Pod must match PodSelector and its Namespace must match NamespaceSelector.
type AppliedTo struct {
	// PodSelector selects Pods by their labels. If NamespaceSelector is omitted, matching Pods from all
	// Namespaces are selected.
	// +optional
	PodSelector *metav1.LabelSelector `json:"podSelector,omitempty"`
	// NamespaceSelector selects Namespaces by their labels. If PodSelector is omitted, all Pods from matching
	// Namespaces are selected.
	// +optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type EgressList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`
	// +required
	Items []Egress `json:"items"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ExternalIPPool defines one or multiple IP sets that can be used in the external network. For instance, the IPs can be
// allocated to the Egress resources as the Egress IPs.
type ExternalIPPool struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec ExternalIPPoolSpec `json:"spec"`
	// +optional
	Status ExternalIPPoolStatus `json:"status,omitzero"`
}

// ExternalIPPoolSpec defines the desired state for ExternalIPPool.
type ExternalIPPoolSpec struct {
	// IPRanges specifies the IP address ranges in this pool, each represented by a CIDR or an inclusive start and end.
	// The ranges may contain IPv4 addresses, IPv6 addresses, or both.
	// +required
	// +listType=atomic
	IPRanges []IPRange `json:"ipRanges"`
	// Subnets specifies the subnet attributes for each IP family. At most one entry per family is allowed. When
	// omitted, the allocated IPs are assumed to be on the same subnet as the hosting Node, and no separate subnet gateway
	// or VLAN is configured.
	// +optional
	// +listType=atomic
	Subnets []SubnetInfo `json:"subnets,omitempty"`
	// NodeSelector selects the Nodes to which the external IPs can be assigned. An empty selector matches all Nodes.
	// +required
	NodeSelector metav1.LabelSelector `json:"nodeSelector"`
}

// IPRange is a set of contiguous IP addresses, represented by a CIDR or a pair of start and end IPs.
type IPRange struct {
	// CIDR specifies this range in CIDR notation, e.g. 10.10.10.0/24.
	// +optional
	CIDR string `json:"cidr,omitempty"`
	// Start specifies the start IP of the range, e.g. 10.10.20.5, inclusive.
	// +optional
	Start string `json:"start,omitempty"`
	// End specifies the end IP of the range, e.g. 10.10.20.20, inclusive.
	// +optional
	End string `json:"end,omitempty"`
}

// SubnetInfo specifies the subnet attributes for one IP family of an ExternalIPPool's IP ranges.
// The IP family is determined by the Gateway address.
type SubnetInfo struct {
	// Gateway is the gateway IP address for this subnet, e.g. 10.10.1.1.
	// +required
	Gateway string `json:"gateway"`
	// PrefixLength is the subnet prefix length, e.g. 24.
	// +required
	PrefixLength int32 `json:"prefixLength"`
	// VLAN is the VLAN ID for this subnet. It defaults to 0. Valid values are 0 through 4094.
	// +optional
	VLAN int32 `json:"vlan,omitempty"`
}

// ExternalIPPoolStatus represents the current status of an ExternalIPPool.
type ExternalIPPoolStatus struct {
	// +optional
	Usage IPPoolUsage `json:"usage,omitempty"`
}

// IPPoolUsage reports the capacity and allocation usage of an IP pool.
type IPPoolUsage struct {
	// Total is the total number of IPs.
	// +optional
	Total int64 `json:"total"`
	// Used is the number of allocated IPs.
	// +optional
	Used int64 `json:"used"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type ExternalIPPoolList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`
	// +required
	Items []ExternalIPPool `json:"items"`
}
