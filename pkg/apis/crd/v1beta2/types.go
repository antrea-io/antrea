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
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   EgressSpec   `json:"spec"`
	Status EgressStatus `json:"status"`
}

// EgressSpec defines the desired state for Egress.
type EgressSpec struct {
	// AppliedTo selects Pods to which the Egress will be applied.
	AppliedTo AppliedTo `json:"appliedTo"`
	// EgressIPs specifies the SNAT IP addresses for the selected workloads. One address represents a single-stack
	// Egress. Two addresses, one for each IP family, represent a dual-stack Egress. When ExternalIPPool is set,
	// EgressIPs may be empty and the addresses will be allocated automatically.
	EgressIPs []string `json:"egressIPs,omitempty"`
	// ExternalIPPool specifies the IP Pool from which EgressIPs are allocated. If it is not set, EgressIPs must be
	// specified and assigned to a Node manually.
	ExternalIPPool string `json:"externalIPPool,omitempty"`
	// IPFamilyPolicy specifies whether the Egress is single-stack or dual-stack. It defaults to PreferDualStack.
	IPFamilyPolicy *corev1.IPFamilyPolicy `json:"ipFamilyPolicy,omitempty"`
	// Bandwidth specifies the rate limit of north-south egress traffic of this Egress.
	Bandwidth *Bandwidth `json:"bandwidth,omitempty"`
}

// EgressStatus represents the current status of an Egress.
type EgressStatus struct {
	// EgressNode is the Node which hosts the effective Egress IPs.
	EgressNode string `json:"egressNode,omitempty"`
	// EgressIPs are the effective Egress IPs for the selected workloads. It may be empty when no IP has been allocated
	// or assigned yet.
	EgressIPs  []string          `json:"egressIPs,omitempty"`
	Conditions []EgressCondition `json:"conditions,omitempty"`
}

type EgressConditionType string

const (
	IPAllocated EgressConditionType = "IPAllocated"
	IPAssigned  EgressConditionType = "IPAssigned"
)

type EgressCondition struct {
	Type               EgressConditionType    `json:"type,omitempty"`
	Status             corev1.ConditionStatus `json:"status,omitempty"`
	LastTransitionTime metav1.Time            `json:"lastTransitionTime,omitempty"`
	Reason             string                 `json:"reason,omitempty"`
	Message            string                 `json:"message,omitempty"`
}

type Bandwidth struct {
	Rate  string `json:"rate"`
	Burst string `json:"burst"`
}

// AppliedTo describes the grouping selector of workloads in the AppliedTo field.
type AppliedTo struct {
	PodSelector       *metav1.LabelSelector `json:"podSelector,omitempty"`
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type EgressList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Egress `json:"items"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ExternalIPPool defines one or multiple IP sets that can be used in the external network.
type ExternalIPPool struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ExternalIPPoolSpec   `json:"spec"`
	Status ExternalIPPoolStatus `json:"status"`
}

type ExternalIPPoolSpec struct {
	IPRanges     []IPRange                 `json:"ipRanges"`
	SubnetInfo   *ExternalIPPoolSubnetInfo `json:"subnetInfo,omitempty"`
	NodeSelector metav1.LabelSelector      `json:"nodeSelector"`
}

type IPRange struct {
	CIDR  string `json:"cidr,omitempty"`
	Start string `json:"start,omitempty"`
	End   string `json:"end,omitempty"`
}

// ExternalIPPoolSubnetInfo specifies subnet attributes for IP ranges in an ExternalIPPool.
type ExternalIPPoolSubnetInfo struct {
	// Gateway is the gateway IP for a single-stack subnet. It cannot be set together with Gateways.
	Gateway string `json:"gateway,omitempty"`
	// PrefixLength is the prefix length for a single-stack subnet. It cannot be set together with Gateways.
	PrefixLength int32 `json:"prefixLength,omitempty"`
	// Gateways specifies subnet gateways by IP family. It cannot be set with Gateway or PrefixLength.
	Gateways []SubnetGateway `json:"gateways,omitempty"`
	// VLAN is the VLAN ID shared by all subnets.
	VLAN int32 `json:"vlan,omitempty"`
}

type SubnetGateway struct {
	Gateway      string `json:"gateway"`
	PrefixLength int32  `json:"prefixLength"`
}

// SubnetInfo specifies subnet attributes for an IP address.
type SubnetInfo struct {
	Gateway      string `json:"gateway"`
	PrefixLength int32  `json:"prefixLength"`
	VLAN         int32  `json:"vlan,omitempty"`
}

type ExternalIPPoolStatus struct {
	Usage IPPoolUsage `json:"usage,omitempty"`
}

type IPPoolUsage struct {
	Total int `json:"total"`
	Used  int `json:"used"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type ExternalIPPoolList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ExternalIPPool `json:"items"`
}
