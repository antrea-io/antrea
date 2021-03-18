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
	"k8s.io/apimachinery/pkg/util/intstr"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type NetworkPolicy struct {
	metav1.TypeMeta `json:",inline"`
	// Standard metadata of the object.
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired behavior of NetworkPolicy.
	Spec NetworkPolicySpec `json:"spec"`
	// Most recently observed status of the NetworkPolicy.
	Status NetworkPolicyStatus `json:"status"`
}

// NetworkPolicySpec defines the desired state for NetworkPolicy.
type NetworkPolicySpec struct {
	// Tier specifies the tier to which this NetworkPolicy belongs to.
	// The NetworkPolicy order will be determined based on the combination of the
	// Tier's Priority and the NetworkPolicy's own Priority. If not specified,
	// this policy will be created in the Application Tier right above the K8s
	// NetworkPolicy which resides at the bottom.
	Tier string `json:"tier,omitempty"`
	// Priority specfies the order of the NetworkPolicy relative to other
	// NetworkPolicies.
	Priority float64 `json:"priority"`
	// Select workloads on which the rules will be applied to. Cannot be set in
	// conjunction with AppliedTo in each rule.
	// +optional
	AppliedTo []NetworkPolicyPeer `json:"appliedTo,omitempty"`
	// Set of ingress rules evaluated based on the order in which they are set.
	// Currently Ingress rule supports setting the `From` field but not the `To`
	// field within a Rule.
	// +optional
	Ingress []Rule `json:"ingress"`
	// Set of egress rules evaluated based on the order in which they are set.
	// Currently Egress rule supports setting the `To` field but not the `From`
	// field within a Rule.
	// +optional
	Egress []Rule `json:"egress"`
}

// NetworkPolicyPhase defines the phase in which a NetworkPolicy is.
type NetworkPolicyPhase string

// These are the valid values for NetworkPolicyPhase.
const (
	// NetworkPolicyPending means the NetworkPolicy has been accepted by the system, but it has not been processed by Antrea.
	NetworkPolicyPending NetworkPolicyPhase = "Pending"
	// NetworkPolicyRealizing means the NetworkPolicy has been observed by Antrea and is being realized.
	NetworkPolicyRealizing NetworkPolicyPhase = "Realizing"
	// NetworkPolicyRealized means the NetworkPolicy has been enforced to all Pods on all Nodes it applies to.
	NetworkPolicyRealized NetworkPolicyPhase = "Realized"
)

// NetworkPolicyStatus represents information about the status of a NetworkPolicy.
type NetworkPolicyStatus struct {
	// The phase of a NetworkPolicy is a simple, high-level summary of the NetworkPolicy's status.
	Phase NetworkPolicyPhase `json:"phase"`
	// The generation observed by Antrea.
	ObservedGeneration int64 `json:"observedGeneration"`
	// The number of nodes that have realized the NetworkPolicy.
	CurrentNodesRealized int32 `json:"currentNodesRealized"`
	// The total number of nodes that should realize the NetworkPolicy.
	DesiredNodesRealized int32 `json:"desiredNodesRealized"`
}

// Rule describes the traffic allowed to/from the workloads selected by
// Spec.AppliedTo. Based on the action specified in the rule, traffic is either
// allowed or denied which exactly match the specified ports and protocol.
type Rule struct {
	// Action specifies the action to be applied on the rule.
	Action *RuleAction `json:"action"`
	// Set of port and protocol allowed/denied by the rule. If this field is unset
	// or empty, this rule matches all ports.
	// +optional
	Ports []NetworkPolicyPort `json:"ports,omitempty"`
	// Rule is matched if traffic originates from workloads selected by
	// this field. If this field is empty, this rule matches all sources.
	// +optional
	From []NetworkPolicyPeer `json:"from"`
	// Rule is matched if traffic is intended for workloads selected by
	// this field. If this field is empty or missing, this rule matches all
	// destinations.
	// +optional
	To []NetworkPolicyPeer `json:"to"`
	// Name describes the intention of this rule.
	// Name should be unique within the policy.
	// +optional
	Name string `json:"name"`
	// EnableLogging is used to indicate if agent should generate logs
	// when rules are matched. Should be default to false.
	EnableLogging bool `json:"enableLogging"`
	// Select workloads on which this rule will be applied to. Cannot be set in
	// conjunction with NetworkPolicySpec/ClusterNetworkPolicySpec.AppliedTo.
	// +optional
	AppliedTo []NetworkPolicyPeer `json:"appliedTo,omitempty"`
}

// NetworkPolicyPeer describes the grouping selector of workloads.
type NetworkPolicyPeer struct {
	// IPBlock describes the IPAddresses/IPBlocks that is matched in to/from.
	// IPBlock cannot be set as part of the AppliedTo field.
	// Cannot be set with any other selector.
	// +optional
	IPBlock *IPBlock `json:"ipBlock,omitempty"`
	// Select Pods from NetworkPolicy's Namespace as workloads in
	// AppliedTo/To/From fields. If set with NamespaceSelector, Pods are
	// matched from Namespaces matched by the NamespaceSelector.
	// Cannot be set with any other selector except NamespaceSelector.
	// +optional
	PodSelector *metav1.LabelSelector `json:"podSelector,omitempty"`
	// Select all Pods from Namespaces matched by this selector, as
	// workloads in To/From fields. If set with PodSelector,
	// Pods are matched from Namespaces matched by the NamespaceSelector.
	// Cannot be set with any other selector except PodSelector or
	// ExternalEntitySelector.
	// +optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
	// Select ExternalEntities from NetworkPolicy's Namespace as workloads
	// in AppliedTo/To/From fields. If set with NamespaceSelector,
	// ExternalEntities are matched from Namespaces matched by the
	// NamespaceSelector.
	// Cannot be set with any other selector except NamespaceSelector.
	// +optional
	ExternalEntitySelector *metav1.LabelSelector `json:"externalEntitySelector,omitempty"`
	// Group is the name of the ClusterGroup which can be set as an
	// AppliedTo or within an Ingress or Egress rule in place of
	// a stand-alone selector. A Group cannot be set with any other
	// selector.
	Group string `json:"group,omitempty"`
}

// IPBlock describes a particular CIDR (Ex. "192.168.1.1/24") that is allowed
// or denied to/from the workloads matched by a Spec.AppliedTo.
type IPBlock struct {
	// CIDR is a string representing the IP Block
	// Valid examples are "192.168.1.1/24".
	CIDR string `json:"cidr"`
}

// NetworkPolicyPort describes the port and protocol to match in a rule.
type NetworkPolicyPort struct {
	// The protocol (TCP, UDP, or SCTP) which traffic must match.
	// If not specified, this field defaults to TCP.
	// +optional
	Protocol *v1.Protocol `json:"protocol,omitempty"`
	// The port on the given protocol. This can be either a numerical
	// or named port on a Pod. If this field is not provided, this
	// matches all port names and numbers.
	// +optional
	Port *intstr.IntOrString `json:"port,omitempty"`
	// EndPort defines the end of the port range, being the end included within the range.
	// It can only be specified when a numerical `port` is specified.
	// +optional
	EndPort *int32 `json:"endPort,omitempty"`
}

// RuleAction describes the action to be applied on traffic matching a rule.
type RuleAction string

const (
	// RuleActionAllow describes that the traffic matching the rule must be allowed.
	RuleActionAllow RuleAction = "Allow"
	// RuleActionDrop describes that the traffic matching the rule must be dropped.
	RuleActionDrop RuleAction = "Drop"
	// RuleActionReject indicates that the traffic matching the rule must be rejected and the
	// client will receive a response.
	RuleActionReject RuleAction = "Reject"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type NetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []NetworkPolicy `json:"items"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type ClusterNetworkPolicy struct {
	metav1.TypeMeta `json:",inline"`
	// Standard metadata of the object.
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired behavior of ClusterNetworkPolicy.
	Spec ClusterNetworkPolicySpec `json:"spec"`
	// Most recently observed status of the NetworkPolicy.
	Status NetworkPolicyStatus `json:"status"`
}

// ClusterNetworkPolicySpec defines the desired state for ClusterNetworkPolicy.
type ClusterNetworkPolicySpec struct {
	// Tier specifies the tier to which this ClusterNetworkPolicy belongs to.
	// The ClusterNetworkPolicy order will be determined based on the
	// combination of the Tier's Priority and the ClusterNetworkPolicy's own
	// Priority. If not specified, this policy will be created in the Application
	// Tier right above the K8s NetworkPolicy which resides at the bottom.
	Tier string `json:"tier,omitempty"`
	// Priority specfies the order of the ClusterNetworkPolicy relative to
	// other AntreaClusterNetworkPolicies.
	Priority float64 `json:"priority"`
	// Select workloads on which the rules will be applied to. Cannot be set in
	// conjunction with AppliedTo in each rule.
	// +optional
	AppliedTo []NetworkPolicyPeer `json:"appliedTo,omitempty"`
	// Set of ingress rules evaluated based on the order in which they are set.
	// Currently Ingress rule supports setting the `From` field but not the `To`
	// field within a Rule.
	// +optional
	Ingress []Rule `json:"ingress"`
	// Set of egress rules evaluated based on the order in which they are set.
	// Currently Egress rule supports setting the `To` field but not the `From`
	// field within a Rule.
	// +optional
	Egress []Rule `json:"egress"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type ClusterNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []ClusterNetworkPolicy `json:"items"`
}

// +genclient
// +genclient:nonNamespaced
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type Tier struct {
	metav1.TypeMeta `json:",inline"`
	// Standard metadata of the object.
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the desired behavior of Tier.
	Spec TierSpec `json:"spec"`
}

// TierSpec defines the desired state for Tier.
type TierSpec struct {
	// Priority specfies the order of the Tier relative to other Tiers.
	Priority int32 `json:"priority"`
	// Description is an optional field to add more information regarding
	// the purpose of this Tier.
	Description string `json:"description,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type TierList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []Tier `json:"items"`
}
