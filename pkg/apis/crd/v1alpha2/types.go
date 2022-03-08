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
	"k8s.io/apimachinery/pkg/util/intstr"

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
	ServiceReference *v1alpha1.NamespacedName `json:"serviceReference,omitempty"`
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

// SubnetInfo specifies subnet attributes for IP Range
type SubnetInfo struct {
	// Gateway IP for this subnet, eg. 10.10.1.1
	Gateway string `json:"gateway"`
	// Prefix length for the subnet, eg. 24
	PrefixLength int32 `json:"prefixLength"`
	// VLAN ID for this subnet. Default is 0. String-typed for sake of potential autoselect option.
	VLAN string `json:"vlan,omitempty"`
}

// SubnetIPRange is a set of contiguous IP addresses, represented by a CIDR or a pair of start and end IPs,
// along with subnet definition.
type SubnetIPRange struct {
	IPRange    `json:",inline"`
	SubnetInfo `json:",inline"`
}

type IPPoolStatus struct {
	IPAddresses []IPAddressState `json:"ipAddresses,omitempty"`
	// TODO: add usage statistics
}

type IPAddressPhase string

const (
	IPAddressPhaseAllocated    IPAddressPhase = "Allocated"
	IPAddressPhasePreallocated IPAddressPhase = "Preallocated"
	IPAddressPhaseReserved     IPAddressPhase = "Reserved"
)

type IPAddressState struct {
	// IP Address this entry is tracking
	IPAddress string `json:"ipAddress"`
	// Allocation state - either Allocated or Preallocated
	Phase IPAddressPhase `json:"phase"`
	// Owner this IP Address is allocated to
	Owner IPAddressOwner `json:"owner"`
	// TODO: add usage statistics (consistent with ExternalIPPool status)
}

type IPAddressOwner struct {
	Pod         *PodOwner         `json:"pod,omitempty"`
	StatefulSet *StatefulSetOwner `json:"statefulSet,omitempty"`
}

// Pod owner
type PodOwner struct {
	Name        string `json:"name"`
	Namespace   string `json:"namespace"`
	ContainerID string `json:"containerID"`
}

// StatefulSet owner
type StatefulSetOwner struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Index     int    `json:"index"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type IPPoolList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []IPPool `json:"items"`
}

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
	AppliedTo []v1alpha1.NetworkPolicyPeer `json:"appliedTo,omitempty"`
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

// NetworkPolicyStatus represents information about the status of a NetworkPolicy.
type NetworkPolicyStatus struct {
	// The phase of a NetworkPolicy is a simple, high-level summary of the NetworkPolicy's status.
	Phase v1alpha1.NetworkPolicyPhase `json:"phase"`
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
	Action *v1alpha1.RuleAction `json:"action"`
	// Set of protocol with its specific spec allowed/denied by the rule. If this field
	// is unset or empty, this rule match all protocols supported in PeerProtocol.
	// +optional
	Protocols []PeerProtocol `json:"protocols,omitempty"`
	// Rule is matched if traffic originates from workloads selected by
	// this field. If this field is empty, this rule matches all sources.
	// +optional
	From []v1alpha1.NetworkPolicyPeer `json:"from"`
	// Rule is matched if traffic is intended for workloads selected by
	// this field. This field can't be used with ToServices. If this field
	// and ToServices are both empty or missing this rule matches all destinations.
	// +optional
	To []v1alpha1.NetworkPolicyPeer `json:"to"`
	// Rule is matched if traffic is intended for a Service listed in this field.
	// Currently only ClusterIP types Services are supported in this field. This field
	// can only be used when AntreaProxy is enabled. This field can't be used with To
	// or Ports. If this field and To are both empty or missing, this rule matches all
	// destinations.
	// +optional
	ToServices []v1alpha1.NamespacedName `json:"toServices,omitempty"`
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
	AppliedTo []v1alpha1.NetworkPolicyPeer `json:"appliedTo,omitempty"`
}

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
	AppliedTo []v1alpha1.NetworkPolicyPeer `json:"appliedTo,omitempty"`
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

// PeerProtocol includes all protocols that are supported. All fields should be
// used as a stand-alone field. To match all traffic with a specific protocol, set
// the value of the corresponding field as an empty struct.
type PeerProtocol struct {
	TCP  *L4Protocol   `json:"tcp,omitempty"`
	UDP  *L4Protocol   `json:"udp,omitempty"`
	SCTP *L4Protocol   `json:"sctp,omitempty"`
	ICMP *ICMPProtocol `json:"icmp,omitempty"`
}

type L4Protocol struct {
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

// ICMPProtocol matches ICMP traffic with specific ICMPType and/or ICMPCode. All
// fields could be used alone or together. If all fields are not provided, this
// matches all ICMP traffic.
type ICMPProtocol struct {
	ICMPType *int32 `json:"icmpType,omitempty"`
	ICMPCode *int32 `json:"icmpCode,omitempty"`
}
