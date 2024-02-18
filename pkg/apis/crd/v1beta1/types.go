// Copyright 2019 Antrea Authors
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

package v1beta1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type AntreaAgentInfo struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// Antrea binary version
	Version string `json:"version,omitempty"`
	// The Pod that Antrea Agent is running in
	PodRef corev1.ObjectReference `json:"podRef,omitempty"`
	// The Node that Antrea Agent is running in
	NodeRef corev1.ObjectReference `json:"nodeRef,omitempty"`
	// Node subnets
	NodeSubnets []string `json:"nodeSubnets,omitempty"`
	// OVS Information
	OVSInfo OVSInfo `json:"ovsInfo,omitempty"`
	// Antrea Agent NetworkPolicy information
	NetworkPolicyControllerInfo NetworkPolicyControllerInfo `json:"networkPolicyControllerInfo,omitempty"`
	// The number of Pods which the agent is in charge of
	LocalPodNum int32 `json:"localPodNum,omitempty"`
	// Agent condition contains types like AgentHealthy
	AgentConditions []AgentCondition `json:"agentConditions,omitempty"`
	// The port of Antrea Agent API Server
	APIPort int `json:"apiPort,omitempty"`
	// APICABundle is a PEM encoded CA bundle which can be used to validate the Antrea Agent API
	// server's certificate.
	APICABundle []byte `json:"apiCABundle,omitempty"`
	// The port range used by NodePortLocal
	NodePortLocalPortRange string `json:"nodePortLocalPortRange,omitempty"`
}

type OVSInfo struct {
	Version    string `json:"version,omitempty"`
	BridgeName string `json:"bridgeName,omitempty"`
	// Key: flow table name, Value: flow number
	FlowTable map[string]int32 `json:"flowTable,omitempty"`
}

type AgentConditionType string

const (
	// AgentHealthy's Status is always set to be True and its LastHeartbeatTime is used to check Agent health status.
	AgentHealthy AgentConditionType = "AgentHealthy"
	// ControllerConnectionUp is used to mark the connection status between Agent and Controller.
	ControllerConnectionUp AgentConditionType = "ControllerConnectionUp"
	// OVSDBConnectionUp is used to mark OVSDB connection status.
	OVSDBConnectionUp AgentConditionType = "OVSDBConnectionUp"
	// OpenflowConnectionUp is used to mark Openflow connection status.
	OpenflowConnectionUp AgentConditionType = "OpenflowConnectionUp"
)

type AgentCondition struct {
	// One of the AgentConditionType listed above
	Type AgentConditionType `json:"type"`
	// Mark certain type status, one of True, False, Unknown
	Status corev1.ConditionStatus `json:"status"`
	// The timestamp when AntreaAgentInfo is created/updated, ideally heartbeat interval is 60s
	LastHeartbeatTime metav1.Time `json:"lastHeartbeatTime"`
	// Brief reason
	Reason string `json:"reason,omitempty"`
	// Human readable message indicating details
	Message string `json:"message,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type AntreaAgentInfoList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []AntreaAgentInfo `json:"items"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type AntreaControllerInfo struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Antrea binary version
	Version string `json:"version,omitempty"`
	// The Pod that Antrea Controller is running in
	PodRef corev1.ObjectReference `json:"podRef,omitempty"`
	// The Node that Antrea Controller is running in
	NodeRef corev1.ObjectReference `json:"nodeRef,omitempty"`
	// Antrea Controller Service
	ServiceRef corev1.ObjectReference `json:"serviceRef,omitempty"`
	// Antrea Controller NetworkPolicy information
	NetworkPolicyControllerInfo NetworkPolicyControllerInfo `json:"networkPolicyControllerInfo,omitempty"`
	// Number of agents which are connected to this controller
	ConnectedAgentNum int32 `json:"connectedAgentNum,omitempty"`
	// Controller condition contains types like ControllerHealthy
	ControllerConditions []ControllerCondition `json:"controllerConditions,omitempty"`
	// The port of antrea controller API Server
	APIPort int `json:"apiPort,omitempty"`
}

type NetworkPolicyControllerInfo struct {
	NetworkPolicyNum  int32 `json:"networkPolicyNum,omitempty"`
	AddressGroupNum   int32 `json:"addressGroupNum,omitempty"`
	AppliedToGroupNum int32 `json:"appliedToGroupNum,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type AntreaControllerInfoList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []AntreaControllerInfo `json:"items"`
}

type ControllerConditionType string

const (
	// ControllerHealthy's Status is always set to be True and its LastHeartbeatTime is used to check Controller health
	// status.
	ControllerHealthy ControllerConditionType = "ControllerHealthy"
)

type ControllerCondition struct {
	// One of the ControllerConditionType listed above, controllerHealthy
	Type ControllerConditionType `json:"type"`
	// Mark certain type status, one of True, False, Unknown
	Status corev1.ConditionStatus `json:"status"`
	// The timestamp when AntreaControllerInfo is created/updated, ideally heartbeat interval is 60s
	LastHeartbeatTime metav1.Time `json:"lastHeartbeatTime"`
	// Brief reason
	Reason string `json:"reason,omitempty"`
	// Human readable message indicating details
	Message string `json:"message,omitempty"`
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
	// The Subnet info of this IP pool. If set, all IP ranges in the IP pool should share the same subnet attributes.
	// Currently, it's only used when an IP is allocated from the pool for Egress, and is ignored otherwise.
	SubnetInfo *SubnetInfo `json:"subnetInfo,omitempty"`
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

// SubnetInfo specifies subnet attributes for IP Range.
type SubnetInfo struct {
	// Gateway IP for this subnet, e.g. 10.10.1.1.
	Gateway string `json:"gateway"`
	// Prefix length for the subnet, e.g. 24.
	PrefixLength int32 `json:"prefixLength"`
	// VLAN ID for this subnet. Default is 0. Valid value is 0~4094.
	VLAN int32 `json:"vlan,omitempty"`
}

type ExternalIPPoolStatus struct {
	Usage IPPoolUsage `json:"usage,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type ExternalIPPoolList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []ExternalIPPool `json:"items"`
}

type IPPoolUsage struct {
	// Total number of IPs.
	Total int `json:"total"`
	// Number of allocated IPs.
	Used int `json:"used"`
}

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
	// IPBlocks describe the IPAddresses/IPBlocks that are matched in to/from.
	// IPBlocks cannot be set as part of the AppliedTo field.
	// Cannot be set with any other selector or ServiceReference.
	// +optional
	IPBlocks []IPBlock `json:"ipBlocks,omitempty"`
	// Select backend Pods of the referred Service.
	// Cannot be set with any other selector or ipBlock.
	// +optional
	ServiceReference *NamespacedName `json:"serviceReference,omitempty"`
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
	Type               GroupConditionType     `json:"type"`
	Status             corev1.ConditionStatus `json:"status"`
	LastTransitionTime metav1.Time            `json:"lastTransitionTime,omitempty"`
}

// GroupStatus represents information about the status of a Group.
type GroupStatus struct {
	Conditions []GroupCondition `json:"conditions,omitempty"`
}

// ClusterGroupReference represent reference to a ClusterGroup.
type ClusterGroupReference string

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type ClusterGroupList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []ClusterGroup `json:"items,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Group can be used in AntreaNetworkPolicies. When used with AppliedTo, it cannot include NamespaceSelector,
// otherwise, Antrea will not realize the NetworkPolicy or rule, but will just update the NetworkPolicy
// Status as "Unrealizable".
type Group struct {
	metav1.TypeMeta `json:",inline"`
	// Standard metadata of the object.
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Desired state of the group.
	Spec GroupSpec `json:"spec"`
	// Most recently observed status of the group.
	Status GroupStatus `json:"status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type GroupList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []Group `json:"items,omitempty"`
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
	AppliedTo []AppliedTo `json:"appliedTo,omitempty"`
	// Set of ingress rules evaluated based on the order in which they are set.
	// Currently Ingress rule supports setting the `From` field but not the `To`
	// field within a Rule.
	// +optional
	Ingress []Rule `json:"ingress,omitempty"`
	// Set of egress rules evaluated based on the order in which they are set.
	// Currently Egress rule supports setting the `To` field but not the `From`
	// field within a Rule.
	// +optional
	Egress []Rule `json:"egress,omitempty"`
}

// NetworkPolicyPhase defines the phase in which a NetworkPolicy is.
type NetworkPolicyPhase string

// NetworkPolicyConditionType describes the condition types of NetworkPolicies.
type NetworkPolicyConditionType string

// These are the valid values for NetworkPolicyPhase.
const (
	// NetworkPolicyPending means the NetworkPolicy has been accepted by the system, but it has not been processed by Antrea.
	NetworkPolicyPending NetworkPolicyPhase = "Pending"
	// NetworkPolicyRealizing means the NetworkPolicy has been observed by Antrea and is being realized.
	NetworkPolicyRealizing NetworkPolicyPhase = "Realizing"
	// NetworkPolicyRealized means the NetworkPolicy has been enforced to all Pods on all Nodes it applies to.
	NetworkPolicyRealized NetworkPolicyPhase = "Realized"
	// NetworkPolicyFailed means the NetworkPolicy is failed to be enforced on at least one Node.
	NetworkPolicyFailed NetworkPolicyPhase = "Failed"
)

// These are valid conditions of a deployment.
const (
	// NetworkPolicyConditionRealizable reports whether the NetworkPolicy is realizable and the reasons why it is not.
	NetworkPolicyConditionRealizable NetworkPolicyConditionType = "Realizable"
	// NetworkPolicyConditionRealizationFailure reports information about a failure when realizing the NetworkPolicy on a Node.
	NetworkPolicyConditionRealizationFailure NetworkPolicyConditionType = "RealizationFailure"
)

// NetworkPolicyCondition describes the state of a NetworkPolicy at a certain point.
type NetworkPolicyCondition struct {
	// Type of StatefulSet condition.
	Type NetworkPolicyConditionType `json:"type"`
	// Status of the condition, one of True, False, Unknown.
	Status metav1.ConditionStatus `json:"status"`
	// Last time the condition transitioned from one status to another.
	// +optional
	LastTransitionTime metav1.Time `json:"lastTransitionTime,omitempty"`
	// The reason for the condition's last transition.
	// +optional
	Reason string `json:"reason,omitempty"`
	// A human-readable message indicating details about the transition.
	// +optional
	Message string `json:"message,omitempty"`
}

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
	// Represents the latest available observations of a NetworkPolicy current state.
	Conditions []NetworkPolicyCondition `json:"conditions"`
}

// Rule describes the traffic allowed to/from the workloads selected by
// Spec.AppliedTo. Based on the action specified in the rule, traffic is either
// allowed or denied which exactly match the specified ports and protocol.
type Rule struct {
	// Action specifies the action to be applied on the rule.
	Action *RuleAction `json:"action"`
	// Set of ports and protocols matched by the rule. If this field and Protocols
	// are unset or empty, this rule matches all ports.
	// +optional
	Ports []NetworkPolicyPort `json:"ports,omitempty"`
	// Set of protocols matched by the rule. If this field and Ports are unset or
	// empty, this rule matches all protocols supported.
	// +optional
	Protocols []NetworkPolicyProtocol `json:"protocols,omitempty"`
	// Set of layer 7 protocols matched by the rule. If this field is set, action can only be Allow.
	// When this field is used in a rule, any traffic matching the other layer 3/4 criteria of the rule (typically the
	// 5-tuple) will be forwarded to an application-aware engine for protocol detection and rule enforcement, and the
	// traffic will be allowed if the layer 7 criteria is also matched, otherwise it will be dropped. Therefore, any
	// rules after a layer 7 rule will not be enforced for the traffic.
	L7Protocols []L7Protocol `json:"l7Protocols,omitempty"`
	// Rule is matched if traffic originates from workloads selected by
	// this field. If this field is empty, this rule matches all sources.
	// +optional
	From []NetworkPolicyPeer `json:"from,omitempty"`
	// Rule is matched if traffic is intended for workloads selected by
	// this field. This field can't be used with ToServices. If this field
	// and ToServices are both empty or missing this rule matches all destinations.
	// +optional
	To []NetworkPolicyPeer `json:"to,omitempty"`
	// Rule is matched if traffic is intended for a Service listed in this field.
	// Currently, only ClusterIP types Services are supported in this field.
	// When scope is set to ClusterSet, it matches traffic intended for a multi-cluster
	// Service listed in this field. Service name and Namespace provided should match
	// the original exported Service.
	// This field can only be used when AntreaProxy is enabled. This field can't be used
	// with To or Ports. If this field and To are both empty or missing, this rule matches
	// all destinations.
	// +optional
	ToServices []PeerService `json:"toServices,omitempty"`
	// Name describes the intention of this rule.
	// Name should be unique within the policy.
	// +optional
	Name string `json:"name,omitempty"`
	// EnableLogging is used to indicate if agent should generate logs
	// when rules are matched. Should be default to false.
	// +optional
	EnableLogging bool `json:"enableLogging"`
	// LogLabel is a user-defined arbitrary string which will be printed in the NetworkPolicy logs.
	// +optional
	LogLabel string `json:"logLabel,omitempty"`
	// Select workloads on which this rule will be applied to. Cannot be set in
	// conjunction with NetworkPolicySpec/ClusterNetworkPolicySpec.AppliedTo.
	// +optional
	AppliedTo []AppliedTo `json:"appliedTo,omitempty"`
}

// NetworkPolicyPeer describes the grouping selector of workloads.
type NetworkPolicyPeer struct {
	// IPBlock describes the IPAddresses/IPBlocks that is matched in to/from.
	// IPBlock cannot be set as part of the AppliedTo field.
	// Cannot be set with any other selector.
	// +optional
	IPBlock *IPBlock `json:"ipBlock,omitempty"`
	// Select Pods from NetworkPolicy's Namespace as workloads in
	// To/From fields. If set with NamespaceSelector, Pods are
	// matched from Namespaces matched by the NamespaceSelector.
	// Cannot be set with any other selector except NamespaceSelector.
	// +optional
	PodSelector *metav1.LabelSelector `json:"podSelector,omitempty"`
	// Select all Pods from Namespaces matched by this selector, as
	// workloads in To/From fields. If set with PodSelector,
	// Pods are matched from Namespaces matched by the NamespaceSelector.
	// Cannot be set with any other selector except PodSelector or
	// ExternalEntitySelector. Cannot be set with Namespaces.
	// +optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
	// Select Pod/ExternalEntity from Namespaces matched by specific criteria.
	// Current supported criteria is match: Self, which selects from the same
	// Namespace of the appliedTo workloads.
	// Cannot be set with any other selector except PodSelector or
	// ExternalEntitySelector. This field can only be set when NetworkPolicyPeer
	// is created for ClusterNetworkPolicy ingress/egress rules.
	// Cannot be set with NamespaceSelector.
	// +optional
	Namespaces *PeerNamespaces `json:"namespaces,omitempty"`
	// Select ExternalEntities from NetworkPolicy's Namespace as workloads
	// in To/From fields. If set with NamespaceSelector,
	// ExternalEntities are matched from Namespaces matched by the
	// NamespaceSelector.
	// Cannot be set with any other selector except NamespaceSelector.
	// +optional
	ExternalEntitySelector *metav1.LabelSelector `json:"externalEntitySelector,omitempty"`
	// Group is the name of the ClusterGroup which can be set within
	// an Ingress or Egress rule in place of a stand-alone selector.
	// A Group cannot be set with any other selector.
	Group string `json:"group,omitempty"`
	// Restrict egress access to the Fully Qualified Domain Names prescribed
	// by name or by wildcard match patterns. This field can only be set for
	// NetworkPolicyPeer of egress rules.
	// Supported formats are:
	//  Exact FQDNs such as "google.com".
	//  Wildcard expressions such as "*wayfair.com".
	FQDN string `json:"fqdn,omitempty"`
	// Select all Pods with the ServiceAccount matched by this field, as
	// workloads in To/From fields.
	// Cannot be set with any other selector.
	// +optional
	ServiceAccount *NamespacedName `json:"serviceAccount,omitempty"`
	// Select certain Nodes which match the label selector.
	// A NodeSelector cannot be set with any other selector.
	// +optional
	NodeSelector *metav1.LabelSelector `json:"nodeSelector,omitempty"`
	// Define scope of the Pod/NamespaceSelector(s) of this peer.
	// Can only be used in ingress NetworkPolicyPeers.
	// Defaults to "Cluster".
	// +optional
	Scope PeerScope `json:"scope,omitempty"`
}

// AppliedTo describes the grouping selector of workloads in AppliedTo field.
type AppliedTo struct {
	// Select Pods from NetworkPolicy's Namespace as workloads in
	// AppliedTo fields. If set with NamespaceSelector, Pods are
	// matched from Namespaces matched by the NamespaceSelector.
	// Cannot be set with any other selector except NamespaceSelector.
	// +optional
	PodSelector *metav1.LabelSelector `json:"podSelector,omitempty"`
	// Select all Pods from Namespaces matched by this selector, as
	// workloads in AppliedTo fields. If set with PodSelector,
	// Pods are matched from Namespaces matched by the NamespaceSelector.
	// Cannot be set with any other selector except PodSelector or
	// ExternalEntitySelector. Cannot be set with Namespaces.
	// +optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
	// Select ExternalEntities from NetworkPolicy's Namespace as workloads
	// in AppliedTo fields. If set with NamespaceSelector,
	// ExternalEntities are matched from Namespaces matched by the
	// NamespaceSelector.
	// Cannot be set with any other selector except NamespaceSelector.
	// +optional
	ExternalEntitySelector *metav1.LabelSelector `json:"externalEntitySelector,omitempty"`
	// Group is the name of the ClusterGroup which can be set as an
	// AppliedTo in place of a stand-alone selector. A Group cannot
	// be set with any other selector.
	// +optional
	Group string `json:"group,omitempty"`
	// Select all Pods with the ServiceAccount matched by this field, as
	// workloads in AppliedTo fields.
	// Cannot be set with any other selector.
	// +optional
	ServiceAccount *NamespacedName `json:"serviceAccount,omitempty"`
	// Select a certain Service which matches the NamespacedName.
	// A Service can only be set in either policy level AppliedTo field in a policy
	// that only has ingress rules or rule level AppliedTo field in an ingress rule.
	// Only a NodePort Service can be referred by this field.
	// Cannot be set with any other selector.
	// +optional
	Service *NamespacedName `json:"service,omitempty"`
	// Select Nodes in cluster as workloads in AppliedTo fields.
	// Cannot be set with any other selector.
	// +optional
	NodeSelector *metav1.LabelSelector `json:"nodeSelector,omitempty"`
}

type PeerNamespaces struct {
	Match NamespaceMatchType `json:"match,omitempty"`
}

// NamespaceMatchType describes Namespace matching strategy.
type NamespaceMatchType string

const (
	NamespaceMatchSelf NamespaceMatchType = "Self"
)

type PeerScope string

const (
	ScopeCluster    PeerScope = "Cluster"
	ScopeClusterSet PeerScope = "ClusterSet"
)

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
	Protocol *corev1.Protocol `json:"protocol,omitempty"`
	// The port on the given protocol. This can be either a numerical
	// or named port on a Pod. If this field is not provided, this
	// matches all port names and numbers.
	// +optional
	Port *intstr.IntOrString `json:"port,omitempty"`
	// EndPort defines the end of the port range, inclusive.
	// It can only be specified when a numerical `port` is specified.
	// +optional
	EndPort *int32 `json:"endPort,omitempty"`
	// The source port on the given protocol. This can only be a numerical port.
	// If this field is not provided, rule matches all source ports.
	// +optional
	SourcePort *int32 `json:"sourcePort,omitempty"`
	// SourceEndPort defines the end of the source port range, inclusive.
	// It can only be specified when `sourcePort` is specified.
	// +optional
	SourceEndPort *int32 `json:"sourceEndPort,omitempty"`
}

// RuleAction describes the action to be applied on traffic matching a rule.
type RuleAction string

const (
	// RuleActionAllow describes that the traffic matching the rule must be allowed.
	RuleActionAllow RuleAction = "Allow"
	// RuleActionDrop describes that the traffic matching the rule must be dropped.
	RuleActionDrop RuleAction = "Drop"
	// RuleActionPass indicates that the traffic matching the rule will not be evaluated
	// by Antrea NetworkPolicy or ClusterNetworkPolicy, but rather punt to K8s namespaced
	// NetworkPolicy for evaluation.
	RuleActionPass RuleAction = "Pass"
	// RuleActionReject indicates that the traffic matching the rule must be rejected and the
	// client will receive a response.
	RuleActionReject RuleAction = "Reject"

	IGMPQuery    int32 = 0x11
	IGMPReportV1 int32 = 0x12
	IGMPReportV2 int32 = 0x16
	IGMPReportV3 int32 = 0x22
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
	AppliedTo []AppliedTo `json:"appliedTo,omitempty"`
	// Set of ingress rules evaluated based on the order in which they are set.
	// Currently Ingress rule supports setting the `From` field but not the `To`
	// field within a Rule.
	// +optional
	Ingress []Rule `json:"ingress,omitempty"`
	// Set of egress rules evaluated based on the order in which they are set.
	// Currently Egress rule supports setting the `To` field but not the `From`
	// field within a Rule.
	// +optional
	Egress []Rule `json:"egress,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type ClusterNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []ClusterNetworkPolicy `json:"items"`
}

// NamespacedName refers to a Namespace scoped resource.
// All fields must be used together.
type NamespacedName struct {
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

// PeerService refers to a Service, which can be a in-cluster Service or
// imported multi-cluster service.
type PeerService struct {
	Name      string    `json:"name,omitempty"`
	Namespace string    `json:"namespace,omitempty"`
	Scope     PeerScope `json:"scope,omitempty"`
}

// NetworkPolicyProtocol defines additional protocols that are not supported by
// `ports`. All fields should be used as a standalone field.
type NetworkPolicyProtocol struct {
	ICMP *ICMPProtocol `json:"icmp,omitempty"`
	IGMP *IGMPProtocol `json:"igmp,omitempty"`
}

// ICMPProtocol matches ICMP traffic with specific ICMPType and/or ICMPCode. All
// fields could be used alone or together. If all fields are not provided, this
// matches all ICMP traffic.
type ICMPProtocol struct {
	ICMPType *int32 `json:"icmpType,omitempty"`
	ICMPCode *int32 `json:"icmpCode,omitempty"`
}

// IGMPProtocol matches IGMP traffic with IGMPType and GroupAddress. IGMPType must
// be filled with:
// IGMPQuery    int32 = 0x11
// IGMPReportV1 int32 = 0x12
// IGMPReportV2 int32 = 0x16
// IGMPReportV3 int32 = 0x22
// If groupAddress is empty, all groupAddresses will be matched.
type IGMPProtocol struct {
	IGMPType     *int32 `json:"igmpType,omitempty"`
	GroupAddress string `json:"groupAddress,omitempty"`
}

type L7Protocol struct {
	HTTP *HTTPProtocol `json:"http,omitempty"`
	TLS  *TLSProtocol  `json:"tls,omitempty"`
}

// HTTPProtocol matches HTTP requests with specific host, method, and path. All fields could be used alone or together.
// If all fields are not provided, it matches all HTTP requests.
type HTTPProtocol struct {
	// Host represents the hostname present in the URI or the HTTP Host header to match.
	// It does not contain the port associated with the host.
	Host string `json:"host,omitempty"`
	// Method represents the HTTP method to match.
	// It could be GET, POST, PUT, HEAD, DELETE, TRACE, OPTIONS, CONNECT and PATCH.
	Method string `json:"method,omitempty"`
	// Path represents the URI path to match (Ex. "/index.html", "/admin").
	Path string `json:"path,omitempty"`
}

// TLSProtocol matches TLS handshake packets with specific SNI. If the field is not provided, this
// matches all TLS handshake packets.
type TLSProtocol struct {
	// SNI (Server Name Indication) indicates the server domain name in the TLS/SSL hello message.
	SNI string `json:"sni,omitempty"`
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
	// EgressIP indicates the effective Egress IP for the selected workloads. It could be empty if the Egress IP in spec
	// is not assigned to any Node. It's also useful when there are more than one Egress IP specified in spec.
	EgressIP string `json:"egressIP"`

	Conditions []EgressCondition `json:"conditions,omitempty"`
}

type EgressConditionType string

const (
	// IPAllocated means at least one IP has been allocated to the Egress from ExternalIPPool.
	// It is not applicable for Egresses with empty ExternalIPPool.
	IPAllocated EgressConditionType = "IPAllocated"
	// IPAssigned means the Egress has been assigned to a Node.
	// It is not applicable for Egresses with empty ExternalIPPool.
	IPAssigned EgressConditionType = "IPAssigned"
)

type EgressCondition struct {
	Type               EgressConditionType    `json:"type,omitempty"`
	Status             corev1.ConditionStatus `json:"status,omitempty"`
	LastTransitionTime metav1.Time            `json:"lastTransitionTime,omitempty"`
	Reason             string                 `json:"reason,omitempty"`
	Message            string                 `json:"message,omitempty"`
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
	// EgressIPs specifies multiple SNAT IP addresses for the selected workloads.
	// Cannot be set with EgressIP.
	EgressIPs []string `json:"egressIPs,omitempty"`
	// ExternalIPPool specifies the IP Pool that the EgressIP should be allocated from.
	// If it is empty, the specified EgressIP must be assigned to a Node manually.
	// If it is non-empty, the EgressIP will be assigned to a Node specified by the pool automatically and will failover
	// to a different Node when the Node becomes unreachable.
	ExternalIPPool string `json:"externalIPPool,omitempty"`
	// ExternalIPPools specifies multiple unique IP Pools that the EgressIPs should be allocated from. Entries with the
	// same index in EgressIPs and ExternalIPPools are correlated.
	// Cannot be set with ExternalIPPool.
	ExternalIPPools []string `json:"externalIPPools,omitempty"`
	// Bandwidth specifies the rate limit of north-south egress traffic of this Egress.
	Bandwidth *Bandwidth `json:"bandwidth,omitempty"`
}

type Bandwidth struct {
	// Rate specifies the maximum traffic rate. e.g. 300k, 10M
	Rate string `json:"rate"`
	// Burst specifies the maximum burst size when traffic exceeds the rate. e.g. 300k, 10M
	Burst string `json:"burst"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type EgressList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []Egress `json:"items"`
}

type TraceflowPhase string

const (
	Running   TraceflowPhase = "Running"
	Succeeded TraceflowPhase = "Succeeded"
	Failed    TraceflowPhase = "Failed"
)

type TraceflowComponent string

const (
	ComponentSpoofGuard    TraceflowComponent = "SpoofGuard"
	ComponentLB            TraceflowComponent = "LB"
	ComponentRouting       TraceflowComponent = "Routing"
	ComponentNetworkPolicy TraceflowComponent = "NetworkPolicy"
	ComponentForwarding    TraceflowComponent = "Forwarding"
	ComponentEgress        TraceflowComponent = "Egress"
)

type TraceflowAction string

const (
	ActionDelivered TraceflowAction = "Delivered"
	ActionReceived  TraceflowAction = "Received"
	ActionForwarded TraceflowAction = "Forwarded"
	ActionDropped   TraceflowAction = "Dropped"
	ActionRejected  TraceflowAction = "Rejected"
	// ActionForwardedOutOfOverlay indicates that the packet has been forwarded out of the network
	// managed by Antrea. This indicates that the Traceflow request can be considered complete.
	ActionForwardedOutOfOverlay TraceflowAction = "ForwardedOutOfOverlay"
	ActionMarkedForSNAT         TraceflowAction = "MarkedForSNAT"
	ActionForwardedToEgressNode TraceflowAction = "ForwardedToEgressNode"
)

// List the supported protocols and their codes in traceflow.
// According to code in Antrea agent and controller, default protocol is ICMP if protocol is not inputted by users.
const (
	ICMPProtocolNumber int32 = 1
	IGMPProtocolNumber int32 = 2
	TCPProtocolNumber  int32 = 6
	UDPProtocolNumber  int32 = 17
	SCTPProtocolNumber int32 = 132
)

var SupportedProtocols = map[string]int32{
	"TCP":  TCPProtocolNumber,
	"UDP":  UDPProtocolNumber,
	"ICMP": ICMPProtocolNumber,
}

var ProtocolsToString = map[int32]string{
	TCPProtocolNumber:  "TCP",
	UDPProtocolNumber:  "UDP",
	ICMPProtocolNumber: "ICMP",
	IGMPProtocolNumber: "IGMP",
	SCTPProtocolNumber: "SCTP",
}

// List the supported destination types in traceflow.
const (
	DstTypePod     = "Pod"
	DstTypeService = "Service"
	DstTypeIPv4    = "IPv4"
)

var SupportedDestinationTypes = []string{
	DstTypePod,
	DstTypeService,
	DstTypeIPv4,
}

// Default timeout in seconds.
const DefaultTraceflowTimeout int32 = 20

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type Traceflow struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TraceflowSpec   `json:"spec,omitempty"`
	Status TraceflowStatus `json:"status,omitempty"`
}

// TraceflowSpec describes the spec of the traceflow.
type TraceflowSpec struct {
	Source      Source      `json:"source,omitempty"`
	Destination Destination `json:"destination,omitempty"`
	Packet      Packet      `json:"packet,omitempty"`
	// LiveTraffic indicates the Traceflow is to trace the live traffic
	// rather than an injected packet, when set to true. The first packet of
	// the first connection that matches the packet spec will be traced.
	LiveTraffic bool `json:"liveTraffic,omitempty"`
	// DroppedOnly indicates only the dropped packet should be captured in a
	// live-traffic Traceflow.
	DroppedOnly bool `json:"droppedOnly,omitempty"`
	// Timeout specifies the timeout of the Traceflow in seconds. Defaults
	// to 20 seconds if not set.
	Timeout int32 `json:"timeout,omitempty"`
}

// Source describes the source spec of the traceflow.
type Source struct {
	// Namespace is the source namespace.
	Namespace string `json:"namespace,omitempty"`
	// Pod is the source pod.
	Pod string `json:"pod,omitempty"`
	// IP is the source IPv4 or IPv6 address. IP as the source is supported
	// only for live-traffic Traceflow.
	IP string `json:"ip,omitempty"`
}

// Destination describes the destination spec of the traceflow.
type Destination struct {
	// Namespace is the destination namespace.
	Namespace string `json:"namespace,omitempty"`
	// Pod is the destination pod, exclusive with destination service.
	Pod string `json:"pod,omitempty"`
	// Service is the destination service, exclusive with destination pod.
	Service string `json:"service,omitempty"`
	// IP is the destination IPv4 or IPv6 address.
	IP string `json:"ip,omitempty"`
}

// IPHeader describes spec of an IPv4 header.
type IPHeader struct {
	// Protocol is the IP protocol.
	Protocol int32 `json:"protocol,omitempty" yaml:"protocol,omitempty"`
	// TTL is the IP TTL.
	TTL int32 `json:"ttl,omitempty" yaml:"ttl,omitempty"`
	// Flags is the flags for IP.
	Flags int32 `json:"flags,omitempty" yaml:"flags,omitempty"`
}

// IPv6Header describes spec of an IPv6 header.
type IPv6Header struct {
	// NextHeader is the IPv6 protocol.
	NextHeader *int32 `json:"nextHeader,omitempty" yaml:"nextHeader,omitempty"`
	// HopLimit is the IPv6 Hop Limit.
	HopLimit int32 `json:"hopLimit,omitempty" yaml:"hopLimit,omitempty"`
}

// TransportHeader describes spec of a TransportHeader.
type TransportHeader struct {
	ICMP *ICMPEchoRequestHeader `json:"icmp,omitempty" yaml:"icmp,omitempty"`
	UDP  *UDPHeader             `json:"udp,omitempty" yaml:"udp,omitempty"`
	TCP  *TCPHeader             `json:"tcp,omitempty" yaml:"tcp,omitempty"`
}

// ICMPEchoRequestHeader describes spec of an ICMP echo request header.
type ICMPEchoRequestHeader struct {
	// ID is the ICMPEchoRequestHeader ID.
	ID int32 `json:"id,omitempty"`
	// Sequence is the ICMPEchoRequestHeader sequence.
	Sequence int32 `json:"sequence,omitempty"`
}

// UDPHeader describes spec of a UDP header.
type UDPHeader struct {
	// SrcPort is the source port.
	SrcPort int32 `json:"srcPort,omitempty"`
	// DstPort is the destination port.
	DstPort int32 `json:"dstPort,omitempty"`
}

// TCPHeader describes spec of a TCP header.
type TCPHeader struct {
	// SrcPort is the source port.
	SrcPort int32 `json:"srcPort,omitempty"`
	// DstPort is the destination port.
	DstPort int32 `json:"dstPort,omitempty"`
	// Flags are flags in the header.
	Flags *int32 `json:"flags,omitempty"`
}

// Packet includes header info.
type Packet struct {
	SrcIP string `json:"srcIP,omitempty"`
	DstIP string `json:"dstIP,omitempty"`
	// Length is the IP packet length (includes the IPv4 or IPv6 header length).
	Length          int32           `json:"length,omitempty"`
	IPHeader        *IPHeader       `json:"ipHeader,omitempty"`
	IPv6Header      *IPv6Header     `json:"ipv6Header,omitempty"`
	TransportHeader TransportHeader `json:"transportHeader,omitempty"`
}

// TraceflowStatus describes current status of the traceflow.
type TraceflowStatus struct {
	// Phase is the Traceflow phase.
	Phase TraceflowPhase `json:"phase,omitempty"`
	// Reason is a message indicating the reason of the traceflow's current phase.
	Reason string `json:"reason,omitempty"`
	// StartTime is the time at which the Traceflow as started by the Antrea Controller.
	// Before K8s v1.20, null values (field not set) are not pruned, and a CR where a
	// metav1.Time field is not set would fail OpenAPI validation (type string). The
	// recommendation seems to be to use a pointer instead, and the field will be omitted when
	// serializing.
	// See https://github.com/kubernetes/kubernetes/issues/86811
	StartTime *metav1.Time `json:"startTime,omitempty"`
	// DataplaneTag is a tag to identify a traceflow session across Nodes.
	DataplaneTag int8 `json:"dataplaneTag,omitempty"`
	// Results is the collection of all observations on different nodes.
	Results []NodeResult `json:"results,omitempty"`
	// CapturedPacket is the captured packet in live-traffic Traceflow.
	CapturedPacket *Packet `json:"capturedPacket,omitempty"`
}

type NodeResult struct {
	// Node is the node of the observation.
	Node string `json:"node,omitempty" yaml:"node,omitempty"`
	// Role of the node like sender, receiver, etc.
	Role string `json:"role,omitempty" yaml:"role,omitempty"`
	// Timestamp is the timestamp of the observations on the node.
	Timestamp int64 `json:"timestamp,omitempty" yaml:"timestamp,omitempty"`
	// Observations includes all observations from sender nodes, receiver ones, etc.
	Observations []Observation `json:"observations,omitempty" yaml:"observations,omitempty"`
}

// Observation describes those from sender nodes or receiver nodes.
type Observation struct {
	// Component is the observation component.
	Component TraceflowComponent `json:"component,omitempty" yaml:"component,omitempty"`
	// ComponentInfo is the extension of Component field.
	ComponentInfo string `json:"componentInfo,omitempty" yaml:"componentInfo,omitempty"`
	// Action is the action to the observation.
	Action TraceflowAction `json:"action,omitempty" yaml:"action,omitempty"`
	// Pod is the combination of Pod name and Pod Namespace.
	Pod string `json:"pod,omitempty" yaml:"pod,omitempty"`
	// DstMAC is the destination MAC.
	DstMAC string `json:"dstMAC,omitempty" yaml:"dstMAC,omitempty"`
	// NetworkPolicy is the combination of Namespace and NetworkPolicyName.
	NetworkPolicy string `json:"networkPolicy,omitempty" yaml:"networkPolicy,omitempty"`
	// NetworkPolicyRule is the name of an ingress or an egress rule in NetworkPolicy.
	NetworkPolicyRule string `json:"networkPolicyRule,omitempty" yaml:"networkPolicyRule,omitempty"`
	// Egress is the name of the Egress.
	Egress string `json:"egress,omitempty" yaml:"egress,omitempty"`
	// TTL is the observation TTL.
	TTL int32 `json:"ttl,omitempty" yaml:"ttl,omitempty"`
	// TranslatedSrcIP is the translated source IP.
	TranslatedSrcIP string `json:"translatedSrcIP,omitempty" yaml:"translatedSrcIP,omitempty"`
	// TranslatedDstIP is the translated destination IP.
	TranslatedDstIP string `json:"translatedDstIP,omitempty" yaml:"translatedDstIP,omitempty"`
	// TunnelDstIP is the tunnel destination IP.
	TunnelDstIP string `json:"tunnelDstIP,omitempty" yaml:"tunnelDstIP,omitempty"`
	EgressIP    string `json:"egressIP,omitempty" yaml:"egressIP,omitempty"`
	// EgressNode is the name of the Egress Node.
	EgressNode string `json:"egressNode,omitempty" yaml:"egressNode,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type TraceflowList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []Traceflow `json:"items"`
}
