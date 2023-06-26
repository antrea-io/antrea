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

	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
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
