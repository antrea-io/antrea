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
	// The port of antrea agent API Server
	APIPort int `json:"apiPort,omitempty"`
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
