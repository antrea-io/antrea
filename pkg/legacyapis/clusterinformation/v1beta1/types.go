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

	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type AntreaAgentInfo struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Version                     string                                 `json:"version,omitempty"`                     // Antrea binary version
	PodRef                      corev1.ObjectReference                 `json:"podRef,omitempty"`                      // The Pod that Antrea Agent is running in
	NodeRef                     corev1.ObjectReference                 `json:"nodeRef,omitempty"`                     // The Node that Antrea Agent is running in
	NodeSubnets                 []string                               `json:"nodeSubnets,omitempty"`                 // Node subnets
	OVSInfo                     crdv1beta1.OVSInfo                     `json:"ovsInfo,omitempty"`                     // OVS Information
	NetworkPolicyControllerInfo crdv1beta1.NetworkPolicyControllerInfo `json:"networkPolicyControllerInfo,omitempty"` // Antrea Agent NetworkPolicy information
	LocalPodNum                 int32                                  `json:"localPodNum,omitempty"`                 // The number of Pods which the agent is in charge of
	AgentConditions             []crdv1beta1.AgentCondition            `json:"agentConditions,omitempty"`             // Agent condition contains types like AgentHealthy
	APIPort                     int                                    `json:"apiPort,omitempty"`                     // The port of antrea agent API Server
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

	Version                     string                                 `json:"version,omitempty"`                     // Antrea binary version
	PodRef                      corev1.ObjectReference                 `json:"podRef,omitempty"`                      // The Pod that Antrea Controller is running in
	NodeRef                     corev1.ObjectReference                 `json:"nodeRef,omitempty"`                     // The Node that Antrea Controller is running in
	ServiceRef                  corev1.ObjectReference                 `json:"serviceRef,omitempty"`                  // Antrea Controller Service
	NetworkPolicyControllerInfo crdv1beta1.NetworkPolicyControllerInfo `json:"networkPolicyControllerInfo,omitempty"` // Antrea Controller NetworkPolicy information
	ConnectedAgentNum           int32                                  `json:"connectedAgentNum,omitempty"`           // Number of agents which are connected to this controller
	ControllerConditions        []crdv1beta1.ControllerCondition       `json:"controllerConditions,omitempty"`        // Controller condition contains types like ControllerHealthy
	APIPort                     int                                    `json:"apiPort,omitempty"`                     // The port of antrea controller API Server
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type AntreaControllerInfoList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []AntreaControllerInfo `json:"items"`
}
