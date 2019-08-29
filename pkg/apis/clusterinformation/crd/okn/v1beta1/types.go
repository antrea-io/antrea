// Copyright 2019 OKN Authors
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

type OKNAgentInfo struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Pod                  corev1.ObjectReference `json:"pod,omitempty"`  // The Pod that OKN Agent is running in
	Node                 corev1.ObjectReference `json:"node,omitempty"` // The Node that OKN Agent is running in
	NodeSubnet           []string               `json:"nodeSubnet,omitempty"`
	ControllerConnection ConnectionStatus       `json:"controllerConnectionn,omitempty"` // Agent to Controller connection status
	OVSInfo              OVSInfo                `json:"ovsInfo,omitempty"`               // OVS Information
	PodNum               int32                  `json:"podNum,omitempty"`                // The number of Pods which the agent is in charge of
}

type ConnectionStatus string

const (
	ConnectionStatusUp      ConnectionStatus = "UP"
	ConnectionStatusDown    ConnectionStatus = "DOWN"
	ConnectionStatusUnknown ConnectionStatus = "UNKNOWN"
)

type OVSInfo struct {
	Version            string           `json:"version,omitempty"`
	OVSDBConnection    ConnectionStatus `json:"ovsdbConnection,omitempty"`
	OpenflowConnection ConnectionStatus `json:"openflowConnection,omitempty"`
	Bridge             string           `json:"bridge,omitempty"`
	FlowTable          map[string]int32 `json:"flowTable,omitempty"` // Key: flow table name, Value: flow number
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type OKNAgentInfoList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []OKNAgentInfo `json:"items"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type OKNControllerInfo struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Pod                         corev1.ObjectReference      `json:"pod,omitempty"`                         // The Pod that OKN Controller is running in
	PodCIDR                     string                      `json:"podCIDR,omitempty"`                     // Pod network CIDR
	Node                        corev1.ObjectReference      `json:"node,omitempty"`                        // The Node that OKN Controller is running in
	NetworkPolicyControllerInfo NetworkPolicyControllerInfo `json:"networkPolicyControllerInfo,omitempty"` // NetworkPolicy information
	ConnectedAgentNum           int32                       `json:"connectedAgentNum,omitempty"`           // Number of agents which are connected to this controller
}

type NetworkPolicyControllerInfo struct {
	PolicyNum        int32 `json:"policyNum,omitempty"`
	AddressGroupNum  int32 `json:"addressGroupNum,omitempty"`
	ApplyingGroupNum int32 `json:"applyingGroupNum,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type OKNControllerInfoList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []OKNControllerInfo `json:"items"`
}
