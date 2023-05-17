/*
Copyright 2022 Antrea Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GatewayInfo includes information of a Gateway.
type GatewayInfo struct {
	GatewayIP string `json:"gatewayIP,omitempty"`
}

// WireGuardInfo includes information of a WireGuard tunnel.
type WireGuardInfo struct {
	// Public key of the WireGuard tunnel.
	PublicKey string `json:"publicKey,omitempty"`
}

// +genclient
//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// +kubebuilder:printcolumn:name="Gateway IP",type=string,JSONPath=`.gatewayIP`,description="Cross-cluster tunnel IP"
// +kubebuilder:printcolumn:name="Internal IP",type=string,JSONPath=`.internalIP`,description="In-cluster tunnel IP"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=`.metadata.creationTimestamp`
// Gateway includes information of a Multi-cluster Gateway.
type Gateway struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Cross-cluster tunnel IP of the Gateway.
	GatewayIP string `json:"gatewayIP,omitempty"`
	// In-cluster tunnel IP of the Gateway.
	InternalIP string `json:"internalIP,omitempty"`
	// Service CIDR of the local member cluster.
	ServiceCIDR string         `json:"serviceCIDR,omitempty"`
	WireGuard   *WireGuardInfo `json:"wireGuard,omitempty"`
}

type ClusterInfo struct {
	// ClusterID of the member cluster.
	ClusterID string `json:"clusterID,omitempty"`
	// ServiceCIDR is the IP ranges used by Service ClusterIP.
	ServiceCIDR string `json:"serviceCIDR,omitempty"`
	// GatewayInfos has information of Gateways
	GatewayInfos []GatewayInfo `json:"gatewayInfos,omitempty"`
	// PodCIDRs is the Pod IP address CIDRs.
	PodCIDRs  []string       `json:"podCIDRs,omitempty"`
	WireGuard *WireGuardInfo `json:"wireGuard,omitempty"`
}

//+kubebuilder:object:root=true

type GatewayList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Gateway `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Gateway{}, &GatewayList{})
}
