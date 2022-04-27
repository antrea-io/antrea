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

// +genclient
//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// Gateway includes information of a Multi-cluster Gateway.
type Gateway struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Tunnel IP of the Gateway. It might be assigned by user manually
	// through a Node annotation.
	GatewayIP string `json:"gatewayIP,omitempty"`
	// Internal tunnel IP of the Gateway.
	InternalIP string `json:"internalIP,omitempty"`
}

type ClusterInfo struct {
	// ClusterID of the member cluster.
	ClusterID string `json:"clusterID,omitempty"`
	// ServiceCIDR is the IP ranges used by Service ClusterIP.
	ServiceCIDR string `json:"serviceCIDR,omitempty"`
	// GatewayInfos has information of Gateways
	GatewayInfos []GatewayInfo `json:"gatewayInfos,omitempty"`
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
