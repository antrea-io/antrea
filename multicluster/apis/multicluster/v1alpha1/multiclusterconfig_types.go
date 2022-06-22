/*
Copyright 2021 Antrea Authors.

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
	config "sigs.k8s.io/controller-runtime/pkg/config/v1alpha1"
)

// Precedence defines the precedence of Node IP type.
type Precedence string

const (
	PrecedencePrivate = "private"
	PrecedencePublic  = "public"
)

//+kubebuilder:object:root=true

// +kubebuilder:printcolumn:name="Gateway IP Precedence",type=string,JSONPath=`.gatewayIPPrecedence`,description="Precedence of Gateway IP types"
// +kubebuilder:printcolumn:name="Service CIDR",type=string,JSONPath=`.serviceCIDR`,description="Manually specified Service CIDR"
type MultiClusterConfig struct {
	metav1.TypeMeta `json:",inline"`
	// ControllerManagerConfigurationSpec defines the contfigurations for controllers.
	config.ControllerManagerConfigurationSpec `json:",inline"`
	// ServiceCIDR allows user to set the ClusterIP range of the cluster manually.
	ServiceCIDR string `json:"serviceCIDR,omitempty"`
	// The precedence about which IP address (internal or external IP) of Node is preferred to
	// be used as the cross-cluster tunnel endpoint. if not specified, internal IP will be chosen.
	GatewayIPPrecedence Precedence `json:"gatewayIPPrecedence,omitempty"`
}

func init() {
	SchemeBuilder.Register(&MultiClusterConfig{})
}
