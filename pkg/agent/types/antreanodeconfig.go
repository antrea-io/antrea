// Copyright 2026 Antrea Authors
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

package types

import (
	"k8s.io/apimachinery/pkg/types"

	crdv1beta1 "antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
)

// SecondaryNetworkStatus associates one reconciliation result with its actual ANC target.
// ConfigUID is internal so an older result cannot be attributed to a newer public target.
type SecondaryNetworkStatus struct {
	*crdv1beta1.SecondaryNetworkStatus
	ConfigUID types.UID
}

// DeepCopy returns an independent copy of the result and its configuration identity.
func (s *SecondaryNetworkStatus) DeepCopy() *SecondaryNetworkStatus {
	if s == nil {
		return nil
	}
	return &SecondaryNetworkStatus{SecondaryNetworkStatus: s.SecondaryNetworkStatus.DeepCopy(), ConfigUID: s.ConfigUID}
}

// OVSBridgeConfig describes a single OVS bridge and its uplink interfaces.
type OVSBridgeConfig struct {
	// BridgeName is the name of the OVS bridge.
	BridgeName string
	// PhysicalInterfaces is the list of physical interfaces connected to this bridge.
	PhysicalInterfaces []PhysicalInterfaceConfig
	// EnableMulticastSnooping enables multicast snooping on the bridge.
	EnableMulticastSnooping bool
}

// PhysicalInterfaceConfig describes a physical interface and its optional
// VLAN filter.
type PhysicalInterfaceConfig struct {
	// Name is the name of the physical interface.
	Name string
	// AllowedVLANs is a list of VLAN IDs or VLAN ID ranges (e.g. "100",
	// "200-300") that are allowed on this interface.  If empty, all VLANs
	// are allowed.
	AllowedVLANs []string
}
