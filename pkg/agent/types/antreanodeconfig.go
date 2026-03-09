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

// SecondaryNetworkConfig is the effective secondary network configuration
// derived from matching AntreaNodeConfig resources after applying override semantics.
// It is a richer superset of secondary-network configuration: physical
// interfaces carry per-interface VLAN filters (AllowedVLANs) that are not
// expressible in the static YAML config.
//
// An agent that receives this value should override it with the
// static secondary-network configuration loaded from the agent config file.
type SecondaryNetworkConfig struct {
	// OVSBridge is the single OVS bridge configuration. The CRD schema enforces
	// at most one bridge, so a pointer is used — nil means no bridge is configured.
	OVSBridge *OVSBridgeConfig
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
