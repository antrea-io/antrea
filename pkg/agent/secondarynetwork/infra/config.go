// Copyright 2022 Antrea Authors
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

package infra

import (
        "antrea.io/antrea/pkg/ovs/ovsconfig"
)

// SecondaryNetworkConfig is similar to AgentConfig. But to cover secondary OVS bridge config only.
type SecondaryNetworkConfig struct {
	// Name of the primary OpenVSwitch bridge antrea-agent will create for Secondary interface needs.
	// Make sure it doesn't conflict with your existing OpenVSwitch bridges.
	// Defaults to br-int.
	Secondary_OVSBridge1 string `yaml:"Secondary_OVSBridge1,omitempty"`
        // Name of the OpenVSwitch bridge antrea-agent will create for Secondary network specific tunnel needs.
        // Make sure it doesn't conflict with your existing OpenVSwitch bridges.
        // Defaults to br-int.
	Secondary_OVSBridge2 string `yaml:"Secondary_OVSBridge2,omitempty"`
	// Datapath type to use for the OpenVSwitch bridge created by Antrea. Supported values are:
	// - system
	// - netdev
	// 'system' is the default value and corresponds to the kernel datapath. Use 'netdev' to run
	// OVS in userspace mode. Userspace mode requires the tun device driver to be available.
	Secondary_OVSDatapathType string `yaml:"Secondary_OVSDatapathType,omitempty"`
	// Runtime data directory used by Open vSwitch.
	// Default value:
	// - On Linux platform: /var/run/openvswitch
	// - On Windows platform: C:\openvswitch\var\run\openvswitch
	Secondary_OVSRunDir string `yaml:"Secondary_OVSRunDir,omitempty"`
	// Name of the OVS patch port which would connected two OVS bridges per secondary inteface config.
	Secondary_OVSPatchPort string `yaml:"Secondary_OVSPatchPort,omitempty"`
        // Name of the OVS patch port peer which would connected two OVS bridges per secondary inteface config.
        Secondary_OVSPatchPortPeer string `yaml:"Secondary_OVSPatchPortPeer,omitempty"`
	// Determines how traffic is encapsulated. It has the following options:
	// encap(default):    Inter-node Pod traffic is always encapsulated and Pod to external network
	//                    traffic is SNAT'd.
	// noEncap:           Inter-node Pod traffic is not encapsulated; Pod to external network traffic is
	//                    SNAT'd if noSNAT is not set to true. Underlying network must be capable of
	//                    supporting Pod traffic across IP subnets.
	// hybrid:            noEncap if source and destination Nodes are on the same subnet, otherwise encap.
	// networkPolicyOnly: Antrea enforces NetworkPolicy only, and utilizes CNI chaining and delegates Pod
	//                    IPAM and connectivity to the primary CNI.
	Secondary_TrafficEncapMode string `yaml:"Secondary_TrafficEncapMode,omitempty"`
	// Tunnel protocols used for encapsulating traffic across Nodes. Supported values:
	// - geneve (default)
	// - vxlan
	// - gre
	// - stt
	Secondary_TunnelType ovsconfig.TunnelType `yaml:"Secondary_TunnelType,omitempty"`
}
