// Copyright 2021 Antrea Authors
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

package config

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"antrea.io/antrea/pkg/ovs/ovsconfig"
)

func TestNetworkConfig_NeedsTunnelToPeer(t *testing.T) {
	tests := []struct {
		name    string
		nc      *NetworkConfig
		peerIP  net.IP
		localIP *net.IPNet
		expBool bool
	}{
		{
			name: "encap-mode",
			nc: &NetworkConfig{
				TrafficEncapMode: TrafficEncapModeEncap,
			},
			peerIP: net.ParseIP("192.168.0.5"),
			localIP: &net.IPNet{
				IP:   net.IPv4(192, 168, 0, 1),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
			expBool: true,
		},
		{
			name: "no-encap-mode",
			nc: &NetworkConfig{
				TrafficEncapMode: TrafficEncapModeNoEncap,
			},
			peerIP: net.ParseIP("192.168.0.5"),
			localIP: &net.IPNet{
				IP:   net.IPv4(192, 168, 0, 1),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
			expBool: false,
		},
		{
			name: "hybrid-mode-need-encapsulated",
			nc: &NetworkConfig{
				TrafficEncapMode: TrafficEncapModeHybrid,
			},
			peerIP: net.ParseIP("10.0.0.0"),
			localIP: &net.IPNet{
				IP:   net.IPv4(192, 168, 0, 1),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
			expBool: true,
		},
		{
			name: "hybrid-mode-no-need-encapsulated",
			nc: &NetworkConfig{
				TrafficEncapMode: TrafficEncapModeHybrid,
			},
			peerIP: net.ParseIP("192.168.0.5"),
			localIP: &net.IPNet{
				IP:   net.IPv4(192, 168, 0, 1),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
			expBool: false,
		},
		{
			name: "WireGuard enabled",
			nc: &NetworkConfig{
				TrafficEncapMode:      TrafficEncapModeEncap,
				TrafficEncryptionMode: TrafficEncryptionModeWireGuard,
			},
			peerIP: net.ParseIP("10.0.0.0"),
			localIP: &net.IPNet{
				IP:   net.IPv4(192, 168, 0, 1),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
			expBool: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualBool := tt.nc.NeedsTunnelToPeer(tt.peerIP, tt.localIP)
			assert.Equal(t, tt.expBool, actualBool, "NeedsTunnelToPeer did not return correct result")
		})
	}
}

func TestNetworkConfig_NeedsDirectRoutingToPeer(t *testing.T) {
	tests := []struct {
		name    string
		nc      *NetworkConfig
		peerIP  net.IP
		localIP *net.IPNet
		expBool bool
	}{
		{
			name: "encap-mode",
			nc: &NetworkConfig{
				TrafficEncapMode: TrafficEncapModeEncap,
			},
			peerIP: net.ParseIP("192.168.0.5"),
			localIP: &net.IPNet{
				IP:   net.IPv4(192, 168, 0, 1),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
			expBool: false,
		},
		{
			name: "no-encap-mode-need-direct-routing",
			nc: &NetworkConfig{
				TrafficEncapMode: TrafficEncapModeNoEncap,
			},
			peerIP: net.ParseIP("192.168.0.5"),
			localIP: &net.IPNet{
				IP:   net.IPv4(192, 168, 0, 1),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
			expBool: true,
		},
		{
			name: "no-encap-mode-no-need-direct-routing",
			nc: &NetworkConfig{
				TrafficEncapMode: TrafficEncapModeNoEncap,
			},
			peerIP: net.ParseIP("192.168.1.5"),
			localIP: &net.IPNet{
				IP:   net.IPv4(192, 168, 0, 1),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
			expBool: false,
		},
		{
			name: "hybrid-mode-need-direct-routing",
			nc: &NetworkConfig{
				TrafficEncapMode: TrafficEncapModeHybrid,
			},
			peerIP: net.ParseIP("192.168.0.5"),
			localIP: &net.IPNet{
				IP:   net.IPv4(192, 168, 0, 1),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
			expBool: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualBool := tt.nc.NeedsDirectRoutingToPeer(tt.peerIP, tt.localIP)
			assert.Equal(t, tt.expBool, actualBool, "NeedsDirectRoutingToPeer did not return correct result")
		})
	}
}

func TestIsIPv4Enabled(t *testing.T) {
	_, podIPv4CIDR, _ := net.ParseCIDR("10.10.0.0/24")
	_, nodeIPv4Addr, _ := net.ParseCIDR("192.168.77.100/24")
	tests := []struct {
		name                string
		nodeConfig          *NodeConfig
		trafficEncapMode    TrafficEncapModeType
		expectedErrString   string
		expectedWithError   bool
		expectedIPv4Enabled bool
	}{
		{
			name: "Non-NetworkPolicyOnly, with IPv4PodCIDR, without NodeIPv4Addr",
			nodeConfig: &NodeConfig{
				PodIPv4CIDR: podIPv4CIDR,
			},
			expectedWithError:   true,
			expectedErrString:   "K8s Node should have an IPv4 address if IPv4 Pod CIDR is defined",
			expectedIPv4Enabled: false,
		},
		{
			name: "Non-NetworkPolicyOnly, with IPv4PodCIDR, with NodeIPv4Addr",
			nodeConfig: &NodeConfig{
				PodIPv4CIDR:  podIPv4CIDR,
				NodeIPv4Addr: nodeIPv4Addr,
			},
			expectedIPv4Enabled: true,
		},
		{
			name:                "NetworkPolicyOnly, without NodeIPv4Addr",
			nodeConfig:          &NodeConfig{},
			trafficEncapMode:    TrafficEncapModeNetworkPolicyOnly,
			expectedIPv4Enabled: false,
		},
		{
			name: "NetworkPolicyOnly, with NodeIPv4Addr",
			nodeConfig: &NodeConfig{
				NodeIPv4Addr: nodeIPv4Addr,
			},
			trafficEncapMode:    TrafficEncapModeNetworkPolicyOnly,
			expectedIPv4Enabled: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipv4Enabled, err := IsIPv4Enabled(tt.nodeConfig, tt.trafficEncapMode)
			if tt.expectedWithError {
				assert.ErrorContains(t, err, tt.expectedErrString)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.expectedIPv4Enabled, ipv4Enabled)
		})
	}
}

func TestIsIPv6Enabled(t *testing.T) {
	_, podIPv6CIDR, _ := net.ParseCIDR("10:10::/64")
	_, nodeIPv6Addr, _ := net.ParseCIDR("192:168:77::100/80")
	tests := []struct {
		name                string
		nodeConfig          *NodeConfig
		trafficEncapMode    TrafficEncapModeType
		expectedWithError   bool
		expectedErrString   string
		expectedIPv6Enabled bool
	}{
		{
			name: "Non-NetworkPolicyOnly, with IPv6PodCIDR, without NodeIPv6Addr",
			nodeConfig: &NodeConfig{
				PodIPv6CIDR: podIPv6CIDR,
			},
			expectedWithError:   true,
			expectedErrString:   "K8s Node should have an IPv6 address if IPv6 Pod CIDR is defined",
			expectedIPv6Enabled: false,
		},
		{
			name: "Non-NetworkPolicyOnly, with IPv6PodCIDR, with NodeIPv6Addr",
			nodeConfig: &NodeConfig{
				PodIPv6CIDR:  podIPv6CIDR,
				NodeIPv6Addr: nodeIPv6Addr,
			},
			expectedIPv6Enabled: true,
		},
		{
			name:                "NetworkPolicyOnly, without NodeIPv6Addr",
			nodeConfig:          &NodeConfig{},
			trafficEncapMode:    TrafficEncapModeNetworkPolicyOnly,
			expectedIPv6Enabled: false,
		},
		{
			name: "NetworkPolicyOnly, with NodeIPv6Addr",
			nodeConfig: &NodeConfig{
				NodeIPv6Addr: nodeIPv6Addr,
			},
			trafficEncapMode:    TrafficEncapModeNetworkPolicyOnly,
			expectedIPv6Enabled: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipv6Enabled, err := IsIPv6Enabled(tt.nodeConfig, tt.trafficEncapMode)
			if tt.expectedWithError {
				assert.ErrorContains(t, err, tt.expectedErrString)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.expectedIPv6Enabled, ipv6Enabled)
		})
	}
}

func TestCalculateMTUDeduction(t *testing.T) {
	tests := []struct {
		name                 string
		nc                   *NetworkConfig
		isIPv6               bool
		expectedMTUDeduction int
	}{
		{
			name:                 "VXLan encap without IPv6",
			nc:                   &NetworkConfig{TunnelType: ovsconfig.VXLANTunnel},
			expectedMTUDeduction: 50,
		},
		{
			name:                 "Geneve encap without IPv6",
			nc:                   &NetworkConfig{TunnelType: ovsconfig.GeneveTunnel},
			expectedMTUDeduction: 50,
		},
		{
			name:                 "GRE encap without IPv6",
			nc:                   &NetworkConfig{TunnelType: ovsconfig.GRETunnel},
			expectedMTUDeduction: 42,
		},
		{
			name:                 "Default encap with IPv6",
			nc:                   &NetworkConfig{TunnelType: ovsconfig.GeneveTunnel},
			isIPv6:               true,
			expectedMTUDeduction: 70,
		},
		{
			name:                 "WireGuard enabled",
			nc:                   &NetworkConfig{TrafficEncryptionMode: TrafficEncryptionModeWireGuard},
			expectedMTUDeduction: 60,
		},
		{
			name:                 "IPv6 with WireGuard enabled",
			nc:                   &NetworkConfig{TrafficEncryptionMode: TrafficEncryptionModeWireGuard},
			isIPv6:               true,
			expectedMTUDeduction: 80,
		},
		{
			name:                 "Multicluster enabled with Geneve encap",
			nc:                   &NetworkConfig{TunnelType: ovsconfig.GeneveTunnel, EnableMulticlusterGW: true},
			expectedMTUDeduction: 50,
		},
		{
			name: "Geneve encap with Multicluster WireGuard enabled",
			nc: &NetworkConfig{
				TunnelType:                 ovsconfig.GeneveTunnel,
				EnableMulticlusterGW:       true,
				MulticlusterEncryptionMode: TrafficEncryptionModeWireGuard,
			},
			expectedMTUDeduction: 110,
		},
		{
			name:                 "Geneve encap with IPSec enabled",
			nc:                   &NetworkConfig{TunnelType: ovsconfig.GeneveTunnel, TrafficEncryptionMode: TrafficEncryptionModeIPSec},
			expectedMTUDeduction: 88,
		},
		{
			name:                 "Geneve encap with IPSec enabled and IPv6",
			nc:                   &NetworkConfig{TunnelType: ovsconfig.GeneveTunnel, TrafficEncryptionMode: TrafficEncryptionModeIPSec},
			isIPv6:               true,
			expectedMTUDeduction: 108,
		},
		{
			name:                 "VXLan encap with IPSec enabled",
			nc:                   &NetworkConfig{TunnelType: ovsconfig.VXLANTunnel, TrafficEncryptionMode: TrafficEncryptionModeIPSec},
			expectedMTUDeduction: 88,
		},
		{
			name:                 "GRE encap with IPSec enabled",
			nc:                   &NetworkConfig{TunnelType: ovsconfig.GRETunnel, TrafficEncryptionMode: TrafficEncryptionModeIPSec},
			expectedMTUDeduction: 80,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.nc.CalculateMTUDeduction(tt.isIPv6)
			assert.Equal(t, tt.expectedMTUDeduction, tt.nc.MTUDeduction)
		})
	}
}

func TestNeedsTunnelInterface(t *testing.T) {
	tests := []struct {
		name     string
		nc       *NetworkConfig
		expected bool
	}{
		{
			name:     "Default encap mode",
			nc:       &NetworkConfig{TunnelType: ovsconfig.GeneveTunnel},
			expected: true,
		},
		{
			name:     "networkPolicyOnly with Multicluster enabled",
			nc:       &NetworkConfig{TrafficEncapMode: TrafficEncapModeNetworkPolicyOnly, EnableMulticlusterGW: true},
			expected: true,
		},
		{
			name:     "networkPolicyOnly without Multicluster enabled",
			nc:       &NetworkConfig{TrafficEncapMode: TrafficEncapModeNetworkPolicyOnly, EnableMulticlusterGW: false},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := tt.nc.NeedsTunnelInterface()
			assert.Equal(t, tt.expected, actual)
		})
	}
}
