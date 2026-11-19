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

package flowexporter

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	"antrea.io/antrea/v2/pkg/agent/config"
)

// fakeRemotePodSubnetQuerier implements remotePodSubnetQuerier for a fixed set of Pod subnets of
// other Nodes, mapped to the transport IPs of these Nodes.
type fakeRemotePodSubnetQuerier struct {
	remotePodSubnets map[netip.Prefix]net.IP
}

func (f *fakeRemotePodSubnetQuerier) GetNodeIPForPodIP(ip netip.Addr) (net.IP, bool) {
	for prefix, nodeIP := range f.remotePodSubnets {
		if prefix.Contains(ip) {
			return nodeIP, true
		}
	}
	return nil, false
}

func (f *fakeRemotePodSubnetQuerier) LookupIPInPodSubnets(ip netip.Addr) (bool, bool) {
	for prefix := range f.remotePodSubnets {
		if prefix.Contains(ip) {
			return true, ip == prefix.Masked().Addr().Next()
		}
	}
	return false, false
}

func TestRemotePodQuerier_IsRemotePodIP(t *testing.T) {
	nodeConfig := &config.NodeConfig{
		NodeTransportIPv4Addr: &net.IPNet{IP: net.ParseIP("192.168.77.2"), Mask: net.CIDRMask(24, 32)},
		NodeTransportIPv6Addr: &net.IPNet{IP: net.ParseIP("fd77::2"), Mask: net.CIDRMask(64, 128)},
	}
	nodeRouteQuerier := &fakeRemotePodSubnetQuerier{
		remotePodSubnets: map[netip.Prefix]net.IP{
			// A Node in the same subnet as this Node.
			netip.MustParsePrefix("10.244.2.0/24"):      net.ParseIP("192.168.77.3"),
			netip.MustParsePrefix("fd00:10:244:2::/64"): net.ParseIP("fd77::3"),
			// A Node in another subnet.
			netip.MustParsePrefix("10.244.3.0/24"): net.ParseIP("192.168.78.3"),
		},
	}
	sameSubnetPodIPv4 := netip.MustParseAddr("10.244.2.6")
	sameSubnetPodIPv6 := netip.MustParseAddr("fd00:10:244:2::6")
	otherSubnetPodIPv4 := netip.MustParseAddr("10.244.3.6")
	remoteGwIPv4 := netip.MustParseAddr("10.244.2.1")
	// For example, a local Pod IP, or the IP of a Node.
	unknownIPv4 := netip.MustParseAddr("10.244.1.6")

	tests := []struct {
		name           string
		networkConfig  *config.NetworkConfig
		ip             netip.Addr
		expectedRemote bool
	}{
		{
			name:           "encap mode",
			networkConfig:  &config.NetworkConfig{TrafficEncapMode: config.TrafficEncapModeEncap},
			ip:             sameSubnetPodIPv4,
			expectedRemote: true,
		},
		{
			name:           "encap mode IPv6",
			networkConfig:  &config.NetworkConfig{TrafficEncapMode: config.TrafficEncapModeEncap},
			ip:             sameSubnetPodIPv6,
			expectedRemote: true,
		},
		{
			name:           "encap mode gateway IP",
			networkConfig:  &config.NetworkConfig{TrafficEncapMode: config.TrafficEncapModeEncap},
			ip:             remoteGwIPv4,
			expectedRemote: false,
		},
		{
			name:           "encap mode unknown IP",
			networkConfig:  &config.NetworkConfig{TrafficEncapMode: config.TrafficEncapModeEncap},
			ip:             unknownIPv4,
			expectedRemote: false,
		},
		{
			name:           "encap mode with IPsec",
			networkConfig:  &config.NetworkConfig{TrafficEncapMode: config.TrafficEncapModeEncap, TrafficEncryptionMode: config.TrafficEncryptionModeIPSec},
			ip:             sameSubnetPodIPv4,
			expectedRemote: true,
		},
		{
			name:           "encap mode with WireGuard",
			networkConfig:  &config.NetworkConfig{TrafficEncapMode: config.TrafficEncapModeEncap, TrafficEncryptionMode: config.TrafficEncryptionModeWireGuard},
			ip:             sameSubnetPodIPv4,
			expectedRemote: true,
		},
		{
			name:           "encap mode with WireGuard gateway IP",
			networkConfig:  &config.NetworkConfig{TrafficEncapMode: config.TrafficEncapModeEncap, TrafficEncryptionMode: config.TrafficEncryptionModeWireGuard},
			ip:             remoteGwIPv4,
			expectedRemote: false,
		},
		{
			name:           "noEncap mode",
			networkConfig:  &config.NetworkConfig{TrafficEncapMode: config.TrafficEncapModeNoEncap},
			ip:             sameSubnetPodIPv4,
			expectedRemote: false,
		},
		{
			name:           "noEncap mode with WireGuard",
			networkConfig:  &config.NetworkConfig{TrafficEncapMode: config.TrafficEncapModeNoEncap, TrafficEncryptionMode: config.TrafficEncryptionModeWireGuard},
			ip:             sameSubnetPodIPv4,
			expectedRemote: true,
		},
		{
			name:           "hybrid mode Node in the same subnet",
			networkConfig:  &config.NetworkConfig{TrafficEncapMode: config.TrafficEncapModeHybrid},
			ip:             sameSubnetPodIPv4,
			expectedRemote: false,
		},
		{
			name:           "hybrid mode Node in the same subnet IPv6",
			networkConfig:  &config.NetworkConfig{TrafficEncapMode: config.TrafficEncapModeHybrid},
			ip:             sameSubnetPodIPv6,
			expectedRemote: false,
		},
		{
			name:           "hybrid mode Node in another subnet",
			networkConfig:  &config.NetworkConfig{TrafficEncapMode: config.TrafficEncapModeHybrid},
			ip:             otherSubnetPodIPv4,
			expectedRemote: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			q := newRemotePodQuerier(nodeRouteQuerier, tc.networkConfig, nodeConfig)
			assert.Equal(t, tc.expectedRemote, q.IsRemotePodIP(tc.ip))
		})
	}
}
