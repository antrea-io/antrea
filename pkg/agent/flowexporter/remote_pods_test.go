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
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"

	"antrea.io/antrea/v2/pkg/agent/config"
)

// fakeRemotePodSubnetQuerier implements remotePodSubnetQuerier for a fixed set of Pod subnets of
// this Node, and of other Nodes, mapped to the transport IPs of these Nodes.
type fakeRemotePodSubnetQuerier struct {
	localPodSubnets  []netip.Prefix
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
	prefixes := slices.Clone(f.localPodSubnets)
	for prefix := range f.remotePodSubnets {
		prefixes = append(prefixes, prefix)
	}
	for _, prefix := range prefixes {
		if prefix.Contains(ip) {
			return true, ip == prefix.Masked().Addr().Next()
		}
	}
	return false, false
}

func TestRemotePodQuerier(t *testing.T) {
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
		name                 string
		networkConfig        *config.NetworkConfig
		ip                   netip.Addr
		expectedRemote       bool
		expectedRoutedByHost bool
	}{
		{
			name:                 "encap mode",
			networkConfig:        &config.NetworkConfig{TrafficEncapMode: config.TrafficEncapModeEncap},
			ip:                   sameSubnetPodIPv4,
			expectedRemote:       true,
			expectedRoutedByHost: false,
		},
		{
			name:                 "encap mode IPv6",
			networkConfig:        &config.NetworkConfig{TrafficEncapMode: config.TrafficEncapModeEncap},
			ip:                   sameSubnetPodIPv6,
			expectedRemote:       true,
			expectedRoutedByHost: false,
		},
		{
			name:                 "encap mode gateway IP",
			networkConfig:        &config.NetworkConfig{TrafficEncapMode: config.TrafficEncapModeEncap},
			ip:                   remoteGwIPv4,
			expectedRemote:       false,
			expectedRoutedByHost: false,
		},
		{
			name:                 "encap mode unknown IP",
			networkConfig:        &config.NetworkConfig{TrafficEncapMode: config.TrafficEncapModeEncap},
			ip:                   unknownIPv4,
			expectedRemote:       false,
			expectedRoutedByHost: false,
		},
		{
			name:                 "encap mode with IPsec",
			networkConfig:        &config.NetworkConfig{TrafficEncapMode: config.TrafficEncapModeEncap, TrafficEncryptionMode: config.TrafficEncryptionModeIPSec},
			ip:                   sameSubnetPodIPv4,
			expectedRemote:       true,
			expectedRoutedByHost: false,
		},
		{
			name:                 "encap mode with WireGuard",
			networkConfig:        &config.NetworkConfig{TrafficEncapMode: config.TrafficEncapModeEncap, TrafficEncryptionMode: config.TrafficEncryptionModeWireGuard},
			ip:                   sameSubnetPodIPv4,
			expectedRemote:       true,
			expectedRoutedByHost: true,
		},
		{
			name:                 "encap mode with WireGuard gateway IP",
			networkConfig:        &config.NetworkConfig{TrafficEncapMode: config.TrafficEncapModeEncap, TrafficEncryptionMode: config.TrafficEncryptionModeWireGuard},
			ip:                   remoteGwIPv4,
			expectedRemote:       false,
			expectedRoutedByHost: false,
		},
		{
			name:                 "noEncap mode",
			networkConfig:        &config.NetworkConfig{TrafficEncapMode: config.TrafficEncapModeNoEncap},
			ip:                   sameSubnetPodIPv4,
			expectedRemote:       false,
			expectedRoutedByHost: true,
		},
		{
			name:                 "noEncap mode with WireGuard",
			networkConfig:        &config.NetworkConfig{TrafficEncapMode: config.TrafficEncapModeNoEncap, TrafficEncryptionMode: config.TrafficEncryptionModeWireGuard},
			ip:                   sameSubnetPodIPv4,
			expectedRemote:       true,
			expectedRoutedByHost: true,
		},
		{
			name:                 "hybrid mode Node in the same subnet",
			networkConfig:        &config.NetworkConfig{TrafficEncapMode: config.TrafficEncapModeHybrid},
			ip:                   sameSubnetPodIPv4,
			expectedRemote:       false,
			expectedRoutedByHost: true,
		},
		{
			name:                 "hybrid mode Node in the same subnet IPv6",
			networkConfig:        &config.NetworkConfig{TrafficEncapMode: config.TrafficEncapModeHybrid},
			ip:                   sameSubnetPodIPv6,
			expectedRemote:       false,
			expectedRoutedByHost: true,
		},
		{
			name:                 "hybrid mode Node in another subnet",
			networkConfig:        &config.NetworkConfig{TrafficEncapMode: config.TrafficEncapModeHybrid},
			ip:                   otherSubnetPodIPv4,
			expectedRemote:       true,
			expectedRoutedByHost: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			q := newRemotePodQuerier(nodeRouteQuerier, tc.networkConfig, nodeConfig)
			assert.Equal(t, tc.expectedRemote, q.IsRemotePodIP(tc.ip), "Unexpected IsRemotePodIP")
			assert.Equal(t, tc.expectedRoutedByHost, q.IsRemotePodIPRoutedByHost(tc.ip), "Unexpected IsRemotePodIPRoutedByHost")
		})
	}
}

func TestRemotePodQuerier_IsPodSubnetIP(t *testing.T) {
	nodeRouteQuerier := &fakeRemotePodSubnetQuerier{
		localPodSubnets: []netip.Prefix{netip.MustParsePrefix("10.244.1.0/24")},
		remotePodSubnets: map[netip.Prefix]net.IP{
			netip.MustParsePrefix("10.244.2.0/24"): net.ParseIP("192.168.77.3"),
		},
	}
	q := newRemotePodQuerier(nodeRouteQuerier, &config.NetworkConfig{TrafficEncapMode: config.TrafficEncapModeNoEncap}, &config.NodeConfig{})
	tests := []struct {
		ip       netip.Addr
		expected bool
	}{
		{ip: netip.MustParseAddr("10.244.1.6"), expected: true},
		{ip: netip.MustParseAddr("10.244.1.1"), expected: true},
		{ip: netip.MustParseAddr("10.244.2.6"), expected: true},
		{ip: netip.MustParseAddr("10.244.2.1"), expected: true},
		{ip: netip.MustParseAddr("192.168.77.3"), expected: false},
		{ip: netip.MustParseAddr("8.8.8.8"), expected: false},
	}
	for _, tc := range tests {
		t.Run(tc.ip.String(), func(t *testing.T) {
			assert.Equal(t, tc.expected, q.IsPodSubnetIP(tc.ip))
		})
	}
}
