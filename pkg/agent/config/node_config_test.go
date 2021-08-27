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
