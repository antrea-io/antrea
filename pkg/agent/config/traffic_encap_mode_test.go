package config

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetTrafficEncapModeFromStr(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		expBool bool
		expMode TrafficEncapModeType
	}{
		{"encap-mode-valid", "enCap", true, 0},
		{"no-encap-mode-valid", "Noencap", true, 1},
		{"hybrid-mode-valid", "Hybrid", true, 2},
		{"invalid-str", "en cap", false, -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualBool, actualMode := GetTrafficEncapModeFromStr(tt.mode)
			assert.Equal(t, actualBool, tt.expBool, "GetTrafficEncapModeFromStr did not return correct boolean")
			assert.Equal(t, actualMode, tt.expMode, "GetTrafficEncapModeFromStr did not return correct traffic type")
		})
	}
}

func TestGetTrafficEncapModes(t *testing.T) {
	modes := GetTrafficEncapModes()
	expModes := []TrafficEncapModeType{0, 1, 2}
	assert.Equal(t, modes, expModes, "GetTrafficEncapModes received unexpected encap modes")
}

func TestTrafficEncapModeTypeString(t *testing.T) {
	tests := []struct {
		name     string
		modeType TrafficEncapModeType
		expMode  string
	}{
		{"encap-mode", 0, "Encap"},
		{"no-encap-mode", 1, "NoEncap"},
		{"hybrid-mode", 2, "Hybrid"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualMode := tt.modeType.String()
			assert.Equal(t, actualMode, tt.expMode, "String did not return correct traffic type in string format")
		})
	}
}

func TestTrafficEncapModeTypeSupports(t *testing.T) {
	tests := []struct {
		name       string
		mode       TrafficEncapModeType
		expNoEncap bool
		expEncap   bool
	}{
		{"encap-mode", 0, false, true},
		{"no-encap-mode", 1, true, false},
		{"hybrid-mode", 2, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualNoEncap := tt.mode.SupportsNoEncap()
			actualEncap := tt.mode.SupportsEncap()
			assert.Equal(t, tt.expNoEncap, actualNoEncap, "SupportsNoEncap did not return correct result")
			assert.Equal(t, tt.expEncap, actualEncap, "SupportsEncap did not return correct result")
		})
	}
}

func TestTrafficEncapModeTypeNeedsEncapToPeer(t *testing.T) {
	tests := []struct {
		name    string
		mode    TrafficEncapModeType
		peerIP  net.IP
		localIP *net.IPNet
		expBool bool
	}{
		{
			name:   "encap-mode",
			mode:   0,
			peerIP: net.ParseIP("192.168.0.5"),
			localIP: &net.IPNet{
				IP:   net.IPv4(192, 168, 0, 1),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
			expBool: true,
		},
		{
			name:   "no-encap-mode",
			mode:   1,
			peerIP: net.ParseIP("192.168.0.5"),
			localIP: &net.IPNet{
				IP:   net.IPv4(192, 168, 0, 1),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
			expBool: false,
		},
		{
			name:   "hybrid-mode-need-encapsulated",
			mode:   2,
			peerIP: net.ParseIP("10.0.0.0"),
			localIP: &net.IPNet{
				IP:   net.IPv4(192, 168, 0, 1),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
			expBool: true,
		},
		{
			name:   "hybrid-mode-no-need-encapsulated",
			mode:   2,
			peerIP: net.ParseIP("192.168.0.5"),
			localIP: &net.IPNet{
				IP:   net.IPv4(192, 168, 0, 1),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
			expBool: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualBool := tt.mode.NeedsEncapToPeer(tt.peerIP, tt.localIP)
			assert.Equal(t, tt.expBool, actualBool, "NeedsEncapToPeer did not return correct result")
		})
	}
}

func TestTrafficEncapModeTypeNeedsRoutingToPeer(t *testing.T) {
	tests := []struct {
		name    string
		mode    TrafficEncapModeType
		peerIP  net.IP
		localIP *net.IPNet
		expBool bool
	}{
		{
			name:   "encap-mode",
			mode:   0,
			peerIP: net.ParseIP("192.168.0.5"),
			localIP: &net.IPNet{
				IP:   net.IPv4(192, 168, 0, 1),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
			expBool: false,
		},
		{
			name:   "no-encap-mode-no-need-support",
			mode:   1,
			peerIP: net.ParseIP("192.168.0.5"),
			localIP: &net.IPNet{
				IP:   net.IPv4(192, 168, 0, 1),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
			expBool: false,
		},
		{
			name:   "no-encap-mode-need-support",
			mode:   1,
			peerIP: net.ParseIP("192.168.1.5"),
			localIP: &net.IPNet{
				IP:   net.IPv4(192, 168, 0, 1),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
			expBool: true,
		},
		{
			name:   "hybrid-mode",
			mode:   2,
			peerIP: net.ParseIP("192.168.0.5"),
			localIP: &net.IPNet{
				IP:   net.IPv4(192, 168, 0, 1),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
			expBool: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualBool := tt.mode.NeedsRoutingToPeer(tt.peerIP, tt.localIP)
			assert.Equal(t, tt.expBool, actualBool, "NeedsRoutingToPeer did not return correct result")
		})
	}
}
