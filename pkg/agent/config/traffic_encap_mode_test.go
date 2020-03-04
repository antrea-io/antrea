package config

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetTrafficEncapModeFromStr(t *testing.T) {
	tests := []struct {
		name    string
		mode     string
		expBool bool
		expMode TrafficEncapModeType
	}{
		{
			name:    "encap-mode-valid",
			mode:     "enCap",
			expBool: true,
			expMode: 0,
		},
		{
			name:    "no-encap-mode-valid",
			mode:     "Noencap",
			expBool: true,
			expMode: 1,
		},
		{
			name:    "hybrid-mode-valid",
			mode:     "Hybrid",
			expBool: true,
			expMode: 2,
		},
		{
			name:    "invalid-str",
			mode:     "en cap",
			expBool: false,
			expMode: -1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualBool, actualMode := GetTrafficEncapModeFromStr(tt.mode)
			assert.Equal(t, actualBool, tt.expBool, "GetTrafficEncapModeFromStr not return correct boolean")
			assert.Equal(t, actualMode, tt.expMode, "GetTrafficEncapModes received unexpected encap modes.")
		})
	}
}

func TestGetTrafficEncapModes(t *testing.T) {
	modes := GetTrafficEncapModes()
	expModes := []TrafficEncapModeType{0, 1, 2}
	assert.Equal(t, modes, expModes, "GetTrafficEncapModes not return correct type mapping")
}

func TestTrafficEncapModeTypeString(t *testing.T) {
	tests := []struct {
		name     string
		modeType TrafficEncapModeType
		expMode  string
	}{
		{
			name:     "encap-mode",
			modeType: 0,
			expMode:  "Encap",
		},
		{
			name:     "no-encap-mode",
			modeType: 1,
			expMode:  "NoEncap",
		},
		{
			name:     "hybrid-mode",
			modeType: 2,
			expMode:  "Hybrid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualMode := tt.modeType.String()
			assert.Equal(t, actualMode, tt.expMode, "String not return correct traffic type in string format")
		})
	}
}

func TestTrafficEncapModeTypeSupportsNoEncap(t *testing.T) {
	tests := []struct {
		name    string
		mode    TrafficEncapModeType
		expBool bool
	}{
		{
			name:    "encap-mode",
			mode:    0,
			expBool: false,
		},
		{
			name:    "no-encap-mode",
			mode:    1,
			expBool: true,
		},
		{
			name:    "hybrid-mode",
			mode:    2,
			expBool: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualBool := tt.mode.SupportsNoEncap()
			assert.Equal(t, tt.expBool, actualBool, "SupportsNoEncap not return correct result")
		})
	}
}

func TestTrafficEncapModeTypeSupportsEncap(t *testing.T) {
	tests := []struct {
		name    string
		mode    TrafficEncapModeType
		expBool bool
	}{
		{
			name:    "encap-mode",
			mode:    0,
			expBool: true,
		},
		{
			name:    "no-encap-mode",
			mode:    1,
			expBool: false,
		},
		{
			name:    "hybrid-mode",
			mode:    2,
			expBool: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualBool := tt.mode.SupportsEncap()
			assert.Equal(t, tt.expBool, actualBool, "SupportsEncap not return correct result")
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
			assert.Equal(t, tt.expBool, actualBool, "NeedsEncapToPeer not return correct result")
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
			assert.Equal(t, tt.expBool, actualBool, "NeedsRoutingToPeer not return correct result")
		})
	}
}
