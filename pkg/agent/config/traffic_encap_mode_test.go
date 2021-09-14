package config

import (
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
		{"policy-only-mode-valid", "NetworkPolicyOnly", true, 3},
		{"invalid-str", "en cap", false, -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualBool, actualMode := GetTrafficEncapModeFromStr(tt.mode)
			assert.Equal(t, tt.expBool, actualBool, "GetTrafficEncapModeFromStr did not return correct boolean")
			assert.Equal(t, tt.expMode, actualMode, "GetTrafficEncapModeFromStr did not return correct traffic type")
		})
	}
}

func TestGetTrafficEncapModes(t *testing.T) {
	modes := GetTrafficEncapModes()
	expModes := []TrafficEncapModeType{0, 1, 2, 3}
	assert.Equal(t, expModes, modes, "GetTrafficEncapModes received unexpected encap modes")
}

func TestTrafficEncapModeTypeString(t *testing.T) {
	tests := []struct {
		name     string
		modeType TrafficEncapModeType
		expMode  string
	}{
		{"encap-mode", 0, "encap"},
		{"no-encap-mode", 1, "noEncap"},
		{"hybrid-mode", 2, "hybrid"},
		{"policy-only-mode-valid", 3, "networkPolicyOnly"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualMode := tt.modeType.String()
			assert.Equal(t, tt.expMode, actualMode, "String did not return correct traffic type in string format")
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
		{"policy-only-mode-valid", 3, true, false},
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
