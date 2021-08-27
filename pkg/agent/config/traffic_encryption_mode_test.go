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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetTrafficEncryptionModes(t *testing.T) {
	modes := GetTrafficEncryptionModes()
	expModes := []TrafficEncryptionModeType{0, 1, 2}
	assert.Equal(t, expModes, modes, "TestGetTrafficEncryptionModes received unexpected encryption modes")
}

func TestGetTrafficEncryptionModeFromStr(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		expBool bool
		expMode TrafficEncryptionModeType
	}{
		{"None by default", "none", true, TrafficEncryptionModeNone},
		{"IPsec", "ipsec", true, TrafficEncryptionModeIPSec},
		{"WireGuard", "wireguard", true, TrafficEncryptionModeWireGuard},
		{"Capital case", "IPsec", true, TrafficEncryptionModeIPSec},
		{"Invalid string", "wire guard", false, TrafficEncryptionModeInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, mode := GetTrafficEncryptionModeFromStr(tt.input)
			assert.Equal(t, tt.expBool, ok, "GetTrafficEncryptionModeFromStr did not return correct boolean")
			assert.Equal(t, tt.expMode, mode, "GetTrafficEncryptionModeFromStr did not return correct string")
		})
	}
}

func TestTrafficEncryptionModeType_String(t *testing.T) {
	tests := []struct {
		name string
		m    TrafficEncryptionModeType
		want string
	}{
		{"None", TrafficEncryptionModeNone, "None"},
		{"IPsec", TrafficEncryptionModeIPSec, "IPsec"},
		{"WireGuard", TrafficEncryptionModeWireGuard, "WireGuard"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.m.String(), "TrafficEncryptionModeType.String did not return correct string representation")
		})
	}
}
