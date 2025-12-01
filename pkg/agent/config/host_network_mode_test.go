// Copyright 2025 Antrea Authors
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

func TestProxyHostNetworkModeFromStr(t *testing.T) {
	tests := []struct {
		name         string
		str          string
		expectedOK   bool
		expectedMode HostNetworkMode
	}{
		{
			name:         "lowercase iptables",
			str:          "iptables",
			expectedOK:   true,
			expectedMode: HostNetworkModeIPTables,
		},
		{
			name:         "lowercase nftables",
			str:          "nftables",
			expectedOK:   true,
			expectedMode: HostNetworkModeNFTables,
		},
		{
			name:       "invalid",
			str:        "nft",
			expectedOK: false,
		},
		{
			name:         "uppercase iptables",
			str:          "IPTABLES",
			expectedOK:   true,
			expectedMode: HostNetworkModeIPTables,
		},
		{
			name:         "uppercase nftables",
			str:          "NFTABLES",
			expectedOK:   true,
			expectedMode: HostNetworkModeNFTables,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotOK, gotMode := GetHostNetworkModeFromStr(tt.str)
			assert.Equal(t, tt.expectedOK, gotOK)
			if tt.expectedOK {
				assert.Equal(t, tt.expectedMode, gotMode)
			}
		})
	}
}

func TestProxyHostNetworkModeString(t *testing.T) {
	tests := []struct {
		name string
		mode HostNetworkMode
		want string
	}{
		{
			name: "iptables",
			mode: HostNetworkModeIPTables,
			want: "iptables",
		},
		{
			name: "nftables",
			mode: HostNetworkModeNFTables,
			want: "nftables",
		},
		{
			name: "invalid",
			mode: HostNetworkModeInvalid,
			want: "invalid",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.mode.String())
		})
	}
}
