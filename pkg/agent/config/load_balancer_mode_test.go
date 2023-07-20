// Copyright 2023 Antrea Authors
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

func TestGetLoadBalancerModeFromStr(t *testing.T) {
	tests := []struct {
		name         string
		str          string
		expectedOK   bool
		expectedMode LoadBalancerMode
	}{
		{
			name:         "lowercase nat",
			str:          "nat",
			expectedOK:   true,
			expectedMode: LoadBalancerModeNAT,
		},
		{
			name:         "lowercase dsr",
			str:          "dsr",
			expectedOK:   true,
			expectedMode: LoadBalancerModeDSR,
		},
		{
			name:       "invalid",
			str:        "drs",
			expectedOK: false,
		},
		{
			name:         "uppercase nat",
			str:          "NAT",
			expectedOK:   true,
			expectedMode: LoadBalancerModeNAT,
		},
		{
			name:         "uppercase dsr",
			str:          "DSR",
			expectedOK:   true,
			expectedMode: LoadBalancerModeDSR,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotOK, gotMode := GetLoadBalancerModeFromStr(tt.str)
			assert.Equal(t, tt.expectedOK, gotOK)
			if tt.expectedOK {
				assert.Equal(t, tt.expectedMode, gotMode)
			}
		})
	}
}

func TestLoadBalancerModeString(t *testing.T) {
	tests := []struct {
		name string
		mode LoadBalancerMode
		want string
	}{
		{
			name: "nat",
			mode: LoadBalancerModeNAT,
			want: "NAT",
		},
		{
			name: "dsr",
			mode: LoadBalancerModeDSR,
			want: "DSR",
		},
		{
			name: "invalid",
			mode: LoadBalancerModeInvalid,
			want: "invalid",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.mode.String())
		})
	}
}
