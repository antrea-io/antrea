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

package apis

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBGPPolicyResponseGetTableRow(t *testing.T) {
	tests := []struct {
		name        string
		response    BGPPolicyResponse
		expectedRow []string
	}{
		{
			name: "BGPPolicy in effect",
			response: BGPPolicyResponse{
				BGPPolicyName:           "policy-1",
				RouterID:                "192.168.77.100",
				LocalASN:                64512,
				ListenPort:              179,
				ConfederationIdentifier: 65000,
				MemberASNs:              []uint32{64514, 64513},
			},
			expectedRow: []string{"policy-1", "192.168.77.100", "64512", "179", "65000", "64513,64514", "Effective"},
		},
		{
			name: "BGPPolicy whose last sync failed after the BGP server started",
			response: BGPPolicyResponse{
				BGPPolicyName: "policy-1",
				RouterID:      "192.168.77.100",
				LocalASN:      64512,
				ListenPort:    179,
				LastSyncError: "failed to advertise routes",
			},
			expectedRow: []string{"policy-1", "192.168.77.100", "64512", "179", "", "", "Failed"},
		},
		{
			name: "BGPPolicy whose BGP server could not be started",
			response: BGPPolicyResponse{
				BGPPolicyName: "policy-1",
				LastSyncError: "failed to start BGP server: listen tcp :179: bind: address already in use",
			},
			expectedRow: []string{"policy-1", "", "", "", "", "", "Failed"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedRow, tt.response.GetTableRow(32))
		})
	}
}
