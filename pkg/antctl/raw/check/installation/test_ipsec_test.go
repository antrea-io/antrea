// Copyright 2026 Antrea Authors.
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

package installation

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseIPsecStatus(t *testing.T) {
	tests := []struct {
		name                        string
		output                      string
		expectedRoutedConnections   int
		expectedSecurityAssociation int
	}{
		{
			name: "Geneve with 2 peers",
			output: `Routed Connections:
worker2-a0d026-out-1{4}:  ROUTED, TRANSPORT, reqid 4
worker2-a0d026-out-1{4}:   fd98:a1ac:2207::3/128[udp] === fd98:a1ac:2207::4/128[udp/6081]
worker2-a0d026-in-1{3}:  ROUTED, TRANSPORT, reqid 3
worker2-a0d026-in-1{3}:   fd98:a1ac:2207::3/128[udp/6081] === fd98:a1ac:2207::4/128[udp]
ol-plane-a39e0c-out-1{2}:  ROUTED, TRANSPORT, reqid 2
ol-plane-a39e0c-out-1{2}:   fd98:a1ac:2207::3/128[udp] === fd98:a1ac:2207::2/128[udp/6081]
ol-plane-a39e0c-in-1{1}:  ROUTED, TRANSPORT, reqid 1
ol-plane-a39e0c-in-1{1}:   fd98:a1ac:2207::3/128[udp/6081] === fd98:a1ac:2207::2/128[udp]
Security Associations (1 up, 0 connecting):
worker2-a0d026-in-1[1]: ESTABLISHED 7 minutes ago, fd98:a1ac:2207::3[fd98:a1ac:2207::3]...fd98:a1ac:2207::4[fd98:a1ac:2207::4]
worker2-a0d026-out-1{5}:  INSTALLED, TRANSPORT, reqid 4, ESP SPIs: ca7cbbab_i c95f12bc_o
worker2-a0d026-out-1{5}:   fd98:a1ac:2207::3/128[udp] === fd98:a1ac:2207::4/128[udp/6081]
worker2-a0d026-in-1{6}:  INSTALLED, TRANSPORT, reqid 3, ESP SPIs: c37adb22_i c640af36_o
worker2-a0d026-in-1{6}:   fd98:a1ac:2207::3/128[udp/6081] === fd98:a1ac:2207::4/128[udp]
`,
			expectedRoutedConnections:   2,
			expectedSecurityAssociation: 1,
		},
		{
			name: "GRE with 2 peers",
			output: `Routed Connections:
ol-plane-a39e0c-1{2}:  ROUTED, TRANSPORT, reqid 2
ol-plane-a39e0c-1{2}:   172.19.0.2/32[gre] === 172.19.0.3/32[gre]
worker2-a0d026-1{1}:  ROUTED, TRANSPORT, reqid 1
worker2-a0d026-1{1}:   172.19.0.2/32[gre] === 172.19.0.4/32[gre]
Security Associations (1 up, 0 connecting):
worker2-a0d026-1[1]: ESTABLISHED 31 minutes ago, 172.19.0.2[172.19.0.2]...172.19.0.4[172.19.0.4]
worker2-a0d026-1{3}:  INSTALLED, TRANSPORT, reqid 1, ESP SPIs: c23e2664_i c44fc621_o
worker2-a0d026-1{3}:   172.19.0.2/32[gre] === 172.19.0.4/32[gre]
`,
			expectedRoutedConnections:   2,
			expectedSecurityAssociation: 1,
		},
		{
			name: "No connections",
			output: `Routed Connections:
Security Associations (0 up, 0 connecting):
`,
			expectedRoutedConnections:   0,
			expectedSecurityAssociation: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			routed, sa, err := parseIPsecStatus(tt.output)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedRoutedConnections, routed, "routed connections mismatch")
			assert.Equal(t, tt.expectedSecurityAssociation, sa, "security associations mismatch")
		})
	}
}
