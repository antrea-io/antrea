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

package ovsctl

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOvsCtlClientGetDPFeatures(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   map[DPFeature]bool
	}{
		{
			name: "fully supported",
			output: `Masked set action: Yes
Tunnel push pop: No
Ufid: Yes
Truncate action: Yes
Clone action: No
Sample nesting: 10
Conntrack eventmask: Yes
Conntrack clear: Yes
Max dp_hash algorithm: 0
Check pkt length action: No
Conntrack timeout policy: No
Explicit Drop action: No
Optimized Balance TCP mode: No
Max VLAN headers: 2
Max MPLS depth: 1
Recirc: Yes
CT state: Yes
CT zone: Yes
CT mark: Yes
CT label: Yes
CT state NAT: Yes
CT orig tuple: Yes
CT orig tuple for IPv6: Yes
IPv6 ND Extension: No`,
			want: map[DPFeature]bool{
				CTStateFeature:    true,
				CTZoneFeature:     true,
				CTMarkFeature:     true,
				CTLabelFeature:    true,
				CTStateNATFeature: true,
			},
		},
		{
			name: "partially supported",
			output: `Masked set action: Yes
Tunnel push pop: No
Ufid: Yes
Truncate action: No
Clone action: No
Sample nesting: 3
Conntrack eventmask: No
Conntrack clear: No
Max dp_hash algorithm: 0
Check pkt length action: No
Conntrack timeout policy: No
Explicit Drop action: No
Optimized Balance TCP mode: No
Max VLAN headers: 1
Max MPLS depth: 1
Recirc: Yes
CT state: Yes
CT zone: Yes
CT mark: Yes
CT label: Yes
CT state NAT: No
CT orig tuple: No
CT orig tuple for IPv6: No
IPv6 ND Extension: No`,
			want: map[DPFeature]bool{
				CTStateFeature:    true,
				CTZoneFeature:     true,
				CTMarkFeature:     true,
				CTLabelFeature:    true,
				CTStateNATFeature: false,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &ovsCtlClient{
				bridge: "br-int",
				runAppCtl: func(cmd string, needsBridge bool, args ...string) ([]byte, *ExecError) {
					return []byte(tt.output), nil
				},
			}
			got, err := c.GetDPFeatures()
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
