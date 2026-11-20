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

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEgressIPByFamily(t *testing.T) {
	for _, tc := range []struct {
		name       string
		ips        []string
		ipv4, ipv6 string
	}{
		{name: "unassigned"},
		{name: "IPv4", ips: []string{"192.0.2.10"}, ipv4: "192.0.2.10"},
		{name: "IPv6", ips: []string{"2001:db8::10"}, ipv6: "2001:db8::10"},
		{name: "dual stack IPv4 first", ips: []string{"192.0.2.10", "2001:db8::10"}, ipv4: "192.0.2.10", ipv6: "2001:db8::10"},
		{name: "dual stack IPv6 first", ips: []string{"2001:db8::10", "192.0.2.10"}, ipv4: "192.0.2.10", ipv6: "2001:db8::10"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := EgressConfig{EgressIPs: tc.ips}
			assert.Equal(t, tc.ipv4, config.EgressIPByFamily(false))
			assert.Equal(t, tc.ipv6, config.EgressIPByFamily(true))
		})
	}
}
