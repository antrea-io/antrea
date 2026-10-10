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

package v1beta2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCompareExternalIPPoolSubnetsWithGateways(t *testing.T) {
	subnetInfo := []SubnetInfo{
		{Gateway: "192.168.1.1", PrefixLength: 24, VLAN: 100},
		{Gateway: "2001:db8::1", PrefixLength: 64, VLAN: 100},
	}
	reversed := []SubnetInfo{
		{Gateway: "2001:db8::1", PrefixLength: 64, VLAN: 100},
		{Gateway: "192.168.1.1", PrefixLength: 24, VLAN: 100},
	}
	differentGateway := append([]SubnetInfo(nil), reversed...)
	differentGateway[0].Gateway = "2001:db8::2"
	ipv4Subnet := []SubnetInfo{{Gateway: "192.168.1.1", PrefixLength: 24}}
	ipv6Subnet := []SubnetInfo{{Gateway: "2001:db8::1", PrefixLength: 24}}

	tests := []struct {
		name            string
		a               []SubnetInfo
		b               []SubnetInfo
		ignoringGateway bool
		want            bool
	}{
		{
			name: "subnet order is ignored",
			a:    subnetInfo,
			b:    reversed,
			want: true,
		},
		{
			name: "different gateways are detected",
			a:    subnetInfo,
			b:    differentGateway,
			want: false,
		},
		{
			name:            "gateways are ignored",
			a:               subnetInfo,
			b:               differentGateway,
			ignoringGateway: true,
			want:            true,
		},
		{
			name:            "different IP families are detected when gateways are ignored",
			a:               ipv4Subnet,
			b:               ipv6Subnet,
			ignoringGateway: true,
			want:            false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CompareExternalIPPoolSubnets(tt.a, tt.b, tt.ignoringGateway)
			assert.Equal(t, tt.want, got, "CompareExternalIPPoolSubnets(%+v, %+v, %t)", tt.a, tt.b, tt.ignoringGateway)
		})
	}
}
