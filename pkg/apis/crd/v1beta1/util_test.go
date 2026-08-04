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

package v1beta1

import "testing"

func TestCompareSubnetInfoWithIPFamilySubnets(t *testing.T) {
	subnetInfo := &SubnetInfo{
		IPFamilySubnets: []IPFamilySubnetInfo{
			{Gateway: "192.168.1.1", PrefixLength: 24},
			{Gateway: "2001:db8::1", PrefixLength: 64},
		},
		VLAN: 100,
	}
	reversed := &SubnetInfo{
		IPFamilySubnets: []IPFamilySubnetInfo{
			{Gateway: "2001:db8::1", PrefixLength: 64},
			{Gateway: "192.168.1.1", PrefixLength: 24},
		},
		VLAN: 100,
	}
	if !CompareSubnetInfo(subnetInfo, reversed, false) {
		t.Fatal("expected subnet order to be ignored")
	}

	differentGateway := reversed.DeepCopy()
	differentGateway.IPFamilySubnets[0].Gateway = "2001:db8::2"
	if CompareSubnetInfo(subnetInfo, differentGateway, false) {
		t.Fatal("expected different gateways to be detected")
	}
	if !CompareSubnetInfo(subnetInfo, differentGateway, true) {
		t.Fatal("expected gateways to be ignored")
	}

	ipv4Subnet := &SubnetInfo{IPFamilySubnets: []IPFamilySubnetInfo{{Gateway: "192.168.1.1", PrefixLength: 24}}}
	ipv6Subnet := &SubnetInfo{IPFamilySubnets: []IPFamilySubnetInfo{{Gateway: "2001:db8::1", PrefixLength: 24}}}
	if CompareSubnetInfo(ipv4Subnet, ipv6Subnet, true) {
		t.Fatal("expected different IP families to be detected when gateways are ignored")
	}
}
