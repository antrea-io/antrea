// Copyright 2020 Antrea Authors
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

package ip

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
)

func newCIDR(cidrStr string) *net.IPNet {
	_, tmpIPNet, _ := net.ParseCIDR(cidrStr)
	return tmpIPNet
}

func TestDiffCIDRs(t *testing.T) {
	testList := []*net.IPNet{newCIDR("10.20.0.0/16"),
		newCIDR("10.20.1.0/24"),
		newCIDR("10.20.2.0/28")}

	exceptList1 := []*net.IPNet{testList[1]}
	correctList1 := []*net.IPNet{newCIDR("10.20.128.0/17"),
		newCIDR("10.20.64.0/18"),
		newCIDR("10.20.32.0/19"),
		newCIDR("10.20.16.0/20"),
		newCIDR("10.20.8.0/21"),
		newCIDR("10.20.4.0/22"),
		newCIDR("10.20.2.0/23"),
		newCIDR("10.20.0.0/24")}

	diffCIDRs, err := DiffFromCIDRs(testList[0], exceptList1)
	if err != nil {
		t.Fatalf("diffFromCIDRs() error = %v", err)
	} else {
		assert.ElementsMatch(t, correctList1, diffCIDRs)
	}

	exceptList2 := []*net.IPNet{testList[1], testList[2]}
	correctList2 := []*net.IPNet{newCIDR("10.20.128.0/17"),
		newCIDR("10.20.64.0/18"),
		newCIDR("10.20.32.0/19"),
		newCIDR("10.20.16.0/20"),
		newCIDR("10.20.8.0/21"),
		newCIDR("10.20.4.0/22"),
		newCIDR("10.20.0.0/24"),
		newCIDR("10.20.3.0/24"),
		newCIDR("10.20.2.128/25"),
		newCIDR("10.20.2.64/26"),
		newCIDR("10.20.2.32/27"),
		newCIDR("10.20.2.16/28")}
	diffCIDRs, err = DiffFromCIDRs(testList[0], exceptList2)
	if err != nil {
		t.Fatalf("diffFromCIDRs() error = %v", err)
	} else {
		assert.ElementsMatch(t, correctList2, diffCIDRs)
	}

}

func TestMergeCIDRs(t *testing.T) {
	testList := []*net.IPNet{newCIDR("10.10.0.0/16"),
		newCIDR("10.20.0.0/16"),
		newCIDR("10.20.1.2/32"),
		newCIDR("10.20.1.3/32")}

	ipNetList0 := []*net.IPNet{testList[0], testList[1],
		testList[2], testList[3]}
	correctList0 := []*net.IPNet{testList[0], testList[1]}

	ipNetList0 = mergeCIDRs(ipNetList0)

	assert.ElementsMatch(t, correctList0, ipNetList0)

	ipNetList1 := []*net.IPNet{testList[0]}
	correctList1 := []*net.IPNet{testList[0]}

	ipNetList1 = mergeCIDRs(ipNetList1)
	assert.ElementsMatch(t, correctList1, ipNetList1)

	ipNetList2 := []*net.IPNet{testList[2], testList[3]}
	correctList2 := []*net.IPNet{testList[2], testList[3]}

	ipNetList2 = mergeCIDRs(ipNetList2)
	assert.ElementsMatch(t, correctList2, ipNetList2)

	ipNetList3 := []*net.IPNet{testList[0], testList[3]}
	correctList3 := []*net.IPNet{testList[0], testList[3]}

	ipNetList3 = mergeCIDRs(ipNetList3)
	assert.ElementsMatch(t, correctList3, ipNetList3)

	ipNetList4 := []*net.IPNet{}
	correctList4 := []*net.IPNet{}

	ipNetList4 = mergeCIDRs(ipNetList4)
	assert.ElementsMatch(t, correctList4, ipNetList4)
}

func TestComplementAddressesInCIDR(t *testing.T) {
	// Test edge cases of excluding 0.0.0.0 and 255.255.255.255
	testList1 := []net.IP{
		net.IPv4zero,
		net.IPv4bcast,
	}

	correctList1 := []*net.IPNet{
		newCIDR("0.0.0.1/32"), newCIDR("0.0.0.2/31"), newCIDR("0.0.0.4/30"),
		newCIDR("0.0.0.8/29"), newCIDR("0.0.0.16/28"), newCIDR("0.0.0.32/27"),
		newCIDR("0.0.0.64/26"), newCIDR("0.0.0.128/25"), newCIDR("0.0.1.0/24"),
		newCIDR("0.0.2.0/23"), newCIDR("0.0.4.0/22"), newCIDR("0.0.8.0/21"),
		newCIDR("0.0.16.0/20"), newCIDR("0.0.32.0/19"), newCIDR("0.0.64.0/18"),
		newCIDR("0.0.128.0/17"), newCIDR("0.1.0.0/16"), newCIDR("0.2.0.0/15"),
		newCIDR("0.4.0.0/14"), newCIDR("0.8.0.0/13"), newCIDR("0.16.0.0/12"),
		newCIDR("0.32.0.0/11"), newCIDR("0.64.0.0/10"), newCIDR("0.128.0.0/9"),
		newCIDR("1.0.0.0/8"), newCIDR("2.0.0.0/7"), newCIDR("4.0.0.0/6"),
		newCIDR("8.0.0.0/5"), newCIDR("16.0.0.0/4"), newCIDR("32.0.0.0/3"),
		newCIDR("64.0.0.0/2"), newCIDR("128.0.0.0/2"), newCIDR("192.0.0.0/3"),
		newCIDR("224.0.0.0/4"), newCIDR("240.0.0.0/5"), newCIDR("248.0.0.0/6"),
		newCIDR("252.0.0.0/7"), newCIDR("254.0.0.0/8"), newCIDR("255.0.0.0/9"),
		newCIDR("255.128.0.0/10"), newCIDR("255.192.0.0/11"), newCIDR("255.224.0.0/12"),
		newCIDR("255.240.0.0/13"), newCIDR("255.248.0.0/14"), newCIDR("255.252.0.0/15"),
		newCIDR("255.254.0.0/16"), newCIDR("255.255.0.0/17"), newCIDR("255.255.128.0/18"),
		newCIDR("255.255.192.0/19"), newCIDR("255.255.224.0/20"), newCIDR("255.255.240.0/21"),
		newCIDR("255.255.248.0/22"), newCIDR("255.255.252.0/23"), newCIDR("255.255.254.0/24"),
		newCIDR("255.255.255.0/25"), newCIDR("255.255.255.128/26"), newCIDR("255.255.255.192/27"),
		newCIDR("255.255.255.224/28"), newCIDR("255.255.255.240/29"), newCIDR("255.255.255.248/30"),
		newCIDR("255.255.255.252/31"), newCIDR("255.255.255.254/32"),
	}

	compCIDRs := ComplementAddressesInCIDR(testList1)
	assert.ElementsMatch(t, correctList1, compCIDRs)

	// Test general cases of excluding 10.0.0.1
	testList2 := []net.IP{
		net.ParseIP("10.0.0.1"),
	}

	correctList2 := []*net.IPNet{
		newCIDR("0.0.0.0/5"), newCIDR("8.0.0.0/7"), newCIDR("10.0.0.0/32"),
		newCIDR("10.0.0.2/31"), newCIDR("10.0.0.4/30"), newCIDR("10.0.0.8/29"),
		newCIDR("10.0.0.16/28"), newCIDR("10.0.0.32/27"), newCIDR("10.0.0.64/26"),
		newCIDR("10.0.0.128/25"), newCIDR("10.0.1.0/24"), newCIDR("10.0.2.0/23"),
		newCIDR("10.0.4.0/22"), newCIDR("10.0.8.0/21"), newCIDR("10.0.16.0/20"),
		newCIDR("10.0.32.0/19"), newCIDR("10.0.64.0/18"), newCIDR("10.0.128.0/17"),
		newCIDR("10.1.0.0/16"), newCIDR("10.2.0.0/15"), newCIDR("10.4.0.0/14"),
		newCIDR("10.8.0.0/13"), newCIDR("10.16.0.0/12"), newCIDR("10.32.0.0/11"),
		newCIDR("10.64.0.0/10"), newCIDR("10.128.0.0/9"), newCIDR("11.0.0.0/8"),
		newCIDR("12.0.0.0/6"), newCIDR("16.0.0.0/4"), newCIDR("32.0.0.0/3"),
		newCIDR("64.0.0.0/2"), newCIDR("128.0.0.0/1"),
	}

	compCIDRs = ComplementAddressesInCIDR(testList2)
	assert.ElementsMatch(t, correctList2, compCIDRs)

	// Test general cases of excluding 2001:db8::1
	testList3 := []net.IP{
		net.ParseIP("2001:db8::1"),
	}
	correctList3Length := 128

	compCIDRs = ComplementAddressesInCIDR(testList3)
	assert.Equal(t, correctList3Length, len(compCIDRs))

	// Test dual-stack case of excluding 10.0.0.1 and 2001:db8::1
	testList4 := []net.IP{
		net.ParseIP("10.0.0.1"),
		net.ParseIP("2001:db8::1"),
	}

	correctList4Length := len(correctList2) + correctList3Length

	compCIDRs = ComplementAddressesInCIDR(testList4)
	assert.Equal(t, correctList4Length, len(compCIDRs))
}

func TestIPNetToNetIPNet(t *testing.T) {
	tests := []struct {
		name  string
		ipNet *v1beta2.IPNet
		want  *net.IPNet
	}{
		{
			name: "valid IPv4 CIDR",
			ipNet: &v1beta2.IPNet{
				IP:           v1beta2.IPAddress(net.ParseIP("10.10.0.0")),
				PrefixLength: 16,
			},
			want: newCIDR("10.10.0.0/16"),
		},
		{
			name: "valid IPv6 CIDR",
			ipNet: &v1beta2.IPNet{
				IP:           v1beta2.IPAddress(net.ParseIP("2001:ab03:cd04:55ef::")),
				PrefixLength: 64,
			},
			want: newCIDR("2001:ab03:cd04:55ef::/64"),
		},
		{
			name: "non standard IPv4 CIDR",
			ipNet: &v1beta2.IPNet{
				IP:           v1beta2.IPAddress(net.ParseIP("10.10.10.10")),
				PrefixLength: 16,
			},
			want: newCIDR("10.10.0.0/16"),
		},
		{
			name: "non standard IPv6 CIDR",
			ipNet: &v1beta2.IPNet{
				IP:           v1beta2.IPAddress(net.ParseIP("fe80::7015:efff:fe9a:146b")),
				PrefixLength: 64,
			},
			want: newCIDR("fe80::/64"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IPNetToNetIPNet(tt.ipNet))
		})
	}
}

func TestIPProtocolNumberToString(t *testing.T) {
	const defaultValue = "UnknownProtocol"
	assert.Equal(t, "IPv6-ICMP", IPProtocolNumberToString(ICMPv6Protocol, defaultValue))
	assert.Equal(t, defaultValue, IPProtocolNumberToString(44, defaultValue))
}

func TestMustIPv6(t *testing.T) {
	tests := []struct {
		name    string
		ipv6Str string
		wantIP  net.IP
	}{
		{
			name:    "valid IPv6 local",
			ipv6Str: "::1",
			wantIP:  net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1},
		},
		{
			name:    "valid IPv6",
			ipv6Str: "2021:4860:0000:2001:0000:0000:0000:0068",
			wantIP:  net.IP{0x20, 0x21, 0x48, 0x60, 0, 0, 0x20, 0x01, 0, 0, 0, 0, 0, 0, 0x00, 0x68},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantIP, MustIPv6(tt.ipv6Str))
		})
	}
}
