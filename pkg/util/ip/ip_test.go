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
	"net/netip"
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

func TestAppendPortIfMissing(t *testing.T) {
	tests := []struct {
		name string
		addr string
		port string
		want string
	}{
		{
			name: "IPv4 address without port",
			addr: "10.96.0.10",
			port: "80",
			want: "10.96.0.10:80",
		},
		{
			name: "IPv4 address with port",
			addr: "10.96.0.10:53",
			port: "80",
			want: "10.96.0.10:53",
		},
		{
			name: "IPv6 address without port",
			addr: "fd00:10:96::a",
			port: "80",
			want: "[fd00:10:96::a]:80",
		},
		{
			name: "IPv6 address with port",
			addr: "[fd00:10:96::a]:53",
			port: "80",
			want: "[fd00:10:96::a]:53",
		},
		{
			name: "Empty address",
			addr: "",
			port: "80",
			want: "",
		},
		{
			name: "Invalid address",
			addr: "10.96.0.10.6",
			port: "80",
			want: "10.96.0.10.6",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AppendPortIfMissing(tt.addr, tt.port); got != tt.want {
				t.Errorf("AppendPortIfMissing() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIPNetEqual(t *testing.T) {
	tests := []struct {
		name   string
		ipNet1 *net.IPNet
		ipNet2 *net.IPNet
		want   bool
	}{
		{
			name:   "equal",
			ipNet1: MustParseCIDR("1.1.1.0/30"),
			ipNet2: MustParseCIDR("1.1.1.0/30"),
			want:   true,
		},
		{
			name:   "different mask",
			ipNet1: MustParseCIDR("1.1.1.0/30"),
			ipNet2: MustParseCIDR("1.1.1.0/29"),
			want:   false,
		},
		{
			name:   "different prefix",
			ipNet1: MustParseCIDR("1.1.1.4/30"),
			ipNet2: MustParseCIDR("1.1.1.0/30"),
			want:   false,
		},
		{
			name:   "different family",
			ipNet1: MustParseCIDR("1.1.1.4/30"),
			ipNet2: MustParseCIDR("1:1:1:4::/30"),
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IPNetEqual(tt.ipNet1, tt.ipNet2))
		})
	}
}

func TestIPNetContains(t *testing.T) {
	tests := []struct {
		name   string
		ipNet1 *net.IPNet
		ipNet2 *net.IPNet
		want   bool
	}{
		{
			name:   "equal",
			ipNet1: MustParseCIDR("10.0.0.0/24"),
			ipNet2: MustParseCIDR("10.0.0.0/24"),
			want:   true,
		},
		{
			name:   "contain smaller subnet",
			ipNet1: MustParseCIDR("10.0.0.0/24"),
			ipNet2: MustParseCIDR("10.0.0.0/25"),
			want:   true,
		},
		{
			name:   "contain smaller subnet with different prefix",
			ipNet1: MustParseCIDR("10.0.0.0/24"),
			ipNet2: MustParseCIDR("10.0.0.128/25"),
			want:   true,
		},
		{
			name:   "not contain larger subnet",
			ipNet1: MustParseCIDR("10.0.0.0/24"),
			ipNet2: MustParseCIDR("10.0.0.0/23"),
			want:   false,
		},
		{
			name:   "not contain smaller subnet with different prefix",
			ipNet1: MustParseCIDR("10.0.0.0/24"),
			ipNet2: MustParseCIDR("10.0.1.0/25"),
			want:   false,
		},
		{
			name:   "not contain subnet of different family",
			ipNet1: MustParseCIDR("1.1.1.4/30"),
			ipNet2: MustParseCIDR("1:1:1:4::/30"),
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IPNetContains(tt.ipNet1, tt.ipNet2))
		})
	}
}

func TestGetStartAndEndOfPrefix(t *testing.T) {
	testCases := []struct {
		prefix string
		start  string
		end    string
	}{
		{
			prefix: "10.20.30.0/26",
			start:  "10.20.30.0",
			end:    "10.20.30.63",
		},
		{
			prefix: "10.10.40.0/24",
			start:  "10.10.40.0",
			end:    "10.10.40.255",
		},
		{
			prefix: "10.20.30.0/20",
			start:  "10.20.16.0",
			end:    "10.20.31.255",
		},
		{
			prefix: "10.30.20.0/16",
			start:  "10.30.0.0",
			end:    "10.30.255.255",
		},
		{
			prefix: "10.10.10.10/12",
			start:  "10.0.0.0",
			end:    "10.15.255.255",
		},
		{
			prefix: "10.10.10.10/6",
			start:  "8.0.0.0",
			end:    "11.255.255.255",
		},
		{
			prefix: "2001:0db8::/42",
			start:  "2001:db8::",
			end:    "2001:db8:3f:ffff:ffff:ffff:ffff:ffff",
		},
		{
			prefix: "2001:4860:4860::8888/56",
			start:  "2001:4860:4860::",
			end:    "2001:4860:4860:ff:ffff:ffff:ffff:ffff",
		},
		{
			prefix: "2001:0db8::/64",
			start:  "2001:db8::",
			end:    "2001:db8::ffff:ffff:ffff:ffff",
		},
		{
			prefix: "2001:0db8::/84",
			start:  "2001:db8::",
			end:    "2001:db8::fff:ffff:ffff",
		},
		{
			prefix: "fd00:10:96::/100",
			start:  "fd00:10:96::",
			end:    "fd00:10:96::fff:ffff",
		},
		{
			prefix: "fd00:10:96::/112",
			start:  "fd00:10:96::",
			end:    "fd00:10:96::ffff",
		},
		{
			prefix: "2001:4860:4860::8888/124",
			start:  "2001:4860:4860::8880",
			end:    "2001:4860:4860::888f",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.prefix, func(t *testing.T) {
			start, end := GetStartAndEndOfPrefix(netip.MustParsePrefix(tc.prefix))
			assert.Equal(t, 0, netip.MustParseAddr(tc.start).Compare(start))
			assert.Equal(t, 0, netip.MustParseAddr(tc.end).Compare(end))
		})
	}
}
