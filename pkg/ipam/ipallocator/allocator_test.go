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

package ipallocator

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newCIDRAllocator(cidr string, reservedIPs []string) *SingleIPAllocator {
	_, ipNet, _ := net.ParseCIDR(cidr)
	var parsedIPs []net.IP
	for _, ip := range reservedIPs {
		parsedIPs = append(parsedIPs, net.ParseIP(ip))
	}
	allocator, _ := NewCIDRAllocator(ipNet, parsedIPs)
	return allocator
}

func newIPRangeAllocator(start, end string) *SingleIPAllocator {
	allocator, _ := NewIPRangeAllocator(net.ParseIP(start), net.ParseIP(end))
	return allocator
}

func TestAllocateNext(t *testing.T) {
	tests := []struct {
		name        string
		ipAllocator IPAllocator
		ipRanges    []string
		wantNum     int
		wantFirst   net.IP
		wantLast    net.IP
	}{
		{
			name:        "IPv4-CIDR-prefix-24",
			ipAllocator: newCIDRAllocator("10.10.10.0/24", []string{"10.10.10.255"}),
			wantNum:     254,
			wantFirst:   net.ParseIP("10.10.10.1"),
			wantLast:    net.ParseIP("10.10.10.254"),
		},
		{
			name:        "IPv4-CIDR-prefix-30",
			ipAllocator: newCIDRAllocator("10.10.10.128/30", nil),
			wantNum:     3,
			wantFirst:   net.ParseIP("10.10.10.129"),
			wantLast:    net.ParseIP("10.10.10.131"),
		},
		{
			name:        "IPv4-range",
			ipAllocator: newIPRangeAllocator("1.1.1.10", "1.1.1.20"),
			wantNum:     11,
			wantFirst:   net.ParseIP("1.1.1.10"),
			wantLast:    net.ParseIP("1.1.1.20"),
		},
		{
			name:        "IPv4-multiple",
			ipAllocator: MultiIPAllocator{newIPRangeAllocator("1.1.1.10", "1.1.1.20"), newCIDRAllocator("10.10.10.128/30", []string{"10.10.10.131"})},
			wantNum:     13,
			wantFirst:   net.ParseIP("1.1.1.10"),
			wantLast:    net.ParseIP("10.10.10.130"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotFirst, err := tt.ipAllocator.AllocateNext()
			require.NoError(t, err)
			assert.Equal(t, tt.wantFirst, gotFirst)
			for i := 0; i < tt.wantNum-2; i++ {
				_, err := tt.ipAllocator.AllocateNext()
				require.NoError(t, err)
			}
			gotLast, err := tt.ipAllocator.AllocateNext()
			require.NoError(t, err)
			assert.Equal(t, tt.wantLast, gotLast)

			_, err = tt.ipAllocator.AllocateNext()
			require.Error(t, err)
		})
	}
}

func TestAllocateNextExcludedIPs(t *testing.T) {
	type allocatorWithUsage interface {
		IPAllocator
		Total() int
		Free() int
	}
	tests := []struct {
		name                string
		allocator           allocatorWithUsage
		allocatedIP         string
		excludedIPs         []string
		allIPs              []string
		wantIP              string
		wantUnfilteredIP    string
		wantAfterExhaustion string
	}{
		{
			name:                "IPv4 single",
			allocator:           newCIDRAllocator("192.0.2.0/29", []string{"192.0.2.7"}),
			allocatedIP:         "192.0.2.2",
			excludedIPs:         []string{"192.0.2.1", "192.0.2.1", "192.0.2.2", "192.0.2.0", "192.0.2.8"},
			allIPs:              []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5", "192.0.2.6"},
			wantIP:              "192.0.2.3",
			wantUnfilteredIP:    "192.0.2.1",
			wantAfterExhaustion: "192.0.2.4",
		},
		{
			name:        "IPv6 single",
			allocator:   newCIDRAllocator("2001:db8::/125", []string{"2001:db8::7"}),
			allocatedIP: "2001:db8::2",
			excludedIPs: []string{"2001:db8::1", "2001:0db8:0:0:0:0:0:1", "2001:db8::2", "2001:db8::", "2001:db8::8"},
			allIPs: []string{
				"2001:db8::1", "2001:db8::2", "2001:db8::3", "2001:db8::4", "2001:db8::5", "2001:db8::6",
			},
			wantIP:              "2001:db8::3",
			wantUnfilteredIP:    "2001:db8::1",
			wantAfterExhaustion: "2001:db8::4",
		},
		{
			name: "IPv4 multiple ranges",
			allocator: MultiIPAllocator{
				newIPRangeAllocator("192.0.2.1", "192.0.2.2"),
				newIPRangeAllocator("192.0.2.5", "192.0.2.6"),
			},
			allocatedIP:         "192.0.2.2",
			excludedIPs:         []string{"192.0.2.1", "192.0.2.1", "192.0.2.2", "192.0.2.3"},
			allIPs:              []string{"192.0.2.1", "192.0.2.2", "192.0.2.5", "192.0.2.6"},
			wantIP:              "192.0.2.5",
			wantUnfilteredIP:    "192.0.2.1",
			wantAfterExhaustion: "192.0.2.6",
		},
		{
			name: "IPv6 multiple ranges",
			allocator: MultiIPAllocator{
				newIPRangeAllocator("2001:db8::1", "2001:db8::2"),
				newIPRangeAllocator("2001:db8::5", "2001:db8::6"),
			},
			allocatedIP:         "2001:db8::2",
			excludedIPs:         []string{"2001:db8::1", "2001:0db8:0:0:0:0:0:1", "2001:db8::2", "2001:db8::3"},
			allIPs:              []string{"2001:db8::1", "2001:db8::2", "2001:db8::5", "2001:db8::6"},
			wantIP:              "2001:db8::5",
			wantUnfilteredIP:    "2001:db8::1",
			wantAfterExhaustion: "2001:db8::6",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			total := tt.allocator.Total()
			require.NoError(t, tt.allocator.AllocateIP(net.ParseIP(tt.allocatedIP)))
			var excludedIPs []net.IP
			for _, ip := range tt.excludedIPs {
				excludedIPs = append(excludedIPs, net.ParseIP(ip))
			}
			ip, err := tt.allocator.AllocateNext(excludedIPs...)
			require.NoError(t, err)
			assert.Equal(t, tt.wantIP, ip.String())
			assert.Equal(t, total, tt.allocator.Total())
			assert.Equal(t, 2, tt.allocator.Used())
			assert.Equal(t, total-2, tt.allocator.Free())

			// Exclusion only applies to this call, including for explicit allocation.
			skippedIP := net.ParseIP(tt.wantUnfilteredIP)
			require.NoError(t, tt.allocator.AllocateIP(skippedIP))
			require.NoError(t, tt.allocator.Release(skippedIP))
			ip, err = tt.allocator.AllocateNext()
			require.NoError(t, err)
			assert.Equal(t, tt.wantUnfilteredIP, ip.String())

			var allIPs []net.IP
			for _, ip := range tt.allIPs {
				allIPs = append(allIPs, net.ParseIP(ip))
			}
			ip, err = tt.allocator.AllocateNext(allIPs...)
			require.Error(t, err)
			assert.Nil(t, ip)
			assert.Equal(t, total, tt.allocator.Total())
			assert.Equal(t, 3, tt.allocator.Used())
			assert.Equal(t, total-3, tt.allocator.Free())
			ip, err = tt.allocator.AllocateNext()
			require.NoError(t, err)
			assert.Equal(t, tt.wantAfterExhaustion, ip.String())
		})
	}
}

func TestAllocateIP(t *testing.T) {
	tests := []struct {
		name         string
		ipAllocator  IPAllocator
		allocatedIP1 net.IP
		allocatedIP2 net.IP
		wantErr1     bool
		wantErr2     bool
	}{
		{
			name:         "IPv4-duplicate",
			ipAllocator:  newCIDRAllocator("10.10.10.0/24", nil),
			allocatedIP1: net.ParseIP("10.10.10.1"),
			allocatedIP2: net.ParseIP("10.10.10.1"),
			wantErr1:     false,
			wantErr2:     true,
		},
		{
			name:         "IPv4-no-duplicate",
			ipAllocator:  MultiIPAllocator{newIPRangeAllocator("1.1.1.10", "1.1.1.20"), newCIDRAllocator("10.10.10.128/30", nil)},
			allocatedIP1: net.ParseIP("1.1.1.10"),
			allocatedIP2: net.ParseIP("10.10.10.130"),
			wantErr1:     false,
			wantErr2:     false,
		},
		{
			name:         "IPv4-out-of-scope",
			ipAllocator:  MultiIPAllocator{newIPRangeAllocator("1.1.1.10", "1.1.1.20"), newCIDRAllocator("10.10.10.128/30", []string{"10.10.10.128"})},
			allocatedIP1: net.ParseIP("1.1.1.21"),
			allocatedIP2: net.ParseIP("10.10.10.127"),
			wantErr1:     true,
			wantErr2:     true,
		},
		{
			name:         "IPv4-reserved",
			ipAllocator:  MultiIPAllocator{newCIDRAllocator("10.10.10.128/30", []string{"10.10.10.1", "10.10.10.5"})},
			allocatedIP1: net.ParseIP("10.10.10.1"),
			allocatedIP2: net.ParseIP("10.10.10.5"),
			wantErr1:     true,
			wantErr2:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.ipAllocator.AllocateIP(tt.allocatedIP1)
			if tt.wantErr1 {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			err = tt.ipAllocator.AllocateIP(tt.allocatedIP2)
			if tt.wantErr2 {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestIPv6OffsetsDoNotWrap(t *testing.T) {
	tests := []struct {
		name      string
		allocator *SingleIPAllocator
	}{
		{"CIDR", newCIDRAllocator("2001:db8:0:1::/125", nil)},
		{"range", newIPRangeAllocator("2001:db8:0:1::1", "2001:db8:0:1::7")},
	}
	// These offsets differ from the first usable address by positive and negative multiples of 2^64.
	invalidIPs := []net.IP{net.ParseIP("2001:db8:0:2::1"), net.ParseIP("2001:db8::1")}
	validIP := net.ParseIP("2001:db8:0:1::1")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, ip := range invalidIPs {
				assert.False(t, tt.allocator.Has(ip), "IP %s must be outside the allocator", ip)
				require.Error(t, tt.allocator.AllocateIP(ip))
			}
			assert.Zero(t, tt.allocator.Used())
			require.NoError(t, tt.allocator.AllocateIP(validIP))
			for _, ip := range invalidIPs {
				require.Error(t, tt.allocator.Release(ip))
				assert.Equal(t, 1, tt.allocator.Used())
			}
			require.Error(t, tt.allocator.AllocateIP(validIP), "invalid releases must preserve the valid allocation")
			require.NoError(t, tt.allocator.Release(validIP))
			ip, err := tt.allocator.AllocateNext()
			require.NoError(t, err)
			assert.True(t, validIP.Equal(ip))
		})
	}
}

func TestAllocateRelease(t *testing.T) {
	tests := []struct {
		name        string
		ipAllocator IPAllocator
	}{
		{
			name:        "IPv4-single",
			ipAllocator: newCIDRAllocator("10.10.10.0/24", []string{"10.10.10.1", "10.10.10.255"}),
		},
		{
			name:        "IPv4-multiple",
			ipAllocator: MultiIPAllocator{newIPRangeAllocator("1.1.1.10", "1.1.1.20"), newCIDRAllocator("10.10.10.128/30", nil)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got1, err := tt.ipAllocator.AllocateNext()
			require.NoError(t, err)
			assert.Equal(t, 1, tt.ipAllocator.Used())

			err = tt.ipAllocator.Release(got1)
			require.NoError(t, err)
			assert.Equal(t, 0, tt.ipAllocator.Used())

			err = tt.ipAllocator.Release(got1)
			require.Error(t, err)

			got2, err := tt.ipAllocator.AllocateNext()
			require.NoError(t, err)
			assert.Equal(t, got1, got2)
		})
	}
}

func TestHas(t *testing.T) {
	tests := []struct {
		name        string
		ipAllocator IPAllocator
		ip          net.IP
		expectedHas bool
	}{
		{
			name:        "IPv4-single",
			ipAllocator: newCIDRAllocator("10.10.10.0/24", nil),
			ip:          net.ParseIP("10.10.10.0"),
			expectedHas: false,
		},
		{
			name:        "IPv4-multiple",
			ipAllocator: MultiIPAllocator{newIPRangeAllocator("1.1.1.10", "1.1.1.20"), newCIDRAllocator("10.10.10.128/30", nil)},
			ip:          net.ParseIP("10.10.10.130"),
			expectedHas: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedHas, tt.ipAllocator.Has(tt.ip))
		})
	}
}

func TestAllocateRange(t *testing.T) {
	tests := []struct {
		name        string
		ipAllocator IPAllocator
		size        int
		prevIPs     []net.IP
		wantError   bool
		wantFirst   net.IP
		wantLast    net.IP
	}{
		{
			name:        "IPv4-CIDR-Empty-OK",
			ipAllocator: newCIDRAllocator("10.10.10.0/24", []string{"10.10.10.255"}),
			wantError:   false,
			size:        15,
			wantFirst:   net.ParseIP("10.10.10.1"),
			wantLast:    net.ParseIP("10.10.10.15"),
		},
		{
			name:        "IPv4-CIDR-Middle-OK",
			ipAllocator: newCIDRAllocator("10.10.10.0/24", nil),
			wantError:   false,
			prevIPs:     []net.IP{net.ParseIP("10.10.10.13"), net.ParseIP("10.10.10.30")},
			size:        15,
			wantFirst:   net.ParseIP("10.10.10.14"),
			wantLast:    net.ParseIP("10.10.10.28"),
		},
		{
			name:        "IPv4-Range-Error",
			ipAllocator: newIPRangeAllocator("1.1.1.10", "1.1.1.20"),
			wantError:   true,
			prevIPs:     []net.IP{net.ParseIP("1.1.1.12"), net.ParseIP("1.1.1.16")},
			size:        5,
		},
		{
			name:        "IPv4-Multiple-OK",
			ipAllocator: MultiIPAllocator{newIPRangeAllocator("1.1.1.10", "1.1.1.20"), newCIDRAllocator("10.10.10.128/30", nil)},
			wantError:   false,
			prevIPs:     []net.IP{net.ParseIP("1.1.1.12")},
			size:        5,
			wantFirst:   net.ParseIP("1.1.1.13"),
			wantLast:    net.ParseIP("1.1.1.17"),
		},
		{
			name:        "IPv4-Multiple-Second-OK",
			ipAllocator: MultiIPAllocator{newIPRangeAllocator("1.1.1.10", "1.1.1.20"), newIPRangeAllocator("2.2.2.10", "2.2.2.30")},
			wantError:   false,
			prevIPs:     []net.IP{net.ParseIP("1.1.1.15"), net.ParseIP("2.2.2.15"), net.ParseIP("2.2.2.16")},
			size:        10,
			wantFirst:   net.ParseIP("2.2.2.17"),
			wantLast:    net.ParseIP("2.2.2.26"),
		},
		{
			name:        "IPv6-Multiple-Full-Range-OK",
			ipAllocator: MultiIPAllocator{newIPRangeAllocator("1000::2", "1000::5"), newIPRangeAllocator("1000::10", "1000::12"), newIPRangeAllocator("1000::20", "1000::29")},
			wantError:   false,
			size:        10,
			wantFirst:   net.ParseIP("1000::20"),
			wantLast:    net.ParseIP("1000::29"),
		},
		{
			name:        "IPv6-Multiple-Error",
			ipAllocator: MultiIPAllocator{newIPRangeAllocator("1000::2", "1000::5"), newIPRangeAllocator("1000::10", "1000::12"), newIPRangeAllocator("1000::20", "1000::30")},
			wantError:   true,
			prevIPs:     []net.IP{net.ParseIP("1000::23"), net.ParseIP("1000::2d"), net.ParseIP("1000::30")},
			size:        10,
			wantFirst:   net.ParseIP("1000::20"),
			wantLast:    net.ParseIP("1000::2a"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// preallocate IPs for the test
			for _, ip := range tt.prevIPs {
				err := tt.ipAllocator.AllocateIP(ip)
				require.NoError(t, err)
			}
			prevUsed := tt.ipAllocator.Used()
			ips, err := tt.ipAllocator.AllocateRange(tt.size)
			if tt.wantError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantFirst, ips[0])
			assert.Equal(t, tt.wantLast, ips[len(ips)-1])
			assert.Equal(t, prevUsed+len(ips), tt.ipAllocator.Used())

			// Verify every returned IP is marked allocated and cannot be re-allocated.
			for _, ip := range ips {
				err := tt.ipAllocator.AllocateIP(ip)
				assert.Errorf(t, err, "expected error re-allocating %v, but got nil", ip)
			}
		})
	}
}

func TestAllocatedIPs(t *testing.T) {
	a := newCIDRAllocator("10.10.10.0/29", []string{"10.10.10.2"})
	assert.Empty(t, a.AllocatedIPs())
	for _, ip := range []string{"10.10.10.1", "10.10.10.3", "10.10.10.4"} {
		require.NoError(t, a.AllocateIP(net.ParseIP(ip)))
	}
	require.NoError(t, a.Release(net.ParseIP("10.10.10.3")))
	require.Error(t, a.AllocateIP(net.ParseIP("10.10.10.2")))

	ips := a.AllocatedIPs()
	require.Len(t, ips, 2)
	assert.Equal(t, "10.10.10.1", ips[0].String())
	assert.Equal(t, "10.10.10.4", ips[1].String())
	// Mutating the returned IPs or slice must not affect the allocator.
	ips[0][len(ips[0])-1] = 99
	ips[1] = nil
	snapshot := a.AllocatedIPs()
	require.Len(t, snapshot, 2)
	assert.Equal(t, "10.10.10.1", snapshot[0].String())
	assert.Equal(t, "10.10.10.4", snapshot[1].String())
	require.NoError(t, a.Release(net.ParseIP("10.10.10.1")))
	assert.Equal(t, "10.10.10.1", snapshot[0].String())
	remaining := a.AllocatedIPs()
	require.Len(t, remaining, 1)
	assert.Equal(t, "10.10.10.4", remaining[0].String())
}

func TestNameAndTotal(t *testing.T) {
	ma := MultiIPAllocator{newIPRangeAllocator("1.1.1.10", "1.1.1.20"), newCIDRAllocator("10.10.10.128/30", nil)}
	assert.Equal(t, []string{"1.1.1.10-1.1.1.20", "10.10.10.128/30"}, ma.Names())
	assert.Equal(t, 14, ma.Total())
}

func TestReservedIPs(t *testing.T) {
	tests := []struct {
		name     string
		cidr     string
		start    string
		end      string
		reserved []string
		wantIPs  []string
	}{
		{
			name:     "IPv4 CIDR",
			cidr:     "10.10.10.0/29",
			reserved: []string{"10.10.10.0", "10.10.10.1", "10.10.10.1", "10.10.10.7", "10.10.10.8"},
			wantIPs:  []string{"10.10.10.2", "10.10.10.3", "10.10.10.4", "10.10.10.5", "10.10.10.6"},
		},
		{
			name:     "IPv6 CIDR",
			cidr:     "fd00::/125",
			reserved: []string{"fd00::", "fd00::1", "fd00:0:0:0:0:0:0:1", "fd00::7", "fd00::8"},
			wantIPs:  []string{"fd00::2", "fd00::3", "fd00::4", "fd00::5", "fd00::6"},
		},
		{
			name:     "IPv4 range",
			start:    "10.10.10.0",
			end:      "10.10.10.4",
			reserved: []string{"10.10.9.255", "10.10.10.0", "10.10.10.2", "10.10.10.2", "10.10.10.5"},
			wantIPs:  []string{"10.10.10.1", "10.10.10.3", "10.10.10.4"},
		},
		{
			name:     "IPv6 range",
			start:    "fd00::",
			end:      "fd00::4",
			reserved: []string{"fcff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "fd00::", "fd00::2", "fd00::2", "fd00::5"},
			wantIPs:  []string{"fd00::1", "fd00::3", "fd00::4"},
		},
		{
			name:     "all IPs reserved",
			start:    "10.10.10.1",
			end:      "10.10.10.1",
			reserved: []string{"10.10.10.1", "10.10.10.1"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var reservedIPs []net.IP
			for _, ip := range tt.reserved {
				reservedIPs = append(reservedIPs, net.ParseIP(ip))
			}
			var allocator *SingleIPAllocator
			var err error
			if tt.cidr != "" {
				_, ipNet, parseErr := net.ParseCIDR(tt.cidr)
				require.NoError(t, parseErr)
				allocator, err = NewCIDRAllocator(ipNet, reservedIPs)
			} else {
				allocator, err = NewIPRangeAllocator(net.ParseIP(tt.start), net.ParseIP(tt.end), reservedIPs...)
			}
			require.NoError(t, err)
			assert.Equal(t, len(tt.wantIPs), allocator.Total())
			assert.Equal(t, len(tt.wantIPs), allocator.Free())
			for _, ip := range reservedIPs {
				require.Error(t, allocator.AllocateIP(ip), "reserved or out-of-range IP %s must not be allocated", ip)
			}
			assert.Zero(t, allocator.Used())
			for i, wantIP := range tt.wantIPs {
				ip, err := allocator.AllocateNext()
				require.NoError(t, err)
				assert.Equal(t, wantIP, ip.String())
				assert.Equal(t, i+1, allocator.Used())
				assert.Equal(t, len(tt.wantIPs)-i-1, allocator.Free())
			}
			_, err = allocator.AllocateNext()
			require.Error(t, err)
			if len(tt.wantIPs) > 0 {
				ip := net.ParseIP(tt.wantIPs[0])
				require.NoError(t, allocator.Release(ip))
				require.NoError(t, allocator.AllocateIP(ip))
				assert.Zero(t, allocator.Free())
			}
		})
	}
}

func TestReservedIPsWithLimitedRange(t *testing.T) {
	tests := []struct {
		name    string
		cidr    string
		start   string
		end     string
		first   string
		last    string
		outside string
	}{
		{
			name:    "IPv4 CIDR",
			cidr:    "10.10.0.0/15",
			first:   "10.10.0.1",
			last:    "10.11.0.0",
			outside: "10.11.0.1",
		},
		{
			name:    "IPv6 CIDR",
			cidr:    "fd00::/64",
			first:   "fd00::1",
			last:    "fd00::1:0",
			outside: "fd00::1:1",
		},
		{
			name:    "IPv4 range",
			start:   "10.10.0.0",
			end:     "10.11.0.1",
			first:   "10.10.0.0",
			last:    "10.10.255.255",
			outside: "10.11.0.0",
		},
		{
			name:    "IPv6 range",
			start:   "fd00::",
			end:     "fd00::1:1",
			first:   "fd00::",
			last:    "fd00::ffff",
			outside: "fd00::1:0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reservedIPs := []net.IP{
				net.ParseIP(tt.first), net.ParseIP(tt.first), net.ParseIP(tt.last), net.ParseIP(tt.outside),
			}
			var allocator *SingleIPAllocator
			var err error
			if tt.cidr != "" {
				_, ipNet, parseErr := net.ParseCIDR(tt.cidr)
				require.NoError(t, parseErr)
				allocator, err = NewCIDRAllocator(ipNet, reservedIPs)
			} else {
				allocator, err = NewIPRangeAllocator(net.ParseIP(tt.start), net.ParseIP(tt.end), reservedIPs...)
			}
			require.NoError(t, err)
			assert.Equal(t, 65534, allocator.Total())
			assert.Equal(t, 65534, allocator.Free())
			for _, ip := range reservedIPs {
				require.Error(t, allocator.AllocateIP(ip))
			}
			ips, err := allocator.AllocateRange(65534)
			require.NoError(t, err)
			assert.Len(t, ips, 65534)
			assert.Equal(t, 65534, allocator.Used())
			assert.Zero(t, allocator.Free())
			_, err = allocator.AllocateNext()
			require.Error(t, err)
		})
	}
}
