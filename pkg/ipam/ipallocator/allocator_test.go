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
		})
	}
}

func TestNameAndTotal(t *testing.T) {
	ma := MultiIPAllocator{newIPRangeAllocator("1.1.1.10", "1.1.1.20"), newCIDRAllocator("10.10.10.128/30", nil)}
	assert.Equal(t, []string{"1.1.1.10-1.1.1.20", "10.10.10.128/30"}, ma.Names())
	assert.Equal(t, 14, ma.Total())
}
