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

package ipallocator

import (
	"net/netip"
	"testing"
)

func BenchmarkNewCIDRAllocator(b *testing.B) {
	cidr := netip.MustParsePrefix("10.10.0.0/16")
	reservedIPs := []netip.Addr{netip.MustParseAddr("10.10.255.255")}
	for b.Loop() {
		NewCIDRAllocator(cidr, reservedIPs)
	}
}

func BenchmarkNewIPRangeAllocator(b *testing.B) {
	startIP := netip.MustParseAddr("10.10.0.1")
	endIP := netip.MustParseAddr("10.10.0.254")
	for b.Loop() {
		NewIPRangeAllocator(startIP, endIP)
	}
}

func BenchmarkAllocateIPAndRelease(b *testing.B) {
	cidr := netip.MustParsePrefix("10.10.0.0/24")
	a, _ := NewCIDRAllocator(cidr, nil)
	ip := netip.MustParseAddr("10.10.0.100")
	for b.Loop() {
		a.AllocateIP(ip)
		a.Release(ip)
	}
}

func BenchmarkAllocateNextAndRelease(b *testing.B) {
	cidr := netip.MustParsePrefix("10.10.0.0/24")
	a, _ := NewCIDRAllocator(cidr, nil)
	for b.Loop() {
		ip, _ := a.AllocateNext()
		a.Release(ip)
	}
}

func BenchmarkAllocateNextLargeSequence(b *testing.B) {
	for b.Loop() {
		cidr := netip.MustParsePrefix("10.10.0.0/24")
		a, _ := NewCIDRAllocator(cidr, nil)
		for i := 0; i < 100; i++ {
			a.AllocateNext()
		}
	}
}

// BenchmarkAllocateNextHalfFull measures AllocateNext when the allocator is half-full,
// forcing the scan to skip the first half of the range before finding a free slot.
func BenchmarkAllocateNextHalfFull(b *testing.B) {
	cidr := netip.MustParsePrefix("10.10.0.0/24")
	a, _ := NewCIDRAllocator(cidr, nil)
	for i := 0; i < 127; i++ {
		_, _ = a.AllocateNext()
	}
	for b.Loop() {
		ip, _ := a.AllocateNext()
		// need to release, otherwise we may run out of IPs
		a.Release(ip)
	}
}

func BenchmarkRelease(b *testing.B) {
	cidr := netip.MustParsePrefix("10.10.0.0/24")
	a, _ := NewCIDRAllocator(cidr, nil)
	ip := netip.MustParseAddr("10.10.0.100")
	_ = a.AllocateIP(ip)
	for b.Loop() {
		_ = a.Release(ip)
		_ = a.AllocateIP(ip)
	}
}

func BenchmarkHas(b *testing.B) {
	cidr := netip.MustParsePrefix("10.10.0.0/24")
	a, _ := NewCIDRAllocator(cidr, nil)
	ip := netip.MustParseAddr("10.10.0.100")
	for b.Loop() {
		a.Has(ip)
	}
}

func BenchmarkAllocateRangeAndRelease(b *testing.B) {
	cidr := netip.MustParsePrefix("10.10.0.0/16")
	a, _ := NewCIDRAllocator(cidr, nil)
	for b.Loop() {
		ips, _ := a.AllocateRange(10)
		for _, ip := range ips {
			a.Release(ip)
		}
	}
}

func BenchmarkAllocateLargeRange(b *testing.B) {
	cidr := netip.MustParsePrefix("10.10.0.0/16")
	for b.Loop() {
		a, _ := NewCIDRAllocator(cidr, nil)
		a.AllocateRange(200)
	}
}

// BenchmarkAllocateRangeSkipSmallGaps measures AllocateRange when several free runs
// shorter than the requested size precede the first run that is large enough.
func BenchmarkAllocateRangeSkipSmallGaps(b *testing.B) {
	const (
		gapSize      = 10
		requestSize  = 20
		numSmallGaps = 2
	)

	cidr := netip.MustParsePrefix("10.10.0.0/16")
	ip1 := netip.MustParseAddr("10.10.0.10")
	ip2 := netip.MustParseAddr("10.10.0.20")
	ip3 := netip.MustParseAddr("10.10.0.30")

	for b.Loop() {
		a, _ := NewCIDRAllocator(cidr, nil)
		a.AllocateIP(ip1)
		a.AllocateIP(ip2)
		a.AllocateIP(ip3)
		a.AllocateRange(requestSize)
	}
}

// BenchmarkAllocateNextWithReserved measures AllocateNext when the first several offsets
// are reserved, requiring isReserved checks before a free slot is found.
func BenchmarkAllocateNextWithReserved(b *testing.B) {
	cidr := netip.MustParsePrefix("10.10.0.0/24")
	reservedIPs := []netip.Addr{
		netip.MustParseAddr("10.10.0.1"),
		netip.MustParseAddr("10.10.0.2"),
		netip.MustParseAddr("10.10.0.3"),
		netip.MustParseAddr("10.10.0.4"),
		netip.MustParseAddr("10.10.0.5"),
	}
	a, _ := NewCIDRAllocator(cidr, reservedIPs)
	for b.Loop() {
		ip, _ := a.AllocateNext()
		a.Release(ip)

	}
}
