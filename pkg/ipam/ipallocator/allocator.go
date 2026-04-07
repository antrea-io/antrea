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
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
	"net/netip"
	"sync"
)

const maxAllocatedSize = 65536

type IPAllocator interface {
	AllocateIP(ip netip.Addr) error

	AllocateNext() (netip.Addr, error)

	// AllocateRange allocates a range of continuous IPs in one go. If a
	// contiguous chunk is not available, an error will be returned.
	AllocateRange(size int) ([]netip.Addr, error)

	Release(ip netip.Addr) error

	Used() int

	Has(ip netip.Addr) bool
}

// SingleIPAllocator is responsible for allocating IPs from a contiguous IP range.
type SingleIPAllocator struct {
	// The string format of the IP range. e.g. 10.10.10.0/24, or 10.10.10.10-10.10.10.20.
	ipRangeStr string

	mutex sync.RWMutex
	// base is the first allocatable IP in the range.
	base netip.Addr
	// max is the maximum size of the usable addresses in the range.
	max int
	// allocated is a bit array of the allocated items in the range.
	allocated *big.Int
	// count is the number of currently allocated elements in the range.
	count int
	// IPs inside the cidr not available for allocation.
	reservedIPs []netip.Addr
}

// NewCIDRAllocator creates an IPAllocator based on the provided CIDR prefix.
func NewCIDRAllocator(cidr netip.Prefix, reservedIPs []netip.Addr) (*SingleIPAllocator, error) {
	cidr = cidr.Masked()
	// Start from "x.x.x.1".
	base := cidr.Addr().Next()
	bits := cidr.Addr().BitLen() - cidr.Bits()
	var max int
	if bits >= 16 {
		// In case a big range occupies too much memory, allow at most maxAllocatedSize IPs for each IP range.
		max = maxAllocatedSize
	} else {
		max = (1 << bits) - 1
	}
	if max <= 0 {
		return nil, fmt.Errorf("no available IP in %s", cidr.String())
	}

	allocator := &SingleIPAllocator{
		ipRangeStr:  cidr.String(),
		base:        base,
		max:         max,
		allocated:   big.NewInt(0),
		count:       0,
		reservedIPs: reservedIPs,
	}
	return allocator, nil
}

// NewIPRangeAllocator creates an IPAllocator based on the provided start IP and end IP.
// The start IP and end IP are inclusive.
func NewIPRangeAllocator(startIP, endIP netip.Addr) (*SingleIPAllocator, error) {
	ipRangeStr := fmt.Sprintf("%s-%s", startIP.String(), endIP.String())
	offset := getIPOffset(startIP, endIP)
	if offset < 0 {
		return nil, fmt.Errorf("invalid IP range %s", ipRangeStr)
	}
	max := offset + 1
	// In case a big range occupies too much memory, allow at most maxAllocatedSize IPs for each IP range.
	if max > maxAllocatedSize {
		max = maxAllocatedSize
	}

	allocator := &SingleIPAllocator{
		ipRangeStr: ipRangeStr,
		base:       startIP,
		max:        max,
		allocated:  big.NewInt(0),
		count:      0,
	}
	return allocator, nil
}

func (a *SingleIPAllocator) Name() string {
	return a.ipRangeStr
}

func (a *SingleIPAllocator) isReserved(ip netip.Addr) bool {
	for _, reservedIP := range a.reservedIPs {
		if reservedIP == ip {
			return true
		}
	}
	return false
}

// AllocateIP allocates the specified IP. It returns error if the IP is not in the range or already allocated.
func (a *SingleIPAllocator) AllocateIP(ip netip.Addr) error {
	offset := getIPOffset(a.base, ip)
	if offset < 0 || offset >= a.max {
		return fmt.Errorf("IP %v is not in the ipset", ip)
	}

	if a.isReserved(ip) {
		return fmt.Errorf("IP %v is reserved and not available for allocation", ip)
	}

	a.mutex.Lock()
	defer a.mutex.Unlock()
	if a.allocated.Bit(offset) != 0 {
		return fmt.Errorf("IP %v is already allocated", ip)
	}
	a.allocated.SetBit(a.allocated, offset, 1)
	a.count++
	return nil
}

// AllocateNext allocates an IP from the IP range. It returns error if no IP is available.
func (a *SingleIPAllocator) AllocateNext() (netip.Addr, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	if a.count >= a.max-len(a.reservedIPs) {
		return netip.Addr{}, fmt.Errorf("no available IP")
	}
	ip := a.base
	for i := 0; i < a.max; i++ {
		if a.allocated.Bit(i) != 0 || a.isReserved(ip) {
			ip = ip.Next()
			continue
		}
		a.allocated.SetBit(a.allocated, i, 1)
		a.count++
		return ip, nil
	}

	// We should never reach here.
	return netip.Addr{}, fmt.Errorf("no available IP")
}

// AllocateRange allocates continuous range of specified size. If not available, error is returned.
func (a *SingleIPAllocator) AllocateRange(size int) ([]netip.Addr, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	if a.count+size > a.max-len(a.reservedIPs) {
		return nil, fmt.Errorf("not enough available IPs")
	}

	// rangeAvailable returns whether the range starting at the specified offset is
	// available. The IP address corresponding to the offset also needs to be provided as a
	// parameter. The function returns the last visited IP and offset, so that subsequent calls
	// to rangeAvailable (if necessary) can be done more efficiently.
	rangeAvailable := func(ip netip.Addr, offset int) (bool, netip.Addr, int) {
		for i := offset; i < offset+size; i++ {
			if a.allocated.Bit(i) != 0 || a.isReserved(ip) {
				return false, ip, i
			}
			ip = ip.Next()
		}
		return true, ip, offset + size
	}

	ip := a.base
	start := 0
	for start <= a.max-size {
		// Check if a continuous range of the requested size is available.
		available, maxIP, maxOffset := rangeAvailable(ip, start)
		if available {
			// Perform the actual allocation.
			ips := make([]netip.Addr, 0, size)
			for i := 0; i < size; i++ {
				offset := start + i
				a.allocated.SetBit(a.allocated, offset, 1)
				a.count++
				ips = append(ips, ip)
				ip = ip.Next()
			}
			return ips, nil
		}
		ip = maxIP.Next()
		start = maxOffset + 1
	}

	return nil, fmt.Errorf("continuous range of size %d is not available", size)
}

func (a *SingleIPAllocator) getOffset(ip netip.Addr) int {
	return getIPOffset(a.base, ip)
}

// Release releases the provided IP. It returns error if the IP is not in the range or not allocated.
func (a *SingleIPAllocator) Release(ip netip.Addr) error {
	offset := a.getOffset(ip)
	if offset < 0 || offset >= a.max {
		return fmt.Errorf("IP %v is not in the ipset", ip)
	}

	a.mutex.Lock()
	defer a.mutex.Unlock()
	if a.allocated.Bit(offset) == 0 {
		return fmt.Errorf("IP %v is not allocated", ip)
	}
	a.allocated.SetBit(a.allocated, offset, 0)
	a.count--
	return nil
}

// Used returns the number of the allocated IPs.
func (a *SingleIPAllocator) Used() int {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	return a.count
}

// Free returns the number of free IPs.
func (a *SingleIPAllocator) Free() int {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	return a.max - a.count - len(a.reservedIPs)
}

// Total returns the number total of IPs within the pool.
func (a *SingleIPAllocator) Total() int {
	return a.max - len(a.reservedIPs)
}

// Has returns whether the provided IP is in the range or not.
func (a *SingleIPAllocator) Has(ip netip.Addr) bool {
	offset := a.getOffset(ip)
	return offset >= 0 && offset < a.max
}

// MultiIPAllocator is responsible for allocating IPs from multiple contiguous IP ranges.
type MultiIPAllocator []*SingleIPAllocator

func (ma MultiIPAllocator) Names() []string {
	names := make([]string, 0, len(ma))
	for _, a := range ma {
		names = append(names, a.Name())
	}
	return names
}

func (ma MultiIPAllocator) AllocateIP(ip netip.Addr) error {
	for _, a := range ma {
		if err := a.AllocateIP(ip); err == nil {
			return nil
		}
	}
	return fmt.Errorf("cannot allocate IP %v in any range", ip)
}

func (ma MultiIPAllocator) AllocateNext() (netip.Addr, error) {
	for _, a := range ma {
		if ip, err := a.AllocateNext(); err == nil {
			return ip, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("cannot allocate IP in any range")
}

// AllocateRange allocates continuous range of specified size.
// If not available in any allocator, error is returned.
func (ma MultiIPAllocator) AllocateRange(size int) ([]netip.Addr, error) {
	if size > ma.Free() {
		return nil, fmt.Errorf("not enough IPs to reserve range of size %d", size)
	}

	for _, a := range ma {
		if ips, err := a.AllocateRange(size); err == nil {
			return ips, nil
		}
	}

	return nil, fmt.Errorf("cannot allocate contiguous IPs in any range")
}

func (ma MultiIPAllocator) Release(ip netip.Addr) error {
	for _, a := range ma {
		if err := a.Release(ip); err == nil {
			return nil
		}
	}
	return fmt.Errorf("cannot release IP in any range")
}

func (ma MultiIPAllocator) Used() int {
	used := 0
	for _, a := range ma {
		used += a.Used()
	}
	return used
}

func (ma MultiIPAllocator) Free() int {
	return ma.Total() - ma.Used()
}

func (ma MultiIPAllocator) Total() int {
	total := 0
	for _, a := range ma {
		total += a.Total()
	}
	return total
}

func (ma MultiIPAllocator) Has(ip netip.Addr) bool {
	for _, a := range ma {
		if a.Has(ip) {
			return true
		}
	}
	return false
}

// getIPOffset returns the offset of ip from base as a non-negative int, or -1 if ip is before base
// or of a different address family. It returns math.MaxInt if the offset overflows int.
func getIPOffset(base, ip netip.Addr) int {
	if base.Is4() != ip.Is4() {
		return -1
	}
	b := base.As16()
	i := ip.As16()
	hiB := binary.BigEndian.Uint64(b[:8])
	loB := binary.BigEndian.Uint64(b[8:])
	hiI := binary.BigEndian.Uint64(i[:8])
	loI := binary.BigEndian.Uint64(i[8:])
	if hiI < hiB || (hiI == hiB && loI < loB) {
		return -1
	}
	if hiI > hiB {
		return math.MaxInt
	}
	diff := loI - loB
	if diff > math.MaxInt {
		return math.MaxInt
	}
	return int(diff)
}
