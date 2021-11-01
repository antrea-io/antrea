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
	"fmt"
	"math/big"
	"net"
	"sync"

	utilnet "k8s.io/utils/net"
)

type IPAllocator interface {
	AllocateIP(ip net.IP) error

	AllocateNext() (net.IP, error)

	Release(ip net.IP) error

	Used() int

	Has(ip net.IP) bool
}

// SingleIPAllocator is responsible for allocating IPs from a contiguous IP range.
type SingleIPAllocator struct {
	// The string format of the IP range. e.g. 10.10.10.0/24, or 10.10.10.10-10.10.10.20.
	ipRangeStr string

	mutex sync.RWMutex
	// base is a cached version of the start IP in the CIDR range as a *big.Int.
	base *big.Int
	// max is the maximum size of the usable addresses in the range.
	max int
	// allocated is a bit array of the allocated items in the range.
	allocated *big.Int
	// count is the number of currently allocated elements in the range.
	count int
	// IPs inside the cidr not available for allocation
	reservedIPs []net.IP
}

// NewCIDRAllocator creates an IPAllocator based on the provided CIDR.
func NewCIDRAllocator(cidr *net.IPNet, reservedIPs []net.IP) (*SingleIPAllocator, error) {
	base := utilnet.BigForIP(cidr.IP)
	// Start from "x.x.x.1".
	base.Add(base, big.NewInt(1))
	max := utilnet.RangeSize(cidr) - 1
	if max < 0 {
		return nil, fmt.Errorf("no available IP in %s", cidr.String())
	}
	// In case a big range occupies too much memory, allow at most 65536 IP for each IP range.
	if max > 65536 {
		max = 65536
	}

	allocator := &SingleIPAllocator{
		ipRangeStr:  cidr.String(),
		base:        base,
		max:         int(max),
		allocated:   big.NewInt(0),
		count:       0,
		reservedIPs: reservedIPs,
	}
	return allocator, nil
}

// NewIPRangeAllocator creates an IPAllocator based on the provided start IP and end IP.
// The start IP and end IP are inclusive.
func NewIPRangeAllocator(startIP, endIP net.IP) (*SingleIPAllocator, error) {
	ipRangeStr := fmt.Sprintf("%s-%s", startIP.String(), endIP.String())
	base := utilnet.BigForIP(startIP)
	offset := big.NewInt(0).Sub(utilnet.BigForIP(endIP), base).Int64()
	if offset < 0 {
		return nil, fmt.Errorf("invalid IP range %s", ipRangeStr)
	}
	max := offset + 1
	// In case a big range occupies too much memory, allow at most 65536 IP for each ipset.
	if max > 65536 {
		max = 65536
	}

	allocator := &SingleIPAllocator{
		ipRangeStr: ipRangeStr,
		base:       base,
		max:        int(max),
		allocated:  big.NewInt(0),
		count:      0,
	}
	return allocator, nil
}

func (a *SingleIPAllocator) Name() string {
	return a.ipRangeStr
}

func (a *SingleIPAllocator) checkReserved(ip net.IP) error {
	for _, reservedIP := range a.reservedIPs {
		if reservedIP.Equal(ip) {
			return fmt.Errorf("IP %v is reserved and not available for allocation", ip)
		}
	}
	return nil
}

// AllocateIP allocates the specified IP. It returns error if the IP is not in the range or already allocated.
func (a *SingleIPAllocator) AllocateIP(ip net.IP) error {
	offset := int(big.NewInt(0).Sub(utilnet.BigForIP(ip), a.base).Int64())
	if offset < 0 || offset >= a.max {
		return fmt.Errorf("IP %v is not in the ipset", ip)
	}

	err := a.checkReserved(ip)
	if err != nil {
		return err
	}

	a.mutex.Lock()
	defer a.mutex.Unlock()
	if a.allocated.Bit(offset) == 1 {
		return fmt.Errorf("IP %v is already allocated", ip)
	}
	a.allocated.SetBit(a.allocated, offset, 1)
	a.count++
	return nil
}

// AllocateNext allocates an IP from the IP range. It returns error if no IP is available.
func (a *SingleIPAllocator) AllocateNext() (net.IP, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	if a.count >= (a.max - len(a.reservedIPs)) {
		return nil, fmt.Errorf("no available IP")
	}
	for i := 0; i < a.max; i++ {
		if a.allocated.Bit(i) == 0 {
			ip := utilnet.AddIPOffset(a.base, i)
			if a.checkReserved(ip) != nil {
				continue
			}
			a.allocated.SetBit(a.allocated, i, 1)
			a.count++
			return ip, nil
		}
	}
	return nil, fmt.Errorf("no available IP")
}

// Release releases the provided IP. It returns error if the IP is not in the range or not allocated.
func (a *SingleIPAllocator) Release(ip net.IP) error {
	offset := int(big.NewInt(0).Sub(utilnet.BigForIP(ip), a.base).Int64())
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

// Has returns whether the provided IP is in the range or not.
func (a *SingleIPAllocator) Has(ip net.IP) bool {
	offset := int(big.NewInt(0).Sub(utilnet.BigForIP(ip), a.base).Int64())
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

func (ma MultiIPAllocator) AllocateIP(ip net.IP) error {
	for _, a := range ma {
		if err := a.AllocateIP(ip); err == nil {
			return nil
		}
	}
	return fmt.Errorf("cannot allocate IP %v in any range", ip)
}

func (ma MultiIPAllocator) AllocateNext() (net.IP, error) {
	for _, a := range ma {
		if ip, err := a.AllocateNext(); err == nil {
			return ip, nil
		}
	}
	return nil, fmt.Errorf("cannot allocate IP in any range")
}

func (ma MultiIPAllocator) Release(ip net.IP) error {
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

func (ma MultiIPAllocator) Total() int {
	total := 0
	for _, a := range ma {
		total += a.max - len(a.reservedIPs)
	}
	return total
}

func (ma MultiIPAllocator) Has(ip net.IP) bool {
	for _, a := range ma {
		if a.Has(ip) {
			return true
		}
	}
	return false
}
