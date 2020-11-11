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
	"bytes"
	"fmt"
	"net"
	"sort"

	"github.com/vmware-tanzu/antrea/pkg/apis/controlplane/v1beta2"
)

const (
	v4BitLen = 8 * net.IPv4len
	v6BitLen = 8 * net.IPv6len
)

// This function takes in one allow CIDR and multiple except CIDRs and gives diff CIDRs
// in allowCIDR eliminating except CIDRs. It currently supports only IPv4. except CIDR input
// can be changed.
func DiffFromCIDRs(allowCIDR *net.IPNet, exceptCIDRs []*net.IPNet) ([]*net.IPNet, error) {
	// Remove the redundant CIDRs
	exceptCIDRs = mergeCIDRs(exceptCIDRs)
	newCIDRs := []*net.IPNet{allowCIDR}
	for _, exceptCIDR := range exceptCIDRs {
	beginLoop:
		for i, indCIDR := range newCIDRs {
			// Consider masked IP from IPNet struct
			if indCIDR.Contains(exceptCIDR.IP.Mask(exceptCIDR.Mask)) {
				result := diffFromCIDR(indCIDR, exceptCIDR)
				// Delete the considered CIDR block and add resulting CIDR blocks
				copy(newCIDRs[i:], newCIDRs[i+1:])
				newCIDRs[len(newCIDRs)-1] = nil
				newCIDRs = newCIDRs[:len(newCIDRs)-1]
				// Append the result CIDRs
				newCIDRs = append(newCIDRs, result...)
				// This step can be optimized by having iterator over just the index. Went with reinitialization of iterator.
				goto beginLoop
			} else if exceptCIDR.Contains(indCIDR.IP) {
				// Just delete the CIDR block
				copy(newCIDRs[i:], newCIDRs[i+1:])
				newCIDRs[len(newCIDRs)-1] = nil
				newCIDRs = newCIDRs[:len(newCIDRs)-1]
				goto beginLoop
			}
		}
	}
	return newCIDRs, nil
}

// This function gives diff CIDRs between a superset CIDR (allow CIDR) and subset CIDR
// (except CIDR)
func diffFromCIDR(allowCIDR, exceptCIDR *net.IPNet) []*net.IPNet {
	allowPrefix, _ := allowCIDR.Mask.Size()
	exceptPrefix, _ := exceptCIDR.Mask.Size()

	// Mask the IP to get the start IP of range
	allowStartIP := allowCIDR.IP.Mask(allowCIDR.Mask)
	exceptStartIP := exceptCIDR.IP.Mask(exceptCIDR.Mask)
	var bits int
	if allowStartIP.To4() != nil {
		bits = v4BitLen
	} else {
		bits = v6BitLen
	}

	// New CIDRs should not contain the IPs in exceptCIDR. Manipulating the bits in start IP of
	// exceptCIDR will give remainder IPs in allowCIDR, specifically the masked IPs for remaining
	// CIDRs with prefix ranging from [allowPrefix+1, exceptPrefix].
	remainingCIDRs := make([]*net.IPNet, 0, exceptPrefix-allowPrefix)
	for i := allowPrefix + 1; i <= exceptPrefix; i++ {
		// Flip the (ipBitLen - i)th bit from LSB in exceptCIDR to get the IP which is not in exceptCIDR
		ipOfNewCIDR := flipSingleBit(&exceptStartIP, uint8(bits-i))
		newCIDRMask := net.CIDRMask(i, bits)
		for j := range allowStartIP {
			ipOfNewCIDR[j] = allowStartIP[j] | ipOfNewCIDR[j]
		}

		newCIDR := net.IPNet{IP: ipOfNewCIDR.Mask(newCIDRMask), Mask: newCIDRMask}
		remainingCIDRs = append(remainingCIDRs, &newCIDR)
	}
	return remainingCIDRs
}

func flipSingleBit(ip *net.IP, bitIndex uint8) net.IP {
	newIP := make(net.IP, len(*ip))
	copy(newIP, *ip)
	byteIndex := uint8(len(newIP)) - (bitIndex / 8) - 1
	// XOR bit operation to flip
	newIP[byteIndex] = newIP[byteIndex] ^ (1 << (bitIndex % 8))
	return newIP
}

// This function is to check for redundant CIDRs in the list that are
// covered by other CIDRs and remove them. Input array can be modified.
func mergeCIDRs(cidrBlocks []*net.IPNet) []*net.IPNet {
	// Sort the list by netmask in ascending order
	sort.Slice(cidrBlocks, func(i, j int) bool {
		return bytes.Compare(cidrBlocks[i].Mask, cidrBlocks[j].Mask) < 0
	})

	// Check and remove if there are redundant CIDRs that are part of bigger CIDRs
	// or repeated CIDRs
	for i := 0; i < len(cidrBlocks); i++ {
		for j := i + 1; j < len(cidrBlocks); j++ {
			if cidrBlocks[i].Contains(cidrBlocks[j].IP) {
				// Delete the CIDR block and truncate the slice
				copy(cidrBlocks[j:], cidrBlocks[j+1:])
				cidrBlocks[len(cidrBlocks)-1] = nil
				cidrBlocks = cidrBlocks[:len(cidrBlocks)-1]
				// Decrement the tracker to consider next element
				j = j - 1
			}
		}
	}
	return cidrBlocks
}

// Function to transform Antrea IPNet to net.IPNet
func IPNetToNetIPNet(ipNet *v1beta2.IPNet) *net.IPNet {
	ip := net.IP(ipNet.IP)
	var bits int
	if ip.To4() != nil {
		bits = v4BitLen
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(int(ipNet.PrefixLength), bits)}
	} else {
		// Since OVS will report error when using an IPv6 CIDR in the OpenFlow messages if the bit is not zero in the
		// address but it is zero in the mask. Here using the function in "net" library to ensure the result is valid.
		_, ipNet, _ := net.ParseCIDR(fmt.Sprintf("%s/%d", ip.String(), ipNet.PrefixLength))
		return ipNet
	}
}

// NetIPNetToIPNet transforms net.IPNet to Antrea IPNet
func NetIPNetToIPNet(ipNet *net.IPNet) *v1beta2.IPNet {
	prefix, _ := ipNet.Mask.Size()
	return &v1beta2.IPNet{IP: v1beta2.IPAddress(ipNet.IP), PrefixLength: int32(prefix)}
}
