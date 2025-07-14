// Copyright 2025 Antrea Authors.
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

package validation

import (
	"fmt"
	"net/netip"

	"k8s.io/apimachinery/pkg/util/sets"

	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	utilip "antrea.io/antrea/pkg/util/ip"
)

// GetIPRangeSet returns a set of string representations of IP ranges
func GetIPRangeSet(ipRanges []crdv1beta1.IPRange) sets.Set[string] {
	set := sets.New[string]()
	for _, ipRange := range ipRanges {
		ipRangeStr := ipRange.CIDR
		if ipRangeStr == "" {
			ipRangeStr = fmt.Sprintf("%s-%s", ipRange.Start, ipRange.End)
		}
		set.Insert(ipRangeStr)
	}
	return set
}

// ParseIPRangeCIDR parses a CIDR string into a netip.Prefix
func ParseIPRangeCIDR(cidrStr string) (netip.Prefix, string) {
	cidr, err := netip.ParsePrefix(cidrStr)
	if err != nil {
		return cidr, fmt.Sprintf("invalid cidr %s", cidrStr)
	}
	return cidr.Masked(), ""
}

// ParseIPRangeStartEnd parses start and end IP addresses
func ParseIPRangeStartEnd(startStr, endStr string) (netip.Addr, netip.Addr, string) {
	start, err := netip.ParseAddr(startStr)
	if err != nil {
		return start, netip.Addr{}, fmt.Sprintf("invalid start ip address %s", startStr)
	}

	end, err := netip.ParseAddr(endStr)
	if err != nil {
		return start, end, fmt.Sprintf("invalid end ip address %s", endStr)
	}
	return start, end, ""
}

// ValidateIPRange validates an IP range specification
func ValidateIPRange(ipRange crdv1beta1.IPRange) (string, bool) {
	start, end, errMsg := ParseIPRangeStartEnd(ipRange.Start, ipRange.End)
	if errMsg != "" {
		return errMsg, false
	}

	if start.Is4() != end.Is4() {
		return fmt.Sprintf("range start %s and range end %s should belong to same family",
			ipRange.Start, ipRange.End), false
	}

	// validate if start address <= end address
	if start.Compare(end) == 1 {
		return fmt.Sprintf("range start %s should not be greater than range end %s",
			ipRange.Start, ipRange.End), false
	}
	return "", true
}

// ValidateIPRangesAndSubnetInfo validates IP ranges and SubnetInfo
func ValidateIPRangesAndSubnetInfo(subnetInfo *crdv1beta1.SubnetInfo, ipRanges []crdv1beta1.IPRange) (string, bool) {
	var subnet *netip.Prefix
	if subnetInfo != nil {
		gatewayAddr, err := netip.ParseAddr(subnetInfo.Gateway)
		if err != nil {
			return fmt.Sprintf("invalid gateway address %s", subnetInfo.Gateway), false
		}

		// Validate prefix length based on IP family
		if gatewayAddr.Is4() {
			if subnetInfo.PrefixLength <= 0 || subnetInfo.PrefixLength >= 32 {
				return fmt.Sprintf("invalid prefixLength %d", subnetInfo.PrefixLength), false
			}
		} else {
			if subnetInfo.PrefixLength <= 0 || subnetInfo.PrefixLength >= 128 {
				return fmt.Sprintf("invalid prefixLength %d", subnetInfo.PrefixLength), false
			}
		}
		prefix := netip.PrefixFrom(gatewayAddr, int(subnetInfo.PrefixLength)).Masked()
		subnet = &prefix
	}

	currentRanges := make(map[string][2]netip.Addr)

	for _, ipRange := range ipRanges {
		cur := NormalizeRange(ipRange, "")
		if cur.Error != "" {
			return cur.Error, false
		}
		start, end := cur.Start, cur.End
		key := cur.Origin

		// Validate range is within subnet
		if subnet != nil && (!subnet.Contains(start) || !subnet.Contains(end)) {
			return fmt.Sprintf("%s must be a strict subset of the subnet %s/%d",
				key, subnetInfo.Gateway, subnetInfo.PrefixLength), false
		}

		// Check for overlaps with other ranges in the same pool
		for existingKey, existingRange := range currentRanges {
			if Overlaps(start, end, existingRange[0], existingRange[1]) {
				return fmt.Sprintf("%s overlaps with %s", key, existingKey), false
			}
		}
		currentRanges[key] = [2]netip.Addr{start, end}
	}

	return "", true
}

// NormalizedIPRange represents a normalized IP range
type NormalizedIPRange struct {
	Start  netip.Addr
	End    netip.Addr
	Origin string // describes the origin of the range
	Error  string
}

// NormalizeCurrentRanges normalizes all IP ranges
func NormalizeCurrentRanges(ipRanges []crdv1beta1.IPRange) []NormalizedIPRange {
	normalized := make([]NormalizedIPRange, 0, len(ipRanges))
	for _, ipRange := range ipRanges {
		normalized = append(normalized, NormalizeRange(ipRange, ""))
	}
	return normalized
}

// NormalizeRange normalizes an IP range specification
func NormalizeRange(ipRange crdv1beta1.IPRange, context string) NormalizedIPRange {
	var start, end netip.Addr
	var origin string

	if ipRange.CIDR != "" {
		cidr, msg := ParseIPRangeCIDR(ipRange.CIDR)
		if msg != "" {
			return NormalizedIPRange{Error: msg}
		}
		start, end = utilip.GetStartAndEndOfPrefix(cidr)
		origin = fmt.Sprintf("range [%s]", ipRange.CIDR)
	} else {
		var msg string
		start, end, msg = ParseIPRangeStartEnd(ipRange.Start, ipRange.End)
		if msg != "" {
			return NormalizedIPRange{Error: msg}
		}
		if msg, valid := ValidateIPRange(ipRange); !valid {
			return NormalizedIPRange{Error: msg}
		}
		origin = fmt.Sprintf("range [%s-%s]", ipRange.Start, ipRange.End)
	}

	if context != "" {
		origin = fmt.Sprintf("%s of %s", origin, context)
	}

	return NormalizedIPRange{
		Start:  start,
		End:    end,
		Origin: origin,
	}
}

// Overlaps checks if two IP ranges overlap
func Overlaps(start1, end1, start2, end2 netip.Addr) bool {
	return start1.Compare(end2) <= 0 && end1.Compare(start2) >= 0
}
