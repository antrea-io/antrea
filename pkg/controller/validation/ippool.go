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
func ParseIPRangeCIDR(cidrStr string) (netip.Prefix, error) {
	cidr, err := netip.ParsePrefix(cidrStr)
	if err != nil {
		return cidr, fmt.Errorf("invalid cidr %s", cidrStr)
	}
	return cidr.Masked(), nil
}

// ParseIPRangeStartEnd parses start and end IP addresses
func ParseIPRangeStartEnd(startStr, endStr string) (netip.Addr, netip.Addr, error) {
	start, err := netip.ParseAddr(startStr)
	if err != nil {
		return start, netip.Addr{}, fmt.Errorf("invalid start ip address %s", startStr)
	}

	end, err := netip.ParseAddr(endStr)
	if err != nil {
		return start, end, fmt.Errorf("invalid end ip address %s", endStr)
	}
	return start, end, nil
}

// ValidateIPRange validates an IP range specification
func ValidateIPRange(ipRange crdv1beta1.IPRange) error {
	start, end, err := ParseIPRangeStartEnd(ipRange.Start, ipRange.End)
	if err != nil {
		return err
	}

	if start.Is4() != end.Is4() {
		return fmt.Errorf("range start %s and range end %s should belong to same family",
			ipRange.Start, ipRange.End)
	}

	if start.Compare(end) > 0 {
		return fmt.Errorf("range start %s should not be greater than range end %s",
			ipRange.Start, ipRange.End)
	}
	return nil
}

// ValidateIPRangesAndSubnetInfo validates IP ranges and SubnetInfo
func ValidateIPRangesAndSubnetInfo(subnetInfo *crdv1beta1.SubnetInfo, ipRanges []crdv1beta1.IPRange) error {
	var subnet *netip.Prefix
	if subnetInfo != nil {
		gatewayAddr, err := netip.ParseAddr(subnetInfo.Gateway)
		if err != nil {
			return fmt.Errorf("invalid gateway address %s", subnetInfo.Gateway)
		}

		if gatewayAddr.Is4() {
			if subnetInfo.PrefixLength <= 0 || subnetInfo.PrefixLength >= 32 {
				return fmt.Errorf("invalid prefixLength %d", subnetInfo.PrefixLength)
			}
		} else {
			if subnetInfo.PrefixLength <= 0 || subnetInfo.PrefixLength >= 128 {
				return fmt.Errorf("invalid prefixLength %d", subnetInfo.PrefixLength)
			}
		}
		prefix := netip.PrefixFrom(gatewayAddr, int(subnetInfo.PrefixLength)).Masked()
		subnet = &prefix
	}

	currentRanges := make(map[string][2]netip.Addr)

	for _, ipRange := range ipRanges {
		cur, err := NormalizeRange(ipRange, "")
		if err != nil {
			return err
		}
		start, end := cur.Start, cur.End
		key := cur.Origin

		// Validate range is within subnet
		if subnet != nil && (!subnet.Contains(start) || !subnet.Contains(end)) {
			return fmt.Errorf("%s must be a strict subset of the subnet %s/%d",
				key, subnetInfo.Gateway, subnetInfo.PrefixLength)
		}

		// Check for overlaps with other ranges in the same pool
		for existingKey, existingRange := range currentRanges {
			if Overlaps(start, end, existingRange[0], existingRange[1]) {
				return fmt.Errorf("%s overlaps with %s", key, existingKey)
			}
		}
		currentRanges[key] = [2]netip.Addr{start, end}
	}

	return nil
}

// NormalizedIPRange represents a normalized IP range
type NormalizedIPRange struct {
	Start  netip.Addr
	End    netip.Addr
	Origin string // describes the origin of the range
}

// NormalizeCurrentRanges normalizes all IP ranges
func NormalizeCurrentRanges(ipRanges []crdv1beta1.IPRange) ([]NormalizedIPRange, error) {
	normalized := make([]NormalizedIPRange, 0, len(ipRanges))
	for _, ipRange := range ipRanges {
		nr, err := NormalizeRange(ipRange, "")
		if err != nil {
			return nil, err
		}
		normalized = append(normalized, nr)
	}
	return normalized, nil
}

// NormalizeRange normalizes an IP range specification
func NormalizeRange(ipRange crdv1beta1.IPRange, context string) (NormalizedIPRange, error) {
	var start, end netip.Addr
	var origin string

	if ipRange.CIDR != "" {
		cidr, err := ParseIPRangeCIDR(ipRange.CIDR)
		if err != nil {
			return NormalizedIPRange{}, err
		}
		start, end = utilip.GetStartAndEndOfPrefix(cidr)
		origin = fmt.Sprintf("range [%s]", ipRange.CIDR)
	} else {
		var err error
		start, end, err = ParseIPRangeStartEnd(ipRange.Start, ipRange.End)
		if err != nil {
			return NormalizedIPRange{}, err
		}
		if err := ValidateIPRange(ipRange); err != nil {
			return NormalizedIPRange{}, err
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
	}, nil
}

// Overlaps checks if two IP ranges overlap
func Overlaps(start1, end1, start2, end2 netip.Addr) bool {
	return start1.Compare(end2) <= 0 && end1.Compare(start2) >= 0
}
