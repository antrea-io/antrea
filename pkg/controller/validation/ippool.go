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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	crdv1beta1 "antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
	utilip "antrea.io/antrea/v2/pkg/util/ip"
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

// parseIPRangeCIDR parses a CIDR string into a netip.Prefix
func parseIPRangeCIDR(cidrStr string) (netip.Prefix, error) {
	cidr, err := netip.ParsePrefix(cidrStr)
	if err != nil {
		return cidr, fmt.Errorf("invalid cidr %s", cidrStr)
	}
	return cidr.Masked(), nil
}

// parseIPRangeStartEnd parses start and end IP addresses
func parseIPRangeStartEnd(startStr, endStr string) (netip.Addr, netip.Addr, error) {
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

// validateIPRange validates an IP range specification
func validateIPRange(ipRange crdv1beta1.IPRange) error {
	start, end, err := parseIPRangeStartEnd(ipRange.Start, ipRange.End)
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

type subnetConfiguration struct {
	gateway      string
	prefixLength int32
	prefix       netip.Prefix
}

func ipFamilyForAddress(address netip.Addr) corev1.IPFamily {
	if address.Is4() {
		return corev1.IPv4Protocol
	}
	return corev1.IPv6Protocol
}

func parseSubnetConfiguration(gateway string, prefixLength int32) (corev1.IPFamily, subnetConfiguration, error) {
	gatewayAddr, err := netip.ParseAddr(gateway)
	if err != nil {
		return "", subnetConfiguration{}, fmt.Errorf("invalid gateway address %s", gateway)
	}

	if gatewayAddr.Is4() {
		if prefixLength <= 0 || prefixLength >= 32 {
			return "", subnetConfiguration{}, fmt.Errorf("invalid prefixLength %d", prefixLength)
		}
	} else if prefixLength <= 0 || prefixLength >= 128 {
		return "", subnetConfiguration{}, fmt.Errorf("invalid prefixLength %d", prefixLength)
	}

	return ipFamilyForAddress(gatewayAddr), subnetConfiguration{
		gateway:      gateway,
		prefixLength: prefixLength,
		prefix:       netip.PrefixFrom(gatewayAddr, int(prefixLength)).Masked(),
	}, nil
}

func subnetConfigurations(subnetInfo *crdv1beta1.SubnetInfo) (map[corev1.IPFamily]subnetConfiguration, error) {
	if subnetInfo == nil {
		return nil, nil
	}

	hasLegacy := subnetInfo.Gateway != "" || subnetInfo.PrefixLength != 0
	hasFamilySubnets := subnetInfo.IPFamilySubnets != nil
	if hasLegacy && hasFamilySubnets {
		return nil, fmt.Errorf("gateway and prefixLength cannot be set with ipFamilySubnets")
	}
	if !hasLegacy && !hasFamilySubnets {
		return nil, fmt.Errorf("subnetInfo must specify gateway and prefixLength or ipFamilySubnets")
	}

	configurations := make(map[corev1.IPFamily]subnetConfiguration, 2)
	if hasLegacy {
		family, subnet, err := parseSubnetConfiguration(subnetInfo.Gateway, subnetInfo.PrefixLength)
		if err != nil {
			return nil, err
		}
		configurations[family] = subnet
		return configurations, nil
	}

	if len(subnetInfo.IPFamilySubnets) == 0 || len(subnetInfo.IPFamilySubnets) > 2 {
		return nil, fmt.Errorf("ipFamilySubnets must contain one or two entries")
	}
	for _, familySubnet := range subnetInfo.IPFamilySubnets {
		family, subnet, err := parseSubnetConfiguration(familySubnet.Gateway, familySubnet.PrefixLength)
		if err != nil {
			return nil, err
		}
		if _, exists := configurations[family]; exists {
			return nil, fmt.Errorf("ipFamilySubnets contains multiple entries for IP family %s", family)
		}
		configurations[family] = subnet
	}
	return configurations, nil
}

// ValidateIPRangesAndSubnetInfo validates IP ranges and SubnetInfo
func ValidateIPRangesAndSubnetInfo(subnetInfo *crdv1beta1.SubnetInfo, ipRanges []crdv1beta1.IPRange) ([]NormalizedIPRange, error) {
	configurations, err := subnetConfigurations(subnetInfo)
	if err != nil {
		return nil, err
	}

	currentRanges := make([]NormalizedIPRange, 0, len(ipRanges))
	poolFamilies := sets.New[corev1.IPFamily]()
	for _, ipRange := range ipRanges {
		cur, err := normalizeRange(ipRange, "")
		if err != nil {
			return nil, err
		}
		family := ipFamilyForAddress(cur.Start)
		poolFamilies.Insert(family)

		// Validate the range against the subnet for its IP family.
		if configurations != nil {
			subnet, exists := configurations[family]
			if !exists {
				return nil, fmt.Errorf("%s has no subnet configuration for IP family %s", cur.Origin, family)
			}
			if !subnet.prefix.Contains(cur.Start) || !subnet.prefix.Contains(cur.End) {
				return nil, fmt.Errorf("%s must be a strict subset of the subnet %s/%d",
					cur.Origin, subnet.gateway, subnet.prefixLength)
			}
		}

		// Check for overlaps with other ranges in the same pool
		for _, existingRange := range currentRanges {
			if RangesOverlap(cur.Start, cur.End, existingRange.Start, existingRange.End) {
				return nil, fmt.Errorf("%s overlaps with %s", cur.Origin, existingRange.Origin)
			}
		}
		currentRanges = append(currentRanges, cur)
	}
	if subnetInfo != nil && subnetInfo.IPFamilySubnets != nil {
		for family := range configurations {
			if !poolFamilies.Has(family) {
				return nil, fmt.Errorf("subnet configuration for IP family %s is not present in the IP pool", family)
			}
		}
	}

	return currentRanges, nil
}

// IPFamiliesForRanges returns the set of IP families represented by the provided IP ranges.
func IPFamiliesForRanges(ipRanges []crdv1beta1.IPRange) (sets.Set[corev1.IPFamily], error) {
	families := sets.New[corev1.IPFamily]()
	for _, ipRange := range ipRanges {
		normalized, err := normalizeRange(ipRange, "")
		if err != nil {
			return nil, err
		}
		families.Insert(ipFamilyForAddress(normalized.Start))
	}
	return families, nil
}

// NormalizedIPRange represents a normalized IP range
type NormalizedIPRange struct {
	Start  netip.Addr
	End    netip.Addr
	Origin string // describes the origin of the range
}

// NormalizeRanges normalizes all IP ranges
func NormalizeRanges(ipRanges []crdv1beta1.IPRange, ctx string) ([]NormalizedIPRange, error) {
	normalized := make([]NormalizedIPRange, 0, len(ipRanges))
	for _, ipRange := range ipRanges {
		nr, err := normalizeRange(ipRange, ctx)
		if err != nil {
			return nil, err
		}
		normalized = append(normalized, nr)
	}
	return normalized, nil
}

// normalizeRange normalizes an IP range specification
func normalizeRange(ipRange crdv1beta1.IPRange, context string) (NormalizedIPRange, error) {
	var start, end netip.Addr
	var origin string

	if ipRange.CIDR != "" {
		cidr, err := parseIPRangeCIDR(ipRange.CIDR)
		if err != nil {
			return NormalizedIPRange{}, err
		}
		start, end = utilip.GetStartAndEndOfPrefix(cidr)
		origin = fmt.Sprintf("range [%s]", ipRange.CIDR)
	} else {
		var err error
		start, end, err = parseIPRangeStartEnd(ipRange.Start, ipRange.End)
		if err != nil {
			return NormalizedIPRange{}, err
		}
		if err := validateIPRange(ipRange); err != nil {
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

// RangesOverlap checks if two IP ranges overlap
func RangesOverlap(start1, end1, start2, end2 netip.Addr) bool {
	return start1.Compare(end2) <= 0 && end1.Compare(start2) >= 0
}
