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
)

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

func ParseIPRangeCIDR(cidrStr string) (netip.Prefix, string) {
	var cidr netip.Prefix
	var err error

	cidr, err = netip.ParsePrefix(cidrStr)
	if err != nil {
		return cidr, fmt.Sprintf("invalid cidr %s", cidrStr)
	}
	cidr = cidr.Masked()
	return cidr, ""
}

func ParseIPRangeStartEnd(startStr, endStr string) (netip.Addr, netip.Addr, string) {
	var start, end netip.Addr
	var err error

	start, err = netip.ParseAddr(startStr)
	if err != nil {
		return start, end, fmt.Sprintf("invalid start ip address %s", startStr)
	}

	end, err = netip.ParseAddr(endStr)
	if err != nil {
		return start, end, fmt.Sprintf("invalid end ip address %s", endStr)
	}
	return start, end, ""
}

func ValidateSubnetInfo(gateway string, prefixLength int32) error {
	gatewayAddr, err := netip.ParseAddr(gateway)
	if err != nil {
		return fmt.Errorf("invalid gateway address %s", gateway)
	}

	if gatewayAddr.Is4() {
		if prefixLength <= 0 || prefixLength >= 32 {
			return fmt.Errorf("invalid prefixLength %d", prefixLength)
		}
	} else {
		if prefixLength <= 0 || prefixLength >= 128 {
			return fmt.Errorf("invalid prefixLength %d", prefixLength)
		}
	}
	return nil
}

func ValidateIPRange(ipRange crdv1beta1.IPRange) (string, bool) {
	start, end, errMsg := ParseIPRangeStartEnd(ipRange.Start, ipRange.End)
	if errMsg != "" {
		return errMsg, false
	}

	// validate if start and end belong to same ip family
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
