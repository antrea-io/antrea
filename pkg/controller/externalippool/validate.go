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

package externalippool

import (
	"encoding/json"
	"fmt"
	"net/netip"

	admv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"

	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	utilip "antrea.io/antrea/pkg/util/ip"
)

func (c *ExternalIPPoolController) ValidateExternalIPPool(review *admv1.AdmissionReview) *admv1.AdmissionResponse {
	var result *metav1.Status
	var msg string
	allowed := true

	klog.V(2).Info("Validating ExternalIPPool", "request", review.Request)
	var newObj, oldObj crdv1beta1.ExternalIPPool
	if review.Request.Object.Raw != nil {
		if err := json.Unmarshal(review.Request.Object.Raw, &newObj); err != nil {
			klog.ErrorS(err, "Error de-serializing current ExternalIPPool")
			return newAdmissionResponseForErr(err)
		}
	}
	if review.Request.OldObject.Raw != nil {
		if err := json.Unmarshal(review.Request.OldObject.Raw, &oldObj); err != nil {
			klog.ErrorS(err, "Error de-serializing old ExternalIPPool")
			return newAdmissionResponseForErr(err)
		}
	}

	externalIPPools, err := c.externalIPPoolLister.List(labels.Everything())
	if err != nil {
		klog.ErrorS(err, "Error listing ExternalIPPools")
		return newAdmissionResponseForErr(err)
	}

	switch review.Request.Operation {
	case admv1.Create:
		klog.V(2).Info("Validating CREATE request for ExternalIPPool")
		if msg, allowed = validateIPRangesAndSubnetInfo(newObj, externalIPPools); !allowed {
			break
		}
	case admv1.Update:
		klog.V(2).Info("Validating UPDATE request for ExternalIPPool")
		if msg, allowed = validateIPRangesAndSubnetInfo(newObj, externalIPPools); !allowed {
			break
		}
		oldIPRangeSet := getIPRangeSet(oldObj.Spec.IPRanges)
		newIPRangeSet := getIPRangeSet(newObj.Spec.IPRanges)
		deletedIPRanges := oldIPRangeSet.Difference(newIPRangeSet)
		if deletedIPRanges.Len() > 0 {
			allowed = false
			msg = fmt.Sprintf("existing IPRanges %v cannot be deleted", sets.List(deletedIPRanges))
		}
	case admv1.Delete:
		// This shouldn't happen with the webhook configuration we include in the Antrea YAML manifests.
		klog.V(2).Info("Validating DELETE request for ExternalIPPool")
		// Always allow DELETE request.
	}

	if msg != "" {
		result = &metav1.Status{
			Message: msg,
		}
	}
	return &admv1.AdmissionResponse{
		Allowed: allowed,
		Result:  result,
	}
}

func validateIPRangesAndSubnetInfo(externalIPPool crdv1beta1.ExternalIPPool, existingExternalIPPools []*crdv1beta1.ExternalIPPool) (string, bool) {
	subnetInfo := externalIPPool.Spec.SubnetInfo
	ipRanges := externalIPPool.Spec.IPRanges

	var subnet *netip.Prefix
	if subnetInfo != nil {
		gatewayAddr, err := netip.ParseAddr(subnetInfo.Gateway)
		if err != nil {
			return fmt.Sprintf("invalid gateway address %s", subnetInfo.Gateway), false
		}

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

	// combinedRanges combines both CIDR and start-end style range together mapped to start and end
	// address of the range. We populate the map with ranges of existing pools and incorporate
	// the ranges from the current pool as we iterate over them. The map's key is utilized to preserve
	// the original user-specified input for formatting validation error, if it occurs.
	combinedRanges := make(map[string][2]netip.Addr)
	for _, pool := range existingExternalIPPools {
		// exclude existing ip ranges of the pool which is being updated
		if pool.Name == externalIPPool.Name {
			continue
		}
		for _, ipRange := range pool.Spec.IPRanges {
			var key string
			var start, end netip.Addr

			if ipRange.CIDR != "" {
				key = fmt.Sprintf("range [%s] of pool %s", ipRange.CIDR, pool.Name)
				cidr, _ := parseIPRangeCIDR(ipRange.CIDR)
				start, end = utilip.GetStartAndEndOfPrefix(cidr)

			} else {
				key = fmt.Sprintf("range [%s-%s] of pool %s", ipRange.Start, ipRange.End, pool.Name)
				start, end, _ = parseIPRangeStartEnd(ipRange.Start, ipRange.End)

			}
			combinedRanges[key] = [2]netip.Addr{start, end}
		}
	}

	for _, ipRange := range ipRanges {
		var key string
		var start, end netip.Addr

		if ipRange.CIDR != "" {
			key = fmt.Sprintf("range [%s]", ipRange.CIDR)
			cidr, errMsg := parseIPRangeCIDR(ipRange.CIDR)
			if errMsg != "" {
				return errMsg, false
			}
			start, end = utilip.GetStartAndEndOfPrefix(cidr)

		} else {
			key = fmt.Sprintf("range [%s-%s]", ipRange.Start, ipRange.End)

			var errMsg string
			start, end, errMsg = parseIPRangeStartEnd(ipRange.Start, ipRange.End)
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
		}

		// validate if range is subset of given subnet info
		if subnet != nil && !(subnet.Contains(start) && subnet.Contains(end)) {
			return fmt.Sprintf("%s must be a strict subset of the subnet %s/%d",
				key, subnetInfo.Gateway, subnetInfo.PrefixLength), false
		}

		// validate if the range overlaps with ranges of any existing pool or already processed
		// range of current pool.
		for combinedKey, combinedRange := range combinedRanges {
			if !(start.Compare(combinedRange[1]) == 1 || end.Compare(combinedRange[0]) == -1) {
				return fmt.Sprintf("%s overlaps with %s", key, combinedKey), false
			}
		}

		combinedRanges[key] = [2]netip.Addr{start, end}
	}
	return "", true
}

func parseIPRangeCIDR(cidrStr string) (netip.Prefix, string) {
	var cidr netip.Prefix
	var err error

	cidr, err = netip.ParsePrefix(cidrStr)
	if err != nil {
		return cidr, fmt.Sprintf("invalid cidr %s", cidrStr)
	}
	cidr = cidr.Masked()
	return cidr, ""
}

func parseIPRangeStartEnd(startStr, endStr string) (netip.Addr, netip.Addr, string) {
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

func getIPRangeSet(ipRanges []crdv1beta1.IPRange) sets.Set[string] {
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

func newAdmissionResponseForErr(err error) *admv1.AdmissionResponse {
	return &admv1.AdmissionResponse{
		Result: &metav1.Status{
			Message: err.Error(),
		},
	}
}
