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

package ipam

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"strings"

	admv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	crdv1alpha2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
)

func ValidateIPPool(review *admv1.AdmissionReview) *admv1.AdmissionResponse {
	var msg string
	allowed := true

	klog.V(2).Info("Validating IPPool", "request", review.Request)
	var newObj, oldObj crdv1alpha2.IPPool
	if review.Request.Object.Raw != nil {
		if err := json.Unmarshal(review.Request.Object.Raw, &newObj); err != nil {
			klog.ErrorS(err, "Error de-serializing current IPPool")
			return newAdmissionResponseForErr(err)
		}
	}
	if review.Request.OldObject.Raw != nil {
		if err := json.Unmarshal(review.Request.OldObject.Raw, &oldObj); err != nil {
			klog.ErrorS(err, "Error de-serializing old IPPool")
			return newAdmissionResponseForErr(err)
		}
	}

	switch review.Request.Operation {
	case admv1.Create:
		klog.V(2).Info("Validating CREATE request for IPPool")

		// Validate individual ranges
		for _, r := range newObj.Spec.IPRanges {
			allowed, msg = validateIPRange(r, newObj.Spec.IPVersion)
			if !allowed {
				return validationResult(allowed, msg)
			}
		}

		// Validate that the added ipRanges do not overlap
		for i, r1 := range newObj.Spec.IPRanges[0 : len(newObj.Spec.IPRanges)-1] {
			for _, r2 := range newObj.Spec.IPRanges[i+1 : len(newObj.Spec.IPRanges)] {
				if rangesOverlap(r1, r2) {
					msg = fmt.Sprintf("IPRanges %s overlap", humanReadableIPRanges([]crdv1alpha2.SubnetIPRange{r1, r2}))
					return validationResult(false, msg)
				}
			}
		}
	case admv1.Update:
		klog.V(2).Info("Validating UPDATE request for IPPool")
		deletedIPRanges := getIPRangeDifference(oldObj.Spec.IPRanges, newObj.Spec.IPRanges)
		if len(deletedIPRanges) > 0 {
			msg = fmt.Sprintf("existing IPRanges %s cannot be updated or deleted", humanReadableIPRanges(deletedIPRanges))
			return validationResult(false, msg)
		}

		addedIPRanges := getIPRangeDifference(newObj.Spec.IPRanges, oldObj.Spec.IPRanges)
		for _, r1 := range addedIPRanges {
			allowed, msg = validateIPRange(r1, newObj.Spec.IPVersion)
			if !allowed {
				return validationResult(allowed, msg)
			}
			for _, r2 := range newObj.Spec.IPRanges {
				if r1 != r2 && rangesOverlap(r1, r2) {
					msg = fmt.Sprintf("IPRanges %s overlap",
						humanReadableIPRanges([]crdv1alpha2.SubnetIPRange{r1, r2}))
					return validationResult(false, msg)
				}
			}
		}
	case admv1.Delete:
		klog.V(2).Info("Validating DELETE request for IPPool")
		if len(oldObj.Status.IPAddresses) > 0 {
			allowed = false
			msg = fmt.Sprintf("IPPool in use cannot be deleted")
		}
	}

	return validationResult(allowed, msg)
}

func validationResult(allowed bool, msg string) *admv1.AdmissionResponse {
	var result *metav1.Status

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

// getIPRangeDifference returns SubnetIPRanges that are in s1 but not in s2.
func getIPRangeDifference(s1, s2 []crdv1alpha2.SubnetIPRange) []crdv1alpha2.SubnetIPRange {
	newSet := map[crdv1alpha2.SubnetIPRange]struct{}{}
	for _, ipRange := range s2 {
		newSet[ipRange] = struct{}{}
	}

	var difference []crdv1alpha2.SubnetIPRange
	for _, ipRange := range s1 {
		if _, exists := newSet[ipRange]; exists {
			continue
		}
		difference = append(difference, ipRange)
	}
	return difference
}

func humanReadableIPRanges(ipRanges []crdv1alpha2.SubnetIPRange) string {
	strs := make([]string, len(ipRanges))
	for i, ipRange := range ipRanges {
		if ipRange.CIDR != "" {
			strs[i] = ipRange.CIDR
		} else {
			strs[i] = fmt.Sprintf("%s-%s", ipRange.Start, ipRange.End)
		}
	}
	return fmt.Sprintf("[%s]", strings.Join(strs, ","))
}

func rangesOverlap(r1, r2 crdv1alpha2.SubnetIPRange) bool {
	if r1.CIDR == "" {
		if r2.CIDR == "" {
			r1start := net.ParseIP(r1.Start)
			r1end := net.ParseIP(r1.End)
			r2start := net.ParseIP(r2.Start)
			r2end := net.ParseIP(r2.End)

			if ipInRange(r1start, r1end, r2start) || ipInRange(r2start, r2end, r1start) {
				return true
			}
		} else {
			_, cidr2, _ := net.ParseCIDR(r2.CIDR)
			r1start := net.ParseIP(r1.Start)
			r1end := net.ParseIP(r1.End)
			if cidr2.Contains(r1start) || cidr2.Contains(r1end) {
				return true
			}
			return ipInRange(r1start, r1end, cidr2.IP)
		}
	} else {
		_, cidr1, _ := net.ParseCIDR(r1.CIDR)
		if r2.CIDR == "" {
			r2start := net.ParseIP(r2.Start)
			r2end := net.ParseIP(r2.End)
			if cidr1.Contains(r2start) || cidr1.Contains(r2end) {
				return true
			}
			return ipInRange(r2start, r2end, cidr1.IP)
		} else {
			_, cidr2, _ := net.ParseCIDR(r2.CIDR)
			return cidr1.Contains(cidr2.IP) || cidr2.Contains(cidr1.IP)
		}
	}
	return false
}

func ipInRange(rangeStart, rangeEnd, ip net.IP) bool {
	// Validate that ip is within start and end of range
	ip16 := ip.To16()
	return bytes.Compare(ip16, rangeStart.To16()) >= 0 && bytes.Compare(ip16, rangeEnd.To16()) <= 0
}

func ipVersion(ip net.IP) int {
	if ip.To4() != nil {
		return 4
	}
	return 6
}

func validateIPRange(r crdv1alpha2.SubnetIPRange, poolIPVersion int) (bool, string) {
	// Validate the integrity the IP range:
	//  Verify that all the IP ranges have the same IP family as the IP pool
	//  Verify that the gateway IP is reachable from the IP range
	gateway := net.ParseIP(r.Gateway)
	var mask net.IPMask
	if ipVersion(gateway) == 4 {
		mask = net.CIDRMask(int(r.PrefixLength), 32)
	} else {
		mask = net.CIDRMask(int(r.PrefixLength), 128)
	}
	netCIDR := net.IPNet{IP: gateway, Mask: mask}

	if r.CIDR != "" {
		_, cidr, _ := net.ParseCIDR(r.CIDR)

		if !netCIDR.Contains(cidr.IP) {
			return false, fmt.Sprintf(
				"Range is invalid. CIDR %s is not contained within subnet %s/%d",
				r.CIDR, netCIDR.IP.String(), r.PrefixLength)
		}
		if ipVersion(cidr.IP) != poolIPVersion {
			return false, fmt.Sprintf(
				"Range is invalid. IP version of range %s differs from Pool IP version", r.CIDR)
		}
	} else {
		rStart := net.ParseIP(r.Start)
		rEnd := net.ParseIP(r.End)
		if !netCIDR.Contains(rStart) || !netCIDR.Contains(rEnd) {
			return false, fmt.Sprintf(
				"Range is invalid. range %s-%s is not contained within subnet %s/%d",
				r.Start, r.End, netCIDR.IP.String(), r.PrefixLength)
		}
		if ipVersion(rStart) != poolIPVersion || ipVersion(rEnd) != poolIPVersion {
			return false, fmt.Sprintf(
				"Range is invalid. IP version of range %s-%s differs from Pool IP version", r.Start, r.End)
		}
	}
	return true, ""
}

func newAdmissionResponseForErr(err error) *admv1.AdmissionResponse {
	return &admv1.AdmissionResponse{
		Result: &metav1.Status{
			Message: err.Error(),
		},
	}
}
