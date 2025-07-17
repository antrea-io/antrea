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

package ipam

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
	"antrea.io/antrea/pkg/util/validation"
)

func (c *AntreaIPAMController) ValidateIPPool(review *admv1.AdmissionReview) *admv1.AdmissionResponse {
	var result *metav1.Status
	var msg string
	allowed := true

	klog.V(2).Info("Validating IPPool", "request", review.Request)
	var newObj, oldObj crdv1beta1.IPPool
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

	ippools, err := c.ipPoolLister.List(labels.Everything())
	if err != nil {
		klog.ErrorS(err, "Error listing IPPools")
		return newAdmissionResponseForErr(err)
	}

	switch review.Request.Operation {
	case admv1.Create:
		klog.V(2).Info("Validating CREATE request for IPPool")
		if msg, allowed = validateIPRangesAndSubnetInfo(newObj, ippools); !allowed {
			break
		}
	case admv1.Update:
		klog.V(2).Info("Validating UPDATE request for IPPool")
		if msg, allowed = validateIPRangesAndSubnetInfo(newObj, ippools); !allowed {
			break
		}
		oldIPRangeSet := validation.GetIPRangeSet(oldObj.Spec.IPRanges)
		newIPRangeSet := validation.GetIPRangeSet(newObj.Spec.IPRanges)
		deletedIPRanges := oldIPRangeSet.Difference(newIPRangeSet)
		if deletedIPRanges.Len() > 0 {
			allowed = false
			msg = fmt.Sprintf("existing IPRanges %v cannot be updated or deleted", sets.List(deletedIPRanges))
		}
	case admv1.Delete:
		klog.V(2).Info("Validating DELETE request for IPPool")
		if len(oldObj.Status.IPAddresses) > 0 {
			allowed = false
			msg = "IPPool in use cannot be deleted"
		}
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

func validateIPRangesAndSubnetInfo(ipPool crdv1beta1.IPPool, existingIPPools []*crdv1beta1.IPPool) (string, bool) {
	subnetInfo := &ipPool.Spec.SubnetInfo // IPPool requires SubnetInfo
	ipRanges := ipPool.Spec.IPRanges

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
	subnet := &prefix

	combinedRanges := make(map[string][2]netip.Addr)
	for _, pool := range existingIPPools {
		if pool.Name == ipPool.Name {
			continue
		}
		for _, ipRange := range pool.Spec.IPRanges {
			var key string
			var start, end netip.Addr

			if ipRange.CIDR != "" {
				key = fmt.Sprintf("range [%s] of pool %s", ipRange.CIDR, pool.Name)
				cidr, _ := validation.ParseIPRangeCIDR(ipRange.CIDR)
				start, end = utilip.GetStartAndEndOfPrefix(cidr)
			} else {
				key = fmt.Sprintf("range [%s-%s] of pool %s", ipRange.Start, ipRange.End, pool.Name)
				start, end, _ = validation.ParseIPRangeStartEnd(ipRange.Start, ipRange.End)
			}
			combinedRanges[key] = [2]netip.Addr{start, end}
		}
	}

	for _, ipRange := range ipRanges {
		var key string
		var start, end netip.Addr

		if ipRange.CIDR != "" {
			key = fmt.Sprintf("range [%s]", ipRange.CIDR)
			cidr, errMsg := validation.ParseIPRangeCIDR(ipRange.CIDR)
			if errMsg != "" {
				return errMsg, false
			}
			start, end = utilip.GetStartAndEndOfPrefix(cidr)
			if (!gatewayAddr.Is4() || !start.Is4() || !end.Is4()) && (!gatewayAddr.Is6() || !start.Is6() || !end.Is6()) {
				return fmt.Sprintf(
					"Range is invalid. IP version of range %s differs from gateway IP version", ipRange.CIDR), false
			}
		} else {
			key = fmt.Sprintf("range [%s-%s]", ipRange.Start, ipRange.End)

			var errMsg string
			start, end, errMsg = validation.ParseIPRangeStartEnd(ipRange.Start, ipRange.End)
			if errMsg != "" {
				return errMsg, false
			}

			if (!gatewayAddr.Is4() || !start.Is4() || !end.Is4()) && (!gatewayAddr.Is6() || !start.Is6() || !end.Is6()) {
				return fmt.Sprintf(
					"Range is invalid. IP version of range %s-%s differs from gateway IP version", ipRange.Start, ipRange.End), false
			}

			if msg, res := validation.ValidateIPRange(ipRange); !res {
				return msg, false
			}
		}

		if !subnet.Contains(start) || !subnet.Contains(end) {
			return fmt.Sprintf("%s must be a strict subset of the subnet %s/%d",
				key, subnetInfo.Gateway, subnetInfo.PrefixLength), false
		}

		for combinedKey, combinedRange := range combinedRanges {
			if start.Compare(combinedRange[1]) != 1 && end.Compare(combinedRange[0]) != -1 {
				return fmt.Sprintf("%s overlaps with %s", key, combinedKey), false
			}
		}

		combinedRanges[key] = [2]netip.Addr{start, end}
	}
	return "", true
}

func newAdmissionResponseForErr(err error) *admv1.AdmissionResponse {
	return &admv1.AdmissionResponse{
		Result: &metav1.Status{
			Message: err.Error(),
		},
	}
}
