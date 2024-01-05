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
	"net"

	admv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"

	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/pkg/util/ip"
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

	switch review.Request.Operation {
	case admv1.Create:
		klog.V(2).Info("Validating CREATE request for ExternalIPPool")
		if msg, allowed = validateIPRangesAndSubnetInfo(newObj.Spec.IPRanges, newObj.Spec.SubnetInfo); !allowed {
			break
		}
	case admv1.Update:
		klog.V(2).Info("Validating UPDATE request for ExternalIPPool")
		if msg, allowed = validateIPRangesAndSubnetInfo(newObj.Spec.IPRanges, newObj.Spec.SubnetInfo); !allowed {
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

func validateIPRangesAndSubnetInfo(ipRanges []crdv1beta1.IPRange, subnetInfo *crdv1beta1.SubnetInfo) (string, bool) {
	if subnetInfo == nil {
		return "", true
	}
	gatewayIP := net.ParseIP(subnetInfo.Gateway)
	var mask net.IPMask
	if gatewayIP.To4() != nil {
		if subnetInfo.PrefixLength <= 0 || subnetInfo.PrefixLength >= 32 {
			return fmt.Sprintf("invalid prefixLength %d", subnetInfo.PrefixLength), false
		}
		mask = net.CIDRMask(int(subnetInfo.PrefixLength), 32)
	} else {
		if subnetInfo.PrefixLength <= 0 || subnetInfo.PrefixLength >= 128 {
			return fmt.Sprintf("invalid prefixLength %d", subnetInfo.PrefixLength), false
		}
		mask = net.CIDRMask(int(subnetInfo.PrefixLength), 128)
	}
	subnet := &net.IPNet{
		IP:   gatewayIP.Mask(mask),
		Mask: mask,
	}
	for _, ipRange := range ipRanges {
		if ipRange.CIDR != "" {
			_, cidr, err := net.ParseCIDR(ipRange.CIDR)
			if err != nil {
				return err.Error(), false
			}
			if !ip.IPNetContains(subnet, cidr) {
				return fmt.Sprintf("cidr %s must be a strict subset of the subnet", ipRange.CIDR), false
			}
		} else {
			start := net.ParseIP(ipRange.Start)
			end := net.ParseIP(ipRange.End)
			if !subnet.Contains(start) || !subnet.Contains(end) {
				return fmt.Sprintf("IP range %s-%s must be a strict subset of the subnet", ipRange.Start, ipRange.End), false
			}
		}
	}
	return "", true
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
