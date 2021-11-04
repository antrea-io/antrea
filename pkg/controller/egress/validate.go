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

package egress

import (
	"encoding/json"
	"fmt"
	"net"

	admv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"

	crdv1alpha2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	bandwidthutil "antrea.io/antrea/pkg/util/bandwidth"
)

func (c *EgressController) ValidateExternalIPPool(review *admv1.AdmissionReview) *admv1.AdmissionResponse {
	var result *metav1.Status
	var msg string
	allowed := true

	klog.V(2).Info("Validating ExternalIPPool", "request", review.Request)
	var newObj, oldObj crdv1alpha2.ExternalIPPool
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
		// This shouldn't happen with the webhook configuration we include in the Antrea YAML manifests.
		klog.V(2).Info("Validating CREATE request for ExternalIPPool")
		// Always allow CREATE request.
	case admv1.Update:
		klog.V(2).Info("Validating UPDATE request for ExternalIPPool")

		oldIPRangeSet := getIPRangeSet(oldObj.Spec.IPRanges)
		newIPRangeSet := getIPRangeSet(newObj.Spec.IPRanges)
		deletedIPRanges := oldIPRangeSet.Difference(newIPRangeSet)
		if deletedIPRanges.Len() > 0 {
			allowed = false
			msg = fmt.Sprintf("existing IPRanges %v cannot be deleted", deletedIPRanges.List())
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

func (c *EgressController) ValidateEgress(review *admv1.AdmissionReview) *admv1.AdmissionResponse {
	var result *metav1.Status
	var msg string
	allowed := true

	klog.V(2).Info("Validating Egress", "request", review.Request)
	var newObj, oldObj crdv1alpha2.Egress
	if review.Request.Object.Raw != nil {
		if err := json.Unmarshal(review.Request.Object.Raw, &newObj); err != nil {
			klog.ErrorS(err, "Error de-serializing current Egress")
			return newAdmissionResponseForErr(err)
		}
	}
	if review.Request.OldObject.Raw != nil {
		if err := json.Unmarshal(review.Request.OldObject.Raw, &oldObj); err != nil {
			klog.ErrorS(err, "Error de-serializing old Egress")
			return newAdmissionResponseForErr(err)
		}
	}

	shouldAllow := func(oldEgress, newEgress *crdv1alpha2.Egress) (bool, string) {
		// Allow it if Egress Bandwidth is valid.
		if _, err := bandwidthutil.ParseBandwidth(newEgress.Spec.Bandwidth, bandwidthutil.Kilo); err != nil {
			return false, fmt.Sprintf("Bandwidth %s is not valid, %v", newEgress.Spec.Bandwidth, err)
		}
		// Allow it if EgressIP and ExternalIPPool don't change.
		if newEgress.Spec.EgressIP == oldEgress.Spec.EgressIP && newEgress.Spec.ExternalIPPool == oldEgress.Spec.ExternalIPPool {
			return true, ""
		}
		// Only validate whether the specified Egress IP is in the Pool when they are both set.
		if newEgress.Spec.EgressIP == "" || newEgress.Spec.ExternalIPPool == "" {
			return true, ""
		}
		ip := net.ParseIP(newEgress.Spec.EgressIP)
		if ip == nil {
			return false, fmt.Sprintf("IP %s is not valid", newEgress.Spec.EgressIP)
		}
		ipAllocator, exists := c.getIPAllocator(newEgress.Spec.ExternalIPPool)
		// The ExternalIPPool doesn't exist, cannot determine whether the IP is in the pool.
		if !exists {
			return false, fmt.Sprintf("ExternalIPPool %s does not exist", newEgress.Spec.ExternalIPPool)
		}
		if !ipAllocator.Has(ip) {
			return false, fmt.Sprintf("IP %s is not within the IP range", newEgress.Spec.EgressIP)
		}
		return true, ""
	}

	switch review.Request.Operation {
	case admv1.Create:
		klog.V(2).Info("Validating CREATE request for Egress")
		allowed, msg = shouldAllow(&oldObj, &newObj)
	case admv1.Update:
		klog.V(2).Info("Validating UPDATE request for Egress")
		allowed, msg = shouldAllow(&oldObj, &newObj)
	case admv1.Delete:
		// This shouldn't happen with the webhook configuration we include in the Antrea YAML manifests.
		klog.V(2).Info("Validating DELETE request for Egress")
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

func getIPRangeSet(ipRanges []crdv1alpha2.IPRange) sets.String {
	set := sets.NewString()
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
