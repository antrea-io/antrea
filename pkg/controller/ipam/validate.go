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
	"encoding/json"
	"fmt"
	"strings"

	admv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	crdv1alpha2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
)

func ValidateIPPool(review *admv1.AdmissionReview) *admv1.AdmissionResponse {
	var result *metav1.Status
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
		// This shouldn't happen with the webhook configuration we include in the Antrea YAML manifests.
		klog.V(2).Info("Validating CREATE request for IPPool")
		// Always allow CREATE request.
	case admv1.Update:
		klog.V(2).Info("Validating UPDATE request for IPPool")
		deletedIPRanges := getIPRangeDifference(oldObj.Spec.IPRanges, newObj.Spec.IPRanges)
		if len(deletedIPRanges) > 0 {
			allowed = false

			msg = fmt.Sprintf("existing IPRanges %s cannot be updated or deleted", humanReadableIPRanges(deletedIPRanges))
		}
	case admv1.Delete:
		klog.V(2).Info("Validating DELETE request for IPPool")
		if len(oldObj.Status.IPAddresses) > 0 {
			allowed = false
			msg = fmt.Sprintf("IPPool in use cannot be deleted")
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

func newAdmissionResponseForErr(err error) *admv1.AdmissionResponse {
	return &admv1.AdmissionResponse{
		Result: &metav1.Status{
			Message: err.Error(),
		},
	}
}
