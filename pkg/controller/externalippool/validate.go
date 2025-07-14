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

	admv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"

	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/pkg/controller/validation"
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
		if msg, allowed = validateIPRangesAndSubnetInfoForExternalIPPool(&newObj, externalIPPools); !allowed {
			break
		}
	case admv1.Update:
		klog.V(2).Info("Validating UPDATE request for ExternalIPPool")
		if msg, allowed = validateIPRangesAndSubnetInfoForExternalIPPool(&newObj, externalIPPools); !allowed {
			break
		}
		oldIPRangeSet := validation.GetIPRangeSet(oldObj.Spec.IPRanges)
		newIPRangeSet := validation.GetIPRangeSet(newObj.Spec.IPRanges)
		deletedIPRanges := oldIPRangeSet.Difference(newIPRangeSet)
		if deletedIPRanges.Len() > 0 {
			allowed = false
			// Fixed error message to be consistent with IPPool controller
			msg = fmt.Sprintf("existing IPRanges %v cannot be updated or deleted", sets.List(deletedIPRanges))
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

func newAdmissionResponseForErr(err error) *admv1.AdmissionResponse {
	return &admv1.AdmissionResponse{
		Result: &metav1.Status{
			Message: err.Error(),
		},
	}
}

func validateIPRangesAndSubnetInfoForExternalIPPool(externalIPPool *crdv1beta1.ExternalIPPool, existingExternalIPPools []*crdv1beta1.ExternalIPPool) (msg string, allowed bool) {
	ipRanges := externalIPPool.Spec.IPRanges
	subnetInfo := externalIPPool.Spec.SubnetInfo
	if msg, allowed = validation.ValidateIPRangesAndSubnetInfo(subnetInfo, ipRanges); !allowed {
		return
	}
	return validateNoOverlappingRanges(ipRanges, existingExternalIPPools, externalIPPool.Name)
}

func collectExistingRanges(pools []*crdv1beta1.ExternalIPPool, skipPool string) []validation.NormalizedIPRange {
	normalized := make([]validation.NormalizedIPRange, 0)
	for _, pool := range pools {
		if pool.Name == skipPool {
			continue
		}
		context := fmt.Sprintf("ExternalIPPool %s", pool.Name)
		for _, ipRange := range pool.Spec.IPRanges {
			normalized = append(normalized, validation.NormalizeRange(ipRange, context))
		}
	}
	return normalized
}

func validateNoOverlappingRanges(ipRanges []crdv1beta1.IPRange, existingExternalIPPools []*crdv1beta1.ExternalIPPool, externalIPPoolName string) (string, bool) {
	existingNormalized := collectExistingRanges(existingExternalIPPools, externalIPPoolName)
	currentNormalized := validation.NormalizeCurrentRanges(ipRanges)

	for _, cur := range currentNormalized {
		if cur.Error != "" {
			return cur.Error, false
		}
		for _, existing := range existingNormalized {
			if existing.Error != "" {
				// Skip invalid existing ranges (shouldn't happen in practice)
				continue
			}
			if validation.Overlaps(cur.Start, cur.End, existing.Start, existing.End) {
				return fmt.Sprintf("%s overlaps with %s", cur.Origin, existing.Origin), false
			}
		}
	}
	return "", true
}
