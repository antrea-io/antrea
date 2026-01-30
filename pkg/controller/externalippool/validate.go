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

	crdv1beta1 "antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/v2/pkg/controller/validation"
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
		if err := validateIPRangesAndSubnetInfoForExternalIPPool(&newObj, externalIPPools); err != nil {
			msg = err.Error()
			allowed = false
		}
	case admv1.Update:
		klog.V(2).Info("Validating UPDATE request for ExternalIPPool")
		if err := validateIPRangesAndSubnetInfoForExternalIPPool(&newObj, externalIPPools); err != nil {
			msg = err.Error()
			allowed = false
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

func validateIPRangesAndSubnetInfoForExternalIPPool(externalIPPool *crdv1beta1.ExternalIPPool, existingExternalIPPools []*crdv1beta1.ExternalIPPool) error {
	ipRanges := externalIPPool.Spec.IPRanges
	subnetInfo := externalIPPool.Spec.SubnetInfo
	currentNormalizedIPRanges, err := validation.ValidateIPRangesAndSubnetInfo(subnetInfo, ipRanges)
	if err != nil {
		return err
	}
	return validateNoOverlappingRanges(currentNormalizedIPRanges, existingExternalIPPools, externalIPPool.Name)
}

func collectExistingRanges(pools []*crdv1beta1.ExternalIPPool, skipPool string) ([]validation.NormalizedIPRange, error) {
	normalized := make([]validation.NormalizedIPRange, 0)
	for _, pool := range pools {
		if pool.Name == skipPool {
			continue
		}
		normalizedRanges, err := validation.NormalizeRanges(pool.Spec.IPRanges, fmt.Sprintf("ExternalIPPool %s", pool.Name))
		if err != nil {
			return nil, err
		}
		normalized = append(normalized, normalizedRanges...)
	}
	return normalized, nil
}

func validateNoOverlappingRanges(currentNormalizedIPRanges []validation.NormalizedIPRange, existingExternalIPPools []*crdv1beta1.ExternalIPPool, externalIPPoolName string) error {
	existingNormalized, err := collectExistingRanges(existingExternalIPPools, externalIPPoolName)
	if err != nil {
		return err
	}

	for _, cur := range currentNormalizedIPRanges {
		for _, existing := range existingNormalized {
			if validation.RangesOverlap(cur.Start, cur.End, existing.Start, existing.End) {
				return fmt.Errorf("%s overlaps with %s", cur.Origin, existing.Origin)
			}
		}
	}
	return nil
}
