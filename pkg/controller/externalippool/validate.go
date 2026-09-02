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
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"

	crdv1beta1 "antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
	crdv1beta2 "antrea.io/antrea/v2/pkg/apis/crd/v1beta2"
	"antrea.io/antrea/v2/pkg/controller/crdconversion"
	"antrea.io/antrea/v2/pkg/controller/validation"
)

func (c *ExternalIPPoolController) ValidateExternalIPPool(review *admv1.AdmissionReview) *admv1.AdmissionResponse {
	var result *metav1.Status
	var msg string
	allowed := true

	klog.V(2).Info("Validating ExternalIPPool", "request", review.Request)
	if err := crdconversion.ValidateAdmissionRequest(review.Request); err != nil {
		return newAdmissionResponseForErr(err)
	}
	externalIPPools, err := c.externalIPPoolLister.List(labels.Everything())
	if err != nil {
		klog.ErrorS(err, "Error listing ExternalIPPools")
		return newAdmissionResponseForErr(err)
	}
	version := review.Request.Resource.Version
	switch version {
	case crdv1beta1.SchemeGroupVersion.Version:
		var newObj, oldObj crdv1beta1.ExternalIPPool
		if err := decodeExternalIPPoolAdmissionObjects(review, &newObj, &oldObj); err != nil {
			klog.ErrorS(err, "Error de-serializing v1beta1 ExternalIPPool")
			return newAdmissionResponseForErr(err)
		}
		isProjection, err := isV1beta2ExternalIPPoolProjection(review.Request.Object.Raw)
		if err != nil {
			return newAdmissionResponseForErr(err)
		}
		if isProjection {
			var newV2, oldV2 crdv1beta2.ExternalIPPool
			if err := convertV1beta1ExternalIPPoolForValidation(review.Request.Object.Raw, &newV2); err != nil {
				return newAdmissionResponseForErr(err)
			}
			if review.Request.OldObject.Raw != nil {
				if err := convertV1beta1ExternalIPPoolForValidation(review.Request.OldObject.Raw, &oldV2); err != nil {
					return newAdmissionResponseForErr(err)
				}
			}
			allowed, msg = validateV1beta2ExternalIPPoolRequest(review.Request.Operation, &oldV2, &newV2, externalIPPools)
		} else {
			allowed, msg = validateV1beta1ExternalIPPoolRequest(review.Request.Operation, &oldObj, &newObj, externalIPPools)
		}
	case crdv1beta2.SchemeGroupVersion.Version, "":
		// An empty version is accepted for direct unit tests and is treated as the current API version.
		var newObj, oldObj crdv1beta2.ExternalIPPool
		if err := decodeExternalIPPoolAdmissionObjects(review, &newObj, &oldObj); err != nil {
			klog.ErrorS(err, "Error de-serializing v1beta2 ExternalIPPool")
			return newAdmissionResponseForErr(err)
		}
		allowed, msg = validateV1beta2ExternalIPPoolRequest(review.Request.Operation, &oldObj, &newObj, externalIPPools)
	default:
		return newAdmissionResponseForErr(fmt.Errorf("unsupported ExternalIPPool API version %q", version))
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

func v1beta1ExternalIPPoolUnstructured(raw []byte) (*unstructured.Unstructured, error) {
	var object unstructured.Unstructured
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, err
	}
	if object.GetAPIVersion() == "" {
		object.SetAPIVersion(crdv1beta1.SchemeGroupVersion.String())
	}
	return &object, nil
}

func isV1beta2ExternalIPPoolProjection(raw []byte) (bool, error) {
	if raw == nil {
		return false, nil
	}
	object, err := v1beta1ExternalIPPoolUnstructured(raw)
	if err != nil {
		return false, err
	}
	return crdconversion.IsV1beta2ExternalIPPoolProjection(object), nil
}

func convertV1beta1ExternalIPPoolForValidation(raw []byte, result *crdv1beta2.ExternalIPPool) error {
	object, err := v1beta1ExternalIPPoolUnstructured(raw)
	if err != nil {
		return err
	}
	converted, status := crdconversion.ConvertExternalIPPool(object, crdv1beta2.SchemeGroupVersion.String())
	if status.Status != metav1.StatusSuccess {
		return fmt.Errorf("failed to convert ExternalIPPool for validation: %s", status.Message)
	}
	convertedRaw, err := json.Marshal(converted)
	if err != nil {
		return err
	}
	return json.Unmarshal(convertedRaw, result)
}

func decodeExternalIPPoolAdmissionObjects(review *admv1.AdmissionReview, newObj, oldObj interface{}) error {
	if review.Request.Object.Raw != nil {
		if err := json.Unmarshal(review.Request.Object.Raw, newObj); err != nil {
			return err
		}
	}
	if review.Request.OldObject.Raw != nil {
		if err := json.Unmarshal(review.Request.OldObject.Raw, oldObj); err != nil {
			return err
		}
	}
	return nil
}

func validateV1beta1ExternalIPPoolRequest(operation admv1.Operation, oldPool, newPool *crdv1beta1.ExternalIPPool, existingPools []*crdv1beta2.ExternalIPPool) (bool, string) {
	if operation == admv1.Delete {
		return true, ""
	}
	if err := validateV1beta1IPRangesAndSubnetInfo(newPool, existingPools); err != nil {
		return false, err.Error()
	}
	if operation == admv1.Update {
		oldIPRangeSet := validation.GetIPRangeSet(oldPool.Spec.IPRanges)
		newIPRangeSet := validation.GetIPRangeSet(newPool.Spec.IPRanges)
		if deletedIPRanges := oldIPRangeSet.Difference(newIPRangeSet); deletedIPRanges.Len() > 0 {
			return false, fmt.Sprintf("existing IPRanges %v cannot be updated or deleted", sets.List(deletedIPRanges))
		}
	}
	return true, ""
}

func validateV1beta2ExternalIPPoolRequest(operation admv1.Operation, oldPool, newPool *crdv1beta2.ExternalIPPool, existingPools []*crdv1beta2.ExternalIPPool) (bool, string) {
	if operation == admv1.Delete {
		return true, ""
	}
	if err := validateIPRangesAndSubnetInfoForExternalIPPool(newPool, existingPools); err != nil {
		return false, err.Error()
	}
	if operation != admv1.Update {
		return true, ""
	}
	oldIPFamilies, err := validation.IPFamiliesForRanges(oldPool.Spec.IPRanges)
	if err != nil {
		return false, err.Error()
	}
	newIPFamilies, err := validation.IPFamiliesForRanges(newPool.Spec.IPRanges)
	if err != nil {
		return false, err.Error()
	}
	// Allow an empty pool to establish its IP families when its first ranges are added.
	if oldIPFamilies.Len() > 0 && !oldIPFamilies.Equal(newIPFamilies) {
		return false, fmt.Sprintf("IP families are immutable (old: %v, new: %v)", sets.List(oldIPFamilies), sets.List(newIPFamilies))
	}
	oldIPRangeSet := validation.GetExternalIPPoolIPRangeSet(oldPool.Spec.IPRanges)
	newIPRangeSet := validation.GetExternalIPPoolIPRangeSet(newPool.Spec.IPRanges)
	if deletedIPRanges := oldIPRangeSet.Difference(newIPRangeSet); deletedIPRanges.Len() > 0 {
		return false, fmt.Sprintf("existing IPRanges %v cannot be updated or deleted", sets.List(deletedIPRanges))
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

func validateIPRangesAndSubnetInfoForExternalIPPool(externalIPPool *crdv1beta2.ExternalIPPool, existingExternalIPPools []*crdv1beta2.ExternalIPPool) error {
	ipRanges := externalIPPool.Spec.IPRanges
	subnetInfo := externalIPPool.Spec.SubnetInfo
	currentNormalizedIPRanges, err := validation.ValidateExternalIPPoolIPRangesAndSubnetInfo(subnetInfo, ipRanges)
	if err != nil {
		return err
	}
	return validateNoOverlappingRanges(currentNormalizedIPRanges, existingExternalIPPools, externalIPPool.Name)
}

func validateV1beta1IPRangesAndSubnetInfo(externalIPPool *crdv1beta1.ExternalIPPool, existingExternalIPPools []*crdv1beta2.ExternalIPPool) error {
	currentNormalizedIPRanges, err := validation.ValidateIPRangesAndSubnetInfo(externalIPPool.Spec.SubnetInfo, externalIPPool.Spec.IPRanges)
	if err != nil {
		return err
	}
	return validateNoOverlappingRanges(currentNormalizedIPRanges, existingExternalIPPools, externalIPPool.Name)
}

func collectExistingRanges(pools []*crdv1beta2.ExternalIPPool, skipPool string) ([]validation.NormalizedIPRange, error) {
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

func validateNoOverlappingRanges(currentNormalizedIPRanges []validation.NormalizedIPRange, existingExternalIPPools []*crdv1beta2.ExternalIPPool, externalIPPoolName string) error {
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
