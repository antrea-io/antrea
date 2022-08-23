// Copyright 2022 Antrea Authors
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

package supportbundlecollection

import (
	"encoding/json"
	"fmt"
	"reflect"

	admv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

func (c *Controller) Validate(review *admv1.AdmissionReview) *admv1.AdmissionResponse {
	klog.V(2).Info("Validating SupportBundleCollection", "request", review.Request)
	var newObj, oldObj crdv1alpha1.SupportBundleCollection
	if review.Request.Object.Raw != nil {
		if err := json.Unmarshal(review.Request.Object.Raw, &newObj); err != nil {
			klog.ErrorS(err, "Error de-serializing current SupportBundleCollection")
			return newAdmissionResponseForErr(err)
		}
	}
	if review.Request.OldObject.Raw != nil {
		if err := json.Unmarshal(review.Request.OldObject.Raw, &oldObj); err != nil {
			klog.ErrorS(err, "Error de-serializing old IPPool")
			return newAdmissionResponseForErr(err)
		}
	}

	validateProcessingCollection := func() *admv1.AdmissionResponse {
		var msg string
		allowed := true
		_, exists, _ := c.supportBundleCollectionStore.Get(oldObj.Name)
		if exists {
			allowed = reflect.DeepEqual(oldObj.Spec, newObj.Spec)
			if !allowed {
				msg = fmt.Sprintf("SupportBundleCollection %s is started, cannot be updated", oldObj.Name)
			}
		}
		return validationResult(allowed, msg)
	}

	if review.Request.Operation == admv1.Update {
		klog.V(2).Info("Validating UPDATE request for SupportBundleCollection")
		if isCollectionCompleted(&oldObj) {
			return validationResult(false, fmt.Sprintf("SupportBundleCollection %s is completed, cannot be updated", oldObj.Name))
		}
		return validateProcessingCollection()
	}

	return &admv1.AdmissionResponse{Allowed: true}
}

func newAdmissionResponseForErr(err error) *admv1.AdmissionResponse {
	return &admv1.AdmissionResponse{
		Result: &metav1.Status{
			Message: err.Error(),
		},
	}
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
