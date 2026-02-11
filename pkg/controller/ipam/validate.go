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

	admv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"

	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/pkg/controller/validation"
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

	switch review.Request.Operation {
	case admv1.Create:
		klog.V(2).Info("Validating CREATE request for IPPool")
		if err := validation.ValidateIPRangeIPFamily(newObj.Spec.IPRanges, c.ipv4Enabled, c.ipv6Enabled); err != nil {
			msg = err.Error()
			allowed = false
			break
		}
		if _, err := validation.ValidateIPRangesAndSubnetInfo(&newObj.Spec.SubnetInfo, newObj.Spec.IPRanges); err != nil {
			msg = err.Error()
			allowed = false
		}
	case admv1.Update:
		klog.V(2).Info("Validating UPDATE request for IPPool")
		if err := validation.ValidateIPRangeIPFamily(newObj.Spec.IPRanges, c.ipv4Enabled, c.ipv6Enabled); err != nil {
			msg = err.Error()
			allowed = false
			break
		}
		if _, err := validation.ValidateIPRangesAndSubnetInfo(&newObj.Spec.SubnetInfo, newObj.Spec.IPRanges); err != nil {
			msg = err.Error()
			allowed = false
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

func newAdmissionResponseForErr(err error) *admv1.AdmissionResponse {
	return &admv1.AdmissionResponse{
		Result: &metav1.Status{
			Message: err.Error(),
		},
	}
}
