// Copyright 2023 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package packetsampling

import (
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"encoding/json"
	"fmt"

	admv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
)

func (c *Controller) Validate(review *admv1.AdmissionReview) *admv1.AdmissionResponse {
	newResponse := func(allowed bool, deniedReason string) *admv1.AdmissionResponse {
		resp := &admv1.AdmissionResponse{
			UID:     review.Request.UID,
			Allowed: allowed,
		}
		if !allowed {
			resp.Result = &metav1.Status{
				Message: deniedReason,
			}
		}
		return resp
	}

	klog.V(2).InfoS("Validating PacketSampling", "request", review.Request)

	var newObj crdv1alpha1.PacketSampling
	if review.Request.Object.Raw != nil {
		if err := json.Unmarshal(review.Request.Object.Raw, &newObj); err != nil {
			klog.ErrorS(err, "Error de-serializing current Traceflow")
			return newResponse(false, err.Error())
		}
	}

	switch review.Request.Operation {
	case admv1.Create:
		klog.V(2).InfoS("Validating CREATE request for PacketSampling", "name", newObj.Name)
		allowed, deniedReason := c.validate(&newObj)
		return newResponse(allowed, deniedReason)
	case admv1.Update:
		klog.V(2).InfoS("Validating UPDATE request for PacketSampling", "name", newObj.Name)
		allowed, deniedReason := c.validate(&newObj)
		return newResponse(allowed, deniedReason)
	default:
		err := fmt.Errorf("invalid request operation %s for Traceflow", review.Request.Operation)
		klog.ErrorS(err, "Failed to validate PacketSampling", "name", newObj.Name)
		return newResponse(false, err.Error())
	}
}

func (c *Controller) validate(tf *crdv1alpha1.PacketSampling) (allowed bool, deniedReason string) {
	if tf.Spec.Source.Pod == "" && tf.Spec.Destination.Pod == "" {
		return false, fmt.Sprintf("PacketSampling %s has neither source nor destination Pod specified", tf.Name)
	}
	return true, ""
}
