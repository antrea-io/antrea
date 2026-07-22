// Copyright 2026 Antrea Authors
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

package antreanodeconfig

import (
	"encoding/json"
	"fmt"

	admv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	crdv1alpha1 "antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/v2/pkg/util/vlan"
)

// Validate validates AntreaNodeConfig admission requests.
func Validate(review *admv1.AdmissionReview) *admv1.AdmissionResponse {
	if review == nil || review.Request == nil {
		return newAdmissionResponseForErr(fmt.Errorf("invalid AdmissionReview: nil request"))
	}

	var result *metav1.Status
	var msg string
	allowed := true

	klog.V(2).InfoS("Validating AntreaNodeConfig", "request", review.Request)
	var newObj crdv1alpha1.AntreaNodeConfig
	if review.Request.Object.Raw != nil {
		if err := json.Unmarshal(review.Request.Object.Raw, &newObj); err != nil {
			klog.ErrorS(err, "Error de-serializing current AntreaNodeConfig")
			return newAdmissionResponseForErr(err)
		}
	}
	if review.Request.Operation != admv1.Delete && review.Request.Object.Raw == nil {
		return newAdmissionResponseForErr(fmt.Errorf("missing object in AdmissionReview"))
	}

	switch review.Request.Operation {
	case admv1.Create:
		klog.V(2).InfoS("Validating CREATE request for AntreaNodeConfig", "name", newObj.Name)
		if err := validateAntreaNodeConfig(&newObj); err != nil {
			msg = err.Error()
			allowed = false
		}
	case admv1.Update:
		klog.V(2).InfoS("Validating UPDATE request for AntreaNodeConfig", "name", newObj.Name)
		if err := validateAntreaNodeConfig(&newObj); err != nil {
			msg = err.Error()
			allowed = false
		}
	case admv1.Delete:
		// This should not happen with the webhook configuration included in Antrea manifests.
	}

	if msg != "" {
		result = &metav1.Status{Message: msg}
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

func validateVLANSpecs(specs []string) error {
	for _, spec := range specs {
		if _, err := vlan.ParseSpec(spec); err != nil {
			return err
		}
	}
	return nil
}

func validateAntreaNodeConfig(anc *crdv1alpha1.AntreaNodeConfig) error {
	if anc.Spec.SecondaryNetwork == nil {
		return nil
	}
	for bridgeIdx, bridge := range anc.Spec.SecondaryNetwork.OVSBridges {
		for ifaceIdx, iface := range bridge.PhysicalInterfaces {
			if len(iface.AllowedVLANs) == 0 {
				continue
			}
			if err := validateVLANSpecs(iface.AllowedVLANs); err != nil {
				return fmt.Errorf("spec.secondaryNetwork.ovsBridges[%d].physicalInterfaces[%d].allowedVLANs is invalid: %v",
					bridgeIdx, ifaceIdx, err)
			}
		}
	}
	return nil
}
