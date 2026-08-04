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
	"net/netip"
	"slices"

	admv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"

	crdv1beta1 "antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
	utilip "antrea.io/antrea/v2/pkg/util/ip"
)

type specifiedEgressIP struct {
	value string
	ip    net.IP
}

func parseSpecifiedEgressIPs(spec *crdv1beta1.EgressSpec) ([]specifiedEgressIP, error) {
	if spec.EgressIP != "" && len(spec.EgressIPs) > 0 {
		return nil, fmt.Errorf("spec.egressIP and spec.egressIPs are mutually exclusive")
	}
	if len(spec.EgressIPs) > 0 && len(spec.EgressIPs) != 2 {
		return nil, fmt.Errorf("spec.egressIPs must contain exactly two addresses, one for each IP family")
	}

	values := spec.EgressIPs
	if spec.EgressIP != "" {
		values = []string{spec.EgressIP}
	}
	parsed := make([]specifiedEgressIP, 0, len(values))
	families := sets.New[corev1.IPFamily]()
	for _, value := range values {
		address, err := netip.ParseAddr(value)
		if err != nil || address.Zone() != "" {
			return nil, fmt.Errorf("IP %s is not valid", value)
		}
		family := utilip.IPFamilyForAddress(address)
		if families.Has(family) {
			return nil, fmt.Errorf("spec.egressIPs contains multiple addresses for IP family %s", family)
		}
		families.Insert(family)
		parsed = append(parsed, specifiedEgressIP{value: value, ip: net.IP(address.AsSlice())})
	}
	return parsed, nil
}

func validateIPFamilyPolicy(policy *corev1.IPFamilyPolicy) error {
	if policy == nil {
		return nil
	}
	switch *policy {
	case corev1.IPFamilyPolicySingleStack,
		corev1.IPFamilyPolicyPreferDualStack,
		corev1.IPFamilyPolicyRequireDualStack:
		return nil
	default:
		return fmt.Errorf("spec.ipFamilyPolicy must be one of SingleStack, PreferDualStack, or RequireDualStack")
	}
}

func egressIPConfigurationEqual(oldSpec, newSpec *crdv1beta1.EgressSpec) bool {
	return oldSpec.EgressIP == newSpec.EgressIP &&
		slices.Equal(oldSpec.EgressIPs, newSpec.EgressIPs) &&
		oldSpec.ExternalIPPool == newSpec.ExternalIPPool &&
		ptr.Equal(oldSpec.IPFamilyPolicy, newSpec.IPFamilyPolicy)
}

func (c *EgressController) validateEgressConfiguration(oldEgress, newEgress *crdv1beta1.Egress) error {
	specifiedIPs, err := parseSpecifiedEgressIPs(&newEgress.Spec)
	if err != nil {
		return err
	}
	if err := validateIPFamilyPolicy(newEgress.Spec.IPFamilyPolicy); err != nil {
		return err
	}
	if newEgress.Spec.IPFamilyPolicy != nil {
		switch {
		case newEgress.Spec.EgressIP != "" && *newEgress.Spec.IPFamilyPolicy == corev1.IPFamilyPolicyRequireDualStack:
			return fmt.Errorf("spec.egressIP cannot be used with ipFamilyPolicy RequireDualStack")
		case len(newEgress.Spec.EgressIPs) > 0 && *newEgress.Spec.IPFamilyPolicy == corev1.IPFamilyPolicySingleStack:
			return fmt.Errorf("spec.egressIPs cannot be used with ipFamilyPolicy SingleStack")
		}
	}

	if newEgress.Spec.ExternalIPPool == "" {
		if len(specifiedIPs) == 0 {
			return fmt.Errorf("an Egress IP or ExternalIPPool must be specified")
		}
		return nil
	}

	// Allow unrelated updates when the referenced pool has already been deleted.
	if egressIPConfigurationEqual(&oldEgress.Spec, &newEgress.Spec) {
		return nil
	}
	poolName := newEgress.Spec.ExternalIPPool
	poolFamilies, err := c.externalIPAllocator.IPPoolIPFamilies(poolName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("ExternalIPPool %s does not exist", poolName)
		}
		return fmt.Errorf("failed to determine IP families for ExternalIPPool %s: %w", poolName, err)
	}
	if poolFamilies.Len() == 0 {
		return fmt.Errorf("ExternalIPPool %s does not contain any IP ranges", poolName)
	}
	if newEgress.Spec.IPFamilyPolicy != nil &&
		*newEgress.Spec.IPFamilyPolicy == corev1.IPFamilyPolicyRequireDualStack &&
		poolFamilies.Len() < 2 {
		return fmt.Errorf("ExternalIPPool %s does not support required dual-stack allocation", poolName)
	}
	for _, specifiedIP := range specifiedIPs {
		if !c.externalIPAllocator.IPPoolHasIP(poolName, specifiedIP.ip) {
			return fmt.Errorf("IP %s is not within the IP range", specifiedIP.value)
		}
	}
	return nil
}

func (c *EgressController) ValidateEgress(review *admv1.AdmissionReview) *admv1.AdmissionResponse {
	var result *metav1.Status
	var msg string
	allowed := true

	klog.V(2).Info("Validating Egress", "request", review.Request)
	var newObj, oldObj crdv1beta1.Egress
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

	shouldAllow := func(oldEgress, newEgress *crdv1beta1.Egress) (bool, string) {
		// Validate Egress trafficShaping
		if newEgress.Spec.Bandwidth != nil {
			_, err := resource.ParseQuantity(newEgress.Spec.Bandwidth.Rate)
			if err != nil {
				return false, fmt.Sprintf("Rate %s in Egress %s is invalid: %v", newEgress.Spec.Bandwidth.Rate, newEgress.Name, err)
			}
			_, err = resource.ParseQuantity(newEgress.Spec.Bandwidth.Burst)
			if err != nil {
				return false, fmt.Sprintf("Burst %s in Egress %s is invalid: %v", newEgress.Spec.Bandwidth.Burst, newEgress.Name, err)
			}
		}
		if err := c.validateEgressConfiguration(oldEgress, newEgress); err != nil {
			return false, err.Error()
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

func newAdmissionResponseForErr(err error) *admv1.AdmissionResponse {
	return &admv1.AdmissionResponse{
		Result: &metav1.Status{
			Message: err.Error(),
		},
	}
}
