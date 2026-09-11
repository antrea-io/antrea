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
	crdv1beta2 "antrea.io/antrea/v2/pkg/apis/crd/v1beta2"
	"antrea.io/antrea/v2/pkg/controller/crdconversion"
	utilip "antrea.io/antrea/v2/pkg/util/ip"
)

const dualStackRuntimeUnsupportedMessage = "dual-stack Egress runtime is not supported yet"

type specifiedEgressIP struct {
	value string
	ip    net.IP
}

func parseSpecifiedEgressIPs(spec *crdv1beta2.EgressSpec) ([]specifiedEgressIP, error) {
	if len(spec.EgressIPs) > 2 {
		return nil, fmt.Errorf("spec.egressIPs must contain at most two addresses, one for each IP family")
	}

	values := spec.EgressIPs
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

func egressIPConfigurationEqual(oldSpec, newSpec *crdv1beta2.EgressSpec) bool {
	return slices.Equal(oldSpec.EgressIPs, newSpec.EgressIPs) &&
		oldSpec.ExternalIPPool == newSpec.ExternalIPPool &&
		ptr.Equal(oldSpec.IPFamilyPolicy, newSpec.IPFamilyPolicy)
}

func (c *EgressController) validateEgressConfiguration(oldEgress, newEgress *crdv1beta2.Egress) error {
	specifiedIPs, err := parseSpecifiedEgressIPs(&newEgress.Spec)
	if err != nil {
		return err
	}
	if err := validateIPFamilyPolicy(newEgress.Spec.IPFamilyPolicy); err != nil {
		return err
	}
	if newEgress.Spec.IPFamilyPolicy != nil {
		switch {
		case len(newEgress.Spec.EgressIPs) == 1 && *newEgress.Spec.IPFamilyPolicy == corev1.IPFamilyPolicyRequireDualStack:
			return fmt.Errorf("one spec.egressIPs entry cannot be used with ipFamilyPolicy RequireDualStack")
		case len(newEgress.Spec.EgressIPs) == 2 && *newEgress.Spec.IPFamilyPolicy == corev1.IPFamilyPolicySingleStack:
			return fmt.Errorf("two spec.egressIPs entries cannot be used with ipFamilyPolicy SingleStack")
		}
	}
	if len(newEgress.Spec.EgressIPs) == 2 ||
		(newEgress.Spec.IPFamilyPolicy != nil && *newEgress.Spec.IPFamilyPolicy == corev1.IPFamilyPolicyRequireDualStack) {
		return fmt.Errorf("%s", dualStackRuntimeUnsupportedMessage)
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
	clearingIP := len(oldEgress.Spec.EgressIPs) == 1 && len(specifiedIPs) == 0 &&
		oldEgress.Spec.ExternalIPPool == poolName && ptr.Equal(oldEgress.Spec.IPFamilyPolicy, newEgress.Spec.IPFamilyPolicy)
	poolFamilies, err := c.externalIPAllocator.IPPoolIPFamilies(poolName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// The Controller must be able to clear an allocation after its Pool has been deleted.
			if clearingIP {
				return nil
			}
			return fmt.Errorf("ExternalIPPool %s does not exist", poolName)
		}
		return fmt.Errorf("failed to determine IP families for ExternalIPPool %s: %w", poolName, err)
	}
	// A Pool may have been recreated with different ranges. Permit clearing the obsolete IP even when no new
	// allocation is currently possible, but do not exempt changes of Pool or policy, or requests to clear a valid IP.
	if clearingIP && !c.externalIPAllocator.IPPoolHasIP(poolName, net.ParseIP(oldEgress.Spec.EgressIPs[0])) {
		return nil
	}
	if poolFamilies.Len() == 0 {
		return fmt.Errorf("ExternalIPPool %s does not contain any IP ranges", poolName)
	}
	policy := corev1.IPFamilyPolicyPreferDualStack
	if newEgress.Spec.IPFamilyPolicy != nil {
		policy = *newEgress.Spec.IPFamilyPolicy
	}
	if len(specifiedIPs) == 0 && policy == corev1.IPFamilyPolicyPreferDualStack && poolFamilies.Len() > 1 {
		return fmt.Errorf("%s", dualStackRuntimeUnsupportedMessage)
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
	if err := crdconversion.ValidateAdmissionRequest(review.Request); err != nil {
		return newAdmissionResponseForErr(err)
	}
	version := review.Request.Resource.Version
	switch version {
	case crdv1beta1.SchemeGroupVersion.Version:
		var newObj, oldObj crdv1beta1.Egress
		if err := decodeAdmissionObjects(review, &newObj, &oldObj); err != nil {
			klog.ErrorS(err, "Error de-serializing v1beta1 Egress")
			return newAdmissionResponseForErr(err)
		}
		allowed, msg = c.validateV1beta1EgressRequest(review.Request.Operation, &oldObj, &newObj)
	case crdv1beta2.SchemeGroupVersion.Version, "":
		// An empty version is accepted for direct unit tests and is treated as the current API version.
		var newObj, oldObj crdv1beta2.Egress
		if err := decodeAdmissionObjects(review, &newObj, &oldObj); err != nil {
			klog.ErrorS(err, "Error de-serializing v1beta2 Egress")
			return newAdmissionResponseForErr(err)
		}
		allowed, msg = c.validateV1beta2EgressRequest(review.Request.Operation, &oldObj, &newObj)
	default:
		return newAdmissionResponseForErr(fmt.Errorf("unsupported Egress API version %q", version))
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

func decodeAdmissionObjects(review *admv1.AdmissionReview, newObj, oldObj interface{}) error {
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

func validateBandwidth(name, rate, burst string) (bool, string) {
	if _, err := resource.ParseQuantity(rate); err != nil {
		return false, fmt.Sprintf("Rate %s in Egress %s is invalid: %v", rate, name, err)
	}
	if _, err := resource.ParseQuantity(burst); err != nil {
		return false, fmt.Sprintf("Burst %s in Egress %s is invalid: %v", burst, name, err)
	}
	return true, ""
}

func (c *EgressController) validateV1beta1EgressRequest(operation admv1.Operation, oldEgress, newEgress *crdv1beta1.Egress) (bool, string) {
	if operation == admv1.Delete {
		return true, ""
	}
	if len(newEgress.Spec.EgressIPs) > 0 {
		return false, "spec.egressIPs is not supported yet"
	}
	if len(newEgress.Spec.ExternalIPPools) > 0 {
		return false, "spec.externalIPPools is not supported yet"
	}
	if newEgress.Spec.Bandwidth != nil {
		if allowed, msg := validateBandwidth(newEgress.Name, newEgress.Spec.Bandwidth.Rate, newEgress.Spec.Bandwidth.Burst); !allowed {
			return allowed, msg
		}
	}
	// Preserve the historical v1beta1 behavior: unrelated updates are allowed, and a Pool is checked only when both
	// the singular Egress IP and Pool fields are set and changed.
	if newEgress.Spec.EgressIP == oldEgress.Spec.EgressIP && newEgress.Spec.ExternalIPPool == oldEgress.Spec.ExternalIPPool {
		return true, ""
	}
	if newEgress.Spec.EgressIP == "" || newEgress.Spec.ExternalIPPool == "" {
		return true, ""
	}
	ip := net.ParseIP(newEgress.Spec.EgressIP)
	if ip == nil {
		return false, fmt.Sprintf("IP %s is not valid", newEgress.Spec.EgressIP)
	}
	if !c.externalIPAllocator.IPPoolExists(newEgress.Spec.ExternalIPPool) {
		return false, fmt.Sprintf("ExternalIPPool %s does not exist", newEgress.Spec.ExternalIPPool)
	}
	if !c.externalIPAllocator.IPPoolHasIP(newEgress.Spec.ExternalIPPool, ip) {
		return false, fmt.Sprintf("IP %s is not within the IP range", newEgress.Spec.EgressIP)
	}
	return true, ""
}

func (c *EgressController) validateV1beta2EgressRequest(operation admv1.Operation, oldEgress, newEgress *crdv1beta2.Egress) (bool, string) {
	if operation == admv1.Delete {
		return true, ""
	}
	if newEgress.Spec.Bandwidth != nil {
		if allowed, msg := validateBandwidth(newEgress.Name, newEgress.Spec.Bandwidth.Rate, newEgress.Spec.Bandwidth.Burst); !allowed {
			return allowed, msg
		}
	}
	if err := c.validateEgressConfiguration(oldEgress, newEgress); err != nil {
		return false, err.Error()
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
