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
	"slices"

	admv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"

	crdv1beta1 "antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
)

type specifiedEgressIP struct {
	value string
	ip    net.IP
}

func ipFamilyForIP(ip net.IP) corev1.IPFamily {
	if ip.To4() != nil {
		return corev1.IPv4Protocol
	}
	return corev1.IPv6Protocol
}

func parseSpecifiedEgressIPs(spec *crdv1beta1.EgressSpec) ([]specifiedEgressIP, sets.Set[corev1.IPFamily], error) {
	if spec.EgressIP != "" && len(spec.EgressIPs) > 0 {
		return nil, nil, fmt.Errorf("spec.egressIP and spec.egressIPs are mutually exclusive")
	}
	if len(spec.EgressIPs) > 0 && len(spec.EgressIPs) != 2 {
		return nil, nil, fmt.Errorf("spec.egressIPs must contain exactly two addresses, one for each IP family")
	}

	values := spec.EgressIPs
	if spec.EgressIP != "" {
		values = []string{spec.EgressIP}
	}
	parsed := make([]specifiedEgressIP, 0, len(values))
	families := sets.New[corev1.IPFamily]()
	for _, value := range values {
		ip := net.ParseIP(value)
		if ip == nil {
			return nil, nil, fmt.Errorf("IP %s is not valid", value)
		}
		family := ipFamilyForIP(ip)
		if families.Has(family) {
			return nil, nil, fmt.Errorf("spec.egressIPs contains multiple addresses for IP family %s", family)
		}
		families.Insert(family)
		parsed = append(parsed, specifiedEgressIP{value: value, ip: ip})
	}
	return parsed, families, nil
}

func requestedIPFamilies(ipFamilies []corev1.IPFamily) (sets.Set[corev1.IPFamily], error) {
	if len(ipFamilies) > 2 {
		return nil, fmt.Errorf("spec.ipFamilies may contain at most two entries")
	}
	families := sets.New[corev1.IPFamily]()
	for _, family := range ipFamilies {
		if family != corev1.IPv4Protocol && family != corev1.IPv6Protocol {
			return nil, fmt.Errorf("spec.ipFamilies contains invalid IP family %s", family)
		}
		if families.Has(family) {
			return nil, fmt.Errorf("spec.ipFamilies contains duplicate IP family %s", family)
		}
		families.Insert(family)
	}
	return families, nil
}

func egressIPConfigurationEqual(oldSpec, newSpec *crdv1beta1.EgressSpec) bool {
	return oldSpec.EgressIP == newSpec.EgressIP &&
		slices.Equal(oldSpec.EgressIPs, newSpec.EgressIPs) &&
		oldSpec.ExternalIPPool == newSpec.ExternalIPPool &&
		slices.Equal(oldSpec.IPFamilies, newSpec.IPFamilies)
}

func (c *EgressController) validateEgressIPConfiguration(oldEgress, newEgress *crdv1beta1.Egress) error {
	specifiedIPs, specifiedFamilies, err := parseSpecifiedEgressIPs(&newEgress.Spec)
	if err != nil {
		return err
	}
	requestedFamilies, err := requestedIPFamilies(newEgress.Spec.IPFamilies)
	if err != nil {
		return err
	}
	if newEgress.Spec.EgressIP != "" && requestedFamilies.Len() > 1 {
		return fmt.Errorf("spec.egressIP is only supported for a single-stack Egress")
	}
	if requestedFamilies.Len() > 0 && specifiedFamilies.Difference(requestedFamilies).Len() > 0 {
		return fmt.Errorf("the IP families of the specified Egress IPs %v must be included in spec.ipFamilies %v",
			sets.List(specifiedFamilies), sets.List(requestedFamilies))
	}

	if newEgress.Spec.ExternalIPPool == "" {
		if len(specifiedIPs) == 0 {
			return fmt.Errorf("an Egress IP or ExternalIPPool must be specified")
		}
		if requestedFamilies.Len() > 0 && !specifiedFamilies.Equal(requestedFamilies) {
			return fmt.Errorf("an Egress IP must be specified for every requested IP family when externalIPPool is empty")
		}
		return nil
	}

	// Allow unrelated updates when the referenced pool has already been deleted.
	if egressIPConfigurationEqual(&oldEgress.Spec, &newEgress.Spec) {
		return nil
	}
	poolName := newEgress.Spec.ExternalIPPool
	if !c.externalIPAllocator.IPPoolExists(poolName) {
		return fmt.Errorf("ExternalIPPool %s does not exist", poolName)
	}
	poolFamilyList, err := c.externalIPAllocator.IPPoolIPFamilies(poolName)
	if err != nil {
		return fmt.Errorf("failed to determine IP families for ExternalIPPool %s: %w", poolName, err)
	}
	poolFamilies := sets.New(poolFamilyList...)
	if poolFamilies.Len() == 0 {
		return fmt.Errorf("ExternalIPPool %s does not contain any IP ranges", poolName)
	}

	if requestedFamilies.Len() == 0 {
		switch {
		case specifiedFamilies.Len() > 0:
			requestedFamilies = specifiedFamilies.Clone()
		case poolFamilies.Len() == 1:
			requestedFamilies = poolFamilies.Clone()
		default:
			return fmt.Errorf("spec.ipFamilies must be specified when dual-stack ExternalIPPool %s is used without an explicit Egress IP", poolName)
		}
	}
	if requestedFamilies.Difference(poolFamilies).Len() > 0 {
		return fmt.Errorf("requested IP families %v are not all available in ExternalIPPool %s (available: %v)",
			sets.List(requestedFamilies), poolName, sets.List(poolFamilies))
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
		if err := c.validateEgressIPConfiguration(oldEgress, newEgress); err != nil {
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
