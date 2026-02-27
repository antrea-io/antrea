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

	admv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	crdv1beta1 "antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
)

func (c *EgressController) validateDualStackEgress(egress *crdv1beta1.Egress) (bool, string) {
	lenIPs := len(egress.Spec.EgressIPs)
	lenPools := len(egress.Spec.ExternalIPPools)

	// EgressIPs and ExternalIPPools must each have an even number of entries (paired as IPv4, IPv6).
	// When both are specified, they must have the same length.
	if lenIPs > 0 && lenIPs%2 != 0 {
		return false, fmt.Sprintf("spec.egressIPs must have an even number of entries (IPv4/IPv6 pairs), got %d", lenIPs)
	}
	if lenPools > 0 && lenPools%2 != 0 {
		return false, fmt.Sprintf("spec.externalIPPools must have an even number of entries (IPv4/IPv6 pairs), got %d", lenPools)
	}
	if lenIPs > 0 && lenPools > 0 && lenIPs != lenPools {
		return false, fmt.Sprintf("spec.egressIPs and spec.externalIPPools must have the same length, got %d and %d", lenIPs, lenPools)
	}

	// Validate IP family order: even indices must be IPv4, odd indices must be IPv6.
	for i, ipStr := range egress.Spec.EgressIPs {
		isIPv6 := (i%2 == 1)
		if ok, msg := c.isCorrectFamilyIP(ipStr, isIPv6, i); !ok {
			return false, msg
		}
	}
	for i, poolName := range egress.Spec.ExternalIPPools {
		isIPv6 := (i%2 == 1)
		if ok, msg := c.isCorrectFamilyPool(poolName, isIPv6); !ok {
			return false, msg
		}
	}

	// When both IPs and pools are specified, validate each IP belongs to its corresponding pool.
	if lenIPs > 0 && lenPools > 0 {
		for i := 0; i < lenIPs; i++ {
			ipStr := egress.Spec.EgressIPs[i]
			poolName := egress.Spec.ExternalIPPools[i]
			if !c.externalIPAllocator.IPPoolHasIP(poolName, net.ParseIP(ipStr)) {
				return false, fmt.Sprintf("EgressIP %s does not belong to ExternalIPPool %s", ipStr, poolName)
			}
		}
	}
	return true, ""
}

func (c *EgressController) isCorrectFamilyIP(ipStr string, expectIPv6 bool, index int) (bool, string) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, fmt.Sprintf("spec.egressIPs[%d] has invalid IP format: %s", index, ipStr)
	}

	isIPv6 := ip.To4() == nil
	if isIPv6 != expectIPv6 {
		expectedFamily := "IPv4"
		actualFamily := "IPv6"
		if expectIPv6 {
			expectedFamily = "IPv6"
			actualFamily = "IPv4"
		}
		return false, fmt.Sprintf("spec.egressIPs[%d] must be %s but got %s (%s)", index, expectedFamily, ipStr, actualFamily)
	}
	return true, ""
}

func (c *EgressController) isCorrectFamilyPool(poolName string, expectIPv6 bool) (bool, string) {
	if poolName == "" {
		return false, "empty pool name"
	}
	isIPv6, err := c.externalIPAllocator.IPPoolIsIPv6(poolName)
	if err != nil {
		return false, fmt.Sprintf("pool %s check failed: %v", poolName, err)
	}
	if isIPv6 != expectIPv6 {
		family := "IPv4"
		if expectIPv6 {
			family = "IPv6"
		}
		return false, fmt.Sprintf("expected %s pool but %s is not", family, poolName)
	}
	return true, ""
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
		// Validate Egress Dual-Stack Configuration
		if len(newEgress.Spec.EgressIPs) > 0 || len(newEgress.Spec.ExternalIPPools) > 0 {
			if newEgress.Spec.EgressIP != "" || newEgress.Spec.ExternalIPPool != "" {
				return false, "{spec.egressIPs, spec.externalIPPools} and {spec.egressIP, spec.externalIPPool} are mutually exclusive"
			}
			if allowed, msg := c.validateDualStackEgress(newEgress); !allowed {
				return false, msg
			}
		}
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
		// Allow it if EgressIP and ExternalIPPool don't change.
		if newEgress.Spec.EgressIP == oldEgress.Spec.EgressIP && newEgress.Spec.ExternalIPPool == oldEgress.Spec.ExternalIPPool {
			return true, ""
		}
		// Only validate whether the specified Egress IP is in the Pool when they are both set.
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
