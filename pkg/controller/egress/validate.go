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

	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
)

func (c *EgressController) validateDualStackEgress(egress *crdv1beta1.Egress) (bool, string) {
	var hasIPsandPools, hasOnlyIPs, hasOnlyPools bool
	var egressIPv4, egressIPv6, egressIPPoolIPv4, egressIPPoolIPv6 string
	lenIPs := len(egress.Spec.EgressIPs)
	lenPools := len(egress.Spec.ExternalIPPools)

	switch {
		case lenIPs == 2 && lenPools == 0:
			hasOnlyIPs = true
		case lenIPs == 0 && lenPools == 2:
			hasOnlyPools = true
		case lenIPs == 2 && lenPools == 2:
			hasIPsandPools = true
		default:
			return false, fmt.Sprintf("invalid dual-stack configuration: %d IPs, %d Pools", lenIPs, lenPools)
	}

	if !hasOnlyIPs {
		for _, poolName := range egress.Spec.ExternalIPPools {
			if poolName == "" {
				return false, "spec.externalIPPools contains empty pool name"
			}
			if !c.externalIPAllocator.IPPoolExists(poolName) {
				return false, fmt.Sprintf("ExternalIPPool %s does not exist", poolName)
			}
			isIPv6, err := c.externalIPAllocator.IPPoolIsIPv6(poolName) 
			if err != nil {
				return false, fmt.Sprintf("failed to determine IP family for ExternalIPPool %s: %v", poolName, err)
			}
			if isIPv6 {
				egressIPPoolIPv6 = poolName
			} else {
				egressIPPoolIPv4 = poolName
			}
		}
		if egressIPPoolIPv4 == "" || egressIPPoolIPv6 == "" {
			return false, fmt.Sprintf("failed to get balanced Dual-Stack externalIPPools: IPv4Pool: %s, IPv6Pool: %s", egressIPPoolIPv4, egressIPPoolIPv6)
		}
	}

	if !hasOnlyPools {
		for _, ipStr := range egress.Spec.EgressIPs {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				return false, fmt.Sprintf("IP %s in spec.egressIPs is not valid", ipStr)
			}
			if ip.To4() != nil {
				egressIPv4 = ipStr
			} else {
				egressIPv6 = ipStr
			}
		}
		if egressIPv4 == "" || egressIPv6 == "" {
			return false, fmt.Sprintf("dual-stack requirements not met: expected one IPv4 and one IPv6 address, but got (v4: %s, v6: %s)", egressIPv4, egressIPv6)
		}
	}
	// If both spec.EgressIPs and spec.ExternalIPPools are set, we must verify that all IPs in EgressIPs belong to their corresponding ExternalIPPools.
	if hasIPsandPools {
		if !c.externalIPAllocator.IPPoolHasIP(egressIPPoolIPv4, net.ParseIP(egressIPv4)) || !c.externalIPAllocator.IPPoolHasIP(egressIPPoolIPv6, net.ParseIP(egressIPv6)) {
			return false, fmt.Sprintf("the specified EgressIPs are not within the ranges of the provided ExternalIPPools (IPv4: %s/%s, IPv6: %s/%s)", egressIPv4, egressIPPoolIPv4, egressIPv6, egressIPPoolIPv6)
		}
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
				return false, "{spec.egressIPs, spec.ExternalIPPools} and {spec.egressIP, spec.ExternalIPPool} are mutual exclusive"
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
