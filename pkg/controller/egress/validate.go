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
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/klog/v2"

	crdv1beta1 "antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
)

type dualStackEgressIPPair struct {
	ipv4Addr netip.Addr
	ipv6Addr netip.Addr
}

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

	// Parse the IPs and validate their family order: even indices must be IPv4, odd indices must be IPv6.
	parsedIPs := make([]net.IP, lenIPs)
	for i, ipStr := range egress.Spec.EgressIPs {
		isIPv6 := (i%2 == 1)
		ip, err := parseIPByFamily(ipStr, isIPv6, i)
		if err != nil {
			return false, err.Error()
		}
		parsedIPs[i] = ip
	}
	seenPools := make(map[string]struct{}, lenPools)
	for i, poolName := range egress.Spec.ExternalIPPools {
		if poolName == "" {
			return false, "empty pool name"
		}
		if _, exists := seenPools[poolName]; exists {
			return false, fmt.Sprintf("spec.externalIPPools[%d] duplicates ExternalIPPool %s", i, poolName)
		}
		seenPools[poolName] = struct{}{}
	}

	// Pool-only dual-stack Egress follows the same auto-allocation behavior as
	// single-stack Egress: it can be created before the referenced ExternalIPPools
	// exist, and the controller will validate the pools later when allocating IPs.
	// Once explicit EgressIPs are present, admission must validate pool existence,
	// pool family order, and IP membership because the user is binding concrete IPs
	// to concrete pools.
	if lenIPs > 0 && lenPools > 0 {
		for i, poolName := range egress.Spec.ExternalIPPools {
			isIPv6 := (i%2 == 1)
			if ok, msg := c.isCorrectFamilyPool(poolName, isIPv6); !ok {
				return false, msg
			}
		}
		for i := 0; i < lenIPs; i++ {
			ipStr := egress.Spec.EgressIPs[i]
			poolName := egress.Spec.ExternalIPPools[i]
			if !c.externalIPAllocator.IPPoolHasIP(poolName, parsedIPs[i]) {
				return false, fmt.Sprintf("EgressIP %s does not belong to ExternalIPPool %s", ipStr, poolName)
			}
		}
	}
	if ok, msg := c.validateNoEgressIPOverlap(egress); !ok {
		return false, msg
	}
	return true, ""
}

func firstDualStackEgressIPPair(egressIPs []string) (dualStackEgressIPPair, bool) {
	if len(egressIPs) < 2 {
		return dualStackEgressIPPair{}, false
	}
	ipv4Addr, ipv4Valid := parseIPAddr(egressIPs[0])
	ipv6Addr, ipv6Valid := parseIPAddr(egressIPs[1])
	if !ipv4Valid || !ipv6Valid {
		return dualStackEgressIPPair{}, false
	}
	return dualStackEgressIPPair{ipv4Addr: ipv4Addr, ipv6Addr: ipv6Addr}, true
}

// parseIPAddr parses and normalizes an IP address for comparison. Unmap makes
// IPv4-mapped IPv6 addresses compare equal to their IPv4 representation.
func parseIPAddr(ip string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

func dualStackEgressIPPairsPartiallyOverlap(a, b dualStackEgressIPPair) bool {
	return (a.ipv4Addr == b.ipv4Addr) != (a.ipv6Addr == b.ipv6Addr)
}

func dualStackEgressIPPairContainsIP(pair dualStackEgressIPPair, ipAddr netip.Addr) bool {
	return ipAddr == pair.ipv4Addr || ipAddr == pair.ipv6Addr
}

func (c *EgressController) validateNoEgressIPOverlap(egress *crdv1beta1.Egress) (bool, string) {
	newPair, newIsDualStack := firstDualStackEgressIPPair(egress.Spec.EgressIPs)
	newSingleStackIP := egress.Spec.EgressIP
	var newSingleStackAddr netip.Addr
	var newSingleStackIPValid bool
	if !newIsDualStack {
		if newSingleStackIP == "" {
			return true, ""
		}
		newSingleStackAddr, newSingleStackIPValid = parseIPAddr(newSingleStackIP)
	}

	// Exact pair sharing is allowed to preserve the existing shared-Egress-IP behavior. Partial overlap is not:
	// if two Egresses share only the IPv4 or only the IPv6 side of a dual-stack pair, the Agent cannot represent
	// their state with one shared mark per pair without leaking or deleting the other Egress's datapath state. Only the
	// first pair is checked because additional pairs are not realized on the datapath in the current implementation.
	egresses, err := c.egressLister.List(labels.Everything())
	if err != nil {
		if newIsDualStack {
			return false, fmt.Sprintf("failed to list Egresses for dual-stack overlap validation: %v", err)
		}
		return false, fmt.Sprintf("failed to list Egresses for single-stack overlap validation: %v", err)
	}
	for _, existingEgress := range egresses {
		if existingEgress.Name == egress.Name {
			continue
		}
		existingPair, existingIsDualStack := firstDualStackEgressIPPair(existingEgress.Spec.EgressIPs)
		if newIsDualStack {
			if existingEgress.Spec.EgressIP != "" {
				existingSingleStackAddr, existingSingleStackIPValid := parseIPAddr(existingEgress.Spec.EgressIP)
				if existingSingleStackIPValid &&
					dualStackEgressIPPairContainsIP(newPair, existingSingleStackAddr) {
					return false, fmt.Sprintf("dual-stack EgressIP pair (%s, %s) overlaps with single-stack Egress %s IP %s; sharing an IP between single-stack and dual-stack Egresses is not supported",
						egress.Spec.EgressIPs[0], egress.Spec.EgressIPs[1], existingEgress.Name, existingEgress.Spec.EgressIP)
				}
			}
			if existingIsDualStack && dualStackEgressIPPairsPartiallyOverlap(newPair, existingPair) {
				return false, fmt.Sprintf("dual-stack EgressIP pair (%s, %s) partially overlaps with Egress %s pair (%s, %s); sharing exactly one IP of a dual-stack pair is not supported",
					egress.Spec.EgressIPs[0], egress.Spec.EgressIPs[1], existingEgress.Name,
					existingEgress.Spec.EgressIPs[0], existingEgress.Spec.EgressIPs[1])
			}
			continue
		}
		if newSingleStackIPValid && existingIsDualStack &&
			dualStackEgressIPPairContainsIP(existingPair, newSingleStackAddr) {
			return false, fmt.Sprintf("single-stack EgressIP %s overlaps with Egress %s dual-stack pair (%s, %s); sharing an IP between single-stack and dual-stack Egresses is not supported",
				newSingleStackIP, existingEgress.Name,
				existingEgress.Spec.EgressIPs[0], existingEgress.Spec.EgressIPs[1])
		}
	}
	return true, ""
}

func parseIPByFamily(ipStr string, expectIPv6 bool, index int) (net.IP, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("spec.egressIPs[%d] has invalid IP format: %s", index, ipStr)
	}

	isIPv6 := ip.To4() == nil
	if isIPv6 != expectIPv6 {
		expectedFamily := "IPv4"
		actualFamily := "IPv6"
		if expectIPv6 {
			expectedFamily = "IPv6"
			actualFamily = "IPv4"
		}
		return nil, fmt.Errorf("spec.egressIPs[%d] must be %s but got %s (%s)", index, expectedFamily, ipStr, actualFamily)
	}
	return ip, nil
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
			// Allow updates that do not change the dual-stack EgressIP / ExternalIPPool fields.
			// Referenced ExternalIPPools may have been deleted already, and in that case validating
			// their family or membership again would make unrelated Egress spec fields impossible
			// to edit. This mirrors the single-stack shortcut below.
			dualStackEgressIPFieldsUnchanged := slices.Equal(oldEgress.Spec.EgressIPs, newEgress.Spec.EgressIPs) &&
				slices.Equal(oldEgress.Spec.ExternalIPPools, newEgress.Spec.ExternalIPPools)
			// Allow the controller to clear allocated dual-stack EgressIPs after a referenced ExternalIPPool is deleted.
			// This aligns with the single-stack cleanup path, which skips pool validation when spec.egressIP is empty.
			dualStackEgressIPsCleanup := len(oldEgress.Spec.EgressIPs) > 0 && len(newEgress.Spec.EgressIPs) == 0 &&
				slices.Equal(oldEgress.Spec.ExternalIPPools, newEgress.Spec.ExternalIPPools)
			if !dualStackEgressIPFieldsUnchanged && !dualStackEgressIPsCleanup {
				if allowed, msg := c.validateDualStackEgress(newEgress); !allowed {
					return false, msg
				}
			}
		}
		if newEgress.Spec.EgressIP != "" {
			if allowed, msg := c.validateNoEgressIPOverlap(newEgress); !allowed {
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
