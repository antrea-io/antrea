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

package crdconversion

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/klog/v2"
)

const (
	v1beta1APIVersion = "crd.antrea.io/v1beta1"
	v1beta2APIVersion = "crd.antrea.io/v1beta2"

	conversionDataAnnotation     = "crd.antrea.io/conversion-data"
	conversionDataVersion        = "v1"
	egressConversionKind         = "Egress"
	externalIPPoolConversionKind = "ExternalIPPool"
)

type conversionDataEnvelope struct {
	Version string          `json:"version"`
	Kind    string          `json:"kind"`
	Data    json.RawMessage `json:"data"`
}

type egressConversionData struct {
	SourceVersion                 string   `json:"sourceVersion"`
	EgressIPs                     []string `json:"egressIPs,omitempty"`
	IPFamilyPolicy                string   `json:"ipFamilyPolicy,omitempty"`
	IPFamilies                    []string `json:"ipFamilies,omitempty"`
	ProjectedEgressIP             string   `json:"projectedEgressIP,omitempty"`
	ProjectedExternalIPPool       string   `json:"projectedExternalIPPool,omitempty"`
	StatusEgressIPs               []string `json:"statusEgressIPs,omitempty"`
	ProjectedStatusEgressIP       string   `json:"projectedStatusEgressIP,omitempty"`
	LegacyExternalIPPools         []string `json:"legacyExternalIPPools,omitempty"`
	LegacyProjectedEgressIPs      []string `json:"legacyProjectedEgressIPs,omitempty"`
	LegacyProjectedExternalIPPool string   `json:"legacyProjectedExternalIPPool,omitempty"`
}

type subnetConversionData struct {
	Gateway      string `json:"gateway"`
	PrefixLength int64  `json:"prefixLength"`
	VLAN         int64  `json:"vlan,omitempty"`
}

type externalIPPoolConversionData struct {
	SourceVersion         string                 `json:"sourceVersion"`
	Subnets               []subnetConversionData `json:"subnets,omitempty"`
	ProjectedGateway      string                 `json:"projectedGateway,omitempty"`
	ProjectedPrefixLength int64                  `json:"projectedPrefixLength,omitempty"`
	ProjectedVLAN         int64                  `json:"projectedVLAN,omitempty"`
	ProjectedSubnetIndex  int                    `json:"projectedSubnetIndex,omitempty"`
}

func statusErrorWithMessage(msg string, params ...interface{}) metav1.Status {
	return metav1.Status{Message: fmt.Sprintf(msg, params...), Status: metav1.StatusFailure}
}

func successStatus() metav1.Status {
	return metav1.Status{Status: metav1.StatusSuccess}
}

func conversionData[T any](object *unstructured.Unstructured, kind string) (T, bool) {
	var data T
	value, ok := object.GetAnnotations()[conversionDataAnnotation]
	if !ok {
		return data, false
	}
	var envelope conversionDataEnvelope
	if err := json.Unmarshal([]byte(value), &envelope); err != nil {
		// Conversion must remain available for reads and deletes even if a user modified the annotation.
		klog.ErrorS(err, "Ignoring invalid CRD conversion data envelope", "object", klog.KObj(object))
		return data, false
	}
	if envelope.Version != conversionDataVersion || envelope.Kind != kind || len(envelope.Data) == 0 {
		// Conversion must remain available for reads and deletes even if a user modified the annotation.
		klog.ErrorS(fmt.Errorf("unexpected conversion data envelope version or kind"), "Ignoring invalid CRD conversion data envelope", "object", klog.KObj(object))
		return data, false
	}
	// Decode into a temporary value first. json.Unmarshal may otherwise leave partially decoded fields behind after an
	// error, which could make malformed, user-controlled annotation data affect the converted object.
	if err := json.Unmarshal(envelope.Data, &data); err != nil {
		klog.ErrorS(err, "Ignoring invalid CRD conversion data", "object", klog.KObj(object))
		var zero T
		return zero, false
	}
	return data, true
}

func setConversionData(object *unstructured.Unstructured, kind string, data interface{}) error {
	rawData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	value, err := json.Marshal(conversionDataEnvelope{Version: conversionDataVersion, Kind: kind, Data: rawData})
	if err != nil {
		return err
	}
	annotations := object.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations[conversionDataAnnotation] = string(value)
	object.SetAnnotations(annotations)
	return nil
}

func removeConversionData(object *unstructured.Unstructured) {
	annotations := object.GetAnnotations()
	if annotations == nil {
		return
	}
	delete(annotations, conversionDataAnnotation)
	if len(annotations) == 0 {
		annotations = nil
	}
	object.SetAnnotations(annotations)
}

// ConvertEgress converts an Egress between the v1beta1 and v1beta2 representations.
func ConvertEgress(object *unstructured.Unstructured, toVersion string) (*unstructured.Unstructured, metav1.Status) {
	converted := object.DeepCopy()
	fromVersion := object.GetAPIVersion()
	if fromVersion == toVersion {
		return nil, statusErrorWithMessage("conversion from a version to itself should not call the webhook: %s", toVersion)
	}

	switch {
	case fromVersion == v1beta1APIVersion && toVersion == v1beta2APIVersion:
		convertEgressToV1beta2(converted)
	case fromVersion == v1beta2APIVersion && toVersion == v1beta1APIVersion:
		if err := convertEgressToV1beta1(converted); err != nil {
			return nil, statusErrorWithMessage("failed to convert Egress to v1beta1: %v", err)
		}
	default:
		return nil, statusErrorWithMessage("unexpected Egress conversion from %q to %q", fromVersion, toVersion)
	}
	converted.SetAPIVersion(toVersion)
	return converted, successStatus()
}

func validIPList(ips []string) bool {
	if len(ips) > 2 {
		return false
	}
	families := map[string]struct{}{}
	for _, ip := range ips {
		address, err := netip.ParseAddr(ip)
		if err != nil || address.Zone() != "" {
			return false
		}
		family := ipFamily(ip)
		if _, exists := families[family]; exists {
			return false
		}
		families[family] = struct{}{}
	}
	return true
}

func validIPFamilyPolicy(policy string) bool {
	switch policy {
	case "", "SingleStack", "PreferDualStack", "RequireDualStack":
		return true
	default:
		return false
	}
}

func validIPFamilies(families []string) bool {
	if len(families) > 2 {
		return false
	}
	seen := map[string]struct{}{}
	for _, family := range families {
		if family != "IPv4" && family != "IPv6" {
			return false
		}
		if _, exists := seen[family]; exists {
			return false
		}
		seen[family] = struct{}{}
	}
	return true
}

func ipFamiliesMatch(ips, families []string) bool {
	if len(ips) == 0 || len(families) == 0 {
		return true
	}
	if len(ips) != len(families) {
		return false
	}
	for _, ip := range ips {
		if !slices.Contains(families, ipFamily(ip)) {
			return false
		}
	}
	return true
}

func getEgressConversionData(object *unstructured.Unstructured) (egressConversionData, bool) {
	data, ok := conversionData[egressConversionData](object, egressConversionKind)
	if !ok || (data.SourceVersion != v1beta1APIVersion && data.SourceVersion != v1beta2APIVersion) ||
		!validIPList(data.EgressIPs) || !validIPList(data.StatusEgressIPs) || !validIPList(data.LegacyProjectedEgressIPs) ||
		!validIPFamilyPolicy(data.IPFamilyPolicy) || !validIPFamilies(data.IPFamilies) ||
		!ipFamiliesMatch(data.EgressIPs, data.IPFamilies) {
		return egressConversionData{}, false
	}
	if data.SourceVersion == v1beta2APIVersion &&
		(data.ProjectedEgressIP != firstIP(data.EgressIPs) || data.ProjectedStatusEgressIP != firstIP(data.StatusEgressIPs) ||
			(len(data.EgressIPs) == 1 && data.IPFamilyPolicy == "RequireDualStack") ||
			(len(data.EgressIPs) == 2 && data.IPFamilyPolicy == "SingleStack") ||
			(len(data.IPFamilies) == 2 && data.IPFamilyPolicy == "SingleStack")) {
		return egressConversionData{}, false
	}
	if data.ProjectedEgressIP != "" {
		address, err := netip.ParseAddr(data.ProjectedEgressIP)
		if err != nil || address.Zone() != "" {
			return egressConversionData{}, false
		}
	}
	if data.ProjectedStatusEgressIP != "" {
		address, err := netip.ParseAddr(data.ProjectedStatusEgressIP)
		if err != nil || address.Zone() != "" {
			return egressConversionData{}, false
		}
	}
	return data, true
}

func firstIP(ips []string) string {
	if len(ips) == 0 {
		return ""
	}
	return ips[0]
}

func convertEgressToV1beta2(object *unstructured.Unstructured) {
	preserved, hasPreserved := getEgressConversionData(object)
	egressIP, egressIPFound, _ := unstructured.NestedString(object.Object, "spec", "egressIP")
	externalIPPool, _, _ := unstructured.NestedString(object.Object, "spec", "externalIPPool")
	legacyEgressIPs, _, _ := unstructured.NestedStringSlice(object.Object, "spec", "egressIPs")
	legacyExternalIPPools, _, _ := unstructured.NestedStringSlice(object.Object, "spec", "externalIPPools")

	projectionUnchanged := hasPreserved && preserved.SourceVersion == v1beta2APIVersion &&
		egressIP == preserved.ProjectedEgressIP && externalIPPool == preserved.ProjectedExternalIPPool &&
		len(legacyExternalIPPools) == 0
	if projectionUnchanged {
		if len(preserved.EgressIPs) > 0 {
			_ = unstructured.SetNestedStringSlice(object.Object, append([]string(nil), preserved.EgressIPs...), "spec", "egressIPs")
		} else {
			unstructured.RemoveNestedField(object.Object, "spec", "egressIPs")
		}
		if preserved.IPFamilyPolicy != "" {
			_ = unstructured.SetNestedField(object.Object, preserved.IPFamilyPolicy, "spec", "ipFamilyPolicy")
		} else {
			unstructured.RemoveNestedField(object.Object, "spec", "ipFamilyPolicy")
		}
		if len(preserved.IPFamilies) > 0 {
			_ = unstructured.SetNestedStringSlice(object.Object, append([]string(nil), preserved.IPFamilies...), "spec", "ipFamilies")
		} else {
			unstructured.RemoveNestedField(object.Object, "spec", "ipFamilies")
		}
	} else {
		if egressIPFound && egressIP != "" {
			legacyEgressIPs = []string{egressIP}
		}
		if len(legacyEgressIPs) > 0 {
			_ = unstructured.SetNestedStringSlice(object.Object, legacyEgressIPs, "spec", "egressIPs")
		} else {
			unstructured.RemoveNestedField(object.Object, "spec", "egressIPs")
		}
		policy := "SingleStack"
		if len(legacyEgressIPs) == 2 {
			policy = "RequireDualStack"
		}
		_ = unstructured.SetNestedField(object.Object, policy, "spec", "ipFamilyPolicy")
		if len(legacyEgressIPs) > 0 {
			families := make([]string, 0, len(legacyEgressIPs))
			for _, ip := range legacyEgressIPs {
				families = append(families, ipFamily(ip))
			}
			_ = unstructured.SetNestedStringSlice(object.Object, families, "spec", "ipFamilies")
		} else {
			unstructured.RemoveNestedField(object.Object, "spec", "ipFamilies")
		}
	}
	unstructured.RemoveNestedField(object.Object, "spec", "egressIP")
	unstructured.RemoveNestedField(object.Object, "spec", "externalIPPools")

	statusEgressIP, statusEgressIPFound, _ := unstructured.NestedString(object.Object, "status", "egressIP")
	if projectionUnchanged && statusEgressIPFound && statusEgressIP != "" && len(preserved.StatusEgressIPs) > 0 {
		statusEgressIPs := append([]string(nil), preserved.StatusEgressIPs...)
		statusEgressIPs[0] = statusEgressIP
		if len(statusEgressIPs) == 2 && ipFamily(statusEgressIPs[0]) == ipFamily(statusEgressIPs[1]) {
			statusEgressIPs = statusEgressIPs[:1]
		}
		_ = unstructured.SetNestedStringSlice(object.Object, statusEgressIPs, "status", "egressIPs")
	} else if projectionUnchanged && statusEgressIP == preserved.ProjectedStatusEgressIP {
		unstructured.RemoveNestedField(object.Object, "status", "egressIPs")
	} else if statusEgressIPFound && statusEgressIP != "" {
		_ = unstructured.SetNestedStringSlice(object.Object, []string{statusEgressIP}, "status", "egressIPs")
	} else {
		unstructured.RemoveNestedField(object.Object, "status", "egressIPs")
	}
	unstructured.RemoveNestedField(object.Object, "status", "egressIP")

	removeConversionData(object)
	// externalIPPools has no v1beta2 representation. Keep it only while the corresponding v1beta2 fields remain
	// unchanged, so a later v1beta2 update cannot resurrect stale legacy data.
	if !projectionUnchanged && len(legacyExternalIPPools) > 0 {
		convertedEgressIPs, _, _ := unstructured.NestedStringSlice(object.Object, "spec", "egressIPs")
		legacyData := egressConversionData{
			SourceVersion:                 v1beta1APIVersion,
			LegacyExternalIPPools:         append([]string(nil), legacyExternalIPPools...),
			LegacyProjectedEgressIPs:      append([]string(nil), convertedEgressIPs...),
			LegacyProjectedExternalIPPool: externalIPPool,
		}
		_ = setConversionData(object, egressConversionKind, &legacyData)
	}
}

func convertEgressToV1beta1(object *unstructured.Unstructured) error {
	prior, hasPrior := getEgressConversionData(object)
	egressIPs, _, _ := unstructured.NestedStringSlice(object.Object, "spec", "egressIPs")
	externalIPPool, _, _ := unstructured.NestedString(object.Object, "spec", "externalIPPool")
	policy, _, _ := unstructured.NestedString(object.Object, "spec", "ipFamilyPolicy")
	ipFamilies, _, _ := unstructured.NestedStringSlice(object.Object, "spec", "ipFamilies")
	statusEgressIPs, _, _ := unstructured.NestedStringSlice(object.Object, "status", "egressIPs")

	// Preserve an unsupported legacy plural representation only while a v1beta2 client has not changed its mapped
	// fields. This is for lossless reads of pre-existing objects; v1beta1 admission continues to reject new uses.
	if hasPrior && prior.SourceVersion == v1beta1APIVersion && len(prior.LegacyExternalIPPools) > 0 &&
		slices.Equal(egressIPs, prior.LegacyProjectedEgressIPs) && externalIPPool == prior.LegacyProjectedExternalIPPool {
		unstructured.RemoveNestedField(object.Object, "spec", "egressIP")
		unstructured.RemoveNestedField(object.Object, "spec", "externalIPPool")
		if len(egressIPs) > 0 {
			_ = unstructured.SetNestedStringSlice(object.Object, egressIPs, "spec", "egressIPs")
		}
		_ = unstructured.SetNestedStringSlice(object.Object, prior.LegacyExternalIPPools, "spec", "externalIPPools")
		unstructured.RemoveNestedField(object.Object, "spec", "ipFamilyPolicy")
		unstructured.RemoveNestedField(object.Object, "spec", "ipFamilies")
		if len(statusEgressIPs) > 0 {
			_ = unstructured.SetNestedField(object.Object, statusEgressIPs[0], "status", "egressIP")
		} else {
			unstructured.RemoveNestedField(object.Object, "status", "egressIP")
		}
		unstructured.RemoveNestedField(object.Object, "status", "egressIPs")
		return setConversionData(object, egressConversionKind, &prior)
	}

	// Every v1beta2 Egress is projected onto the singular v1beta1 branch. In particular, a dual-stack Egress with an
	// externalIPPool must not retain plural egressIPs, or it would satisfy both branches of the v1beta1 oneOf schema.
	projectedEgressIP := firstIP(egressIPs)
	if projectedEgressIP != "" {
		_ = unstructured.SetNestedField(object.Object, projectedEgressIP, "spec", "egressIP")
	} else {
		unstructured.RemoveNestedField(object.Object, "spec", "egressIP")
	}
	unstructured.RemoveNestedField(object.Object, "spec", "egressIPs")
	unstructured.RemoveNestedField(object.Object, "spec", "externalIPPools")
	unstructured.RemoveNestedField(object.Object, "spec", "ipFamilyPolicy")
	unstructured.RemoveNestedField(object.Object, "spec", "ipFamilies")

	projectedStatusEgressIP := firstIP(statusEgressIPs)
	if projectedStatusEgressIP != "" {
		_ = unstructured.SetNestedField(object.Object, projectedStatusEgressIP, "status", "egressIP")
	} else {
		unstructured.RemoveNestedField(object.Object, "status", "egressIP")
	}
	unstructured.RemoveNestedField(object.Object, "status", "egressIPs")
	preserved := egressConversionData{
		SourceVersion:           v1beta2APIVersion,
		EgressIPs:               append([]string(nil), egressIPs...),
		IPFamilyPolicy:          policy,
		IPFamilies:              append([]string(nil), ipFamilies...),
		ProjectedEgressIP:       projectedEgressIP,
		ProjectedExternalIPPool: externalIPPool,
		StatusEgressIPs:         append([]string(nil), statusEgressIPs...),
		ProjectedStatusEgressIP: projectedStatusEgressIP,
	}
	return setConversionData(object, egressConversionKind, &preserved)
}

// ConvertExternalIPPool converts an ExternalIPPool between the v1beta1 and v1beta2 representations.
func ConvertExternalIPPool(object *unstructured.Unstructured, toVersion string) (*unstructured.Unstructured, metav1.Status) {
	converted := object.DeepCopy()
	fromVersion := object.GetAPIVersion()
	if fromVersion == toVersion {
		return nil, statusErrorWithMessage("conversion from a version to itself should not call the webhook: %s", toVersion)
	}

	switch {
	case fromVersion == v1beta1APIVersion && toVersion == v1beta2APIVersion:
		convertExternalIPPoolToV1beta2(converted)
	case fromVersion == v1beta2APIVersion && toVersion == v1beta1APIVersion:
		if err := convertExternalIPPoolToV1beta1(converted); err != nil {
			return nil, statusErrorWithMessage("failed to convert ExternalIPPool to v1beta1: %v", err)
		}
	default:
		return nil, statusErrorWithMessage("unexpected ExternalIPPool conversion from %q to %q", fromVersion, toVersion)
	}
	converted.SetAPIVersion(toVersion)
	return converted, successStatus()
}

func getExternalIPPoolConversionData(object *unstructured.Unstructured) (externalIPPoolConversionData, bool) {
	data, ok := conversionData[externalIPPoolConversionData](object, externalIPPoolConversionKind)
	if !ok || data.SourceVersion != v1beta2APIVersion || len(data.Subnets) == 0 || len(data.Subnets) > 2 ||
		data.ProjectedSubnetIndex < 0 || data.ProjectedSubnetIndex >= len(data.Subnets) {
		return externalIPPoolConversionData{}, false
	}
	families := map[string]struct{}{}
	for _, gateway := range data.Subnets {
		address, err := netip.ParseAddr(gateway.Gateway)
		if err != nil || address.Zone() != "" {
			return externalIPPoolConversionData{}, false
		}
		maxPrefixLength := int64(128)
		if address.Unmap().Is4() {
			maxPrefixLength = 32
		}
		if gateway.PrefixLength <= 0 || gateway.PrefixLength >= maxPrefixLength || gateway.VLAN < 0 || gateway.VLAN > 4094 {
			return externalIPPoolConversionData{}, false
		}
		family := ipFamily(gateway.Gateway)
		if _, exists := families[family]; exists {
			return externalIPPoolConversionData{}, false
		}
		families[family] = struct{}{}
	}
	projected := data.Subnets[data.ProjectedSubnetIndex]
	if projected.Gateway != data.ProjectedGateway || projected.PrefixLength != data.ProjectedPrefixLength ||
		projected.VLAN != data.ProjectedVLAN {
		return externalIPPoolConversionData{}, false
	}
	return data, true
}

// IsV1beta2ExternalIPPoolProjection reports whether a v1beta1 object is a projection produced from v1beta2. Admission
// uses this to validate the restored object instead of applying native v1beta1 subnet semantics to hidden subnets.
func IsV1beta2ExternalIPPoolProjection(object *unstructured.Unstructured) bool {
	data, ok := getExternalIPPoolConversionData(object)
	return ok && data.SourceVersion == v1beta2APIVersion
}

func externalIPPoolRangeFamilies(object *unstructured.Unstructured) (map[string]struct{}, bool) {
	ranges, found, err := unstructured.NestedSlice(object.Object, "spec", "ipRanges")
	if err != nil || !found {
		return nil, false
	}
	families := map[string]struct{}{}
	for _, item := range ranges {
		ipRange, ok := item.(map[string]interface{})
		if !ok {
			return nil, false
		}
		var address netip.Addr
		if cidr, _ := ipRange["cidr"].(string); cidr != "" {
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil {
				return nil, false
			}
			address = prefix.Addr()
		} else {
			start, _ := ipRange["start"].(string)
			var err error
			address, err = netip.ParseAddr(start)
			if err != nil {
				return nil, false
			}
		}
		families[ipFamily(address.String())] = struct{}{}
	}
	return families, true
}

func setExternalIPPoolSubnets(object *unstructured.Unstructured, subnets []subnetConversionData) {
	items := make([]interface{}, 0, len(subnets))
	for _, subnet := range subnets {
		item := map[string]interface{}{
			"gateway":      subnet.Gateway,
			"prefixLength": subnet.PrefixLength,
		}
		if subnet.VLAN != 0 {
			item["vlan"] = subnet.VLAN
		}
		items = append(items, item)
	}
	if len(items) == 0 {
		unstructured.RemoveNestedField(object.Object, "spec", "subnets")
	} else {
		_ = unstructured.SetNestedSlice(object.Object, items, "spec", "subnets")
	}
}

func convertExternalIPPoolToV1beta2(object *unstructured.Unstructured) {
	if _, found, _ := unstructured.NestedMap(object.Object, "spec", "subnetInfo"); !found {
		unstructured.RemoveNestedField(object.Object, "spec", "subnets")
		removeConversionData(object)
		return
	}
	visibleGateway, _, _ := unstructured.NestedString(object.Object, "spec", "subnetInfo", "gateway")
	visiblePrefixLength, _, _ := unstructured.NestedInt64(object.Object, "spec", "subnetInfo", "prefixLength")
	visibleVLAN, _, _ := unstructured.NestedInt64(object.Object, "spec", "subnetInfo", "vlan")
	visible := subnetConversionData{Gateway: visibleGateway, PrefixLength: visiblePrefixLength, VLAN: visibleVLAN}
	preserved, hasPreserved := getExternalIPPoolConversionData(object)
	subnets := []subnetConversionData{visible}
	if hasPreserved {
		subnets = nil
		rangeFamilies, validRanges := externalIPPoolRangeFamilies(object)
		for i, subnet := range preserved.Subnets {
			if i == preserved.ProjectedSubnetIndex {
				// All visible fields, including VLAN, belong to the projected subnet.
				subnets = append(subnets, visible)
				continue
			}
			// A visible family change must not create two entries for the same family.
			if ipFamily(subnet.Gateway) == ipFamily(visible.Gateway) {
				continue
			}
			// An empty pool retains its configured subnets. For non-empty pools, do not
			// resurrect hidden subnets whose ranges were removed by an old client.
			if validRanges && len(rangeFamilies) > 0 {
				if _, exists := rangeFamilies[ipFamily(subnet.Gateway)]; !exists {
					continue
				}
			}
			subnets = append(subnets, subnet)
		}
	}
	setExternalIPPoolSubnets(object, subnets)
	unstructured.RemoveNestedField(object.Object, "spec", "subnetInfo")
	removeConversionData(object)
}

func convertExternalIPPoolToV1beta1(object *unstructured.Unstructured) error {
	subnets, found, err := unstructured.NestedSlice(object.Object, "spec", "subnets")
	if err != nil {
		return err
	}
	// The v1beta2 representation is authoritative, even if a client retained stale conversion data.
	unstructured.RemoveNestedField(object.Object, "spec", "subnetInfo")
	removeConversionData(object)
	if !found || len(subnets) == 0 {
		unstructured.RemoveNestedField(object.Object, "spec", "subnets")
		return nil
	}
	preserved := externalIPPoolConversionData{
		SourceVersion: v1beta2APIVersion,
		Subnets:       make([]subnetConversionData, 0, len(subnets)),
	}
	visibleIndex := 0
	for i, item := range subnets {
		subnet, ok := item.(map[string]interface{})
		if !ok {
			return fmt.Errorf("subnet %d has an unexpected representation", i)
		}
		gateway, _ := subnet["gateway"].(string)
		prefixLength, _ := subnet["prefixLength"].(int64)
		vlan, _ := subnet["vlan"].(int64)
		preserved.Subnets = append(preserved.Subnets, subnetConversionData{
			Gateway: gateway, PrefixLength: prefixLength, VLAN: vlan,
		})
		if ipFamily(gateway) == "IPv4" {
			visibleIndex = i
		}
	}
	visible := preserved.Subnets[visibleIndex]
	preserved.ProjectedGateway = visible.Gateway
	preserved.ProjectedPrefixLength = visible.PrefixLength
	preserved.ProjectedVLAN = visible.VLAN
	preserved.ProjectedSubnetIndex = visibleIndex
	subnetInfo := map[string]interface{}{"gateway": visible.Gateway, "prefixLength": visible.PrefixLength}
	if visible.VLAN != 0 {
		subnetInfo["vlan"] = visible.VLAN
	}
	if err := unstructured.SetNestedMap(object.Object, subnetInfo, "spec", "subnetInfo"); err != nil {
		return err
	}
	unstructured.RemoveNestedField(object.Object, "spec", "subnets")
	// A single subnet is fully representable in v1beta1 without an annotation.
	if len(subnets) == 1 {
		return nil
	}
	return setConversionData(object, externalIPPoolConversionKind, &preserved)
}

func ipFamily(ip string) string {
	address, err := netip.ParseAddr(ip)
	if err == nil && address.Unmap().Is4() {
		return "IPv4"
	}
	return "IPv6"
}
