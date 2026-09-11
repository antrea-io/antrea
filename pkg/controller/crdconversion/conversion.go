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
	ProjectedEgressIP             string   `json:"projectedEgressIP,omitempty"`
	ProjectedExternalIPPool       string   `json:"projectedExternalIPPool,omitempty"`
	StatusEgressIPs               []string `json:"statusEgressIPs,omitempty"`
	ProjectedStatusEgressIP       string   `json:"projectedStatusEgressIP,omitempty"`
	LegacyExternalIPPools         []string `json:"legacyExternalIPPools,omitempty"`
	LegacyProjectedEgressIPs      []string `json:"legacyProjectedEgressIPs,omitempty"`
	LegacyProjectedExternalIPPool string   `json:"legacyProjectedExternalIPPool,omitempty"`
}

type subnetGatewayConversionData struct {
	Gateway      string `json:"gateway"`
	PrefixLength int64  `json:"prefixLength"`
}

type externalIPPoolConversionData struct {
	SourceVersion         string                        `json:"sourceVersion"`
	Gateways              []subnetGatewayConversionData `json:"gateways,omitempty"`
	ProjectedGateway      string                        `json:"projectedGateway,omitempty"`
	ProjectedPrefixLength int64                         `json:"projectedPrefixLength,omitempty"`
	ProjectedGatewayIndex int                           `json:"projectedGatewayIndex,omitempty"`
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

func getEgressConversionData(object *unstructured.Unstructured) (egressConversionData, bool) {
	data, ok := conversionData[egressConversionData](object, egressConversionKind)
	if !ok || (data.SourceVersion != v1beta1APIVersion && data.SourceVersion != v1beta2APIVersion) ||
		!validIPList(data.EgressIPs) || !validIPList(data.StatusEgressIPs) || !validIPList(data.LegacyProjectedEgressIPs) ||
		!validIPFamilyPolicy(data.IPFamilyPolicy) {
		return egressConversionData{}, false
	}
	if data.SourceVersion == v1beta2APIVersion &&
		(data.ProjectedEgressIP != firstIP(data.EgressIPs) || data.ProjectedStatusEgressIP != firstIP(data.StatusEgressIPs) ||
			(len(data.EgressIPs) == 1 && data.IPFamilyPolicy == "RequireDualStack") ||
			(len(data.EgressIPs) == 2 && data.IPFamilyPolicy == "SingleStack")) {
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
	if !ok || data.SourceVersion != v1beta2APIVersion || len(data.Gateways) == 0 || len(data.Gateways) > 2 ||
		data.ProjectedGatewayIndex < 0 || data.ProjectedGatewayIndex >= len(data.Gateways) {
		return externalIPPoolConversionData{}, false
	}
	families := map[string]struct{}{}
	for _, gateway := range data.Gateways {
		address, err := netip.ParseAddr(gateway.Gateway)
		if err != nil || address.Zone() != "" {
			return externalIPPoolConversionData{}, false
		}
		maxPrefixLength := int64(128)
		if address.Unmap().Is4() {
			maxPrefixLength = 32
		}
		if gateway.PrefixLength <= 0 || gateway.PrefixLength >= maxPrefixLength {
			return externalIPPoolConversionData{}, false
		}
		family := ipFamily(gateway.Gateway)
		if _, exists := families[family]; exists {
			return externalIPPoolConversionData{}, false
		}
		families[family] = struct{}{}
	}
	projected := data.Gateways[data.ProjectedGatewayIndex]
	if projected.Gateway != data.ProjectedGateway || projected.PrefixLength != data.ProjectedPrefixLength {
		return externalIPPoolConversionData{}, false
	}
	return data, true
}

// IsV1beta2ExternalIPPoolProjection reports whether a v1beta1 object is a projection produced from v1beta2. Admission
// uses this to validate the restored object instead of applying native v1beta1 subnet semantics to hidden gateways.
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

func setExternalIPPoolGateways(object *unstructured.Unstructured, gateways []subnetGatewayConversionData) {
	items := make([]interface{}, 0, len(gateways))
	for _, gateway := range gateways {
		items = append(items, map[string]interface{}{
			"gateway":      gateway.Gateway,
			"prefixLength": gateway.PrefixLength,
		})
	}
	if len(items) == 0 {
		unstructured.RemoveNestedField(object.Object, "spec", "subnetInfo", "gateways")
	} else {
		_ = unstructured.SetNestedSlice(object.Object, items, "spec", "subnetInfo", "gateways")
	}
}

func convertExternalIPPoolToV1beta2(object *unstructured.Unstructured) {
	if _, found, _ := unstructured.NestedMap(object.Object, "spec", "subnetInfo"); !found {
		removeConversionData(object)
		return
	}

	visibleGateway, visibleGatewayFound, _ := unstructured.NestedString(object.Object, "spec", "subnetInfo", "gateway")
	visiblePrefixLength, _, _ := unstructured.NestedInt64(object.Object, "spec", "subnetInfo", "prefixLength")
	preserved, hasPreserved := getExternalIPPoolConversionData(object)
	var gateways []subnetGatewayConversionData
	if hasPreserved {
		gateways = append([]subnetGatewayConversionData(nil), preserved.Gateways...)
		projectionChanged := visibleGateway != preserved.ProjectedGateway || visiblePrefixLength != preserved.ProjectedPrefixLength
		if projectionChanged && visibleGatewayFound && visibleGateway != "" {
			// Replace the exact entry which was projected to v1beta1. Matching by the new gateway family would update the
			// wrong hidden entry when an old client changes the visible gateway from one family to another.
			updated := subnetGatewayConversionData{Gateway: visibleGateway, PrefixLength: visiblePrefixLength}
			merged := []subnetGatewayConversionData{updated}
			seenFamilies := map[string]struct{}{ipFamily(updated.Gateway): {}}
			for i, gateway := range gateways {
				if i == preserved.ProjectedGatewayIndex {
					continue
				}
				family := ipFamily(gateway.Gateway)
				if _, exists := seenFamilies[family]; exists {
					continue
				}
				seenFamilies[family] = struct{}{}
				merged = append(merged, gateway)
			}
			gateways = merged
		} else if projectionChanged {
			gateways = nil
		}
		// When an old client removes all ranges of one family, do not resurrect that family's hidden gateway.
		if rangeFamilies, ok := externalIPPoolRangeFamilies(object); ok {
			filtered := gateways[:0]
			for _, gateway := range gateways {
				if _, exists := rangeFamilies[ipFamily(gateway.Gateway)]; exists {
					filtered = append(filtered, gateway)
				}
			}
			gateways = filtered
		}
	} else {
		// A native v1beta1 subnet is fully representable by the legacy fields which remain available in v1beta2.
		// Leave it unchanged instead of inventing conversion state.
		removeConversionData(object)
		return
	}
	setExternalIPPoolGateways(object, gateways)
	unstructured.RemoveNestedField(object.Object, "spec", "subnetInfo", "gateway")
	unstructured.RemoveNestedField(object.Object, "spec", "subnetInfo", "prefixLength")
	removeConversionData(object)
}

func convertExternalIPPoolToV1beta1(object *unstructured.Unstructured) error {
	gateways, found, _ := unstructured.NestedSlice(object.Object, "spec", "subnetInfo", "gateways")
	if !found || len(gateways) == 0 {
		removeConversionData(object)
		return nil
	}
	preserved := externalIPPoolConversionData{
		SourceVersion: v1beta2APIVersion,
		Gateways:      make([]subnetGatewayConversionData, 0, len(gateways)),
	}
	visibleIndex := -1
	for i, item := range gateways {
		gateway, ok := item.(map[string]interface{})
		if !ok {
			return fmt.Errorf("gateway %d has an unexpected representation", i)
		}
		gatewayIP, _ := gateway["gateway"].(string)
		prefixLength, _ := gateway["prefixLength"].(int64)
		preserved.Gateways = append(preserved.Gateways, subnetGatewayConversionData{Gateway: gatewayIP, PrefixLength: prefixLength})
		if visibleIndex == -1 || ipFamily(gatewayIP) == "IPv4" {
			visibleIndex = i
		}
	}
	if visibleIndex >= 0 {
		visible := preserved.Gateways[visibleIndex]
		preserved.ProjectedGateway = visible.Gateway
		preserved.ProjectedPrefixLength = visible.PrefixLength
		preserved.ProjectedGatewayIndex = visibleIndex
		_ = unstructured.SetNestedField(object.Object, visible.Gateway, "spec", "subnetInfo", "gateway")
		_ = unstructured.SetNestedField(object.Object, visible.PrefixLength, "spec", "subnetInfo", "prefixLength")
	}
	unstructured.RemoveNestedField(object.Object, "spec", "subnetInfo", "gateways")
	return setConversionData(object, externalIPPoolConversionKind, &preserved)
}

func ipFamily(ip string) string {
	address, err := netip.ParseAddr(ip)
	if err == nil && address.Unmap().Is4() {
		return "IPv4"
	}
	return "IPv6"
}
