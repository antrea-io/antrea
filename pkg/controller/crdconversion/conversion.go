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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/klog/v2"
)

const (
	v1beta1APIVersion = "crd.antrea.io/v1beta1"
	v1beta2APIVersion = "crd.antrea.io/v1beta2"

	conversionDataAnnotation = "crd.antrea.io/conversion-data"
)

type egressConversionData struct {
	IPFamilyPolicy        string   `json:"ipFamilyPolicy,omitempty"`
	StatusEgressIPs       []string `json:"statusEgressIPs,omitempty"`
	LegacyExternalIPPools []string `json:"legacyExternalIPPools,omitempty"`
}

type externalIPPoolConversionData struct {
	Gateways []map[string]interface{} `json:"gateways,omitempty"`
}

func statusErrorWithMessage(msg string, params ...interface{}) metav1.Status {
	return metav1.Status{Message: fmt.Sprintf(msg, params...), Status: metav1.StatusFailure}
}

func successStatus() metav1.Status {
	return metav1.Status{Status: metav1.StatusSuccess}
}

func conversionData(object *unstructured.Unstructured, data interface{}) {
	value, ok := object.GetAnnotations()[conversionDataAnnotation]
	if !ok {
		return
	}
	if err := json.Unmarshal([]byte(value), data); err != nil {
		// Conversion must remain available for reads and deletes even if a user modified the annotation.
		klog.ErrorS(err, "Ignoring invalid CRD conversion data", "object", klog.KObj(object))
	}
}

func setConversionData(object *unstructured.Unstructured, data interface{}) error {
	value, err := json.Marshal(data)
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

func convertEgressToV1beta2(object *unstructured.Unstructured) {
	var preserved egressConversionData
	conversionData(object, &preserved)

	if egressIP, found, _ := unstructured.NestedString(object.Object, "spec", "egressIP"); found && egressIP != "" {
		_ = unstructured.SetNestedStringSlice(object.Object, []string{egressIP}, "spec", "egressIPs")
	}
	unstructured.RemoveNestedField(object.Object, "spec", "egressIP")
	if externalIPPools, found, _ := unstructured.NestedStringSlice(object.Object, "spec", "externalIPPools"); found && len(externalIPPools) > 0 {
		preserved.LegacyExternalIPPools = externalIPPools
	} else {
		// The v1beta1 representation is authoritative. In particular, an old client may have removed this field.
		preserved.LegacyExternalIPPools = nil
	}
	unstructured.RemoveNestedField(object.Object, "spec", "externalIPPools")
	if preserved.IPFamilyPolicy != "" {
		_ = unstructured.SetNestedField(object.Object, preserved.IPFamilyPolicy, "spec", "ipFamilyPolicy")
	} else {
		// Objects created through v1beta1 predate IPFamilyPolicy and must retain their single-stack allocation
		// behavior. Setting the value explicitly prevents the v1beta2 PreferDualStack default from changing them.
		policy := "SingleStack"
		if egressIPs, found, _ := unstructured.NestedStringSlice(object.Object, "spec", "egressIPs"); found && len(egressIPs) == 2 {
			policy = "RequireDualStack"
		}
		_ = unstructured.SetNestedField(object.Object, policy, "spec", "ipFamilyPolicy")
	}

	statusEgressIP, statusEgressIPFound, _ := unstructured.NestedString(object.Object, "status", "egressIP")
	if statusEgressIPFound && statusEgressIP != "" && len(preserved.StatusEgressIPs) > 0 {
		statusEgressIPs := append([]string(nil), preserved.StatusEgressIPs...)
		// status.egressIP is the v1beta1-visible representation of the first address. Treat changes made by an old
		// client as authoritative while preserving the second address when it still belongs to another family.
		statusEgressIPs[0] = statusEgressIP
		if len(statusEgressIPs) == 2 && ipFamily(statusEgressIPs[0]) == ipFamily(statusEgressIPs[1]) {
			statusEgressIPs = statusEgressIPs[:1]
		}
		_ = unstructured.SetNestedStringSlice(object.Object, statusEgressIPs, "status", "egressIPs")
	} else if statusEgressIPFound && statusEgressIP != "" {
		_ = unstructured.SetNestedStringSlice(object.Object, []string{statusEgressIP}, "status", "egressIPs")
	} else {
		// Absence and an explicit empty value both mean that an old client cleared the status.
		unstructured.RemoveNestedField(object.Object, "status", "egressIPs")
	}
	unstructured.RemoveNestedField(object.Object, "status", "egressIP")

	// Policy and status are first-class v1beta2 fields, so keeping copies of them in the annotation would make stale
	// data capable of overriding later v1beta2 updates. Only retain data which has no v1beta2 representation.
	removeConversionData(object)
	if len(preserved.LegacyExternalIPPools) > 0 {
		_ = setConversionData(object, &egressConversionData{LegacyExternalIPPools: preserved.LegacyExternalIPPools})
	}
}

func convertEgressToV1beta1(object *unstructured.Unstructured) error {
	var preserved egressConversionData
	conversionData(object, &preserved)
	if policy, found, _ := unstructured.NestedString(object.Object, "spec", "ipFamilyPolicy"); found {
		preserved.IPFamilyPolicy = policy
	} else {
		preserved.IPFamilyPolicy = ""
	}
	unstructured.RemoveNestedField(object.Object, "spec", "ipFamilyPolicy")

	if egressIPs, found, _ := unstructured.NestedStringSlice(object.Object, "spec", "egressIPs"); found && len(egressIPs) == 1 {
		_ = unstructured.SetNestedField(object.Object, egressIPs[0], "spec", "egressIP")
		unstructured.RemoveNestedField(object.Object, "spec", "egressIPs")
	}
	if len(preserved.LegacyExternalIPPools) > 0 {
		_ = unstructured.SetNestedStringSlice(object.Object, preserved.LegacyExternalIPPools, "spec", "externalIPPools")
	}

	preserved.StatusEgressIPs = nil
	if egressIPs, found, _ := unstructured.NestedStringSlice(object.Object, "status", "egressIPs"); found && len(egressIPs) > 0 {
		preserved.StatusEgressIPs = egressIPs
		_ = unstructured.SetNestedField(object.Object, egressIPs[0], "status", "egressIP")
	} else {
		unstructured.RemoveNestedField(object.Object, "status", "egressIP")
	}
	unstructured.RemoveNestedField(object.Object, "status", "egressIPs")
	return setConversionData(object, &preserved)
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

func convertExternalIPPoolToV1beta2(object *unstructured.Unstructured) {
	var preserved externalIPPoolConversionData
	conversionData(object, &preserved)
	if len(preserved.Gateways) == 0 {
		removeConversionData(object)
		return
	}
	if _, found, _ := unstructured.NestedMap(object.Object, "spec", "subnetInfo"); !found {
		// An old client removed subnetInfo, so its hidden dual-stack representation must be discarded as well.
		removeConversionData(object)
		return
	}

	// Changes made through v1beta1 to the visible subnet are authoritative for that IP family.
	if gateway, found, _ := unstructured.NestedString(object.Object, "spec", "subnetInfo", "gateway"); found {
		prefixLength, _, _ := unstructured.NestedInt64(object.Object, "spec", "subnetInfo", "prefixLength")
		family := ipFamily(gateway)
		for i := range preserved.Gateways {
			preservedGateway, _ := preserved.Gateways[i]["gateway"].(string)
			if ipFamily(preservedGateway) == family {
				preserved.Gateways[i]["gateway"] = gateway
				preserved.Gateways[i]["prefixLength"] = prefixLength
			}
		}
	}
	gateways := make([]interface{}, 0, len(preserved.Gateways))
	for _, gateway := range preserved.Gateways {
		gateways = append(gateways, gateway)
	}
	_ = unstructured.SetNestedSlice(object.Object, gateways, "spec", "subnetInfo", "gateways")
	unstructured.RemoveNestedField(object.Object, "spec", "subnetInfo", "gateway")
	unstructured.RemoveNestedField(object.Object, "spec", "subnetInfo", "prefixLength")
	removeConversionData(object)
}

func convertExternalIPPoolToV1beta1(object *unstructured.Unstructured) error {
	gateways, found, _ := unstructured.NestedSlice(object.Object, "spec", "subnetInfo", "gateways")
	if !found || len(gateways) == 0 {
		// The v1beta2 representation is authoritative. Do not let conversion data from an earlier dual-stack value
		// resurrect gateways after a v1beta2 client switches to the legacy single-stack representation.
		removeConversionData(object)
		return nil
	}
	preserved := externalIPPoolConversionData{Gateways: make([]map[string]interface{}, 0, len(gateways))}
	var visible map[string]interface{}
	for _, item := range gateways {
		gateway, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		preserved.Gateways = append(preserved.Gateways, gateway)
		gatewayIP, _ := gateway["gateway"].(string)
		if visible == nil || ipFamily(gatewayIP) == "IPv4" {
			visible = gateway
		}
	}
	if visible != nil {
		_ = unstructured.SetNestedField(object.Object, visible["gateway"], "spec", "subnetInfo", "gateway")
		_ = unstructured.SetNestedField(object.Object, visible["prefixLength"], "spec", "subnetInfo", "prefixLength")
	}
	unstructured.RemoveNestedField(object.Object, "spec", "subnetInfo", "gateways")
	return setConversionData(object, &preserved)
}

func ipFamily(ip string) string {
	address, err := netip.ParseAddr(ip)
	if err == nil && address.Unmap().Is4() {
		return "IPv4"
	}
	return "IPv6"
}
