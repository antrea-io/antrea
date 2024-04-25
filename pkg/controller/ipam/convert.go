// Copyright 2024 Antrea Authors
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

package ipam

import (
	"fmt"
	"net"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/klog/v2"
)

func statusErrorWithMessage(msg string, params ...interface{}) metav1.Status {
	return metav1.Status{
		Message: fmt.Sprintf(msg, params...),
		Status:  metav1.StatusFailure,
	}
}

func ConvertIPPool(object *unstructured.Unstructured, toVersion string) (*unstructured.Unstructured, metav1.Status) {
	convertedObject := object.DeepCopy()
	fromVersion := object.GetAPIVersion()
	if toVersion == fromVersion {
		return nil, statusErrorWithMessage("conversion from a version to itself should not call the webhook: %s", toVersion)
	}
	klog.V(2).InfoS("Converting CRD for IPPool", "fromVersion", fromVersion, "toVersion", toVersion)
	switch fromVersion {
	case "crd.antrea.io/v1alpha2":
		switch toVersion {
		case "crd.antrea.io/v1beta1":
			unstructured.RemoveNestedField(convertedObject.Object, "spec", "ipVersion")
			ipRanges, _, _ := unstructured.NestedSlice(convertedObject.Object, "spec", "ipRanges")
			var subnetInfo map[string]interface{}
			for _, r := range ipRanges {
				ipRange, ok := r.(map[string]interface{})
				if !ok {
					return nil, statusErrorWithMessage("failed to convert ipRange")
				}
				if subnetInfo == nil {
					subnetInfo = make(map[string]interface{})
					subnetInfo["gateway"] = ipRange["gateway"]
					subnetInfo["prefixLength"] = ipRange["prefixLength"]
					vlan, ok := ipRange["vlan"]
					if ok {
						subnetInfo["vlan"] = vlan
					}
				} else {
					if subnetInfo["gateway"] != ipRange["gateway"] || subnetInfo["prefixLength"] != ipRange["prefixLength"] || subnetInfo["vlan"] != ipRange["vlan"] {
						return nil, statusErrorWithMessage("failed to convert IPPool from version v1alpha2 to to version v1beta1 because the original ipRanges have different subnet information")
					}
				}
				delete(ipRange, "gateway")
				delete(ipRange, "prefixLength")
				delete(ipRange, "vlan")

			}
			unstructured.SetNestedField(convertedObject.Object, ipRanges, "spec", "ipRanges")
			unstructured.SetNestedField(convertedObject.Object, subnetInfo, "spec", "subnetInfo")
		default:
			return nil, statusErrorWithMessage("unexpected conversion fromVersion %q to toVersion %q", fromVersion, toVersion)
		}
	case "crd.antrea.io/v1beta1":
		switch toVersion {
		case "crd.antrea.io/v1alpha2":
			gateway, _, _ := unstructured.NestedString(convertedObject.Object, "spec", "subnetInfo", "gateway")
			gatewayIP := net.ParseIP(gateway)
			ipVersion := 4
			if gatewayIP.To4() == nil {
				ipVersion = 6
			}
			unstructured.SetNestedField(convertedObject.Object, int64(ipVersion), "spec", "ipVersion")
			ipRanges, _, _ := unstructured.NestedSlice(convertedObject.Object, "spec", "ipRanges")
			subnetInfo, _, _ := unstructured.NestedMap(convertedObject.Object, "spec", "subnetInfo")
			for _, r := range ipRanges {
				ipRange, ok := r.(map[string]interface{})
				if !ok {
					return nil, statusErrorWithMessage("failed to convert ipRange")
				}
				ipRange["gateway"] = subnetInfo["gateway"]
				ipRange["prefixLength"] = subnetInfo["prefixLength"]
				vlan, ok := subnetInfo["vlan"]
				if ok {
					ipRange["vlan"] = vlan
				}
			}
			unstructured.SetNestedField(convertedObject.Object, ipRanges, "spec", "ipRanges")
			unstructured.RemoveNestedField(convertedObject.Object, "spec", "subnetInfo")
		default:
			return nil, statusErrorWithMessage("unexpected conversion fromVersion %q to toVersion %q", fromVersion, toVersion)
		}
	default:
		return nil, statusErrorWithMessage("unexpected conversion fromVersion %q to toVersion %q", fromVersion, toVersion)
	}
	return convertedObject, metav1.Status{
		Status: metav1.StatusSuccess,
	}
}
