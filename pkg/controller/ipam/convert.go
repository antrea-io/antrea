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

func ConvertIPPoolCRD(object *unstructured.Unstructured, toVersion string) (*unstructured.Unstructured, metav1.Status) {
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
			newRanges := make([]interface{}, len(ipRanges))
			var subnetInfo map[string]interface{}
			for i, r := range ipRanges {
				ipRange, ok := r.(map[string]interface{})
				if !ok {
					return nil, statusErrorWithMessage("failed to convert ipRange")
				}
				if subnetInfo == nil {
					subnetInfo = make(map[string]interface{})
					subnetInfo["gateway"] = ipRange["gateway"]
					delete(ipRange, "gateway")
					subnetInfo["prefixLength"] = ipRange["prefixLength"]
					delete(ipRange, "prefixLength")
					vlan, ok := ipRange["vlan"]
					if ok {
						subnetInfo["vlan"] = vlan
						delete(ipRange, "vlan")
					}
				}
				newRanges[i] = ipRange
			}
			unstructured.SetNestedField(convertedObject.Object, newRanges, "spec", "ipRanges")
			unstructured.SetNestedField(convertedObject.Object, subnetInfo, "spec", "subnetInfo")
		default:
			return nil, statusErrorWithMessage("unexpected conversion fromVersion %q to toVersion %q", fromVersion, toVersion)
		}
	case "crd.antrea.io/v1beta1":
		switch toVersion {
		case "crd.antrea.io/v1alpha2":
			klog.V(2).InfoS("Converting CRD for IPPool, nothing to do in this case", "fromVersion", fromVersion, "toVersion", toVersion)
			return convertedObject, metav1.Status{
				Status: metav1.StatusSuccess,
			}
		default:
			return nil, statusErrorWithMessage("unexpected conversion version %q", toVersion)
		}
	default:
		return nil, statusErrorWithMessage("unexpected conversion fromVersion %q to toVersion %q", fromVersion, toVersion)
	}
	return convertedObject, metav1.Status{
		Status: metav1.StatusSuccess,
	}
}
