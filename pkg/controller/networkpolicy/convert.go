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

package networkpolicy

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

func ConvertClusterGroupCRD(Object *unstructured.Unstructured, toVersion string) (*unstructured.Unstructured, metav1.Status) {
	klog.V(2).Infof("Converting CRD for ClusterGroup %s", Object.GetName())
	convertedObject := Object.DeepCopy()
	fromVersion := Object.GetAPIVersion()
	if toVersion == fromVersion {
		return nil, statusErrorWithMessage("conversion from a version to itself should not call the webhook: %s", toVersion)
	}
	switch Object.GetAPIVersion() {
	case "crd.antrea.io/v1alpha2":
		switch toVersion {
		case "crd.antrea.io/v1alpha3":
			ipb, found, err := unstructured.NestedMap(convertedObject.Object, "spec", "ipBlock")
			if err == nil && found && len(ipb) > 0 {
				unstructured.RemoveNestedField(convertedObject.Object, "spec", "ipBlock")
				// unstructured.SetNestedSlice expects a slice of interface as value
				ipBlocks := make([]interface{}, 1)
				ipBlocks[0] = ipb
				unstructured.SetNestedSlice(convertedObject.Object, ipBlocks, "spec", "ipBlocks")
			}
		default:
			return nil, statusErrorWithMessage("unexpected conversion version %q", toVersion)
		}
	case "crd.antrea.io/v1alpha3":
		switch toVersion {
		case "crd.antrea.io/v1alpha2":
			return convertedObject, metav1.Status{
				Status: metav1.StatusSuccess,
			}
		default:
			return nil, statusErrorWithMessage("unexpected conversion version %q", toVersion)
		}
	default:
		return nil, statusErrorWithMessage("unexpected conversion version %q", fromVersion)
	}
	return convertedObject, metav1.Status{
		Status: metav1.StatusSuccess,
	}
}
