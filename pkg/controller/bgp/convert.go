// Copyright 2025 Antrea Authors
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

package bgp

import (
	"fmt"
	"math"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func statusErrorWithMessage(msg string, params ...interface{}) metav1.Status {
	return metav1.Status{
		Message: fmt.Sprintf(msg, params...),
		Status:  metav1.StatusFailure,
	}
}

func ConvertBGPPolicy(object *unstructured.Unstructured, toVersion string) (*unstructured.Unstructured, metav1.Status) {
	convertedObject := object.DeepCopy()
	fromVersion := object.GetAPIVersion()
	if toVersion == fromVersion {
		return nil, statusErrorWithMessage("conversion from a version to itself should not call the webhook: %s", toVersion)
	}

	switch fromVersion {
	case "crd.antrea.io/v1alpha1":
		switch toVersion {
		case "crd.antrea.io/v1alpha2":
			// Nothing to do; a valid v1alpha1 object is also a valid v1alpha2 object.
			break
		default:
			return nil, statusErrorWithMessage("unexpected conversion fromVersion %q to toVersion %q", fromVersion, toVersion)
		}
	case "crd.antrea.io/v1alpha2":
		switch toVersion {
		case "crd.antrea.io/v1alpha1":
			// When converting from v1alpha2 to v1alpha2 we have a problem.
			// * v1alpha2 allows for 32-bit ASNs, v1alpha1 only allows 16-bit ASNs.
			// * Conversion between object versions /must/ succeed, failure is not a (valid) option
			// As 32-bit ASNs can't be represented using 16-bits (doh), we instead replace them with 0.
			// The resulting object isn't valid according to the CRD or BGP spec, and should be ignored.

			localASN, _, _ := unstructured.NestedInt64(convertedObject.Object, "spec", "localASN")
			if localASN > math.MaxUint16 {
				unstructured.SetNestedField(convertedObject.Object, int64(0), "spec", "localASN")
			}

			bgpPeers, _, _ := unstructured.NestedSlice(convertedObject.Object, "spec", "bgpPeers")
			for _, r := range bgpPeers {
				bgpPeer, _ := r.(map[string]interface{})
				peerASN, _ := bgpPeer["asn"].(int64)
				if peerASN > math.MaxUint16 {
					bgpPeer["asn"] = int64(0)
				}
			}

			unstructured.SetNestedSlice(convertedObject.Object, bgpPeers, "spec", "bgpPeers")

			confederation, ok, _ := unstructured.NestedMap(convertedObject.Object, "spec", "confederation")
			if ok {
				confederationID, _ := confederation["identifier"].(int64)
				if confederationID > math.MaxUint16 {
					confederation["identifier"] = int64(0)
				}

				memberASNs, _ := confederation["memberASNs"].([]interface{})
				for i := range memberASNs {
					memberASN := memberASNs[i].(int64)
					// We replace invalid ASNs with 0 here instead of removing them
					// from the list to avoid generating valid v1alpha1 objects where
					// the configuration is functionally different from the v1alpha2 version.
					if memberASN > math.MaxUint16 {
						memberASNs[i] = int64(0)
					}
				}

				unstructured.SetNestedMap(convertedObject.Object, confederation, "spec", "confederation")
			}

		default:
			return nil, statusErrorWithMessage("unexpected conversion fromVersion %q to toVersion %q", fromVersion, toVersion)
		}
	}

	return convertedObject, metav1.Status{
		Status: metav1.StatusSuccess,
	}
}
