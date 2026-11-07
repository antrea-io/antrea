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

	admv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ValidateAdmissionRequest verifies that admission receives the original representation and that clients do not
// manipulate conversion state. The validating webhooks register both API versions with matchPolicy Exact: a lossy
// conversion cannot recover all the original fields needed for version-specific validation.
func ValidateAdmissionRequest(request *admv1.AdmissionRequest) error {
	if request == nil {
		return fmt.Errorf("missing admission request")
	}
	if request.RequestResource != nil && request.RequestResource.Version != "" &&
		request.RequestResource.Version != request.Resource.Version {
		return fmt.Errorf("admission requires the original API version; configure the webhook with matchPolicy Exact")
	}
	if request.Operation == admv1.Delete {
		return nil
	}
	type objectMetadata struct {
		metav1.TypeMeta `json:",inline"`
		Metadata        metav1.ObjectMeta `json:"metadata"`
	}
	var newObject, oldObject objectMetadata
	for _, item := range []struct {
		raw    []byte
		object *objectMetadata
	}{{request.Object.Raw, &newObject}, {request.OldObject.Raw, &oldObject}} {
		if len(item.raw) == 0 {
			continue
		}
		if err := json.Unmarshal(item.raw, item.object); err != nil {
			return err
		}
		if request.Resource.Version != "" && item.object.APIVersion != "" &&
			item.object.APIVersion != request.Resource.Group+"/"+request.Resource.Version {
			return fmt.Errorf("object apiVersion %q does not match admission resource version", item.object.APIVersion)
		}
	}
	newData, newFound := newObject.Metadata.Annotations[conversionDataAnnotation]
	oldData, oldFound := oldObject.Metadata.Annotations[conversionDataAnnotation]
	if (request.Operation == admv1.Create && newFound) ||
		(request.Operation == admv1.Update && (newFound != oldFound || newData != oldData)) {
		return fmt.Errorf("annotation %s is reserved for API conversion and cannot be set, changed, or removed by clients", conversionDataAnnotation)
	}
	return nil
}
