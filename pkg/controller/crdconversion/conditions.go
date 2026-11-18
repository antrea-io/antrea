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
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

func convertEgressConditionsToV1beta1(object *unstructured.Unstructured) ([]metav1.Condition, error) {
	conditions, found, _ := unstructured.NestedSlice(object.Object, "status", "conditions")
	if !found {
		return nil, nil
	}
	var preserved []metav1.Condition
	for _, value := range conditions {
		condition, ok := value.(map[string]interface{})
		if !ok {
			continue
		}
		generation, _, _ := unstructured.NestedInt64(condition, "observedGeneration")
		if generation > 0 {
			var snapshot metav1.Condition
			if err := runtime.DefaultUnstructuredConverter.FromUnstructured(condition, &snapshot); err != nil {
				return nil, fmt.Errorf("preserving Egress condition: %w", err)
			}
			preserved = append(preserved, snapshot)
		}
		delete(condition, "observedGeneration")
	}
	_ = unstructured.SetNestedSlice(object.Object, conditions, "status", "conditions")
	return preserved, nil
}

func convertEgressConditionsToV1beta2(object *unstructured.Unstructured, preserved []metav1.Condition) {
	conditions, found, _ := unstructured.NestedSlice(object.Object, "status", "conditions")
	if !found {
		return
	}
	for _, value := range conditions {
		condition, ok := value.(map[string]interface{})
		if !ok {
			continue
		}
		var current metav1.Condition
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(condition, &current); err == nil {
			for _, snapshot := range preserved {
				// A legacy writer cannot report observedGeneration. Restore it only while all fields it can
				// update are unchanged, so a new observation is never inferred from an old condition.
				if current.Type == snapshot.Type && current.Status == snapshot.Status &&
					current.Reason == snapshot.Reason && current.Message == snapshot.Message &&
					current.LastTransitionTime.Equal(&snapshot.LastTransitionTime) {
					condition["observedGeneration"] = snapshot.ObservedGeneration
					break
				}
			}
		}
		// v1beta1 allowed these fields to be omitted. Use stable defaults instead of the conversion time,
		// so reads do not manufacture new transitions and old objects can be updated through v1beta2.
		if reason, _, _ := unstructured.NestedString(condition, "reason"); reason == "" {
			condition["reason"] = "Unknown"
		}
		if _, found := condition["message"]; !found {
			condition["message"] = ""
		}
		if timestamp, _, _ := unstructured.NestedString(condition, "lastTransitionTime"); timestamp == "" {
			transitionTime := object.GetCreationTimestamp()
			if transitionTime.IsZero() {
				transitionTime = metav1.NewTime(time.Unix(0, 0).UTC())
			}
			condition["lastTransitionTime"] = transitionTime.UTC().Format(time.RFC3339)
		}
	}
	_ = unstructured.SetNestedSlice(object.Object, conditions, "status", "conditions")
}
