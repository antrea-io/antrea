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
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/schema"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/schema/listtype"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/yaml"
)

func TestEgressConditionsSchema(t *testing.T) {
	raw, err := os.ReadFile("../../../build/charts/antrea/crds/egress.yaml")
	require.NoError(t, err)
	var crd apiextensionsv1.CustomResourceDefinition
	require.NoError(t, yaml.Unmarshal(raw, &crd))
	var versionSchema *apiextensionsv1.JSONSchemaProps
	for _, version := range crd.Spec.Versions {
		if version.Name == "v1beta2" {
			versionSchema = version.Schema.OpenAPIV3Schema
		}
	}
	require.NotNil(t, versionSchema)
	conditions := versionSchema.Properties["status"].Properties["conditions"]
	require.NotNil(t, conditions.XListType)
	assert.Equal(t, "map", *conditions.XListType)
	assert.Equal(t, []string{"type"}, conditions.XListMapKeys)
	assert.ElementsMatch(t, []string{"type", "status", "lastTransitionTime", "reason", "message"}, conditions.Items.Schema.Required)
	var internalSchema apiextensions.JSONSchemaProps
	require.NoError(t, apiextensionsv1.Convert_v1_JSONSchemaProps_To_apiextensions_JSONSchemaProps(versionSchema, &internalSchema, nil))
	structural, err := schema.NewStructural(&internalSchema)
	require.NoError(t, err)
	require.Empty(t, schema.ValidateStructural(field.NewPath("schema"), structural))
	validator, _, err := validation.NewSchemaValidator(&internalSchema)
	require.NoError(t, err)
	condition := func(fields map[string]interface{}) map[string]interface{} {
		result := map[string]interface{}{
			"type": "IPAllocated", "status": "True", "lastTransitionTime": "2026-11-08T00:00:00Z",
			"reason": "Allocated", "message": "EgressIP is successfully allocated",
		}
		for key, value := range fields {
			result[key] = value
		}
		return result
	}
	for _, tc := range []struct {
		name       string
		conditions []interface{}
		omitField  string
		omitStatus bool
		valid      bool
	}{
		{name: "status omitted", omitStatus: true, valid: true},
		{name: "conditions omitted", valid: true},
		{name: "empty", conditions: []interface{}{}, valid: true},
		{name: "standard condition", conditions: []interface{}{condition(nil)}, valid: true},
		{name: "unknown status", conditions: []interface{}{condition(map[string]interface{}{"status": "Unknown"})}, valid: true},
		{name: "empty message", conditions: []interface{}{condition(map[string]interface{}{"message": ""})}, valid: true},
		{name: "qualified type", conditions: []interface{}{condition(map[string]interface{}{"type": "example.com/Ready"})}, valid: true},
		{name: "observed generation", conditions: []interface{}{condition(map[string]interface{}{"observedGeneration": int64(7)})}, valid: true},
		{name: "negative observed generation", conditions: []interface{}{condition(map[string]interface{}{"observedGeneration": int64(-1)})}},
		{name: "invalid type", conditions: []interface{}{condition(map[string]interface{}{"type": "invalid type"})}},
		{name: "invalid status", conditions: []interface{}{condition(map[string]interface{}{"status": "invalid"})}},
		{name: "empty reason", conditions: []interface{}{condition(map[string]interface{}{"reason": ""})}},
		{name: "invalid reason", conditions: []interface{}{condition(map[string]interface{}{"reason": "invalid reason"})}},
		{name: "reason too long", conditions: []interface{}{condition(map[string]interface{}{"reason": strings.Repeat("A", 1025)})}},
		{name: "message too long", conditions: []interface{}{condition(map[string]interface{}{"message": strings.Repeat("a", 32769)})}},
		{name: "transition time with offset", conditions: []interface{}{condition(map[string]interface{}{"lastTransitionTime": "2026-11-08T08:00:00+08:00"})}, valid: true},
		{name: "invalid transition time", conditions: []interface{}{condition(map[string]interface{}{"lastTransitionTime": "not-a-time"})}},
		{name: "date without time", conditions: []interface{}{condition(map[string]interface{}{"lastTransitionTime": "2026-11-08"})}},
		{name: "distinct types", conditions: []interface{}{condition(nil), condition(map[string]interface{}{"type": "IPAssigned"})}, valid: true},
		{name: "duplicate types", conditions: []interface{}{condition(nil), condition(nil)}},
		{name: "missing type", conditions: []interface{}{condition(nil)}, omitField: "type"},
		{name: "missing status", conditions: []interface{}{condition(nil)}, omitField: "status"},
		{name: "missing transition time", conditions: []interface{}{condition(nil)}, omitField: "lastTransitionTime"},
		{name: "missing reason", conditions: []interface{}{condition(nil)}, omitField: "reason"},
		{name: "missing message", conditions: []interface{}{condition(nil)}, omitField: "message"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status := map[string]interface{}{}
			if tc.conditions != nil {
				if tc.omitField != "" {
					delete(tc.conditions[0].(map[string]interface{}), tc.omitField)
				}
				status["conditions"] = tc.conditions
			}
			object := map[string]interface{}{"spec": map[string]interface{}{
				"appliedTo": map[string]interface{}{}, "egressIPs": []interface{}{"192.0.2.10"},
			}}
			if !tc.omitStatus {
				object["status"] = status
			}
			errs := validation.ValidateCustomResource(field.NewPath("object"), object, validator)
			errs = append(errs, listtype.ValidateListSetsAndMaps(field.NewPath("object"), structural, object)...)
			if tc.valid {
				assert.Empty(t, errs)
			} else {
				assert.NotEmpty(t, errs)
			}
		})
	}
}

func TestEgressConditionsRoundTrip(t *testing.T) {
	conditions := []interface{}{
		map[string]interface{}{
			"type": "IPAllocated", "status": "True", "lastTransitionTime": "2026-11-08T00:00:00Z",
			"reason": "Allocated", "message": "EgressIP is successfully allocated", "observedGeneration": int64(7),
		},
		map[string]interface{}{
			"type": "IPAssigned", "status": "False", "lastTransitionTime": "2026-11-08T00:01:00Z",
			"reason": "AssignmentError", "message": "No Node is available",
		},
	}
	original := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": v1beta2APIVersion, "kind": "Egress",
		"metadata": map[string]interface{}{"name": "conditions"},
		"spec": map[string]interface{}{
			"appliedTo": map[string]interface{}{}, "egressIPs": []interface{}{"192.0.2.10"},
		},
		"status": map[string]interface{}{"conditions": conditions},
	}}
	requireValidForCRDVersion(t, "../../../build/charts/antrea/crds/egress.yaml", "v1beta2", original)
	legacy, status := ConvertEgress(original, v1beta1APIVersion)
	requireConversionSuccess(t, status)
	requireValidForCRDVersion(t, "../../../build/charts/antrea/crds/egress.yaml", "v1beta1", legacy)
	converted, status := ConvertEgress(legacy, v1beta2APIVersion)
	requireConversionSuccess(t, status)
	requireValidForCRDVersion(t, "../../../build/charts/antrea/crds/egress.yaml", "v1beta2", converted)
	actual, found, err := unstructured.NestedSlice(converted.Object, "status", "conditions")
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, conditions, actual)
	legacyConditions, _, err := unstructured.NestedSlice(legacy.Object, "status", "conditions")
	require.NoError(t, err)
	for _, condition := range legacyConditions {
		assert.NotContains(t, condition.(map[string]interface{}), "observedGeneration")
	}
}

func TestEgressLegacyConditions(t *testing.T) {
	for _, tc := range []struct {
		name      string
		created   string
		timestamp string
	}{
		{name: "creation time", created: "2026-11-08T00:00:00Z", timestamp: "2026-11-08T00:00:00Z"},
		{name: "no creation time", timestamp: "1970-01-01T00:00:00Z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			object := &unstructured.Unstructured{Object: map[string]interface{}{
				"apiVersion": v1beta1APIVersion, "kind": "Egress",
				"metadata": map[string]interface{}{"name": "legacy", "generation": int64(99)},
				"spec":     map[string]interface{}{"appliedTo": map[string]interface{}{}, "egressIP": "192.0.2.10"},
				"status": map[string]interface{}{"conditions": []interface{}{
					map[string]interface{}{"type": "IPAssigned", "status": "True"},
				}},
			}}
			if tc.created != "" {
				require.NoError(t, unstructured.SetNestedField(object.Object, tc.created, "metadata", "creationTimestamp"))
			}
			requireValidForCRDVersion(t, "../../../build/charts/antrea/crds/egress.yaml", "v1beta1", object)
			converted, status := ConvertEgress(object, v1beta2APIVersion)
			requireConversionSuccess(t, status)
			requireValidForCRDVersion(t, "../../../build/charts/antrea/crds/egress.yaml", "v1beta2", converted)
			conditions, _, err := unstructured.NestedSlice(converted.Object, "status", "conditions")
			require.NoError(t, err)
			assert.Equal(t, map[string]interface{}{
				"type": "IPAssigned", "status": "True", "reason": "Unknown", "message": "",
				"lastTransitionTime": tc.timestamp,
			}, conditions[0])
			again, status := ConvertEgress(object, v1beta2APIVersion)
			requireConversionSuccess(t, status)
			assert.Equal(t, converted.Object, again.Object, "conversion must not generate a new timestamp on each read")
		})
	}
}

func TestEgressConditionObservedGenerationAfterLegacyUpdate(t *testing.T) {
	for _, tc := range []struct {
		name       string
		field      string
		value      string
		generation int64
	}{
		{name: "unchanged", generation: 7},
		{name: "status changed", field: "status", value: "False"},
		{name: "reason changed", field: "reason", value: "AllocationError"},
		{name: "message changed", field: "message", value: "another observation"},
		{name: "time changed", field: "lastTransitionTime", value: "2026-11-09T00:00:00Z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			object := &unstructured.Unstructured{Object: map[string]interface{}{
				"apiVersion": v1beta2APIVersion, "kind": "Egress",
				"metadata": map[string]interface{}{"name": "conditions"},
				"spec":     map[string]interface{}{"appliedTo": map[string]interface{}{}, "egressIPs": []interface{}{"192.0.2.10"}},
				"status": map[string]interface{}{"conditions": []interface{}{
					map[string]interface{}{
						"type": "IPAllocated", "status": "True", "reason": "Allocated", "message": "allocated",
						"lastTransitionTime": "2026-11-08T00:00:00Z", "observedGeneration": int64(7),
					},
				}},
			}}
			legacy, status := ConvertEgress(object, v1beta1APIVersion)
			requireConversionSuccess(t, status)
			conditions, _, err := unstructured.NestedSlice(legacy.Object, "status", "conditions")
			require.NoError(t, err)
			if tc.field != "" {
				conditions[0].(map[string]interface{})[tc.field] = tc.value
			}
			// A different condition must not inherit the preserved generation.
			conditions = append(conditions, map[string]interface{}{
				"type": "IPAssigned", "status": "True", "reason": "Assigned", "message": "assigned",
				"lastTransitionTime": "2026-11-08T00:00:00Z",
			})
			require.NoError(t, unstructured.SetNestedSlice(legacy.Object, conditions, "status", "conditions"))
			converted, status := ConvertEgress(legacy, v1beta2APIVersion)
			requireConversionSuccess(t, status)
			actual, _, err := unstructured.NestedSlice(converted.Object, "status", "conditions")
			require.NoError(t, err)
			generation, _, err := unstructured.NestedInt64(actual[0].(map[string]interface{}), "observedGeneration")
			require.NoError(t, err)
			assert.Equal(t, tc.generation, generation)
			assert.NotContains(t, actual[1].(map[string]interface{}), "observedGeneration")
		})
	}
}
