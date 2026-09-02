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

package egress

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/schema"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/yaml"
)

func newEgressSchemaValidator(t *testing.T, version string) validation.SchemaValidator {
	t.Helper()
	data, err := os.ReadFile("../../../build/charts/antrea/crds/egress.yaml")
	require.NoError(t, err)
	var crd apiextensionsv1.CustomResourceDefinition
	require.NoError(t, yaml.Unmarshal(data, &crd))
	var versionSchema *apiextensionsv1.JSONSchemaProps
	for _, candidate := range crd.Spec.Versions {
		if candidate.Name == version {
			versionSchema = candidate.Schema.OpenAPIV3Schema
			break
		}
	}
	require.NotNil(t, versionSchema)
	var internalSchema apiextensions.JSONSchemaProps
	require.NoError(t, apiextensionsv1.Convert_v1_JSONSchemaProps_To_apiextensions_JSONSchemaProps(
		versionSchema, &internalSchema, nil))
	structural, err := schema.NewStructural(&internalSchema)
	require.NoError(t, err)
	require.Empty(t, schema.ValidateStructural(field.NewPath("schema"), structural))
	validator, _, err := validation.NewSchemaValidator(&internalSchema)
	require.NoError(t, err)
	return validator
}

func egressForSelectorSchema(version, selectorField string, selector map[string]any) map[string]any {
	appliedTo := map[string]any{}
	if selector != nil {
		appliedTo[selectorField] = selector
	}
	return map[string]any{
		"apiVersion": "crd.antrea.io/" + version,
		"kind":       "Egress",
		"metadata":   map[string]any{"name": "test-egress"},
		"spec": map[string]any{
			"appliedTo":      appliedTo,
			"externalIPPool": "pool",
		},
	}
}

func TestEgressAppliedToSelectorSchema(t *testing.T) {
	validator := newEgressSchemaValidator(t, "v1beta2")
	for _, selectorField := range []string{"podSelector", "namespaceSelector"} {
		t.Run(selectorField, func(t *testing.T) {
			validateSelector := func(t *testing.T, selector map[string]any, valid bool) {
				t.Helper()
				// Exercise the manifest schema without invoking admission webhooks.
				result := validator.Validate(egressForSelectorSchema("v1beta2", selectorField, selector))
				assert.Equal(t, valid, result.IsValid(), "validation errors: %v", result.Errors)
			}
			for _, operator := range []string{"In", "NotIn", "Exists", "DoesNotExist"} {
				for _, values := range []struct {
					name   string
					values []any
				}{
					{name: "omitted"},
					{name: "empty", values: []any{}},
					{name: "nonempty", values: []any{"worker"}},
				} {
					t.Run(operator+"/"+values.name, func(t *testing.T) {
						expression := map[string]any{"key": "role", "operator": operator}
						if values.values != nil {
							expression["values"] = values.values
						}
						valid := len(values.values) == 0
						if operator == "In" || operator == "NotIn" {
							valid = len(values.values) > 0
						}
						validateSelector(t, map[string]any{"matchExpressions": []any{expression}}, valid)
					})
				}
			}

			prefix := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." +
				strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
			for _, tt := range []struct {
				name  string
				key   string
				valid bool
			}{
				{name: "simple key", key: "role", valid: true},
				{name: "qualified key", key: "example.com/Role_Name", valid: true},
				{name: "maximum name length", key: strings.Repeat("a", 63), valid: true},
				{name: "maximum prefix and name length", key: prefix + "/" + strings.Repeat("a", 63), valid: true},
				{name: "empty key"},
				{name: "multiple slashes", key: "invalid/key/name"},
				{name: "uppercase prefix", key: "Example.com/role"},
				{name: "empty DNS label", key: "example..com/role"},
				{name: "name too long", key: strings.Repeat("a", 64)},
				{name: "qualified name too long", key: "example.com/" + strings.Repeat("a", 64)},
				{name: "prefix too long", key: prefix + "d/role"},
			} {
				t.Run(tt.name, func(t *testing.T) {
					validateSelector(t, map[string]any{"matchExpressions": []any{
						map[string]any{"key": tt.key, "operator": "Exists"},
					}}, tt.valid)
				})
			}
			for _, tt := range []struct {
				name  string
				value string
				valid bool
			}{
				{name: "empty value", valid: true},
				{name: "valid value", value: "Worker_1", valid: true},
				{name: "maximum value length", value: strings.Repeat("a", 63), valid: true},
				{name: "value too long", value: strings.Repeat("a", 64)},
				{name: "invalid value", value: "invalid/value"},
			} {
				t.Run(tt.name, func(t *testing.T) {
					validateSelector(t, map[string]any{"matchLabels": map[string]any{"role": tt.value}}, tt.valid)
					validateSelector(t, map[string]any{"matchExpressions": []any{
						map[string]any{"key": "role", "operator": "In", "values": []any{tt.value}},
					}}, tt.valid)
				})
			}
			for _, tt := range []struct {
				name       string
				expression map[string]any
			}{
				{name: "missing key", expression: map[string]any{"operator": "Exists"}},
				{name: "missing operator", expression: map[string]any{"key": "role"}},
				{name: "unknown operator", expression: map[string]any{"key": "role", "operator": "unknown"}},
			} {
				t.Run(tt.name, func(t *testing.T) {
					validateSelector(t, map[string]any{"matchExpressions": []any{tt.expression}}, false)
				})
			}
			t.Run("empty selector", func(t *testing.T) {
				validateSelector(t, map[string]any{}, true)
			})
			t.Run("omitted selector", func(t *testing.T) {
				validateSelector(t, nil, true)
			})
		})
	}
}

func TestEgressAppliedToSelectorRatcheting(t *testing.T) {
	legacyValidator := newEgressSchemaValidator(t, "v1beta1")
	validator := newEgressSchemaValidator(t, "v1beta2")
	// Only v1beta2 tightens selector validation. Updates through v1beta2 which retain invalid legacy selectors
	// require CRD validation ratcheting, enabled by default since Kubernetes 1.30. v1beta1 keeps its previous rules.
	for _, selectorField := range []string{"podSelector", "namespaceSelector"} {
		t.Run(selectorField, func(t *testing.T) {
			for _, tt := range []struct {
				name     string
				selector map[string]any
			}{
				{
					name: "missing key",
					selector: map[string]any{"matchExpressions": []any{
						map[string]any{"operator": "Exists"},
					}},
				},
				{
					name: "missing operator",
					selector: map[string]any{"matchExpressions": []any{
						map[string]any{"key": "role"},
					}},
				},
				{
					name: "In without values",
					selector: map[string]any{"matchExpressions": []any{
						map[string]any{"key": "role", "operator": "In"},
					}},
				},
				{
					name: "Exists with values",
					selector: map[string]any{"matchExpressions": []any{
						map[string]any{"key": "role", "operator": "Exists", "values": []any{"worker"}},
					}},
				},
				{
					name: "invalid key",
					selector: map[string]any{"matchExpressions": []any{
						map[string]any{"key": "invalid/key/name", "operator": "Exists"},
					}},
				},
				{
					name:     "value too long",
					selector: map[string]any{"matchLabels": map[string]any{"role": strings.Repeat("a", 64)}},
				},
			} {
				t.Run(tt.name, func(t *testing.T) {
					legacy := egressForSelectorSchema("v1beta1", selectorField, tt.selector)
					result := legacyValidator.Validate(legacy)
					require.True(t, result.IsValid(), "legacy validation errors: %v", result.Errors)
					legacyUpdate := runtime.DeepCopyJSON(legacy)
					legacyUpdate["spec"].(map[string]any)["egressIP"] = "192.0.2.10"
					assert.True(t, legacyValidator.ValidateUpdate(legacyUpdate, legacy).IsValid())

					old := egressForSelectorSchema("v1beta2", selectorField, tt.selector)
					require.False(t, validator.Validate(old).IsValid(), "new objects must reject the invalid selector")
					for _, update := range []string{"metadata", "Egress IP"} {
						t.Run(update, func(t *testing.T) {
							updated := runtime.DeepCopyJSON(old)
							if update == "metadata" {
								updated["metadata"].(map[string]any)["labels"] = map[string]any{"updated": "true"}
							} else {
								// Match the Controller's merge patch of spec.egressIPs, retaining the selector as stored.
								updated["spec"].(map[string]any)["egressIPs"] = []any{"192.0.2.10"}
							}
							result := validator.ValidateUpdate(updated, old, validation.WithRatcheting(nil))
							assert.True(t, result.IsValid(), "ratcheting errors: %v", result.Errors)
							assert.False(t, validator.ValidateUpdate(updated, old).IsValid(),
								"unchanged invalid selectors require ratcheting")
						})
					}

					repaired := egressForSelectorSchema("v1beta2", selectorField, map[string]any{})
					assert.True(t, validator.ValidateUpdate(repaired, old).IsValid(), "repair must work without ratcheting")
					assert.True(t, validator.ValidateUpdate(repaired, old, validation.WithRatcheting(nil)).IsValid())
					assert.False(t, validator.ValidateUpdate(old, repaired, validation.WithRatcheting(nil)).IsValid(),
						"ratcheting must not allow a valid selector to become invalid")
				})
			}
			t.Run("changing an invalid requirement", func(t *testing.T) {
				old := egressForSelectorSchema("v1beta2", selectorField, map[string]any{
					"matchExpressions": []any{map[string]any{"key": "role", "operator": "In"}},
				})
				updated := egressForSelectorSchema("v1beta2", selectorField, map[string]any{
					"matchExpressions": []any{map[string]any{"key": "tier", "operator": "In"}},
				})
				assert.False(t, validator.ValidateUpdate(updated, old, validation.WithRatcheting(nil)).IsValid())
			})
		})
	}
}
