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

package externalippool

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/schema"
	schemacel "k8s.io/apiextensions-apiserver/pkg/apiserver/schema/cel"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
	"sigs.k8s.io/yaml"
)

func TestExternalIPPoolNodeSelectorSchema(t *testing.T) {
	data, err := os.ReadFile("../../../build/charts/antrea/crds/externalippool.yaml")
	require.NoError(t, err)
	var crd apiextensionsv1.CustomResourceDefinition
	require.NoError(t, yaml.Unmarshal(data, &crd))
	var openAPISchema apiextensions.JSONSchemaProps
	require.NoError(t, apiextensionsv1.Convert_v1_JSONSchemaProps_To_apiextensions_JSONSchemaProps(
		crd.Spec.Versions[0].Schema.OpenAPIV3Schema, &openAPISchema, nil))
	structural, err := schema.NewStructural(&openAPISchema)
	require.NoError(t, err)
	require.Empty(t, schema.ValidateStructural(field.NewPath("schema"), structural))
	validator, _, err := validation.NewSchemaValidator(&openAPISchema)
	require.NoError(t, err)

	validateSelector := func(t *testing.T, selector map[string]any, valid bool) {
		t.Helper()
		// Validate only the manifest schema, without invoking the admission webhook.
		object := map[string]any{"spec": map[string]any{
			"ipRanges":     []any{map[string]any{"cidr": "192.0.2.0/24"}},
			"nodeSelector": selector,
		}}
		errs := validation.ValidateCustomResource(field.NewPath(""), object, validator)
		if valid {
			assert.Empty(t, errs)
		} else {
			assert.NotEmpty(t, errs)
		}
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
				var valid bool
				switch operator {
				case "In", "NotIn":
					valid = len(values.values) > 0
				case "Exists", "DoesNotExist":
					valid = len(values.values) == 0
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
}

func TestExternalIPPoolSubnetInfoSchema(t *testing.T) {
	data, err := os.ReadFile("../../../build/charts/antrea/crds/externalippool.yaml")
	require.NoError(t, err)
	var crd apiextensionsv1.CustomResourceDefinition
	require.NoError(t, yaml.Unmarshal(data, &crd))
	var openAPISchema apiextensions.JSONSchemaProps
	require.NoError(t, apiextensionsv1.Convert_v1_JSONSchemaProps_To_apiextensions_JSONSchemaProps(
		crd.Spec.Versions[0].Schema.OpenAPIV3Schema, &openAPISchema, nil))
	structural, err := schema.NewStructural(&openAPISchema)
	require.NoError(t, err)
	require.Empty(t, schema.ValidateStructural(field.NewPath("schema"), structural))
	validator := schemacel.NewValidator(structural, true, celconfig.PerCallLimit)
	require.NotNil(t, validator)

	newObject := func(withSubnetInfo bool) map[string]any {
		spec := map[string]any{
			"ipRanges":     []any{map[string]any{"cidr": "192.0.2.0/24"}},
			"nodeSelector": map[string]any{},
		}
		if withSubnetInfo {
			spec["subnetInfo"] = map[string]any{
				"gateway":      "192.0.2.1",
				"prefixLength": int64(24),
			}
		}
		return map[string]any{"spec": spec}
	}
	for _, tt := range []struct {
		name          string
		create        bool
		oldSubnetInfo bool
		newSubnetInfo bool
		mutate        func(map[string]any)
		errMsg        string
	}{
		{
			name:   "create without subnetInfo",
			create: true,
		},
		{
			name:          "create with subnetInfo",
			create:        true,
			newSubnetInfo: true,
		},
		{
			name: "unchanged without subnetInfo",
		},
		{
			name:          "unchanged with subnetInfo",
			oldSubnetInfo: true,
			newSubnetInfo: true,
		},
		{
			name:          "gateway mutation",
			oldSubnetInfo: true,
			newSubnetInfo: true,
			mutate: func(object map[string]any) {
				object["spec"].(map[string]any)["subnetInfo"].(map[string]any)["gateway"] = "192.0.2.2"
			},
			errMsg: "gateway is immutable",
		},
		{
			name:          "prefixLength mutation",
			oldSubnetInfo: true,
			newSubnetInfo: true,
			mutate: func(object map[string]any) {
				object["spec"].(map[string]any)["subnetInfo"].(map[string]any)["prefixLength"] = int64(25)
			},
			errMsg: "prefixLength is immutable",
		},
		{
			name:          "add subnetInfo",
			newSubnetInfo: true,
			errMsg:        "subnetInfo cannot be added or removed",
		},
		{
			name:          "remove subnetInfo",
			oldSubnetInfo: true,
			errMsg:        "subnetInfo cannot be added or removed",
		},
		{
			name:          "VLAN mutation",
			oldSubnetInfo: true,
			newSubnetInfo: true,
			mutate: func(object map[string]any) {
				object["spec"].(map[string]any)["subnetInfo"].(map[string]any)["vlan"] = int64(10)
			},
		},
		{
			name:          "status mutation",
			oldSubnetInfo: true,
			newSubnetInfo: true,
			mutate: func(object map[string]any) {
				object["status"] = map[string]any{"usage": map[string]any{"total": int64(252), "used": int64(1)}}
			},
		},
		{
			name:          "nodeSelector mutation with subnetInfo",
			oldSubnetInfo: true,
			newSubnetInfo: true,
			mutate: func(object map[string]any) {
				object["spec"].(map[string]any)["nodeSelector"] = map[string]any{
					"matchLabels": map[string]any{"role": "worker"},
				}
			},
		},
		{
			name: "nodeSelector mutation without subnetInfo",
			mutate: func(object map[string]any) {
				object["spec"].(map[string]any)["nodeSelector"] = map[string]any{
					"matchLabels": map[string]any{"role": "worker"},
				}
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			object := newObject(tt.newSubnetInfo)
			if tt.mutate != nil {
				tt.mutate(object)
			}
			var oldObject any
			if !tt.create {
				oldObject = newObject(tt.oldSubnetInfo)
			}
			// Execute the manifest's CEL transition rules without invoking the admission webhook.
			errs, _ := validator.Validate(t.Context(), field.NewPath(""), structural, object, oldObject,
				celconfig.RuntimeCELCostBudget)
			if tt.errMsg == "" {
				assert.Empty(t, errs)
			} else {
				require.Len(t, errs, 1)
				assert.Equal(t, tt.errMsg, errs[0].Detail)
			}
		})
	}
}
