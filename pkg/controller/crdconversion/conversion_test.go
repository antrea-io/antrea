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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	crvalidation "k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/yaml"
)

func requireConversionSuccess(t *testing.T, status metav1.Status) {
	t.Helper()
	require.Equal(t, metav1.StatusSuccess, status.Status, status.Message)
}

func requireStringSlice(t *testing.T, object *unstructured.Unstructured, expected []string, fields ...string) {
	t.Helper()
	actual, found, err := unstructured.NestedStringSlice(object.Object, fields...)
	require.NoError(t, err)
	require.True(t, found, "field %v was not found", fields)
	assert.Equal(t, expected, actual)
}

func requireValidForCRDVersion(t *testing.T, path, version string, object *unstructured.Unstructured) {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var crd apiextensionsv1.CustomResourceDefinition
	require.NoError(t, yaml.Unmarshal(raw, &crd))
	for _, candidate := range crd.Spec.Versions {
		if candidate.Name != version {
			continue
		}
		var schema apiextensions.JSONSchemaProps
		require.NoError(t, apiextensionsv1.Convert_v1_JSONSchemaProps_To_apiextensions_JSONSchemaProps(candidate.Schema.OpenAPIV3Schema, &schema, nil))
		validator, _, err := crvalidation.NewSchemaValidator(&schema)
		require.NoError(t, err)
		errors := crvalidation.ValidateCustomResource(field.NewPath("object"), object.Object, validator)
		require.Empty(t, errors, "converted object does not satisfy %s/%s: %v", crd.Name, version, errors)
		return
	}
	t.Fatalf("version %s not found in %s", version, path)
}

func TestConvertEgressSingleStack(t *testing.T) {
	v1beta1Egress := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": v1beta1APIVersion,
		"kind":       "Egress",
		"metadata":   map[string]interface{}{"name": "single"},
		"spec": map[string]interface{}{
			"egressIP":       "192.0.2.10",
			"externalIPPool": "pool",
		},
		"status": map[string]interface{}{
			"egressIP":   "192.0.2.10",
			"egressNode": "node-a",
		},
	}}

	v1beta2Egress, status := ConvertEgress(v1beta1Egress, v1beta2APIVersion)
	requireConversionSuccess(t, status)
	require.Equal(t, v1beta2APIVersion, v1beta2Egress.GetAPIVersion())
	requireStringSlice(t, v1beta2Egress, []string{"192.0.2.10"}, "spec", "egressIPs")
	requireStringSlice(t, v1beta2Egress, []string{"192.0.2.10"}, "status", "egressIPs")
	assert.Equal(t, "SingleStack", mustNestedString(t, v1beta2Egress, "spec", "ipFamilyPolicy"))
	_, found, _ := unstructured.NestedFieldNoCopy(v1beta2Egress.Object, "spec", "egressIP")
	assert.False(t, found)
	_, found, _ = unstructured.NestedFieldNoCopy(v1beta2Egress.Object, "status", "egressIP")
	assert.False(t, found)

	roundTripped, status := ConvertEgress(v1beta2Egress, v1beta1APIVersion)
	requireConversionSuccess(t, status)
	assert.Equal(t, "192.0.2.10", mustNestedString(t, roundTripped, "spec", "egressIP"))
	assert.Equal(t, "192.0.2.10", mustNestedString(t, roundTripped, "status", "egressIP"))
	_, found, _ = unstructured.NestedFieldNoCopy(roundTripped.Object, "status", "egressIPs")
	assert.False(t, found)
}

func TestConvertEgressDualStackRoundTrip(t *testing.T) {
	v1beta2Egress := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": v1beta2APIVersion,
		"kind":       "Egress",
		"metadata":   map[string]interface{}{"name": "dual"},
		"spec": map[string]interface{}{
			"appliedTo":      map[string]interface{}{},
			"egressIPs":      []interface{}{"192.0.2.10", "2001:db8::10"},
			"externalIPPool": "pool",
			"ipFamilyPolicy": "RequireDualStack",
		},
		"status": map[string]interface{}{
			"egressIPs":  []interface{}{"192.0.2.10", "2001:db8::10"},
			"egressNode": "node-a",
		},
	}}

	v1beta1Egress, status := ConvertEgress(v1beta2Egress, v1beta1APIVersion)
	requireConversionSuccess(t, status)
	requireValidForCRDVersion(t, "../../../build/charts/antrea/crds/egress.yaml", "v1beta1", v1beta1Egress)
	assert.Equal(t, "192.0.2.10", mustNestedString(t, v1beta1Egress, "spec", "egressIP"))
	assert.Equal(t, "192.0.2.10", mustNestedString(t, v1beta1Egress, "status", "egressIP"))
	_, found, _ := unstructured.NestedFieldNoCopy(v1beta1Egress.Object, "spec", "ipFamilyPolicy")
	assert.False(t, found)
	_, found, _ = unstructured.NestedFieldNoCopy(v1beta1Egress.Object, "spec", "egressIPs")
	assert.False(t, found, "the v1beta1 projection must use only the singular oneOf branch")
	_, found, _ = unstructured.NestedFieldNoCopy(v1beta1Egress.Object, "spec", "externalIPPools")
	assert.False(t, found)
	_, found, _ = unstructured.NestedFieldNoCopy(v1beta1Egress.Object, "status", "egressIPs")
	assert.False(t, found)
	// A status update made through the old API must update the visible address without dropping the other family.
	require.NoError(t, unstructured.SetNestedField(v1beta1Egress.Object, "192.0.2.20", "status", "egressIP"))

	roundTripped, status := ConvertEgress(v1beta1Egress, v1beta2APIVersion)
	requireConversionSuccess(t, status)
	requireStringSlice(t, roundTripped, []string{"192.0.2.10", "2001:db8::10"}, "spec", "egressIPs")
	requireStringSlice(t, roundTripped, []string{"192.0.2.20", "2001:db8::10"}, "status", "egressIPs")
	assert.Equal(t, "RequireDualStack", mustNestedString(t, roundTripped, "spec", "ipFamilyPolicy"))
	_, found, _ = unstructured.NestedFieldNoCopy(roundTripped.Object, "status", "egressIP")
	assert.False(t, found)
}

func TestConvertEgressOldClientChangesDualStackSpec(t *testing.T) {
	v1beta2Egress := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": v1beta2APIVersion,
		"kind":       "Egress",
		"metadata":   map[string]interface{}{"name": "dual"},
		"spec": map[string]interface{}{
			"egressIPs":      []interface{}{"192.0.2.10", "2001:db8::10"},
			"externalIPPool": "pool",
			"ipFamilyPolicy": "RequireDualStack",
		},
	}}

	v1beta1Egress, status := ConvertEgress(v1beta2Egress, v1beta1APIVersion)
	requireConversionSuccess(t, status)
	require.NoError(t, unstructured.SetNestedField(v1beta1Egress.Object, "192.0.2.20", "spec", "egressIP"))

	roundTripped, status := ConvertEgress(v1beta1Egress, v1beta2APIVersion)
	requireConversionSuccess(t, status)
	requireStringSlice(t, roundTripped, []string{"192.0.2.20"}, "spec", "egressIPs")
	assert.Equal(t, "SingleStack", mustNestedString(t, roundTripped, "spec", "ipFamilyPolicy"))
}

func TestConvertEgressIgnoresPartiallyDecodableAnnotation(t *testing.T) {
	v1beta1Egress := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": v1beta1APIVersion,
		"kind":       "Egress",
		"metadata": map[string]interface{}{
			"name": "single",
			"annotations": map[string]interface{}{
				conversionDataAnnotation: `{"version":"v1","kind":"Egress","data":{"sourceVersion":"crd.antrea.io/v1beta2","egressIPs":["192.0.2.10","2001:db8::10"],"ipFamilyPolicy":"RequireDualStack","statusEgressIPs":"invalid"}}`,
			},
		},
		"spec": map[string]interface{}{"egressIP": "192.0.2.20"},
	}}

	converted, status := ConvertEgress(v1beta1Egress, v1beta2APIVersion)
	requireConversionSuccess(t, status)
	requireStringSlice(t, converted, []string{"192.0.2.20"}, "spec", "egressIPs")
	assert.Equal(t, "SingleStack", mustNestedString(t, converted, "spec", "ipFamilyPolicy"))
	_, found := converted.GetAnnotations()[conversionDataAnnotation]
	assert.False(t, found)
}

func TestConvertEgressOldClientClearsStatusAndExternalIPPools(t *testing.T) {
	v1beta2Egress := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": v1beta2APIVersion,
		"kind":       "Egress",
		"metadata": map[string]interface{}{
			"name": "dual",
			"annotations": map[string]interface{}{
				conversionDataAnnotation: `{"legacyExternalIPPools":["pool-v4","pool-v6"]}`,
			},
		},
		"spec": map[string]interface{}{
			"egressIPs":      []interface{}{"192.0.2.10", "2001:db8::10"},
			"ipFamilyPolicy": "RequireDualStack",
		},
		"status": map[string]interface{}{
			"egressIPs": []interface{}{"192.0.2.10", "2001:db8::10"},
		},
	}}

	v1beta1Egress, status := ConvertEgress(v1beta2Egress, v1beta1APIVersion)
	requireConversionSuccess(t, status)
	unstructured.RemoveNestedField(v1beta1Egress.Object, "status", "egressIP")
	unstructured.RemoveNestedField(v1beta1Egress.Object, "spec", "externalIPPools")

	roundTripped, status := ConvertEgress(v1beta1Egress, v1beta2APIVersion)
	requireConversionSuccess(t, status)
	_, found, _ := unstructured.NestedFieldNoCopy(roundTripped.Object, "status", "egressIPs")
	assert.False(t, found)
	_, found, _ = unstructured.NestedFieldNoCopy(roundTripped.Object, "spec", "externalIPPools")
	assert.False(t, found)
	_, found = roundTripped.GetAnnotations()[conversionDataAnnotation]
	assert.False(t, found)
}

func TestConvertExternalIPPoolDualStackRoundTrip(t *testing.T) {
	v1beta2Pool := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": v1beta2APIVersion,
		"kind":       "ExternalIPPool",
		"metadata":   map[string]interface{}{"name": "dual"},
		"spec": map[string]interface{}{
			"ipRanges": []interface{}{
				map[string]interface{}{"cidr": "192.0.2.0/24"},
				map[string]interface{}{"cidr": "2001:db8::/64"},
			},
			"nodeSelector": map[string]interface{}{},
			"subnetInfo": map[string]interface{}{
				"gateways": []interface{}{
					map[string]interface{}{"gateway": "192.0.2.1", "prefixLength": int64(24)},
					map[string]interface{}{"gateway": "2001:db8::1", "prefixLength": int64(64)},
				},
				"vlan": int64(10),
			},
		},
	}}

	v1beta1Pool, status := ConvertExternalIPPool(v1beta2Pool, v1beta1APIVersion)
	requireConversionSuccess(t, status)
	requireValidForCRDVersion(t, "../../../build/charts/antrea/crds/externalippool.yaml", "v1beta1", v1beta1Pool)
	assert.Equal(t, "192.0.2.1", mustNestedString(t, v1beta1Pool, "spec", "subnetInfo", "gateway"))
	prefixLength, found, err := unstructured.NestedInt64(v1beta1Pool.Object, "spec", "subnetInfo", "prefixLength")
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, int64(24), prefixLength)
	_, found, _ = unstructured.NestedFieldNoCopy(v1beta1Pool.Object, "spec", "subnetInfo", "gateways")
	assert.False(t, found)

	roundTripped, status := ConvertExternalIPPool(v1beta1Pool, v1beta2APIVersion)
	requireConversionSuccess(t, status)
	gateways, found, err := unstructured.NestedSlice(roundTripped.Object, "spec", "subnetInfo", "gateways")
	require.NoError(t, err)
	require.True(t, found)
	require.Len(t, gateways, 2)
	assert.Equal(t, "192.0.2.1", gateways[0].(map[string]interface{})["gateway"])
	assert.Equal(t, "2001:db8::1", gateways[1].(map[string]interface{})["gateway"])
	_, found, _ = unstructured.NestedFieldNoCopy(roundTripped.Object, "spec", "subnetInfo", "gateway")
	assert.False(t, found)
}

func TestConvertExternalIPPoolOldClientChangesProjectedFamily(t *testing.T) {
	v1beta2Pool := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": v1beta2APIVersion,
		"kind":       "ExternalIPPool",
		"metadata":   map[string]interface{}{"name": "dual"},
		"spec": map[string]interface{}{
			"ipRanges": []interface{}{
				map[string]interface{}{"cidr": "192.0.2.0/24"},
				map[string]interface{}{"cidr": "2001:db8::/64"},
			},
			"subnetInfo": map[string]interface{}{
				"gateways": []interface{}{
					map[string]interface{}{"gateway": "192.0.2.1", "prefixLength": int64(24)},
					map[string]interface{}{"gateway": "2001:db8::1", "prefixLength": int64(64)},
				},
			},
		},
	}}

	v1beta1Pool, status := ConvertExternalIPPool(v1beta2Pool, v1beta1APIVersion)
	requireConversionSuccess(t, status)
	require.NoError(t, unstructured.SetNestedSlice(v1beta1Pool.Object, []interface{}{
		map[string]interface{}{"cidr": "2001:db8::/64"},
	}, "spec", "ipRanges"))
	require.NoError(t, unstructured.SetNestedField(v1beta1Pool.Object, "2001:db8::2", "spec", "subnetInfo", "gateway"))
	require.NoError(t, unstructured.SetNestedField(v1beta1Pool.Object, int64(64), "spec", "subnetInfo", "prefixLength"))

	roundTripped, status := ConvertExternalIPPool(v1beta1Pool, v1beta2APIVersion)
	requireConversionSuccess(t, status)
	gateways, found, err := unstructured.NestedSlice(roundTripped.Object, "spec", "subnetInfo", "gateways")
	require.NoError(t, err)
	require.True(t, found)
	require.Len(t, gateways, 1)
	assert.Equal(t, "2001:db8::2", gateways[0].(map[string]interface{})["gateway"])
}

func TestConvertExternalIPPoolV1beta2LegacySubnetDoesNotRestoreStaleGateways(t *testing.T) {
	v1beta2Pool := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": v1beta2APIVersion,
		"kind":       "ExternalIPPool",
		"metadata": map[string]interface{}{
			"name": "single",
			"annotations": map[string]interface{}{
				conversionDataAnnotation: `{"gateways":[{"gateway":"192.0.2.1","prefixLength":24},{"gateway":"2001:db8::1","prefixLength":64}]}`,
			},
		},
		"spec": map[string]interface{}{
			"subnetInfo": map[string]interface{}{
				"gateway":      "192.0.2.254",
				"prefixLength": int64(24),
			},
		},
	}}

	v1beta1Pool, status := ConvertExternalIPPool(v1beta2Pool, v1beta1APIVersion)
	requireConversionSuccess(t, status)
	_, found := v1beta1Pool.GetAnnotations()[conversionDataAnnotation]
	assert.False(t, found)

	roundTripped, status := ConvertExternalIPPool(v1beta1Pool, v1beta2APIVersion)
	requireConversionSuccess(t, status)
	assert.Equal(t, "192.0.2.254", mustNestedString(t, roundTripped, "spec", "subnetInfo", "gateway"))
	_, found, _ = unstructured.NestedFieldNoCopy(roundTripped.Object, "spec", "subnetInfo", "gateways")
	assert.False(t, found)
}

func mustNestedString(t *testing.T, object *unstructured.Unstructured, fields ...string) string {
	t.Helper()
	value, found, err := unstructured.NestedString(object.Object, fields...)
	require.NoError(t, err)
	require.True(t, found, "field %v was not found", fields)
	return value
}

func TestEgressConversionRejectsInconsistentProjection(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*egressConversionData)
	}{
		{name: "spec snapshot does not match preserved IP", mutate: func(data *egressConversionData) { data.EgressIPs = []string{"192.0.2.99"} }},
		{name: "status snapshot does not match preserved IP", mutate: func(data *egressConversionData) { data.StatusEgressIPs = []string{"192.0.2.99"} }},
		{name: "single IP with dual-stack policy", mutate: func(data *egressConversionData) { data.IPFamilyPolicy = "RequireDualStack" }},
		{name: "two IPs with single-stack policy", mutate: func(data *egressConversionData) { data.EgressIPs = []string{"192.0.2.10", "2001:db8::10"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			object := &unstructured.Unstructured{Object: map[string]interface{}{
				"apiVersion": v1beta1APIVersion, "kind": "Egress",
				"metadata": map[string]interface{}{"name": "projection"},
				"spec":     map[string]interface{}{"egressIP": "192.0.2.10"},
				"status":   map[string]interface{}{"egressIP": "192.0.2.10"},
			}}
			data := egressConversionData{
				SourceVersion: v1beta2APIVersion,
				EgressIPs:     []string{"192.0.2.10"}, ProjectedEgressIP: "192.0.2.10", IPFamilyPolicy: "SingleStack",
				StatusEgressIPs: []string{"192.0.2.10"}, ProjectedStatusEgressIP: "192.0.2.10",
			}
			tc.mutate(&data)
			require.NoError(t, setConversionData(object, egressConversionKind, &data))
			converted, status := ConvertEgress(object, v1beta2APIVersion)
			requireConversionSuccess(t, status)
			requireStringSlice(t, converted, []string{"192.0.2.10"}, "spec", "egressIPs")
			requireStringSlice(t, converted, []string{"192.0.2.10"}, "status", "egressIPs")
			assert.Equal(t, "SingleStack", mustNestedString(t, converted, "spec", "ipFamilyPolicy"))
		})
	}
}
