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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	crdv1beta1 "antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
	crdv1beta2 "antrea.io/antrea/v2/pkg/apis/crd/v1beta2"
)

func TestExternalIPPoolNativeV1beta1RoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name   string
		subnet *crdv1beta1.SubnetInfo
		ranges []crdv1beta1.IPRange
	}{
		{name: "no subnet", ranges: []crdv1beta1.IPRange{{CIDR: "192.0.2.0/24"}}},
		{name: "IPv4", subnet: &crdv1beta1.SubnetInfo{Gateway: "192.0.2.1", PrefixLength: 24, VLAN: 10}, ranges: []crdv1beta1.IPRange{{CIDR: "192.0.2.0/24"}}},
		{name: "IPv6", subnet: &crdv1beta1.SubnetInfo{Gateway: "2001:db8::1", PrefixLength: 64}, ranges: []crdv1beta1.IPRange{{CIDR: "2001:db8::/64"}}},
		{name: "empty pool retains subnet", subnet: &crdv1beta1.SubnetInfo{Gateway: "192.0.2.1", PrefixLength: 24, VLAN: 4094}, ranges: []crdv1beta1.IPRange{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := &crdv1beta1.ExternalIPPool{
				TypeMeta:   metav1.TypeMeta{APIVersion: v1beta1APIVersion, Kind: "ExternalIPPool"},
				ObjectMeta: metav1.ObjectMeta{Name: "native", Annotations: map[string]string{"user": "keep"}},
				Spec:       crdv1beta1.ExternalIPPoolSpec{SubnetInfo: tc.subnet, IPRanges: tc.ranges},
			}
			raw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(old)
			require.NoError(t, err)
			source := &unstructured.Unstructured{Object: raw}
			v2, status := ConvertExternalIPPool(source, v1beta2APIVersion)
			requireConversionSuccess(t, status)
			requireValidForCRDVersion(t, "../../../build/charts/antrea/crds/externalippool.yaml", "v1beta2", v2)
			_, found, err := unstructured.NestedFieldNoCopy(v2.Object, "spec", "subnetInfo")
			require.NoError(t, err)
			assert.False(t, found)
			var pool crdv1beta2.ExternalIPPool
			require.NoError(t, runtime.DefaultUnstructuredConverter.FromUnstructured(v2.Object, &pool))
			if tc.subnet == nil {
				assert.Empty(t, pool.Spec.Subnets)
			} else {
				assert.Equal(t, []crdv1beta2.SubnetInfo{{
					Gateway: tc.subnet.Gateway, PrefixLength: tc.subnet.PrefixLength, VLAN: tc.subnet.VLAN,
				}}, pool.Spec.Subnets)
			}
			back, status := ConvertExternalIPPool(v2, v1beta1APIVersion)
			requireConversionSuccess(t, status)
			requireValidForCRDVersion(t, "../../../build/charts/antrea/crds/externalippool.yaml", "v1beta1", back)
			assert.Equal(t, source.Object, back.Object)
		})
	}
}

func TestExternalIPPoolProjectedSubnetUpdates(t *testing.T) {
	v4 := crdv1beta2.SubnetInfo{Gateway: "192.0.2.1", PrefixLength: 24, VLAN: 10}
	v6 := crdv1beta2.SubnetInfo{Gateway: "2001:db8::1", PrefixLength: 64, VLAN: 20}
	for _, tc := range []struct {
		name     string
		mutate   func(*testing.T, *unstructured.Unstructured)
		expected []crdv1beta2.SubnetInfo
	}{
		{name: "unrelated update preserves both subnets and order", mutate: func(t *testing.T, o *unstructured.Unstructured) {
			o.SetLabels(map[string]string{"unrelated": "change"})
		}, expected: []crdv1beta2.SubnetInfo{v6, v4}},
		{name: "visible gateway update preserves hidden subnet", mutate: func(t *testing.T, o *unstructured.Unstructured) {
			require.NoError(t, unstructured.SetNestedField(o.Object, "192.0.2.2", "spec", "subnetInfo", "gateway"))
		}, expected: []crdv1beta2.SubnetInfo{v6, {Gateway: "192.0.2.2", PrefixLength: 24, VLAN: 10}}},
		{name: "visible prefix update preserves hidden subnet", mutate: func(t *testing.T, o *unstructured.Unstructured) {
			require.NoError(t, unstructured.SetNestedField(o.Object, int64(25), "spec", "subnetInfo", "prefixLength"))
		}, expected: []crdv1beta2.SubnetInfo{v6, {Gateway: "192.0.2.1", PrefixLength: 25, VLAN: 10}}},
		{name: "visible VLAN update preserves hidden VLAN", mutate: func(t *testing.T, o *unstructured.Unstructured) {
			require.NoError(t, unstructured.SetNestedField(o.Object, int64(30), "spec", "subnetInfo", "vlan"))
		}, expected: []crdv1beta2.SubnetInfo{v6, {Gateway: "192.0.2.1", PrefixLength: 24, VLAN: 30}}},
		{name: "remove visible VLAN", mutate: func(t *testing.T, o *unstructured.Unstructured) {
			unstructured.RemoveNestedField(o.Object, "spec", "subnetInfo", "vlan")
		}, expected: []crdv1beta2.SubnetInfo{v6, {Gateway: "192.0.2.1", PrefixLength: 24}}},
		{name: "remove subnet configuration", mutate: func(t *testing.T, o *unstructured.Unstructured) {
			unstructured.RemoveNestedField(o.Object, "spec", "subnetInfo")
		}},
		{name: "empty pool retains both subnets", mutate: func(t *testing.T, o *unstructured.Unstructured) {
			require.NoError(t, unstructured.SetNestedSlice(o.Object, []interface{}{}, "spec", "ipRanges"))
		}, expected: []crdv1beta2.SubnetInfo{v6, v4}},
		{name: "removed hidden family is not resurrected", mutate: func(t *testing.T, o *unstructured.Unstructured) {
			require.NoError(t, unstructured.SetNestedSlice(o.Object, []interface{}{map[string]interface{}{"cidr": "192.0.2.0/24"}}, "spec", "ipRanges"))
		}, expected: []crdv1beta2.SubnetInfo{v4}},
		{name: "family change replaces projected entry", mutate: func(t *testing.T, o *unstructured.Unstructured) {
			require.NoError(t, unstructured.SetNestedMap(o.Object, map[string]interface{}{
				"gateway": "2001:db8::2", "prefixLength": int64(64), "vlan": int64(30),
			}, "spec", "subnetInfo"))
			require.NoError(t, unstructured.SetNestedSlice(o.Object, []interface{}{map[string]interface{}{"cidr": "2001:db8::/64"}}, "spec", "ipRanges"))
		}, expected: []crdv1beta2.SubnetInfo{{Gateway: "2001:db8::2", PrefixLength: 64, VLAN: 30}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool := &crdv1beta2.ExternalIPPool{
				TypeMeta:   metav1.TypeMeta{APIVersion: v1beta2APIVersion, Kind: "ExternalIPPool"},
				ObjectMeta: metav1.ObjectMeta{Name: "dual", Annotations: map[string]string{"user": "keep"}},
				Spec: crdv1beta2.ExternalIPPoolSpec{
					Subnets:  []crdv1beta2.SubnetInfo{v6, v4},
					IPRanges: []crdv1beta2.IPRange{{CIDR: "192.0.2.0/24"}, {CIDR: "2001:db8::/64"}},
				},
			}
			raw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(pool)
			require.NoError(t, err)
			old, status := ConvertExternalIPPool(&unstructured.Unstructured{Object: raw}, v1beta1APIVersion)
			requireConversionSuccess(t, status)
			requireValidForCRDVersion(t, "../../../build/charts/antrea/crds/externalippool.yaml", "v1beta1", old)
			assert.True(t, IsV1beta2ExternalIPPoolProjection(old))
			assert.Equal(t, v4.Gateway, mustNestedString(t, old, "spec", "subnetInfo", "gateway"))
			tc.mutate(t, old)
			converted, status := ConvertExternalIPPool(old, v1beta2APIVersion)
			requireConversionSuccess(t, status)
			requireValidForCRDVersion(t, "../../../build/charts/antrea/crds/externalippool.yaml", "v1beta2", converted)
			var actual crdv1beta2.ExternalIPPool
			require.NoError(t, runtime.DefaultUnstructuredConverter.FromUnstructured(converted.Object, &actual))
			assert.Equal(t, tc.expected, actual.Spec.Subnets)
			assert.Equal(t, "keep", actual.Annotations["user"])
			_, found := actual.Annotations[conversionDataAnnotation]
			assert.False(t, found)
			_, found, err = unstructured.NestedFieldNoCopy(converted.Object, "spec", "subnetInfo")
			require.NoError(t, err)
			assert.False(t, found)
		})
	}
}
