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

package externalippool

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admv1 "k8s.io/api/admission/v1"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	crdvalidation "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/validation"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/schema"
	schemacel "k8s.io/apiextensions-apiserver/pkg/apiserver/schema/cel"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/yaml"

	crdv1b1 "antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
	crdv1b2 "antrea.io/antrea/v2/pkg/apis/crd/v1beta2"
	"antrea.io/antrea/v2/pkg/controller/crdconversion"
)

func marshal(object runtime.Object) []byte {
	raw, _ := json.Marshal(object)
	return raw
}

func mutateExternalIPPool(pool *crdv1b2.ExternalIPPool, mutate func(*crdv1b2.ExternalIPPool)) *crdv1b2.ExternalIPPool {
	mutate(pool)
	return pool
}

func TestControllerValidateExternalIPPool(t *testing.T) {
	tests := []struct {
		name             string
		request          *admv1.AdmissionRequest
		expectedResponse *admv1.AdmissionResponse
	}{
		{
			name: "CREATE operation without SubnetInfo should be allowed",
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "CREATE",
				Object:    runtime.RawExtension{Raw: marshal(newExternalIPPool("foo", "10.10.10.0/24", "", ""))},
			},
			expectedResponse: &admv1.AdmissionResponse{Allowed: true},
		},
		{
			name: "CREATE operation with valid SubnetInfo should be allowed",
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "CREATE",
				Object: runtime.RawExtension{Raw: marshal(mutateExternalIPPool(newExternalIPPool("foo", "10.10.10.0/24", "", ""), func(pool *crdv1b2.ExternalIPPool) {
					pool.Spec.Subnets = []crdv1b2.SubnetInfo{{Gateway: "10.10.0.1",
						PrefixLength: 16,
						VLAN:         2}}
				}))},
			},
			expectedResponse: &admv1.AdmissionResponse{Allowed: true},
		},
		{
			name: "CREATE operation with valid dual-stack SubnetInfo should be allowed",
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "CREATE",
				Object: runtime.RawExtension{Raw: marshal(mutateExternalIPPool(newExternalIPPool("foo", "10.10.10.0/24", "", ""), func(pool *crdv1b2.ExternalIPPool) {
					pool.Spec.IPRanges = append(pool.Spec.IPRanges, crdv1b2.IPRange{CIDR: "2001:db8:10::/64"})
					pool.Spec.Subnets = []crdv1b2.SubnetInfo{
						{Gateway: "10.10.10.1", PrefixLength: 24, VLAN: 100},
						{Gateway: "2001:db8:10::1", PrefixLength: 64, VLAN: 100},
					}
				}))},
			},
			expectedResponse: &admv1.AdmissionResponse{Allowed: true},
		},
		{
			name: "Adding matched SubnetInfo should be allowed",
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "UPDATE",
				OldObject: runtime.RawExtension{Raw: marshal(newExternalIPPool("foo", "10.10.10.0/24", "10.10.20.1", "10.10.20.2"))},
				Object: runtime.RawExtension{Raw: marshal(mutateExternalIPPool(newExternalIPPool("foo", "10.10.10.0/24", "10.10.20.1", "10.10.20.2"), func(pool *crdv1b2.ExternalIPPool) {
					pool.Spec.Subnets = []crdv1b2.SubnetInfo{{Gateway: "10.10.0.1",
						PrefixLength: 16,
						VLAN:         2}}
				}))},
			},
			expectedResponse: &admv1.AdmissionResponse{Allowed: true},
		},
		{
			name: "Deleting IPRange should not be allowed",
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "UPDATE",
				OldObject: runtime.RawExtension{Raw: marshal(newExternalIPPool("foo", "10.10.10.0/24", "10.10.20.1", "10.10.20.2"))},
				Object:    runtime.RawExtension{Raw: marshal(newExternalIPPool("foo", "10.10.10.0/24", "", ""))},
			},
			expectedResponse: &admv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Message: "existing IPRanges [10.10.20.1-10.10.20.2] cannot be updated or deleted",
				},
			},
		},
		{
			name: "Adding IPRange should be allowed",
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "UPDATE",
				OldObject: runtime.RawExtension{Raw: marshal(newExternalIPPool("foo", "10.10.10.0/24", "", ""))},
				Object:    runtime.RawExtension{Raw: marshal(newExternalIPPool("foo", "10.10.10.0/24", "10.10.20.1", "10.10.20.2"))},
			},
			expectedResponse: &admv1.AdmissionResponse{Allowed: true},
		},
		{
			name: "Adding the first IPv4 range to an empty pool should be allowed",
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "UPDATE",
				OldObject: runtime.RawExtension{Raw: marshal(mutateExternalIPPool(newExternalIPPool("foo", "", "", ""), func(pool *crdv1b2.ExternalIPPool) {
					pool.Spec.IPRanges = []crdv1b2.IPRange{}
				}))},
				Object: runtime.RawExtension{Raw: marshal(newExternalIPPool("foo", "10.10.10.0/24", "", ""))},
			},
			expectedResponse: &admv1.AdmissionResponse{Allowed: true},
		},
		{
			name: "Adding the first IPv6 range to an empty pool should be allowed",
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "UPDATE",
				OldObject: runtime.RawExtension{Raw: marshal(mutateExternalIPPool(newExternalIPPool("foo", "", "", ""), func(pool *crdv1b2.ExternalIPPool) {
					pool.Spec.IPRanges = []crdv1b2.IPRange{}
				}))},
				Object: runtime.RawExtension{Raw: marshal(newExternalIPPool("foo", "2001:db8:10::/64", "", ""))},
			},
			expectedResponse: &admv1.AdmissionResponse{Allowed: true},
		},
		{
			name: "Adding the first dual-stack ranges to an empty pool should be allowed",
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "UPDATE",
				OldObject: runtime.RawExtension{Raw: marshal(mutateExternalIPPool(newExternalIPPool("foo", "", "", ""), func(pool *crdv1b2.ExternalIPPool) {
					pool.Spec.IPRanges = []crdv1b2.IPRange{}
				}))},
				Object: runtime.RawExtension{Raw: marshal(mutateExternalIPPool(newExternalIPPool("foo", "10.10.10.0/24", "", ""), func(pool *crdv1b2.ExternalIPPool) {
					pool.Spec.IPRanges = append(pool.Spec.IPRanges, crdv1b2.IPRange{CIDR: "2001:db8:10::/64"})
					pool.Spec.Subnets = []crdv1b2.SubnetInfo{
						{Gateway: "10.10.10.1", PrefixLength: 24},
						{Gateway: "2001:db8:10::1", PrefixLength: 64},
					}
				}))},
			},
			expectedResponse: &admv1.AdmissionResponse{Allowed: true},
		},
		{
			name: "Adding an IP family should not be allowed",
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "UPDATE",
				OldObject: runtime.RawExtension{Raw: marshal(newExternalIPPool("foo", "10.10.10.0/24", "", ""))},
				Object: runtime.RawExtension{Raw: marshal(mutateExternalIPPool(newExternalIPPool("foo", "10.10.10.0/24", "", ""), func(pool *crdv1b2.ExternalIPPool) {
					pool.Spec.IPRanges = append(pool.Spec.IPRanges, crdv1b2.IPRange{CIDR: "2001:db8:10::/64"})
				}))},
			},
			expectedResponse: &admv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Message: "IP families are immutable (old: [IPv4], new: [IPv4 IPv6])",
				},
			},
		},
		{
			name: "v1beta1 keeps allowing an additional IP family",
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: admv1.Update,
				Resource:  metav1.GroupVersionResource{Group: "crd.antrea.io", Version: "v1beta1", Resource: "externalippools"},
				OldObject: runtime.RawExtension{Raw: marshal(&crdv1b1.ExternalIPPool{
					TypeMeta: metav1.TypeMeta{APIVersion: crdv1b1.SchemeGroupVersion.String(), Kind: "ExternalIPPool"},
					Spec:     crdv1b1.ExternalIPPoolSpec{IPRanges: []crdv1b1.IPRange{{CIDR: "10.10.10.0/24"}}},
				})},
				Object: runtime.RawExtension{Raw: marshal(&crdv1b1.ExternalIPPool{
					TypeMeta: metav1.TypeMeta{APIVersion: crdv1b1.SchemeGroupVersion.String(), Kind: "ExternalIPPool"},
					Spec:     crdv1b1.ExternalIPPoolSpec{IPRanges: []crdv1b1.IPRange{{CIDR: "10.10.10.0/24"}, {CIDR: "2001:db8:10::/64"}}},
				})},
			},
			expectedResponse: &admv1.AdmissionResponse{Allowed: true},
		},
		{
			name: "DELETE operation should be allowed",
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "DELETE",
				Object:    runtime.RawExtension{Raw: marshal(newExternalIPPool("foo", "10.10.10.0/24", "", ""))},
			},
			expectedResponse: &admv1.AdmissionResponse{Allowed: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newController(nil)
			stopCh := make(chan struct{})
			defer close(stopCh)
			c.crdInformerFactory.Start(stopCh)
			c.crdInformerFactory.WaitForCacheSync(stopCh)
			go c.Run(stopCh)
			require.True(t, cache.WaitForCacheSync(stopCh, c.HasSynced))
			review := &admv1.AdmissionReview{
				Request: tt.request,
			}
			gotResponse := c.ValidateExternalIPPool(review)
			assert.Equal(t, tt.expectedResponse, gotResponse)
		})
	}
}

func TestValidateExternalIPPoolSubnetUpdate(t *testing.T) {
	raw, err := os.ReadFile("../../../build/charts/antrea/crds/externalippool.yaml")
	require.NoError(t, err)
	var crd apiextensionsv1.CustomResourceDefinition
	require.NoError(t, yaml.Unmarshal(raw, &crd))
	apiextensionsv1.SetObjectDefaults_CustomResourceDefinition(&crd)
	var internalCRD apiextensions.CustomResourceDefinition
	require.NoError(t, apiextensionsv1.Convert_v1_CustomResourceDefinition_To_apiextensions_CustomResourceDefinition(&crd, &internalCRD, nil))
	require.Empty(t, crdvalidation.ValidateCustomResourceDefinition(t.Context(), &internalCRD))
	var structuralSchema *schema.Structural
	for _, version := range internalCRD.Spec.Versions {
		if version.Name == crdv1b2.SchemeGroupVersion.Version {
			structuralSchema, err = schema.NewStructural(version.Schema.OpenAPIV3Schema)
			require.NoError(t, err)
			break
		}
	}
	require.NotNil(t, structuralSchema)
	celValidator := schemacel.NewValidator(structuralSchema, true, celconfig.PerCallLimit)
	require.NotNil(t, celValidator)

	c := newController(nil)
	stopCh := make(chan struct{})
	defer close(stopCh)
	c.crdInformerFactory.Start(stopCh)
	c.crdInformerFactory.WaitForCacheSync(stopCh)

	tests := []struct {
		name      string
		operation admv1.Operation
		mutate    func(oldPool, newPool *crdv1b2.ExternalIPPool)
		errMsg    string
	}{
		{
			name:      "creating pool",
			operation: admv1.Create,
		},
		{
			name: "changing IPv4 gateway",
			mutate: func(_, newPool *crdv1b2.ExternalIPPool) {
				newPool.Spec.Subnets[0].Gateway = "192.0.2.2"
			},
			errMsg: "gateway 192.0.2.1 cannot be changed or removed through v1beta2",
		},
		{
			name: "changing IPv6 gateway",
			mutate: func(_, newPool *crdv1b2.ExternalIPPool) {
				newPool.Spec.Subnets[1].Gateway = "2001:db8::2"
			},
			errMsg: "gateway 2001:db8::1 cannot be changed or removed through v1beta2",
		},
		{
			name: "removing subnet configuration",
			mutate: func(_, newPool *crdv1b2.ExternalIPPool) {
				newPool.Spec.Subnets = nil
			},
			errMsg: "gateway 192.0.2.1 cannot be changed or removed through v1beta2",
		},
		{
			name: "removing one subnet from an empty pool",
			mutate: func(oldPool, newPool *crdv1b2.ExternalIPPool) {
				oldPool.Spec.IPRanges = nil
				newPool.Spec.IPRanges = nil
				newPool.Spec.Subnets = newPool.Spec.Subnets[:1]
			},
			errMsg: "gateway 2001:db8::1 cannot be changed or removed through v1beta2",
		},
		{
			name: "reordering subnets",
			mutate: func(_, newPool *crdv1b2.ExternalIPPool) {
				newPool.Spec.Subnets[0], newPool.Spec.Subnets[1] = newPool.Spec.Subnets[1], newPool.Spec.Subnets[0]
			},
		},
		{
			name: "changing IPv6 gateway representation",
			mutate: func(_, newPool *crdv1b2.ExternalIPPool) {
				newPool.Spec.Subnets[1].Gateway = "2001:0db8::1"
			},
			errMsg: "gateway 2001:db8::1 cannot be changed or removed through v1beta2",
		},
		{
			name: "adding initial subnet configuration",
			mutate: func(oldPool, _ *crdv1b2.ExternalIPPool) {
				oldPool.Spec.Subnets = nil
			},
		},
		{
			name: "changing VLAN",
			mutate: func(_, newPool *crdv1b2.ExternalIPPool) {
				newPool.Spec.Subnets[0].VLAN = 20
			},
		},
		{
			name: "changing IPv4 prefix length",
			mutate: func(_, newPool *crdv1b2.ExternalIPPool) {
				newPool.Spec.Subnets[0].PrefixLength = 23
			},
			errMsg: "prefixLength for gateway 192.0.2.1 cannot be changed through v1beta2",
		},
		{
			name: "narrowing IPv4 subnet while keeping all ranges within it",
			mutate: func(oldPool, newPool *crdv1b2.ExternalIPPool) {
				ipRange := crdv1b2.IPRange{Start: "192.0.2.2", End: "192.0.2.10"}
				oldPool.Spec.IPRanges[0] = ipRange
				newPool.Spec.IPRanges[0] = ipRange
				newPool.Spec.Subnets[0].PrefixLength = 28
			},
			errMsg: "prefixLength for gateway 192.0.2.1 cannot be changed through v1beta2",
		},
		{
			name: "changing IPv6 prefix length",
			mutate: func(_, newPool *crdv1b2.ExternalIPPool) {
				newPool.Spec.Subnets[1].PrefixLength = 63
			},
			errMsg: "prefixLength for gateway 2001:db8::1 cannot be changed through v1beta2",
		},
		{
			name: "changing labels",
			mutate: func(_, newPool *crdv1b2.ExternalIPPool) {
				newPool.Labels = map[string]string{"updated": "true"}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldPool := newExternalIPPool("dual", "192.0.2.0/24", "", "")
			oldPool.TypeMeta = metav1.TypeMeta{APIVersion: crdv1b2.SchemeGroupVersion.String(), Kind: "ExternalIPPool"}
			oldPool.Spec.IPRanges = append(oldPool.Spec.IPRanges, crdv1b2.IPRange{CIDR: "2001:db8::/64"})
			oldPool.Spec.Subnets = []crdv1b2.SubnetInfo{
				{Gateway: "192.0.2.1", PrefixLength: 24, VLAN: 10},
				{Gateway: "2001:db8::1", PrefixLength: 64, VLAN: 10},
			}
			newPool := oldPool.DeepCopy()
			if tt.mutate != nil {
				tt.mutate(oldPool, newPool)
			}
			operation := tt.operation
			if operation == "" {
				operation = admv1.Update
			}
			newObject, err := runtime.DefaultUnstructuredConverter.ToUnstructured(newPool)
			require.NoError(t, err)
			var oldObject interface{}
			var oldRaw []byte
			if operation == admv1.Update {
				oldObject, err = runtime.DefaultUnstructuredConverter.ToUnstructured(oldPool)
				require.NoError(t, err)
				oldRaw = marshal(oldPool)
			}
			errs, _ := celValidator.Validate(t.Context(), field.NewPath("object"), structuralSchema,
				newObject, oldObject, celconfig.RuntimeCELCostBudget)
			if tt.errMsg == "" {
				assert.Empty(t, errs, "unexpected schema rejection")
			} else {
				require.NotEmpty(t, errs, "schema should reject gateway or prefix length changes")
				assert.Contains(t, errs.ToAggregate().Error(), "gateway and prefixLength are immutable")
			}
			review := &admv1.AdmissionReview{Request: &admv1.AdmissionRequest{
				Operation: operation,
				Resource: metav1.GroupVersionResource{
					Group: "crd.antrea.io", Version: "v1beta2", Resource: "externalippools",
				},
				OldObject: runtime.RawExtension{Raw: oldRaw},
				Object:    runtime.RawExtension{Raw: marshal(newPool)},
			}}
			response := c.ValidateExternalIPPool(review)
			if tt.errMsg == "" {
				assert.True(t, response.Allowed, "unexpected rejection: %+v", response.Result)
			} else {
				require.False(t, response.Allowed)
				require.NotNil(t, response.Result)
				assert.Equal(t, tt.errMsg, response.Result.Message)
			}
		})
	}
}

func TestValidateV1beta1ProjectionOfDualStackPool(t *testing.T) {
	v2Pool := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": crdv1b2.SchemeGroupVersion.String(),
		"kind":       "ExternalIPPool",
		"metadata":   map[string]interface{}{"name": "dual"},
		"spec": map[string]interface{}{
			"ipRanges": []interface{}{
				map[string]interface{}{"cidr": "192.0.2.0/24"},
				map[string]interface{}{"cidr": "2001:db8::/64"},
			},
			"nodeSelector": map[string]interface{}{},
			"subnets": []interface{}{
				map[string]interface{}{"gateway": "192.0.2.1", "prefixLength": int64(24), "vlan": int64(10)},
				map[string]interface{}{"gateway": "2001:db8::1", "prefixLength": int64(64), "vlan": int64(20)},
			},
		},
	}}
	v1Pool, status := crdconversion.ConvertExternalIPPool(v2Pool, crdv1b1.SchemeGroupVersion.String())
	require.Equal(t, metav1.StatusSuccess, status.Status, status.Message)
	updatedV1Pool := v1Pool.DeepCopy()
	updatedV1Pool.SetLabels(map[string]string{"unrelated": "change"})

	c := newController(nil)
	stopCh := make(chan struct{})
	defer close(stopCh)
	c.crdInformerFactory.Start(stopCh)
	c.crdInformerFactory.WaitForCacheSync(stopCh)
	review := &admv1.AdmissionReview{Request: &admv1.AdmissionRequest{
		Name:      "dual",
		Operation: admv1.Update,
		Resource:  metav1.GroupVersionResource{Group: "crd.antrea.io", Version: "v1beta1", Resource: "externalippools"},
		OldObject: runtime.RawExtension{Raw: marshal(v1Pool)},
		Object:    runtime.RawExtension{Raw: marshal(updatedV1Pool)},
	}}
	assert.Equal(t, &admv1.AdmissionResponse{Allowed: true}, c.ValidateExternalIPPool(review))

	// The old client may edit the projected gateway without touching the conversion annotation.
	require.NoError(t, unstructured.SetNestedField(updatedV1Pool.Object, "192.0.2.2", "spec", "subnetInfo", "gateway"))
	review.Request.Object.Raw = marshal(updatedV1Pool)
	assert.Equal(t, &admv1.AdmissionResponse{Allowed: true}, c.ValidateExternalIPPool(review))

	// Editing the hidden gateway through metadata must not bypass validation or alter conversion state.
	annotations := updatedV1Pool.GetAnnotations()
	var envelope map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(annotations["crd.antrea.io/conversion-data"]), &envelope))
	gateways := envelope["data"].(map[string]interface{})["subnets"].([]interface{})
	gateways[1].(map[string]interface{})["gateway"] = "2001:db8::2"
	raw, err := json.Marshal(envelope)
	require.NoError(t, err)
	annotations["crd.antrea.io/conversion-data"] = string(raw)
	updatedV1Pool.SetAnnotations(annotations)
	review.Request.Object.Raw = marshal(updatedV1Pool)
	response := c.ValidateExternalIPPool(review)
	require.False(t, response.Allowed)
	assert.Contains(t, response.Result.Message, "reserved for API conversion")
}

func TestValidateIPRangesAndSubnetInfo(t *testing.T) {
	testCases := []struct {
		name                    string
		externalIPPool          *crdv1b2.ExternalIPPool
		existingExternalIPPools []*crdv1b2.ExternalIPPool
		errMsg                  string
	}{
		{
			name: "invalid gateway address",
			externalIPPool: mutateExternalIPPool(newExternalIPPool("foo", "10.10.10.0/24", "10.10.20.1", "10.10.20.2"), func(pool *crdv1b2.ExternalIPPool) {
				pool.Spec.Subnets = []crdv1b2.SubnetInfo{{Gateway: "10.10.0",
					PrefixLength: 16,
					VLAN:         2}}
			}),
			errMsg: "invalid gateway address 10.10.0",
		},
		{
			name: "invalid ipv4 prefix",
			externalIPPool: mutateExternalIPPool(newExternalIPPool("foo", "10.10.10.0/24", "", ""), func(pool *crdv1b2.ExternalIPPool) {
				pool.Spec.Subnets = []crdv1b2.SubnetInfo{{Gateway: "10.10.0.1",
					PrefixLength: 42,
					VLAN:         2}}
			}),
			errMsg: "invalid prefixLength 42",
		},
		{
			name: "invalid ipv6 prefix",
			externalIPPool: mutateExternalIPPool(newExternalIPPool("foo", "10.10.10.0/24", "", ""), func(pool *crdv1b2.ExternalIPPool) {
				pool.Spec.Subnets = []crdv1b2.SubnetInfo{{Gateway: "2001:d00::",
					PrefixLength: 130,
					VLAN:         2}}
			}),
			errMsg: "invalid prefixLength 130",
		},
		{
			name:           "range start greater than end",
			externalIPPool: newExternalIPPool("foo", "", "10.10.20.0", "10.10.10.0"),
			errMsg:         "range start 10.10.20.0 should not be greater than range end 10.10.10.0",
		},
		{
			name:           "start-end must belong to same ip family",
			externalIPPool: newExternalIPPool("foo", "", "10.10.20.0", "2001:d00::"),
			errMsg:         "range start 10.10.20.0 and range end 2001:d00:: should belong to same family",
		},
		{
			name: "start-end range must be within subnet info",
			externalIPPool: mutateExternalIPPool(newExternalIPPool("foo", "", "10.10.20.10", "10.10.20.40"), func(pool *crdv1b2.ExternalIPPool) {
				pool.Spec.Subnets = []crdv1b2.SubnetInfo{{Gateway: "10.10.10.0",
					PrefixLength: 24,
					VLAN:         2}}
			}),
			errMsg: "range [10.10.20.10-10.10.20.40] must be a strict subset of the subnet 10.10.10.0/24",
		},
		{
			name: "cidr must be within subnet info",
			externalIPPool: mutateExternalIPPool(newExternalIPPool("foo", "10.20.0.0/16", "", ""), func(pool *crdv1b2.ExternalIPPool) {
				pool.Spec.Subnets = []crdv1b2.SubnetInfo{{Gateway: "10.20.0.0",
					PrefixLength: 24,
					VLAN:         2}}
			}),
			errMsg: "range [10.20.0.0/16] must be a strict subset of the subnet 10.20.0.0/24",
		},
		{
			name: "valid subnet info 1",
			externalIPPool: mutateExternalIPPool(newExternalIPPool("foo", "", "10.10.20.10", "10.10.20.20"), func(pool *crdv1b2.ExternalIPPool) {
				pool.Spec.Subnets = []crdv1b2.SubnetInfo{{Gateway: "10.10.20.0",
					PrefixLength: 24,
					VLAN:         2}}
			}),
		},
		{
			name: "valid subnet info 2",
			externalIPPool: mutateExternalIPPool(newExternalIPPool("foo", "fd00:10:96::/112", "", ""), func(pool *crdv1b2.ExternalIPPool) {
				pool.Spec.Subnets = []crdv1b2.SubnetInfo{{Gateway: "fd00:10:96::",
					PrefixLength: 96,
					VLAN:         2}}
			}),
		},

		// test cases for cidr range overlap
		{
			name:           "cidr must not overlap with any existing cidr",
			externalIPPool: newExternalIPPool("foo", "10.20.30.0/24", "", ""),
			existingExternalIPPools: []*crdv1b2.ExternalIPPool{
				newExternalIPPool("bar", "10.10.10.0/24", "", ""),
				newExternalIPPool("baz", "10.10.20.0/24", "", ""),
				newExternalIPPool("qux", "10.20.0.0/16", "", ""),
			},
			errMsg: "range [10.20.30.0/24] overlaps with range [10.20.0.0/16] of ExternalIPPool qux",
		},
		{
			name:           "cidr must not overlap with any existing start-end range",
			externalIPPool: newExternalIPPool("foo", "10.20.30.0/24", "", ""),
			existingExternalIPPools: []*crdv1b2.ExternalIPPool{
				newExternalIPPool("bar", "", "10.20.30.10", "10.20.30.50"),
			},
			errMsg: "range [10.20.30.0/24] overlaps with range [10.20.30.10-10.20.30.50] of ExternalIPPool bar",
		},
		{
			name: "cidr must not overlap with any cidr",
			externalIPPool: mutateExternalIPPool(newExternalIPPool("foo", "10.10.10.0/24", "", ""), func(pool *crdv1b2.ExternalIPPool) {
				pool.Spec.IPRanges = append(pool.Spec.IPRanges, crdv1b2.IPRange{CIDR: "10.30.20.0/24"})
				pool.Spec.IPRanges = append(pool.Spec.IPRanges, crdv1b2.IPRange{CIDR: "10.10.0.0/16"})
			}),
			errMsg: "range [10.10.0.0/16] overlaps with range [10.10.10.0/24]",
		},
		{
			name: "cidr must not overlap with any start-end range",
			externalIPPool: mutateExternalIPPool(newExternalIPPool("foo", "", "10.10.20.20", "10.10.20.50"), func(pool *crdv1b2.ExternalIPPool) {
				pool.Spec.IPRanges = append(pool.Spec.IPRanges, crdv1b2.IPRange{CIDR: "10.10.20.0/24"})
			}),
			errMsg: "range [10.10.20.0/24] overlaps with range [10.10.20.20-10.10.20.50]",
		},
		{
			name: "valid non overlapping cidr",
			externalIPPool: mutateExternalIPPool(newExternalIPPool("foo", "10.10.20.0/24", "", ""), func(pool *crdv1b2.ExternalIPPool) {
				pool.Spec.IPRanges = append(pool.Spec.IPRanges, crdv1b2.IPRange{CIDR: "10.10.30.0/24"})
			}),
			existingExternalIPPools: []*crdv1b2.ExternalIPPool{
				newExternalIPPool("bar", "", "10.10.40.10", "10.10.40.80"),
				newExternalIPPool("baz", "10.10.40.0/24", "", ""),
				newExternalIPPool("qux", "10.20.0.0/16", "", ""),
			},
		},

		// test cases for start-end range overlap
		{
			name:           "start-end range must not overlap with any existing cidr",
			externalIPPool: newExternalIPPool("foo", "", "10.30.10.0", "10.30.20.0"),
			existingExternalIPPools: []*crdv1b2.ExternalIPPool{
				newExternalIPPool("bar", "", "10.10.10.0", "10.10.20.0"),
				newExternalIPPool("baz", "10.20.0.0/16", "", ""),
				newExternalIPPool("qux", "10.30.0.0/20", "", ""),
			},
			errMsg: "range [10.30.10.0-10.30.20.0] overlaps with range [10.30.0.0/20] of ExternalIPPool qux",
		},
		{
			name:           "start-end range must not overlap with any existing start-end range",
			externalIPPool: newExternalIPPool("foo", "", "10.30.10.0", "10.30.20.0"),
			existingExternalIPPools: []*crdv1b2.ExternalIPPool{
				newExternalIPPool("bar", "10.10.0.0/16", "", ""),
				newExternalIPPool("baz", "", "10.30.20.0", "10.30.40.0"),
			},
			errMsg: "range [10.30.10.0-10.30.20.0] overlaps with range [10.30.20.0-10.30.40.0] of ExternalIPPool baz",
		},
		{
			name: "start-end range must not overlap with any cidr",
			externalIPPool: mutateExternalIPPool(newExternalIPPool("foo", "10.30.0.0/16", "10.30.40.50", "10.30.40.80"), func(pool *crdv1b2.ExternalIPPool) {
				pool.Spec.IPRanges = append(pool.Spec.IPRanges, crdv1b2.IPRange{CIDR: "10.30.0.0/16"})
				pool.Spec.IPRanges = append(pool.Spec.IPRanges, crdv1b2.IPRange{Start: "10.30.40.50", End: "10.30.40.80"})
			}),
			errMsg: "range [10.30.40.50-10.30.40.80] overlaps with range [10.30.0.0/16]",
		},
		{
			name: "start-end range must not overlap with any start-end range",
			externalIPPool: mutateExternalIPPool(newExternalIPPool("foo", "", "10.30.40.50", "10.30.40.80"), func(pool *crdv1b2.ExternalIPPool) {
				pool.Spec.IPRanges = append(pool.Spec.IPRanges, crdv1b2.IPRange{CIDR: "10.30.50.0/24"})
				pool.Spec.IPRanges = append(pool.Spec.IPRanges, crdv1b2.IPRange{Start: "10.30.40.10", End: "10.30.40.90"})
			}),
			errMsg: "range [10.30.40.10-10.30.40.90] overlaps with range [10.30.40.50-10.30.40.80]",
		},
		{
			name: "valid non overlapping start-end range",
			externalIPPool: mutateExternalIPPool(newExternalIPPool("foo", "", "10.30.10.0", "10.30.20.0"), func(pool *crdv1b2.ExternalIPPool) {
				pool.Spec.IPRanges = append(pool.Spec.IPRanges, crdv1b2.IPRange{CIDR: "10.30.50.0/24"})
				pool.Spec.IPRanges = append(pool.Spec.IPRanges, crdv1b2.IPRange{CIDR: "10.50.0.0/16"})
				pool.Spec.IPRanges = append(pool.Spec.IPRanges, crdv1b2.IPRange{Start: "10.30.20.1", End: "10.30.40.10"})
			}),
			existingExternalIPPools: []*crdv1b2.ExternalIPPool{
				newExternalIPPool("bar", "", "10.10.10.0", "10.10.20.0"),
				newExternalIPPool("baz", "10.20.0.0/16", "", ""),
				newExternalIPPool("baz", "10.40.0.0/16", "", ""),
				newExternalIPPool("bar", "", "10.10.10.0", "10.10.20.0"),
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			err := validateIPRangesAndSubnetInfoForExternalIPPool(
				testCase.externalIPPool,
				testCase.existingExternalIPPools,
			)

			if testCase.errMsg == "" {
				assert.Empty(t, err)
			} else {
				assert.Equal(t, testCase.errMsg, err.Error())

				// test if the same message is returned by ValidateExternalIPPool
				var fakeObjects []runtime.Object
				for _, existingExternalIPPool := range testCase.existingExternalIPPools {
					fakeObjects = append(fakeObjects, existingExternalIPPool)
				}

				c := newController(fakeObjects)
				stopCh := make(chan struct{})
				defer close(stopCh)
				c.crdInformerFactory.Start(stopCh)
				c.crdInformerFactory.WaitForCacheSync(stopCh)
				go c.Run(stopCh)
				require.True(t, cache.WaitForCacheSync(stopCh, c.HasSynced))
				review := &admv1.AdmissionReview{
					Request: &admv1.AdmissionRequest{
						Name:      testCase.externalIPPool.Name,
						Operation: "CREATE",
						Object:    runtime.RawExtension{Raw: marshal(testCase.externalIPPool)},
					},
				}
				response := c.ValidateExternalIPPool(review)
				assert.False(t, response.Allowed)
				assert.NotNil(t, response.Result)
				assert.Equal(t, testCase.errMsg, response.Result.Message)
			}
		})
	}
}

func TestValidateExternalIPPoolNodeSelector(t *testing.T) {
	tests := []struct {
		name         string
		selector     metav1.LabelSelector
		expectedPath string
	}{
		{
			name: "empty selector",
		},
		{
			name:     "valid matchLabels",
			selector: metav1.LabelSelector{MatchLabels: map[string]string{"example.com/role": "worker"}},
		},
		{
			name: "valid In",
			selector: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "role", Operator: metav1.LabelSelectorOpIn, Values: []string{"worker"}},
			}},
		},
		{
			name: "valid NotIn",
			selector: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "role", Operator: metav1.LabelSelectorOpNotIn, Values: []string{"control-plane"}},
			}},
		},
		{
			name: "valid Exists",
			selector: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "role", Operator: metav1.LabelSelectorOpExists},
			}},
		},
		{
			name: "valid DoesNotExist",
			selector: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "role", Operator: metav1.LabelSelectorOpDoesNotExist},
			}},
		},
		{
			name: "In without values",
			selector: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "role", Operator: metav1.LabelSelectorOpIn},
			}},
			expectedPath: "spec.nodeSelector.matchExpressions[0].values",
		},
		{
			name: "NotIn without values",
			selector: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "role", Operator: metav1.LabelSelectorOpNotIn},
			}},
			expectedPath: "spec.nodeSelector.matchExpressions[0].values",
		},
		{
			name: "Exists with values",
			selector: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "role", Operator: metav1.LabelSelectorOpExists, Values: []string{"worker"}},
			}},
			expectedPath: "spec.nodeSelector.matchExpressions[0].values",
		},
		{
			name: "DoesNotExist with values",
			selector: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "role", Operator: metav1.LabelSelectorOpDoesNotExist, Values: []string{"worker"}},
			}},
			expectedPath: "spec.nodeSelector.matchExpressions[0].values",
		},
		{
			name:         "invalid matchLabels key",
			selector:     metav1.LabelSelector{MatchLabels: map[string]string{"invalid/key/name": "worker"}},
			expectedPath: "spec.nodeSelector.matchLabels",
		},
		{
			name: "invalid expression key",
			selector: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "invalid/key/name", Operator: metav1.LabelSelectorOpExists},
			}},
			expectedPath: "spec.nodeSelector.matchExpressions[0].key",
		},
		{
			name: "missing expression key",
			selector: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{Operator: metav1.LabelSelectorOpExists},
			}},
			expectedPath: "spec.nodeSelector.matchExpressions[0].key",
		},
		{
			name: "unknown operator",
			selector: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "role", Operator: "invalid"},
			}},
			expectedPath: "spec.nodeSelector.matchExpressions[0].operator",
		},
		{
			name:         "invalid matchLabels value",
			selector:     metav1.LabelSelector{MatchLabels: map[string]string{"role": "invalid/value"}},
			expectedPath: "spec.nodeSelector.matchLabels",
		},
	}
	for _, tt := range tests {
		for _, operation := range []admv1.Operation{admv1.Create, admv1.Update} {
			t.Run(tt.name+"/"+string(operation), func(t *testing.T) {
				c := newController(nil)
				pool := newExternalIPPool("pool", "192.0.2.0/24", "", "")
				oldPool := pool.DeepCopy()
				pool.Spec.NodeSelector = tt.selector
				request := &admv1.AdmissionRequest{
					Operation: operation,
					Object:    runtime.RawExtension{Raw: marshal(pool)},
				}
				if operation == admv1.Update {
					request.OldObject.Raw = marshal(oldPool)
				}
				response := c.ValidateExternalIPPool(&admv1.AdmissionReview{Request: request})
				if tt.expectedPath == "" {
					assert.True(t, response.Allowed)
					assert.Nil(t, response.Result)
				} else {
					assert.False(t, response.Allowed)
					require.NotNil(t, response.Result)
					assert.Contains(t, response.Result.Message, tt.expectedPath)
				}
			})
		}
	}
}

func TestValidateExternalIPPoolRepairNodeSelector(t *testing.T) {
	tests := []struct {
		name     string
		selector metav1.LabelSelector
	}{
		{name: "empty selector"},
		{
			name:     "valid matchLabels",
			selector: metav1.LabelSelector{MatchLabels: map[string]string{"role": "worker"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newController(nil)
			oldPool := newExternalIPPool("pool", "192.0.2.0/24", "", "")
			oldPool.Spec.NodeSelector.MatchExpressions = []metav1.LabelSelectorRequirement{
				{Key: "role", Operator: metav1.LabelSelectorOpIn},
			}
			require.NoError(t, c.crdInformerFactory.Crd().V1beta2().ExternalIPPools().Informer().GetIndexer().Add(oldPool))
			pool := oldPool.DeepCopy()
			pool.Spec.NodeSelector = tt.selector
			response := c.ValidateExternalIPPool(&admv1.AdmissionReview{Request: &admv1.AdmissionRequest{
				Operation: admv1.Update,
				OldObject: runtime.RawExtension{Raw: marshal(oldPool)},
				Object:    runtime.RawExtension{Raw: marshal(pool)},
			}})
			assert.True(t, response.Allowed, "repairing a historical invalid selector must be allowed")
			assert.Nil(t, response.Result)
		})
	}
}
