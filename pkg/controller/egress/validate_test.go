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

package egress

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/utils/ptr"

	crdv1beta1 "antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
	crdv1beta2 "antrea.io/antrea/v2/pkg/apis/crd/v1beta2"
)

func marshal(object runtime.Object) []byte {
	raw, _ := json.Marshal(object)
	return raw
}

func newEgressWithIPFamilyPolicy(name, egressIP, externalIPPool string, policy *corev1.IPFamilyPolicy) *crdv1beta2.Egress {
	egress := newEgress(name, egressIP, externalIPPool, nil, nil, nil)
	egress.Spec.IPFamilyPolicy = policy
	return egress
}

func newDualStackEgress(name, externalIPPool string, egressIPs []string, policy *corev1.IPFamilyPolicy) *crdv1beta2.Egress {
	egress := newEgress(name, "", externalIPPool, nil, nil, nil)
	egress.Spec.EgressIPs = egressIPs
	egress.Spec.IPFamilyPolicy = policy
	return egress
}

func newDualStackExternalIPPool(name string) *crdv1beta2.ExternalIPPool {
	pool := newExternalIPPool(name, "10.10.10.0/24", "", "")
	pool.Spec.IPRanges = append(pool.Spec.IPRanges, crdv1beta2.IPRange{CIDR: "2001:db8:10::/64"})
	return pool
}

func TestEgressControllerValidateEgress(t *testing.T) {
	var (
		bandwidth = crdv1beta2.Bandwidth{
			Rate:  "500k",
			Burst: "10M",
		}
		invalidBandwidthRate = crdv1beta2.Bandwidth{
			Rate:  "500A",
			Burst: "10G",
		}
		invalidBandwidthBurst = crdv1beta2.Bandwidth{
			Rate:  "1.5G",
			Burst: "10b",
		}
		legacyV1beta1Egress = &crdv1beta1.Egress{
			TypeMeta: metav1.TypeMeta{APIVersion: "crd.antrea.io/v1beta1", Kind: "Egress"},
			ObjectMeta: metav1.ObjectMeta{
				Name: "legacy",
			},
			Spec: crdv1beta1.EgressSpec{
				AppliedTo: crdv1beta1.AppliedTo{},
				EgressIP:  "10.10.10.1",
			},
		}
	)
	tests := []struct {
		name                   string
		existingExternalIPPool *crdv1beta2.ExternalIPPool
		request                *admv1.AdmissionRequest
		expectedResponse       *admv1.AdmissionResponse
	}{
		{
			name: "A v1beta1 Egress using egressIP should remain valid",
			request: &admv1.AdmissionRequest{
				Name:      "legacy",
				Operation: "CREATE",
				Resource:  metav1.GroupVersionResource{Group: "crd.antrea.io", Version: "v1beta1", Resource: "egresses"},
				Object:    runtime.RawExtension{Raw: marshal(legacyV1beta1Egress)},
			},
			expectedResponse: &admv1.AdmissionResponse{Allowed: true},
		},
		{
			name:                   "Requesting IP from non-existing ExternalIPPool should not be allowed",
			existingExternalIPPool: nil,
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "CREATE",
				Object:    runtime.RawExtension{Raw: marshal(newEgress("foo", "10.10.10.1", "nonExistingPool", nil, nil, nil))},
			},
			expectedResponse: &admv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Message: "ExternalIPPool nonExistingPool does not exist",
				},
			},
		},
		{
			name:                   "Requesting IP out of range should not be allowed",
			existingExternalIPPool: newExternalIPPool("bar", "10.10.10.0/24", "", ""),
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "CREATE",
				Object:    runtime.RawExtension{Raw: marshal(newEgress("foo", "10.10.11.1", "bar", nil, nil, nil))},
			},
			expectedResponse: &admv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Message: "IP 10.10.11.1 is not within the IP range",
				},
			},
		},
		{
			name:                   "Requesting normal IP should be allowed",
			existingExternalIPPool: newExternalIPPool("bar", "10.10.10.0/24", "", ""),
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "CREATE",
				Object:    runtime.RawExtension{Raw: marshal(newEgress("foo", "10.10.10.1", "bar", nil, nil, nil))},
			},
			expectedResponse: &admv1.AdmissionResponse{Allowed: true},
		},
		{
			name:                   "Requesting explicit dual-stack IPs should be allowed",
			existingExternalIPPool: newDualStackExternalIPPool("dual-stack"),
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "CREATE",
				Object: runtime.RawExtension{Raw: marshal(newDualStackEgress("foo", "dual-stack",
					[]string{"10.10.10.1", "2001:db8:10::1"},
					ptr.To(corev1.IPFamilyPolicyRequireDualStack)))},
			},
			expectedResponse: &admv1.AdmissionResponse{Allowed: true},
		},
		{
			name:                   "Reverse dual-stack IP ordering should be allowed",
			existingExternalIPPool: newDualStackExternalIPPool("dual-stack"),
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "CREATE",
				Object: runtime.RawExtension{Raw: marshal(newDualStackEgress("foo", "dual-stack",
					[]string{"2001:db8:10::1", "10.10.10.1"}, nil))},
			},
			expectedResponse: &admv1.AdmissionResponse{Allowed: true},
		},
		{
			name:                   "PreferDualStack allocation from a dual-stack pool should be allowed",
			existingExternalIPPool: newDualStackExternalIPPool("dual-stack"),
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "CREATE",
				Object: runtime.RawExtension{Raw: marshal(newEgressWithIPFamilyPolicy("foo", "", "dual-stack",
					ptr.To(corev1.IPFamilyPolicyPreferDualStack)))},
			},
			expectedResponse: &admv1.AdmissionResponse{Allowed: true},
		},
		{
			name:                   "SingleStack allocation from a dual-stack pool should be allowed",
			existingExternalIPPool: newDualStackExternalIPPool("dual-stack"),
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "CREATE",
				Object: runtime.RawExtension{Raw: marshal(newEgressWithIPFamilyPolicy("foo", "", "dual-stack",
					ptr.To(corev1.IPFamilyPolicySingleStack)))},
			},
			expectedResponse: &admv1.AdmissionResponse{Allowed: true},
		},
		{
			name:                   "Legacy explicit IP selects one family from a dual-stack pool",
			existingExternalIPPool: newDualStackExternalIPPool("dual-stack"),
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "CREATE",
				Object:    runtime.RawExtension{Raw: marshal(newEgress("foo", "2001:db8:10::1", "dual-stack", nil, nil, nil))},
			},
			expectedResponse: &admv1.AdmissionResponse{Allowed: true},
		},
		{
			name:                   "Dual-stack pool without a policy should default to dual-stack allocation",
			existingExternalIPPool: newDualStackExternalIPPool("dual-stack"),
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "CREATE",
				Object:    runtime.RawExtension{Raw: marshal(newEgress("foo", "", "dual-stack", nil, nil, nil))},
			},
			expectedResponse: &admv1.AdmissionResponse{Allowed: true},
		},
		{
			name:                   "Single-stack pool without family selection should be allowed",
			existingExternalIPPool: newExternalIPPool("bar", "10.10.10.0/24", "", ""),
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "CREATE",
				Object:    runtime.RawExtension{Raw: marshal(newEgress("foo", "", "bar", nil, nil, nil))},
			},
			expectedResponse: &admv1.AdmissionResponse{Allowed: true},
		},
		{
			name: "Non-existing ExternalIPPool without an explicit IP should not be allowed",
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "CREATE",
				Object:    runtime.RawExtension{Raw: marshal(newEgress("foo", "", "nonExistingPool", nil, nil, nil))},
			},
			expectedResponse: &admv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Message: "ExternalIPPool nonExistingPool does not exist",
				},
			},
		},
		{
			name: "egressIPs with duplicate families should not be allowed",
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "CREATE",
				Object: runtime.RawExtension{Raw: marshal(newDualStackEgress("foo", "",
					[]string{"10.10.10.1", "10.10.10.2"}, nil))},
			},
			expectedResponse: &admv1.AdmissionResponse{
				Allowed: false,
				Result:  &metav1.Status{Message: "spec.egressIPs contains multiple addresses for IP family IPv4"},
			},
		},
		{
			name: "Invalid ipFamilyPolicy should not be allowed",
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "CREATE",
				Object: runtime.RawExtension{Raw: marshal(newEgressWithIPFamilyPolicy("foo", "", "",
					ptr.To(corev1.IPFamilyPolicy("Invalid"))))},
			},
			expectedResponse: &admv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Message: "spec.ipFamilyPolicy must be one of SingleStack, PreferDualStack, or RequireDualStack",
				},
			},
		},
		{
			name: "two egressIPs cannot use SingleStack policy",
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "CREATE",
				Object: runtime.RawExtension{Raw: marshal(newDualStackEgress("foo", "",
					[]string{"10.10.10.1", "2001:db8:10::1"}, ptr.To(corev1.IPFamilyPolicySingleStack)))},
			},
			expectedResponse: &admv1.AdmissionResponse{
				Allowed: false,
				Result:  &metav1.Status{Message: "two spec.egressIPs entries cannot be used with ipFamilyPolicy SingleStack"},
			},
		},
		{
			name:                   "RequireDualStack cannot use a single-stack pool",
			existingExternalIPPool: newExternalIPPool("bar", "10.10.10.0/24", "", ""),
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "CREATE",
				Object: runtime.RawExtension{Raw: marshal(newEgressWithIPFamilyPolicy("foo", "", "bar",
					ptr.To(corev1.IPFamilyPolicyRequireDualStack)))},
			},
			expectedResponse: &admv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Message: "ExternalIPPool bar does not support required dual-stack allocation",
				},
			},
		},
		{
			name: "Reverse dual-stack explicit IP ordering without a pool should be allowed",
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "CREATE",
				Object: runtime.RawExtension{Raw: marshal(newDualStackEgress("foo", "",
					[]string{"2001:db8:10::1", "10.10.10.1"}, nil))},
			},
			expectedResponse: &admv1.AdmissionResponse{Allowed: true},
		},
		{
			name: "A single address in egressIPs should be allowed",
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "CREATE",
				Object: runtime.RawExtension{Raw: marshal(newDualStackEgress("foo", "",
					[]string{"10.10.10.1"}, nil))},
			},
			expectedResponse: &admv1.AdmissionResponse{Allowed: true},
		},
		{
			name: "More than two addresses in egressIPs should not be allowed",
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "CREATE",
				Object: runtime.RawExtension{Raw: marshal(newDualStackEgress("foo", "",
					[]string{"10.10.10.1", "2001:db8:10::1", "10.10.10.2"}, nil))},
			},
			expectedResponse: &admv1.AdmissionResponse{
				Allowed: false,
				Result:  &metav1.Status{Message: "spec.egressIPs must contain at most two addresses, one for each IP family"},
			},
		},
		{
			name: "one egressIPs entry cannot use RequireDualStack policy",
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "CREATE",
				Object: runtime.RawExtension{Raw: marshal(newEgressWithIPFamilyPolicy("foo", "10.10.10.1", "",
					ptr.To(corev1.IPFamilyPolicyRequireDualStack)))},
			},
			expectedResponse: &admv1.AdmissionResponse{
				Allowed: false,
				Result:  &metav1.Status{Message: "one spec.egressIPs entry cannot be used with ipFamilyPolicy RequireDualStack"},
			},
		},
		{
			name:                   "Updating EgressIP to invalid one should not be allowed",
			existingExternalIPPool: newExternalIPPool("bar", "10.10.10.0/24", "", ""),
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "UPDATE",
				OldObject: runtime.RawExtension{Raw: marshal(newEgress("foo", "10.10.10.1", "bar", nil, nil, nil))},
				Object:    runtime.RawExtension{Raw: marshal(newEgress("foo", "10.10.11.1", "bar", nil, nil, nil))},
			},
			expectedResponse: &admv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Message: "IP 10.10.11.1 is not within the IP range",
				},
			},
		},
		{
			name:                   "Updating EgressIP to valid one should be allowed",
			existingExternalIPPool: newExternalIPPool("bar", "10.10.10.0/24", "", ""),
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "UPDATE",
				OldObject: runtime.RawExtension{Raw: marshal(newEgress("foo", "10.10.10.1", "bar", nil, nil, nil))},
				Object:    runtime.RawExtension{Raw: marshal(newEgress("foo", "10.10.10.2", "bar", nil, nil, nil))},
			},
			expectedResponse: &admv1.AdmissionResponse{Allowed: true},
		},
		{
			name:                   "Updating podSelector should be allowed",
			existingExternalIPPool: newExternalIPPool("bar", "10.10.10.0/24", "", ""),
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "UPDATE",
				OldObject: runtime.RawExtension{Raw: marshal(newEgress("foo", "10.10.10.1", "bar", nil, nil, nil))},
				Object: runtime.RawExtension{Raw: marshal(newEgress("foo", "10.10.10.2", "bar", &metav1.LabelSelector{
					MatchLabels: map[string]string{"foo": "bar"},
				}, nil, nil))},
			},
			expectedResponse: &admv1.AdmissionResponse{Allowed: true},
		},
		{
			name: "DELETE operation should be allowed",
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "DELETE",
				Object:    runtime.RawExtension{Raw: marshal(newEgress("foo", "10.10.10.2", "bar", nil, nil, nil))},
			},
			expectedResponse: &admv1.AdmissionResponse{Allowed: true},
		},
		{
			name: "Creating an Egress with bandwidth should be allowed",
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "CREATE",
				Object:    runtime.RawExtension{Raw: marshal(newEgress("foo", "10.10.10.1", "", nil, nil, &bandwidth))},
			},
			expectedResponse: &admv1.AdmissionResponse{Allowed: true},
		},
		{
			name: "Update an Egress bandwidth config should be allowed",
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "UPDATE",
				OldObject: runtime.RawExtension{Raw: marshal(newEgress("foo", "10.10.10.1", "", nil, nil, &bandwidth))},
				Object:    runtime.RawExtension{Raw: marshal(newEgress("foo", "10.10.10.1", "", nil, nil, nil))},
			},
			expectedResponse: &admv1.AdmissionResponse{Allowed: true},
		},
		{
			name: "Create an Egress with invalid bandwidth rate",
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "CREATE",
				Object:    runtime.RawExtension{Raw: marshal(newEgress("foo", "10.10.10.1", "", nil, nil, &invalidBandwidthRate))},
			},
			expectedResponse: &admv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Message: "Rate 500A in Egress foo is invalid: quantities must match the regular expression '^([+-]?[0-9.]+)([eEinumkKMGTP]*[-+]?[0-9]*)$'",
				},
			},
		},
		{
			name: "Create an Egress with invalid bandwidth burst",
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "CREATE",
				Object:    runtime.RawExtension{Raw: marshal(newEgress("foo", "10.10.10.1", "", nil, nil, &invalidBandwidthBurst))},
			},
			expectedResponse: &admv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Message: "Burst 10b in Egress foo is invalid: quantities must match the regular expression '^([+-]?[0-9.]+)([eEinumkKMGTP]*[-+]?[0-9]*)$'",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stopCh := make(chan struct{})
			defer close(stopCh)
			var objs []runtime.Object
			if tt.existingExternalIPPool != nil {
				objs = append(objs, tt.existingExternalIPPool)
			}
			controller := newController(nil, objs)
			controller.informerFactory.Start(stopCh)
			controller.crdInformerFactory.Start(stopCh)
			controller.informerFactory.WaitForCacheSync(stopCh)
			controller.crdInformerFactory.WaitForCacheSync(stopCh)
			go controller.externalIPAllocator.Run(stopCh)
			require.True(t, cache.WaitForCacheSync(stopCh, controller.externalIPAllocator.HasSynced))
			controller.externalIPAllocator.RestoreIPAllocations(nil)
			review := &admv1.AdmissionReview{
				Request: tt.request,
			}
			gotResponse := controller.ValidateEgress(review)
			assert.Equal(t, tt.expectedResponse, gotResponse)
		})
	}
}
