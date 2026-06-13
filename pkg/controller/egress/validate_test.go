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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"

	crdv1beta1 "antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
)

func marshal(object runtime.Object) []byte {
	raw, _ := json.Marshal(object)
	return raw
}

func TestEgressControllerValidateEgress(t *testing.T) {
	var (
		bandwidth = crdv1beta1.Bandwidth{
			Rate:  "500k",
			Burst: "10M",
		}
		invalidBandwidthRate = crdv1beta1.Bandwidth{
			Rate:  "500A",
			Burst: "10G",
		}
		invalidBandwidthBurst = crdv1beta1.Bandwidth{
			Rate:  "1.5G",
			Burst: "10b",
		}
	)
	tests := []struct {
		name                   string
		existingExternalIPPool *crdv1beta1.ExternalIPPool
		request                *admv1.AdmissionRequest
		expectedResponse       *admv1.AdmissionResponse
	}{
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

func TestEgressControllerValidateDualStackEgressPartialOverlap(t *testing.T) {
	newDualStackEgress := func(name string, egressIPs ...string) *crdv1beta1.Egress {
		egress := newEgress(name, "", "", nil, nil, nil)
		egress.Spec.EgressIPs = egressIPs
		return egress
	}
	newSingleStackEgress := func(name, egressIP string) *crdv1beta1.Egress {
		return newEgress(name, egressIP, "", nil, nil, nil)
	}

	tests := []struct {
		name             string
		existingEgresses []runtime.Object
		egress           *crdv1beta1.Egress
		allowed          bool
		expectedMessage  string
	}{
		{
			name:             "exact same pair is allowed",
			existingEgresses: []runtime.Object{newDualStackEgress("egress-a", "10.10.10.1", "fd00::1")},
			egress:           newDualStackEgress("egress-b", "10.10.10.1", "fd00::1"),
			allowed:          true,
		},
		{
			name:             "overlapping IPv4 only is not allowed",
			existingEgresses: []runtime.Object{newDualStackEgress("egress-a", "10.10.10.1", "fd00::1")},
			egress:           newDualStackEgress("egress-b", "10.10.10.1", "fd00::2"),
			expectedMessage:  "dual-stack EgressIP pair (10.10.10.1, fd00::2) partially overlaps with Egress egress-a pair (10.10.10.1, fd00::1); sharing exactly one IP of a dual-stack pair is not supported",
		},
		{
			name:             "overlapping IPv6 only is not allowed",
			existingEgresses: []runtime.Object{newDualStackEgress("egress-a", "10.10.10.1", "fd00::1")},
			egress:           newDualStackEgress("egress-b", "10.10.10.2", "fd00::1"),
			expectedMessage:  "dual-stack EgressIP pair (10.10.10.2, fd00::1) partially overlaps with Egress egress-a pair (10.10.10.1, fd00::1); sharing exactly one IP of a dual-stack pair is not supported",
		},
		{
			name:            "partial overlap within the same Egress is not allowed",
			egress:          newDualStackEgress("egress-a", "10.10.10.1", "fd00::1", "10.10.10.1", "fd00::2"),
			expectedMessage: "spec.egressIPs contains partially overlapping dual-stack pairs (10.10.10.1, fd00::1) and (10.10.10.1, fd00::2); sharing exactly one IP of a dual-stack pair is not supported",
		},
		{
			name:             "dual-stack Egress overlapping with single-stack Egress is not allowed",
			existingEgresses: []runtime.Object{newSingleStackEgress("egress-a", "10.10.10.1")},
			egress:           newDualStackEgress("egress-b", "10.10.10.1", "fd00::1"),
			expectedMessage:  "dual-stack EgressIP pair (10.10.10.1, fd00::1) overlaps with single-stack Egress egress-a IP 10.10.10.1; sharing an IP between single-stack and dual-stack Egresses is not supported",
		},
		{
			name:             "single-stack Egress overlapping with dual-stack Egress is not allowed",
			existingEgresses: []runtime.Object{newDualStackEgress("egress-a", "10.10.10.1", "fd00::1")},
			egress:           newSingleStackEgress("egress-b", "fd00::1"),
			expectedMessage:  "single-stack EgressIP fd00::1 overlaps with Egress egress-a dual-stack pair (10.10.10.1, fd00::1); sharing an IP between single-stack and dual-stack Egresses is not supported",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stopCh := make(chan struct{})
			defer close(stopCh)
			controller := newController(nil, tt.existingEgresses)
			controller.informerFactory.Start(stopCh)
			controller.crdInformerFactory.Start(stopCh)
			controller.informerFactory.WaitForCacheSync(stopCh)
			controller.crdInformerFactory.WaitForCacheSync(stopCh)

			gotResponse := controller.ValidateEgress(&admv1.AdmissionReview{
				Request: &admv1.AdmissionRequest{
					Name:      tt.egress.Name,
					Operation: admv1.Create,
					Object:    runtime.RawExtension{Raw: marshal(tt.egress)},
				},
			})
			if tt.allowed {
				assert.Equal(t, &admv1.AdmissionResponse{Allowed: true}, gotResponse)
			} else {
				assert.Equal(t, &admv1.AdmissionResponse{
					Allowed: false,
					Result: &metav1.Status{
						Message: tt.expectedMessage,
					},
				}, gotResponse)
			}
		})
	}
}

func TestEgressControllerValidateDualStackEgressValidationBranches(t *testing.T) {
	newDualStackEgress := func(name string, egressIPs, externalIPPools []string) *crdv1beta1.Egress {
		egress := newEgress(name, "", "", nil, nil, nil)
		egress.Spec.EgressIPs = egressIPs
		egress.Spec.ExternalIPPools = externalIPPools
		return egress
	}
	externalIPPools := []runtime.Object{
		newExternalIPPool("pool-v4", "10.10.10.0/24", "", ""),
		newExternalIPPool("pool-v6", "fd00::/64", "", ""),
	}

	tests := []struct {
		name            string
		egress          *crdv1beta1.Egress
		allowed         bool
		expectedMessage string
	}{
		{
			name:            "odd number of EgressIPs is not allowed",
			egress:          newDualStackEgress("egress-a", []string{"10.10.10.1"}, nil),
			expectedMessage: "spec.egressIPs must have an even number of entries (IPv4/IPv6 pairs), got 1",
		},
		{
			name:            "odd number of ExternalIPPools is not allowed",
			egress:          newDualStackEgress("egress-a", nil, []string{"pool-v4"}),
			expectedMessage: "spec.externalIPPools must have an even number of entries (IPv4/IPv6 pairs), got 1",
		},
		{
			name: "EgressIPs and ExternalIPPools length must match when both are specified",
			egress: newDualStackEgress("egress-a",
				[]string{"10.10.10.1", "fd00::1"},
				[]string{"pool-v4", "pool-v6", "pool-v4", "pool-v6"}),
			expectedMessage: "spec.egressIPs and spec.externalIPPools must have the same length, got 2 and 4",
		},
		{
			name: "EgressIPs must be ordered as IPv4 then IPv6",
			egress: newDualStackEgress("egress-a",
				[]string{"fd00::1", "10.10.10.1"},
				nil),
			expectedMessage: "spec.egressIPs[0] must be IPv4 but got fd00::1 (IPv6)",
		},
		{
			name:            "ExternalIPPools must be ordered as IPv4 then IPv6",
			egress:          newDualStackEgress("egress-a", nil, []string{"pool-v6", "pool-v4"}),
			expectedMessage: "expected IPv4 pool but pool-v6 is not",
		},
		{
			name: "ExternalIPPools must not contain duplicate pools",
			egress: newDualStackEgress("egress-a",
				nil,
				[]string{"pool-v4", "pool-v6", "pool-v4", "pool-v6"}),
			expectedMessage: "spec.externalIPPools[2] duplicates ExternalIPPool pool-v4",
		},
		{
			name: "EgressIP must belong to corresponding ExternalIPPool",
			egress: newDualStackEgress("egress-a",
				[]string{"10.10.20.1", "fd00::1"},
				[]string{"pool-v4", "pool-v6"}),
			expectedMessage: "EgressIP 10.10.20.1 does not belong to ExternalIPPool pool-v4",
		},
		{
			name: "valid dual-stack EgressIPs and ExternalIPPools are allowed",
			egress: newDualStackEgress("egress-a",
				[]string{"10.10.10.1", "fd00::1"},
				[]string{"pool-v4", "pool-v6"}),
			allowed: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stopCh := make(chan struct{})
			defer close(stopCh)
			controller := newController(nil, externalIPPools)
			controller.informerFactory.Start(stopCh)
			controller.crdInformerFactory.Start(stopCh)
			controller.informerFactory.WaitForCacheSync(stopCh)
			controller.crdInformerFactory.WaitForCacheSync(stopCh)
			go controller.externalIPAllocator.Run(stopCh)
			require.True(t, cache.WaitForCacheSync(stopCh, controller.externalIPAllocator.HasSynced))
			controller.externalIPAllocator.RestoreIPAllocations(nil)

			gotResponse := controller.ValidateEgress(&admv1.AdmissionReview{
				Request: &admv1.AdmissionRequest{
					Name:      tt.egress.Name,
					Operation: admv1.Create,
					Object:    runtime.RawExtension{Raw: marshal(tt.egress)},
				},
			})
			if tt.allowed {
				assert.Equal(t, &admv1.AdmissionResponse{Allowed: true}, gotResponse)
			} else {
				assert.Equal(t, &admv1.AdmissionResponse{
					Allowed: false,
					Result: &metav1.Status{
						Message: tt.expectedMessage,
					},
				}, gotResponse)
			}
		})
	}
}
