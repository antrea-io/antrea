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

package ipam

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	admv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
)

var testIPPool = &crdv1beta1.IPPool{
	ObjectMeta: metav1.ObjectMeta{
		Name: "test-ip-pool",
	},
	Spec: crdv1beta1.IPPoolSpec{
		IPRanges: []crdv1beta1.IPRange{
			{
				CIDR: "192.168.0.0/26",
			},
		},
		SubnetInfo: crdv1beta1.SubnetInfo{
			Gateway:      "192.168.0.1",
			PrefixLength: 24,
		},
	},
	Status: crdv1beta1.IPPoolStatus{},
}

func marshal(object runtime.Object) []byte {
	raw, _ := json.Marshal(object)
	return raw
}

func copyAndMutateIPPool(in *crdv1beta1.IPPool, mutateFunc func(*crdv1beta1.IPPool)) *crdv1beta1.IPPool {
	out := in.DeepCopy()
	mutateFunc(out)
	return out
}

func TestEgressControllerValidateExternalIPPool(t *testing.T) {
	tests := []struct {
		name             string
		request          *admv1.AdmissionRequest
		expectedResponse *admv1.AdmissionResponse
	}{
		{
			name: "CREATE operation should be allowed",
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "CREATE",
				Object:    runtime.RawExtension{Raw: marshal(testIPPool)},
			},
			expectedResponse: &admv1.AdmissionResponse{Allowed: true},
		},
		{
			name: "CREATE operation with invalid prefix length should not be allowed",
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "CREATE",
				Object: runtime.RawExtension{Raw: marshal(copyAndMutateIPPool(testIPPool, func(pool *crdv1beta1.IPPool) {
					pool.Spec.IPRanges = []crdv1beta1.IPRange{
						{
							CIDR: "192.168.3.0/26",
						},
					}
					pool.Spec.SubnetInfo = crdv1beta1.SubnetInfo{
						Gateway:      "192.168.3.1",
						PrefixLength: 32,
					}
				}))},
			},
			expectedResponse: &admv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Message: "Invalid prefix length 32",
				},
			},
		},
		{
			name: "CREATE operation with CIDR partially overlap with IP range should not be allowed",
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "CREATE",
				Object: runtime.RawExtension{Raw: marshal(copyAndMutateIPPool(testIPPool, func(pool *crdv1beta1.IPPool) {
					pool.Spec.IPRanges = []crdv1beta1.IPRange{
						{
							CIDR: "192.168.3.0/26",
						},
						{
							Start: "192.168.3.10",
							End:   "192.168.3.20",
						},
					}
					pool.Spec.SubnetInfo = crdv1beta1.SubnetInfo{
						Gateway:      "192.168.3.1",
						PrefixLength: 24,
					}
				}))},
			},
			expectedResponse: &admv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Message: "IPRanges [192.168.3.0/26,192.168.3.10-192.168.3.20] overlap",
				},
			},
		},
		{
			name: "CREATE operation with CIDR contained within with IP range should not be allowed",
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "CREATE",
				Object: runtime.RawExtension{Raw: marshal(copyAndMutateIPPool(testIPPool, func(pool *crdv1beta1.IPPool) {
					pool.Spec.IPRanges = []crdv1beta1.IPRange{
						{
							CIDR: "192.168.3.12/30",
						},
						{
							Start: "192.168.3.10",
							End:   "192.168.3.20",
						},
					}
					pool.Spec.SubnetInfo = crdv1beta1.SubnetInfo{
						Gateway:      "192.168.3.1",
						PrefixLength: 24,
					}
				}))},
			},
			expectedResponse: &admv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Message: "IPRanges [192.168.3.12/30,192.168.3.10-192.168.3.20] overlap",
				},
			},
		},
		{
			name: "CREATE operation with mixed IP version should not be allowed",
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "CREATE",
				Object: runtime.RawExtension{Raw: marshal(copyAndMutateIPPool(testIPPool, func(pool *crdv1beta1.IPPool) {
					pool.Spec.IPRanges = []crdv1beta1.IPRange{
						{
							CIDR: "10:2400::0/96",
						},
					}
					pool.Spec.SubnetInfo = crdv1beta1.SubnetInfo{
						Gateway:      "192.168.3.1",
						PrefixLength: 24,
					}
				}))},
			},
			expectedResponse: &admv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Message: "Range is invalid. IP version of range 10:2400::0/96 differs from gateway IP version",
				},
			},
		},
		{
			name: "CREATE operation with bad gateway not be allowed",
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "CREATE",
				Object: runtime.RawExtension{Raw: marshal(copyAndMutateIPPool(testIPPool, func(pool *crdv1beta1.IPPool) {
					pool.Spec.IPRanges = []crdv1beta1.IPRange{
						{
							CIDR: "192.168.10.0/26",
						},
					}
					pool.Spec.SubnetInfo = crdv1beta1.SubnetInfo{
						Gateway:      "192.168.1.1",
						PrefixLength: 24,
					}
				}))},
			},
			expectedResponse: &admv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Message: "Range is invalid. CIDR 192.168.10.0/26 is not contained within subnet 192.168.1.1/24",
				},
			},
		},
		{
			name: "Deleting IPRange should not be allowed",
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "UPDATE",
				OldObject: runtime.RawExtension{Raw: marshal(testIPPool)},
				Object: runtime.RawExtension{Raw: marshal(copyAndMutateIPPool(testIPPool, func(pool *crdv1beta1.IPPool) {
					pool.Spec.IPRanges = []crdv1beta1.IPRange{}
				}))},
			},
			expectedResponse: &admv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Message: "existing IPRanges [192.168.0.0/26] cannot be updated or deleted",
				},
			},
		},
		{
			name: "Updating IPRange should not be allowed",
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "UPDATE",
				OldObject: runtime.RawExtension{Raw: marshal(testIPPool)},
				Object: runtime.RawExtension{Raw: marshal(copyAndMutateIPPool(testIPPool, func(pool *crdv1beta1.IPPool) {
					pool.Spec.IPRanges[0].CIDR = "192.168.1.0/24"
				}))},
			},
			expectedResponse: &admv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Message: "existing IPRanges [192.168.0.0/26] cannot be updated or deleted",
				},
			},
		},
		{
			name: "Adding IPRange should be allowed",
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "UPDATE",
				OldObject: runtime.RawExtension{Raw: marshal(testIPPool)},
				Object: runtime.RawExtension{Raw: marshal(copyAndMutateIPPool(testIPPool, func(pool *crdv1beta1.IPPool) {
					pool.Spec.IPRanges = append(pool.Spec.IPRanges, crdv1beta1.IPRange{
						Start: "192.168.0.128",
						End:   "192.168.0.132",
					})
				}))},
			},
			expectedResponse: &admv1.AdmissionResponse{Allowed: true},
		},
		{
			name: "Adding overlapping IPRange should not be allowed",
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "UPDATE",
				OldObject: runtime.RawExtension{Raw: marshal(testIPPool)},
				Object: runtime.RawExtension{Raw: marshal(copyAndMutateIPPool(testIPPool, func(pool *crdv1beta1.IPPool) {
					pool.Spec.IPRanges = append(pool.Spec.IPRanges, crdv1beta1.IPRange{
						Start: "192.168.0.5",
						End:   "192.168.0.10",
					})
				}))},
			},
			expectedResponse: &admv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Message: "IPRanges [192.168.0.5-192.168.0.10,192.168.0.0/26] overlap",
				},
			},
		},
		{
			name: "Deleting IPPool in use should not be allowed",
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "DELETE",
				OldObject: runtime.RawExtension{Raw: marshal(copyAndMutateIPPool(testIPPool, func(pool *crdv1beta1.IPPool) {
					pool.Status.IPAddresses = []crdv1beta1.IPAddressState{
						{
							IPAddress: "192.168.0.10",
						},
					}
				}))},
			},
			expectedResponse: &admv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{
					Message: "IPPool in use cannot be deleted",
				},
			},
		},
		{
			name: "Deleting IPPool not in use should be allowed",
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: "DELETE",
				Object:    runtime.RawExtension{Raw: marshal(testIPPool)},
			},
			expectedResponse: &admv1.AdmissionResponse{Allowed: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			review := &admv1.AdmissionReview{
				Request: tt.request,
			}
			gotResponse := ValidateIPPool(review)
			assert.Equal(t, tt.expectedResponse, gotResponse)
		})
	}
}
