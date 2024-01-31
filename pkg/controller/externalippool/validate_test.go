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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"

	crdv1b1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
)

func marshal(object runtime.Object) []byte {
	raw, _ := json.Marshal(object)
	return raw
}

func mutateExternalIPPool(pool *crdv1b1.ExternalIPPool, mutate func(*crdv1b1.ExternalIPPool)) *crdv1b1.ExternalIPPool {
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
				Object: runtime.RawExtension{Raw: marshal(mutateExternalIPPool(newExternalIPPool("foo", "10.10.10.0/24", "", ""), func(pool *crdv1b1.ExternalIPPool) {
					pool.Spec.SubnetInfo = &crdv1b1.SubnetInfo{
						Gateway:      "10.10.0.1",
						PrefixLength: 16,
						VLAN:         2,
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
				Object: runtime.RawExtension{Raw: marshal(mutateExternalIPPool(newExternalIPPool("foo", "10.10.10.0/24", "10.10.20.1", "10.10.20.2"), func(pool *crdv1b1.ExternalIPPool) {
					pool.Spec.SubnetInfo = &crdv1b1.SubnetInfo{
						Gateway:      "10.10.0.1",
						PrefixLength: 16,
						VLAN:         2,
					}
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
					Message: "existing IPRanges [10.10.20.1-10.10.20.2] cannot be deleted",
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

func TestValidateIPRangesAndSubnetInfo(t *testing.T) {
	testCases := []struct {
		name                    string
		externalIPPool          *crdv1b1.ExternalIPPool
		existingExternalIPPools []*crdv1b1.ExternalIPPool
		errMsg                  string
	}{
		{
			name: "invalid gateway address",
			externalIPPool: mutateExternalIPPool(newExternalIPPool("foo", "10.10.10.0/24", "10.10.20.1", "10.10.20.2"), func(pool *crdv1b1.ExternalIPPool) {
				pool.Spec.SubnetInfo = &crdv1b1.SubnetInfo{
					Gateway:      "10.10.0",
					PrefixLength: 16,
					VLAN:         2,
				}
			}),
			errMsg: "invalid gateway address 10.10.0",
		},
		{
			name: "invalid ipv4 prefix",
			externalIPPool: mutateExternalIPPool(newExternalIPPool("foo", "10.10.10.0/24", "", ""), func(pool *crdv1b1.ExternalIPPool) {
				pool.Spec.SubnetInfo = &crdv1b1.SubnetInfo{
					Gateway:      "10.10.0.1",
					PrefixLength: 42,
					VLAN:         2,
				}
			}),
			errMsg: "invalid prefixLength 42",
		},
		{
			name: "invalid ipv6 prefix",
			externalIPPool: mutateExternalIPPool(newExternalIPPool("foo", "10.10.10.0/24", "", ""), func(pool *crdv1b1.ExternalIPPool) {
				pool.Spec.SubnetInfo = &crdv1b1.SubnetInfo{
					Gateway:      "2001:d00::",
					PrefixLength: 130,
					VLAN:         2,
				}
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
			externalIPPool: mutateExternalIPPool(newExternalIPPool("foo", "", "10.10.20.10", "10.10.20.40"), func(pool *crdv1b1.ExternalIPPool) {
				pool.Spec.SubnetInfo = &crdv1b1.SubnetInfo{
					Gateway:      "10.10.10.0",
					PrefixLength: 24,
					VLAN:         2,
				}
			}),
			errMsg: "range [10.10.20.10-10.10.20.40] must be a strict subset of the subnet 10.10.10.0/24",
		},
		{
			name: "cidr must be within subnet info",
			externalIPPool: mutateExternalIPPool(newExternalIPPool("foo", "10.20.0.0/16", "", ""), func(pool *crdv1b1.ExternalIPPool) {
				pool.Spec.SubnetInfo = &crdv1b1.SubnetInfo{
					Gateway:      "10.20.0.0",
					PrefixLength: 24,
					VLAN:         2,
				}
			}),
			errMsg: "range [10.20.0.0/16] must be a strict subset of the subnet 10.20.0.0/24",
		},
		{
			name: "valid subnet info 1",
			externalIPPool: mutateExternalIPPool(newExternalIPPool("foo", "", "10.10.20.10", "10.10.20.20"), func(pool *crdv1b1.ExternalIPPool) {
				pool.Spec.SubnetInfo = &crdv1b1.SubnetInfo{
					Gateway:      "10.10.20.0",
					PrefixLength: 24,
					VLAN:         2,
				}
			}),
		},
		{
			name: "valid subnet info 2",
			externalIPPool: mutateExternalIPPool(newExternalIPPool("foo", "fd00:10:96::/112", "", ""), func(pool *crdv1b1.ExternalIPPool) {
				pool.Spec.SubnetInfo = &crdv1b1.SubnetInfo{
					Gateway:      "fd00:10:96::",
					PrefixLength: 96,
					VLAN:         2,
				}
			}),
		},

		// test cases for cidr range overlap
		{
			name:           "cidr must not overlap with any existing cidr",
			externalIPPool: newExternalIPPool("foo", "10.20.30.0/24", "", ""),
			existingExternalIPPools: []*crdv1b1.ExternalIPPool{
				newExternalIPPool("bar", "10.10.10.0/24", "", ""),
				newExternalIPPool("baz", "10.10.20.0/24", "", ""),
				newExternalIPPool("qux", "10.20.0.0/16", "", ""),
			},
			errMsg: "range [10.20.30.0/24] overlaps with range [10.20.0.0/16] of pool qux",
		},
		{
			name:           "cidr must not overlap with any existing start-end range",
			externalIPPool: newExternalIPPool("foo", "10.20.30.0/24", "", ""),
			existingExternalIPPools: []*crdv1b1.ExternalIPPool{
				newExternalIPPool("bar", "", "10.20.30.10", "10.20.30.50"),
			},
			errMsg: "range [10.20.30.0/24] overlaps with range [10.20.30.10-10.20.30.50] of pool bar",
		},
		{
			name: "cidr must not overlap with any cidr",
			externalIPPool: mutateExternalIPPool(newExternalIPPool("foo", "10.10.10.0/24", "", ""), func(pool *crdv1b1.ExternalIPPool) {
				pool.Spec.IPRanges = append(pool.Spec.IPRanges, crdv1b1.IPRange{CIDR: "10.30.20.0/24"})
				pool.Spec.IPRanges = append(pool.Spec.IPRanges, crdv1b1.IPRange{CIDR: "10.10.0.0/16"})
			}),
			errMsg: "range [10.10.0.0/16] overlaps with range [10.10.10.0/24]",
		},
		{
			name: "cidr must not overlap with any start-end range",
			externalIPPool: mutateExternalIPPool(newExternalIPPool("foo", "", "10.10.20.20", "10.10.20.50"), func(pool *crdv1b1.ExternalIPPool) {
				pool.Spec.IPRanges = append(pool.Spec.IPRanges, crdv1b1.IPRange{CIDR: "10.10.20.0/24"})
			}),
			errMsg: "range [10.10.20.0/24] overlaps with range [10.10.20.20-10.10.20.50]",
		},
		{
			name: "valid non overlapping cidr",
			externalIPPool: mutateExternalIPPool(newExternalIPPool("foo", "10.10.20.0/24", "", ""), func(pool *crdv1b1.ExternalIPPool) {
				pool.Spec.IPRanges = append(pool.Spec.IPRanges, crdv1b1.IPRange{CIDR: "10.10.30.0/24"})
			}),
			existingExternalIPPools: []*crdv1b1.ExternalIPPool{
				newExternalIPPool("bar", "", "10.10.40.10", "10.10.40.80"),
				newExternalIPPool("baz", "10.10.40.0/24", "", ""),
				newExternalIPPool("qux", "10.20.0.0/16", "", ""),
			},
		},

		// test cases for start-end range overlap
		{
			name:           "start-end range must not overlap with any existing cidr",
			externalIPPool: newExternalIPPool("foo", "", "10.30.10.0", "10.30.20.0"),
			existingExternalIPPools: []*crdv1b1.ExternalIPPool{
				newExternalIPPool("bar", "", "10.10.10.0", "10.10.20.0"),
				newExternalIPPool("baz", "10.20.0.0/16", "", ""),
				newExternalIPPool("qux", "10.30.0.0/20", "", ""),
			},
			errMsg: "range [10.30.10.0-10.30.20.0] overlaps with range [10.30.0.0/20] of pool qux",
		},
		{
			name:           "start-end range must not overlap with any existing start-end range",
			externalIPPool: newExternalIPPool("foo", "", "10.30.10.0", "10.30.20.0"),
			existingExternalIPPools: []*crdv1b1.ExternalIPPool{
				newExternalIPPool("bar", "10.10.0.0/16", "", ""),
				newExternalIPPool("baz", "", "10.30.20.0", "10.30.40.0"),
			},
			errMsg: "range [10.30.10.0-10.30.20.0] overlaps with range [10.30.20.0-10.30.40.0] of pool baz",
		},
		{
			name: "start-end range must not overlap with any cidr",
			externalIPPool: mutateExternalIPPool(newExternalIPPool("foo", "10.30.0.0/16", "10.30.40.50", "10.30.40.80"), func(pool *crdv1b1.ExternalIPPool) {
				pool.Spec.IPRanges = append(pool.Spec.IPRanges, crdv1b1.IPRange{CIDR: "10.30.0.0/16"})
				pool.Spec.IPRanges = append(pool.Spec.IPRanges, crdv1b1.IPRange{Start: "10.30.40.50", End: "10.30.40.80"})
			}),
			errMsg: "range [10.30.40.50-10.30.40.80] overlaps with range [10.30.0.0/16]",
		},
		{
			name: "start-end range must not overlap with any start-end range",
			externalIPPool: mutateExternalIPPool(newExternalIPPool("foo", "", "10.30.40.50", "10.30.40.80"), func(pool *crdv1b1.ExternalIPPool) {
				pool.Spec.IPRanges = append(pool.Spec.IPRanges, crdv1b1.IPRange{CIDR: "10.30.50.0/24"})
				pool.Spec.IPRanges = append(pool.Spec.IPRanges, crdv1b1.IPRange{Start: "10.30.40.10", End: "10.30.40.90"})
			}),
			errMsg: "range [10.30.40.10-10.30.40.90] overlaps with range [10.30.40.50-10.30.40.80]",
		},
		{
			name: "valid non overlapping start-end range",
			externalIPPool: mutateExternalIPPool(newExternalIPPool("foo", "", "10.30.10.0", "10.30.20.0"), func(pool *crdv1b1.ExternalIPPool) {
				pool.Spec.IPRanges = append(pool.Spec.IPRanges, crdv1b1.IPRange{CIDR: "10.30.50.0/24"})
				pool.Spec.IPRanges = append(pool.Spec.IPRanges, crdv1b1.IPRange{CIDR: "10.50.0.0/16"})
				pool.Spec.IPRanges = append(pool.Spec.IPRanges, crdv1b1.IPRange{Start: "10.30.20.1", End: "10.30.40.10"})
			}),
			existingExternalIPPools: []*crdv1b1.ExternalIPPool{
				newExternalIPPool("bar", "", "10.10.10.0", "10.10.20.0"),
				newExternalIPPool("baz", "10.20.0.0/16", "", ""),
				newExternalIPPool("baz", "10.40.0.0/16", "", ""),
				newExternalIPPool("bar", "", "10.10.10.0", "10.10.20.0"),
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			errMsg, result := validateIPRangesAndSubnetInfo(
				*testCase.externalIPPool,
				testCase.existingExternalIPPools,
			)

			if testCase.errMsg == "" {
				assert.Empty(t, errMsg)
			} else {

				assert.Equal(t, testCase.errMsg, errMsg)
				if testCase.errMsg != "" {
					assert.False(t, result)
				} else {
					assert.True(t, result)
				}

				// test if same message is returned by ValidateExternalIPPool
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

func TestParseIPRangeCIDR(t *testing.T) {
	testCases := []struct {
		name   string
		cidr   string
		errMsg string
	}{
		{
			name: "valid",
			cidr: "10.96.10.10/20",
		},
		{
			name:   "invalid ipv4 cidr",
			cidr:   "10.96.40.50/36",
			errMsg: "invalid cidr 10.96.40.50/36",
		},
		{
			name:   "invalid ipv6 cidr",
			cidr:   "2001:d00::/132",
			errMsg: "invalid cidr 2001:d00::/132",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// discard parsed net.IPNet, we only need to make assertions on errMsg.
			_, errMsg := parseIPRangeCIDR(testCase.cidr)
			assert.Equal(t, testCase.errMsg, errMsg)
		})
	}
}

func TestParseIPRangeStartEnd(t *testing.T) {
	testCases := []struct {
		name   string
		start  string
		end    string
		errMsg string
	}{
		{
			name:  "valid",
			start: "10.96.10.10",
			end:   "10.96.10.20",
		},
		{
			name:   "invalid start ip",
			start:  "10.96.10.1000",
			end:    "10.96.10.20",
			errMsg: "invalid start ip address 10.96.10.1000",
		},
		{
			name:   "invalid end ip",
			start:  "2001:d00::",
			end:    "2001:g00::",
			errMsg: "invalid end ip address 2001:g00::",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// discard parsed net.IP, we only need to make assertions on errMsg.
			_, _, errMsg := parseIPRangeStartEnd(testCase.start, testCase.end)
			assert.Equal(t, testCase.errMsg, errMsg)
		})
	}
}
