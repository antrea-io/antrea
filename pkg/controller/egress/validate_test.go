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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"

	crdv1beta1 "antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
	fakeversioned "antrea.io/antrea/v2/pkg/client/clientset/versioned/fake"
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
			name: "Updating selector with unchanged IP and missing Pool should be allowed",
			request: &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: admv1.Update,
				OldObject: runtime.RawExtension{Raw: marshal(newEgress("foo", "10.10.10.1", "bar", nil, nil, nil))},
				Object: runtime.RawExtension{Raw: marshal(newEgress("foo", "10.10.10.1", "bar", &metav1.LabelSelector{
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

func TestEgressControllerValidateEgressGateway(t *testing.T) {
	poolWithGateway := func(cidr, start, end, gateway string, prefixLength int32) *crdv1beta1.ExternalIPPool {
		pool := newExternalIPPool("bar", cidr, start, end)
		pool.Spec.SubnetInfo = &crdv1beta1.SubnetInfo{Gateway: gateway, PrefixLength: prefixLength}
		return pool
	}
	ipv4CIDRPool := poolWithGateway("192.168.1.144/28", "", "", "192.168.1.145", 28)
	ipv4RangePool := poolWithGateway("", "192.168.1.145", "192.168.1.158", "192.168.1.145", 28)
	ipv6CIDRPool := poolWithGateway("2001:db8::/124", "", "", "2001:db8::1", 124)
	ipv6RangePool := poolWithGateway("", "2001:db8::1", "2001:db8::e", "2001:db8::1", 124)
	tests := []struct {
		name     string
		pool     *crdv1beta1.ExternalIPPool
		ip       string
		old      *crdv1beta1.Egress
		detached bool
		allowed  bool
	}{
		{
			name: "create with IPv4 CIDR gateway",
			pool: ipv4CIDRPool,
			ip:   "192.168.1.145",
		},
		{
			name: "create with IPv4 range gateway",
			pool: ipv4RangePool,
			ip:   "192.168.1.145",
		},
		{
			name: "create with equivalent IPv6 CIDR gateway",
			pool: ipv6CIDRPool,
			ip:   "2001:0db8:0000:0000:0000:0000:0000:0001",
		},
		{
			name: "create with IPv6 range gateway",
			pool: ipv6RangePool,
			ip:   "2001:db8::1",
		},
		{
			name: "update IP to IPv4 CIDR gateway",
			pool: ipv4CIDRPool,
			ip:   "192.168.1.145",
			old:  newEgress("foo", "192.168.1.146", "bar", nil, nil, nil),
		},
		{
			name: "update IP to IPv4 range gateway",
			pool: ipv4RangePool,
			ip:   "192.168.1.145",
			old:  newEgress("foo", "192.168.1.146", "bar", nil, nil, nil),
		},
		{
			name: "update IP to IPv6 CIDR gateway",
			pool: ipv6CIDRPool,
			ip:   "2001:db8::1",
			old:  newEgress("foo", "2001:db8::2", "bar", nil, nil, nil),
		},
		{
			name: "update IP to IPv6 range gateway",
			pool: ipv6RangePool,
			ip:   "2001:db8::1",
			old:  newEgress("foo", "2001:db8::2", "bar", nil, nil, nil),
		},
		{
			name: "update Pool to one whose gateway matches the IP",
			pool: ipv4CIDRPool,
			ip:   "192.168.1.145",
			old:  newEgress("foo", "192.168.1.145", "other", nil, nil, nil),
		},
		{
			name: "update selector while retaining gateway IP",
			pool: ipv4CIDRPool,
			ip:   "192.168.1.145",
			old:  newEgress("foo", "192.168.1.145", "bar", nil, nil, nil),
		},
		{
			name:    "create with normal IP and subnet",
			pool:    ipv4CIDRPool,
			ip:      "192.168.1.146",
			allowed: true,
		},
		{
			name:    "create with automatic IP allocation",
			pool:    ipv4CIDRPool,
			allowed: true,
		},
		{
			name:    "create without subnet",
			pool:    newExternalIPPool("bar", "192.168.1.144/28", "", ""),
			ip:      "192.168.1.145",
			allowed: true,
		},
		{
			name:     "detach gateway IP from Pool",
			pool:     ipv4CIDRPool,
			ip:       "192.168.1.145",
			old:      newEgress("foo", "192.168.1.145", "bar", nil, nil, nil),
			detached: true,
			allowed:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stopCh := make(chan struct{})
			defer close(stopCh)
			controller := newController(nil, []runtime.Object{tt.pool.DeepCopy()})
			controller.informerFactory.Start(stopCh)
			controller.crdInformerFactory.Start(stopCh)
			controller.informerFactory.WaitForCacheSync(stopCh)
			controller.crdInformerFactory.WaitForCacheSync(stopCh)
			go controller.externalIPAllocator.Run(stopCh)
			require.True(t, cache.WaitForCacheSync(stopCh, controller.externalIPAllocator.HasSynced))
			controller.externalIPAllocator.RestoreIPAllocations(nil)
			poolName := tt.pool.Name
			if tt.detached {
				poolName = ""
			}
			request := &admv1.AdmissionRequest{
				Name:      "foo",
				Operation: admv1.Create,
				Object: runtime.RawExtension{Raw: marshal(newEgress("foo", tt.ip, poolName,
					&metav1.LabelSelector{MatchLabels: map[string]string{"foo": "bar"}}, nil, nil))},
			}
			if tt.old != nil {
				request.Operation = admv1.Update
				request.OldObject = runtime.RawExtension{Raw: marshal(tt.old)}
			}
			expectedResponse := &admv1.AdmissionResponse{Allowed: tt.allowed}
			if !tt.allowed {
				expectedResponse.Result = &metav1.Status{
					Message: "IP " + tt.ip + " is the gateway of ExternalIPPool bar and cannot be used as an Egress IP",
				}
			}
			assert.Equal(t, expectedResponse, controller.ValidateEgress(&admv1.AdmissionReview{Request: request}))
		})
	}
}

func TestEgressControllerValidateEgressGatewayLookupFailure(t *testing.T) {
	controller := newController(nil, nil)
	controller.crdClient.(*fakeversioned.Clientset).PrependReactor("get", "externalippools",
		func(action k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("connection refused")
		})
	request := &admv1.AdmissionRequest{
		Name:      "foo",
		Operation: admv1.Create,
		Object:    runtime.RawExtension{Raw: marshal(newEgress("foo", "192.168.1.145", "bar", nil, nil, nil))},
	}
	expectedResponse := &admv1.AdmissionResponse{
		Allowed: false,
		Result:  &metav1.Status{Message: "failed to get ExternalIPPool bar: connection refused"},
	}
	assert.Equal(t, expectedResponse, controller.ValidateEgress(&admv1.AdmissionReview{Request: request}))
}
