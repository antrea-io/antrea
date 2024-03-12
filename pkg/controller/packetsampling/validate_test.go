// Copyright 2023 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package packetsampling

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	admv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

func TestControllerValidate(t *testing.T) {
	tests := []struct {
		name string

		// input
		oldSpec *crdv1alpha1.PacketSamplingSpec
		newSpec *crdv1alpha1.PacketSamplingSpec

		// expected output
		allowed      bool
		deniedReason string
	}{
		{
			name:         "Traceflow should have either source or destination Pod assigned",
			newSpec:      &crdv1alpha1.PacketSamplingSpec{},
			deniedReason: "PacketSampling ps has neither source nor destination Pod specified",
		},
		{
			name: "Must assign sampling type",
			newSpec: &crdv1alpha1.PacketSamplingSpec{
				Source: crdv1alpha1.Source{
					Namespace: "test-ns",
					Pod:       "test-pod",
				},
			},
			deniedReason: "PacketSampling ps has invalid type  (supported are [FirstNSampling])",
		},
		{
			name: "FistNSampling config not set",
			newSpec: &crdv1alpha1.PacketSamplingSpec{
				Source: crdv1alpha1.Source{
					Namespace: "test-ns",
					Pod:       "test-pod",
				},
				Type: crdv1alpha1.FirstNSampling,
			},
			deniedReason: "PacketSampling ps has no FirstNSamplingConfig",
		},
		{
			name: "Source IP family does not match",
			newSpec: &crdv1alpha1.PacketSamplingSpec{
				Source: crdv1alpha1.Source{
					IP: "127.0.0.1",
				},
				Type: crdv1alpha1.FirstNSampling,
				FirstNSamplingConfig: &crdv1alpha1.FirstNSamplingConfig{
					Number: 4,
				},
				Destination: crdv1alpha1.Destination{
					Namespace: "test-ns",
					Pod:       "test-pod",
				},
				Packet: crdv1alpha1.Packet{
					IPv6Header: &crdv1alpha1.IPv6Header{
						HopLimit: 1,
					},
				},
			},
			allowed:      false,
			deniedReason: "source IP does not match the IP header family",
		},
		{
			name: "Destination IP family does not match",
			newSpec: &crdv1alpha1.PacketSamplingSpec{
				Source: crdv1alpha1.Source{
					Namespace: "test-ns",
					Pod:       "test-pod",
				},
				Type: crdv1alpha1.FirstNSampling,
				FirstNSamplingConfig: &crdv1alpha1.FirstNSamplingConfig{
					Number: 4,
				},
				Destination: crdv1alpha1.Destination{
					IP: "fe80::aede:48ff:fe00:1122",
				},
				Packet: crdv1alpha1.Packet{},
			},
			allowed:      false,
			deniedReason: "destination IP does not match the IP header family",
		},
		{
			name: "Valid request",
			newSpec: &crdv1alpha1.PacketSamplingSpec{
				Source: crdv1alpha1.Source{
					Namespace: "test-ns",
					Pod:       "test-pod",
				},
				Type: crdv1alpha1.FirstNSampling,
				FirstNSamplingConfig: &crdv1alpha1.FirstNSamplingConfig{
					Number: 4,
				},
			},
			allowed: true,
		},
	}
	for _, ps := range tests {
		t.Run(ps.name, func(t *testing.T) {
			stopCh := make(chan struct{})
			defer close(stopCh)

			controller := newController()
			controller.informerFactory.Start(stopCh)
			controller.crdInformerFactory.Start(stopCh)
			// Must wait for cache sync, otherwise resource creation events will be missing if the resources are created
			// in-between list and watch call of an informer. This is because fake clientset doesn't support watching with
			// resourceVersion. A watcher of fake clientset only gets events that happen after the watcher is created.
			controller.informerFactory.WaitForCacheSync(stopCh)
			controller.crdInformerFactory.WaitForCacheSync(stopCh)
			go controller.Run(stopCh)

			var request *admv1.AdmissionRequest
			if ps.oldSpec != nil && ps.newSpec != nil {
				request = &admv1.AdmissionRequest{
					Operation: admv1.Update,
					OldObject: toRawExtension(ps.oldSpec),
					Object:    toRawExtension(ps.newSpec),
				}
			} else if ps.newSpec != nil {
				request = &admv1.AdmissionRequest{
					Operation: admv1.Create,
					Object:    toRawExtension(ps.newSpec),
				}
			}
			review := &admv1.AdmissionReview{
				Request: request,
			}

			expectedResponse := &admv1.AdmissionResponse{
				Allowed: ps.allowed,
			}
			if !ps.allowed {
				expectedResponse.Result = &metav1.Status{
					Message: ps.deniedReason,
				}
			}

			response := controller.Validate(review)
			assert.Equal(t, expectedResponse, response)
		})
	}
}

func toRawExtension(spec *crdv1alpha1.PacketSamplingSpec) runtime.RawExtension {
	ps := &crdv1alpha1.PacketSampling{Spec: *spec}
	ps.Name = "ps"
	raw, _ := json.Marshal(ps)
	return runtime.RawExtension{Raw: raw}
}
