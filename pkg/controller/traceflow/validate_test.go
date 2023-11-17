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

package traceflow

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	admv1 "k8s.io/api/admission/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
)

func TestControllerValidate(t *testing.T) {
	tests := []struct {
		name string

		// environment
		pods []*v1.Pod

		// input
		oldSpec *crdv1beta1.TraceflowSpec
		newSpec *crdv1beta1.TraceflowSpec

		// expected output
		allowed      bool
		deniedReason string
	}{
		{
			name: "Source Pod must be specified in non-live-traffic Traceflow",
			newSpec: &crdv1beta1.TraceflowSpec{
				Destination: crdv1beta1.Destination{IP: "10.0.0.2"},
			},
			deniedReason: "source Pod must be specified in non-live-traffic Traceflow",
		},
		{
			name: "Traceflow should have either source or destination Pod assigned",
			newSpec: &crdv1beta1.TraceflowSpec{
				LiveTraffic: true,
			},
			deniedReason: "Traceflow tf has neither source nor destination Pod specified",
		},
		{
			name: "Assigned source pod must exist",
			newSpec: &crdv1beta1.TraceflowSpec{
				Source: crdv1beta1.Source{
					Namespace: "test-ns",
					Pod:       "test-pod",
				},
			},
			deniedReason: "requested source Pod test-ns/test-pod not found",
		},
		{
			name: "Using hostNetwork Pod as source in non-live-traffic Traceflow is not supported",
			pods: []*v1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: "test-ns", Name: "test-pod"},
					Spec:       v1.PodSpec{HostNetwork: true},
				},
			},
			newSpec: &crdv1beta1.TraceflowSpec{
				Source: crdv1beta1.Source{
					Namespace: "test-ns",
					Pod:       "test-pod",
				},
			},
			deniedReason: "using hostNetwork Pod as source in non-live-traffic Traceflow is not supported",
		},
		{
			name: "Valid request",
			pods: []*v1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{Namespace: "test-ns", Name: "test-pod"},
				},
			},
			newSpec: &crdv1beta1.TraceflowSpec{
				Source: crdv1beta1.Source{
					Namespace: "test-ns",
					Pod:       "test-pod",
				},
			},
			allowed: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stopCh := make(chan struct{})
			defer close(stopCh)
			pods := make([]runtime.Object, 0)
			for _, p := range tc.pods {
				pods = append(pods, p)
			}
			controller := newController(pods...)
			controller.informerFactory.Start(stopCh)
			controller.crdInformerFactory.Start(stopCh)
			// Must wait for cache sync, otherwise resource creation events will be missing if the resources are created
			// in-between list and watch call of an informer. This is because fake clientset doesn't support watching with
			// resourceVersion. A watcher of fake clientset only gets events that happen after the watcher is created.
			controller.informerFactory.WaitForCacheSync(stopCh)
			controller.crdInformerFactory.WaitForCacheSync(stopCh)
			go controller.Run(stopCh)

			var request *admv1.AdmissionRequest
			if tc.oldSpec != nil && tc.newSpec != nil {
				request = &admv1.AdmissionRequest{
					Operation: admv1.Update,
					OldObject: toRawExtension(tc.oldSpec),
					Object:    toRawExtension(tc.newSpec),
				}
			} else if tc.newSpec != nil {
				request = &admv1.AdmissionRequest{
					Operation: admv1.Create,
					Object:    toRawExtension(tc.newSpec),
				}
			}
			review := &admv1.AdmissionReview{
				Request: request,
			}

			expectedResponse := &admv1.AdmissionResponse{
				Allowed: tc.allowed,
			}
			if !tc.allowed {
				expectedResponse.Result = &metav1.Status{
					Message: tc.deniedReason,
				}
			}

			response := controller.Validate(review)
			assert.Equal(t, expectedResponse, response)
		})
	}
}

func toRawExtension(spec *crdv1beta1.TraceflowSpec) runtime.RawExtension {
	tf := &crdv1beta1.Traceflow{Spec: *spec}
	tf.Name = "tf"
	raw, _ := json.Marshal(tf)
	return runtime.RawExtension{Raw: raw}
}
