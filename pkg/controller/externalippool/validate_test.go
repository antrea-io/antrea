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
)

func marshal(object runtime.Object) []byte {
	raw, _ := json.Marshal(object)
	return raw
}

func TestControllerValidateExternalIPPool(t *testing.T) {
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
				Object:    runtime.RawExtension{Raw: marshal(newExternalIPPool("foo", "10.10.10.0/24", "", ""))},
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
