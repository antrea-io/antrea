/*
Copyright 2022 Antrea Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
	k8smcsv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
)

var gatewayWebhookUnderTest *gatewayValidator

func TestWebhookGatewayEvents(t *testing.T) {
	newGateway := &mcsv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "node-1",
		},
		GatewayIP:  "1.2.3.4",
		InternalIP: "172.168.3.4",
	}
	existingGateway := &mcsv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "node-2",
		},
	}

	newGW, _ := json.Marshal(newGateway)

	newReq := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			UID: "07e52e8d-4513-11e9-a716-42010a800270",
			Kind: metav1.GroupVersionKind{
				Group:   "multicluster.crd.antrea.io",
				Version: "v1alpha1",
				Kind:    "Gateway",
			},
			Resource: metav1.GroupVersionResource{
				Group:    "multicluster.crd.antrea.io",
				Version:  "v1alpha1",
				Resource: "Gateways",
			},
			Name:      "node-1",
			Namespace: "default",
			Operation: v1.Create,
			Object: runtime.RawExtension{
				Raw: newGW,
			},
		},
	}

	newReqCopy := newReq.DeepCopy()
	invalidReq := admission.Request{
		AdmissionRequest: *newReqCopy,
	}
	invalidReq.Object = runtime.RawExtension{Raw: []byte("a")}

	tests := []struct {
		name            string
		req             admission.Request
		existingGateway *mcsv1alpha1.Gateway
		newGateway      *mcsv1alpha1.Gateway
		isAllowed       bool
	}{
		{
			name:      "create a new Gateway successfully",
			req:       newReq,
			isAllowed: true,
		},
		{
			name:            "failed to create a Gateway when there is an existing one",
			existingGateway: existingGateway,
			req:             newReq,
			isAllowed:       false,
		},
		{
			name:      "failed to decode request",
			req:       invalidReq,
			isAllowed: false,
		},
	}

	newScheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(newScheme))
	utilruntime.Must(k8smcsv1alpha1.AddToScheme(newScheme))
	utilruntime.Must(mcsv1alpha1.AddToScheme(newScheme))
	decoder, err := admission.NewDecoder(newScheme)
	if err != nil {
		klog.ErrorS(err, "Error constructing a decoder")
	}
	for _, tt := range tests {
		fakeClient := fake.NewClientBuilder().WithScheme(newScheme).WithObjects().Build()
		if tt.existingGateway != nil {
			fakeClient = fake.NewClientBuilder().WithScheme(newScheme).WithObjects(tt.existingGateway).Build()
		}
		gatewayWebhookUnderTest = &gatewayValidator{
			Client:    fakeClient,
			namespace: "default"}
		gatewayWebhookUnderTest.InjectDecoder(decoder)

		t.Run(tt.name, func(t *testing.T) {
			response := gatewayWebhookUnderTest.Handle(context.Background(), tt.req)
			assert.Equal(t, tt.isAllowed, response.Allowed)
		})
	}
}
