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
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	mcv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
)

var gatewayWebhookUnderTest *gatewayValidator

func TestWebhookGatewayEvents(t *testing.T) {
	newGateway := &mcv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "node-1",
		},
		GatewayIP:  "1.2.3.4",
		InternalIP: "172.168.3.4",
	}
	existingGateway := &mcv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "node-2",
		},
	}
	updatedGateway := &mcv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "node-2",
		},
		ServiceCIDR: "10.100.0.0/16",
	}
	oldGateway := updatedGateway.DeepCopy()
	oldGateway.ServiceCIDR = "10.101.0.0/16"

	newGW, _ := json.Marshal(newGateway)
	updatedGW, _ := json.Marshal(updatedGateway)
	oldGW, _ := json.Marshal(oldGateway)

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
			UserInfo: authenticationv1.UserInfo{
				Username: "system:serviceaccount:mcs1:antrea-mc-controller",
				UID:      "4842eb60-68e3-4e38-adad-3abfd6117241",
			},
		},
	}

	updateReqWithInvalidSA := admission.Request{
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
			Name:      "node-2",
			Namespace: "default",
			Operation: v1.Update,
			OldObject: runtime.RawExtension{
				Raw: oldGW,
			},
			Object: runtime.RawExtension{
				Raw: updatedGW,
			},
			UserInfo: authenticationv1.UserInfo{
				Username: "system:serviceaccount:mcs1:other-sa",
				UID:      "4842eb60-68e3-4e38-adad-3abfd6117241",
			},
		},
	}

	newReqCopy := newReq.DeepCopy()
	invalidReq := admission.Request{
		AdmissionRequest: *newReqCopy,
	}
	invalidReq.Object = runtime.RawExtension{Raw: []byte("a")}
	updateReqCopy := updateReqWithInvalidSA.DeepCopy()
	updateReqCopy.UserInfo.Username = "system:serviceaccount:mcs1:antrea-mc-controller"
	updateReq := admission.Request{
		AdmissionRequest: *updateReqCopy,
	}
	connectReqCopy := updateReqWithInvalidSA.DeepCopy()
	connectReqCopy.Operation = v1.Connect
	connectReq := admission.Request{
		AdmissionRequest: *connectReqCopy,
	}

	tests := []struct {
		name            string
		req             admission.Request
		existingGateway *mcv1alpha1.Gateway
		newGateway      *mcv1alpha1.Gateway
		isAllowed       bool
	}{
		{
			name:      "create a new Gateway successfully",
			req:       newReq,
			isAllowed: true,
		},
		{
			name:      "failed to decode request",
			req:       invalidReq,
			isAllowed: false,
		},
		{
			name:            "failed to update a Gateway with other ServiceAccount",
			existingGateway: existingGateway,
			req:             updateReqWithInvalidSA,
			isAllowed:       false,
		},
		{
			name:            "connect to a Gateway with other ServiceAccount successfully",
			existingGateway: existingGateway,
			req:             connectReq,
			isAllowed:       true,
		},
		{
			name:            "update a Gateway with ServiceAccount antrea-mc-controller successfully",
			existingGateway: existingGateway,
			req:             updateReq,
			isAllowed:       true,
		},
	}

	decoder := admission.NewDecoder(common.TestScheme)
	for _, tt := range tests {
		fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects().Build()
		if tt.existingGateway != nil {
			fakeClient = fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(tt.existingGateway).Build()
		}
		gatewayWebhookUnderTest = &gatewayValidator{
			Client:    fakeClient,
			decoder:   decoder,
			namespace: "default",
		}

		t.Run(tt.name, func(t *testing.T) {
			response := gatewayWebhookUnderTest.Handle(context.Background(), tt.req)
			assert.Equal(t, tt.isAllowed, response.Allowed)
		})
	}
}
