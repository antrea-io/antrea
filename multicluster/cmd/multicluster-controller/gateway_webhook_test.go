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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	mcv1alpha1 "antrea.io/antrea/v2/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/v2/multicluster/controllers/multicluster/common"
	crdv1beta1 "antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
)

var gatewayWebhookUnderTest *gatewayValidator

func newAntreaAgentInfo(nodeName, podNamespace string) *crdv1beta1.AntreaAgentInfo {
	return &crdv1beta1.AntreaAgentInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name: nodeName,
		},
		PodRef: corev1.ObjectReference{
			Kind:      "Pod",
			Namespace: podNamespace,
			Name:      "antrea-agent-" + nodeName,
		},
	}
}

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
				Username: "system:serviceaccount:antrea-multicluster:antrea-mc-controller",
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
				Username: "system:serviceaccount:antrea-multicluster:other-sa",
				UID:      "4842eb60-68e3-4e38-adad-3abfd6117241",
			},
		},
	}

	createReqWithUser := func(username string) admission.Request {
		req := newReq.DeepCopy()
		req.UserInfo.Username = username
		return admission.Request{AdmissionRequest: *req}
	}
	updateReqWithUser := func(username string) admission.Request {
		req := updateReqWithInvalidSA.DeepCopy()
		req.UserInfo.Username = username
		return admission.Request{AdmissionRequest: *req}
	}

	newReqCopy := newReq.DeepCopy()
	invalidReq := admission.Request{
		AdmissionRequest: *newReqCopy,
	}
	invalidReq.Object = runtime.RawExtension{Raw: []byte("a")}
	updateReqCopy := updateReqWithInvalidSA.DeepCopy()
	updateReqCopy.UserInfo.Username = "system:serviceaccount:antrea-multicluster:antrea-mc-controller"
	updateReq := admission.Request{
		AdmissionRequest: *updateReqCopy,
	}
	connectReqCopy := updateReqWithInvalidSA.DeepCopy()
	connectReqCopy.Operation = v1.Connect
	connectReq := admission.Request{
		AdmissionRequest: *connectReqCopy,
	}

	// By default, Antrea Agents run in the kube-system Namespace.
	defaultAgentInfos := []client.Object{
		newAntreaAgentInfo("node-1", "kube-system"),
		newAntreaAgentInfo("node-2", "kube-system"),
	}

	tests := []struct {
		name            string
		req             admission.Request
		existingGateway *mcv1alpha1.Gateway
		newGateway      *mcv1alpha1.Gateway
		// agentInfos defaults to defaultAgentInfos when nil.
		agentInfos   []client.Object
		agentInfoErr error
		isAllowed    bool
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
			name:            "update a Gateway with ServiceAccount antrea-agent successfully",
			existingGateway: existingGateway,
			req:             updateReqWithUser("system:serviceaccount:kube-system:antrea-agent"),
			isAllowed:       true,
		},
		{
			name:      "create a Gateway with ServiceAccount antrea-agent successfully",
			req:       createReqWithUser("system:serviceaccount:kube-system:antrea-agent"),
			isAllowed: true,
		},
		{
			name:            "failed to update a Gateway with ServiceAccount antrea-agent from other Namespace",
			existingGateway: existingGateway,
			req:             updateReqWithUser("system:serviceaccount:other-namespace:antrea-agent"),
			isAllowed:       false,
		},
		{
			name:            "failed to update a Gateway with ServiceAccount antrea-mc-controller from other Namespace",
			existingGateway: existingGateway,
			req:             updateReqWithUser("system:serviceaccount:other-namespace:antrea-mc-controller"),
			isAllowed:       false,
		},
		{
			name:      "failed to create a Gateway with ServiceAccount antrea-mc-controller from other Namespace",
			req:       createReqWithUser("system:serviceaccount:other-namespace:antrea-mc-controller"),
			isAllowed: false,
		},
		{
			name:            "failed to update a Gateway with ServiceAccount antrea-agent from multi-cluster controller Namespace",
			existingGateway: existingGateway,
			req:             updateReqWithUser("system:serviceaccount:antrea-multicluster:antrea-agent"),
			isAllowed:       false,
		},
		{
			name:            "failed to update a Gateway with ServiceAccount antrea-mc-controller from Antrea Namespace",
			existingGateway: existingGateway,
			req:             updateReqWithUser("system:serviceaccount:kube-system:antrea-mc-controller"),
			isAllowed:       false,
		},
		{
			name:            "failed to update a Gateway with other ServiceAccount from Antrea Namespace",
			existingGateway: existingGateway,
			req:             updateReqWithUser("system:serviceaccount:kube-system:other-sa"),
			isAllowed:       false,
		},
		{
			name:            "failed to update a Gateway with non-ServiceAccount user",
			existingGateway: existingGateway,
			req:             updateReqWithUser("kubernetes-admin"),
			isAllowed:       false,
		},
		{
			name:            "update a Gateway with ServiceAccount antrea-agent from custom Antrea Namespace successfully",
			existingGateway: existingGateway,
			agentInfos:      []client.Object{newAntreaAgentInfo("node-2", "antrea-system")},
			req:             updateReqWithUser("system:serviceaccount:antrea-system:antrea-agent"),
			isAllowed:       true,
		},
		{
			name:            "failed to update a Gateway with ServiceAccount antrea-agent from kube-system when Antrea is elsewhere",
			existingGateway: existingGateway,
			agentInfos:      []client.Object{newAntreaAgentInfo("node-2", "antrea-system")},
			req:             updateReqWithUser("system:serviceaccount:kube-system:antrea-agent"),
			isAllowed:       false,
		},
		{
			name:            "failed to update a Gateway with ServiceAccount antrea-agent from Antrea Namespace of another Node",
			existingGateway: existingGateway,
			agentInfos: []client.Object{
				newAntreaAgentInfo("node-1", "antrea-system"),
				newAntreaAgentInfo("node-2", "kube-system"),
			},
			req:       updateReqWithUser("system:serviceaccount:antrea-system:antrea-agent"),
			isAllowed: false,
		},
		{
			name:            "failed to update a Gateway with ServiceAccount antrea-agent without AntreaAgentInfo",
			existingGateway: existingGateway,
			agentInfos:      []client.Object{},
			req:             updateReqWithUser("system:serviceaccount:kube-system:antrea-agent"),
			isAllowed:       false,
		},
		{
			name:            "failed to update a Gateway with ServiceAccount antrea-agent when AntreaAgentInfo has no PodRef",
			existingGateway: existingGateway,
			agentInfos:      []client.Object{newAntreaAgentInfo("node-2", "")},
			req:             updateReqWithUser("system:serviceaccount:kube-system:antrea-agent"),
			isAllowed:       false,
		},
		{
			name:            "failed to update a Gateway with ServiceAccount antrea-agent when getting AntreaAgentInfo fails",
			existingGateway: existingGateway,
			agentInfoErr:    errors.New("fake error"),
			req:             updateReqWithUser("system:serviceaccount:kube-system:antrea-agent"),
			isAllowed:       false,
		},
		{
			name:            "update a Gateway with ServiceAccount antrea-mc-controller without AntreaAgentInfo successfully",
			existingGateway: existingGateway,
			agentInfos:      []client.Object{},
			req:             updateReq,
			isAllowed:       true,
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
		t.Run(tt.name, func(t *testing.T) {
			objects := defaultAgentInfos
			if tt.agentInfos != nil {
				objects = tt.agentInfos
			}
			if tt.existingGateway != nil {
				objects = append(append([]client.Object{}, objects...), tt.existingGateway)
			}
			builder := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(objects...)
			if tt.agentInfoErr != nil {
				builder = builder.WithInterceptorFuncs(interceptor.Funcs{
					Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object,
						opts ...client.GetOption) error {
						if _, ok := obj.(*crdv1beta1.AntreaAgentInfo); ok {
							return tt.agentInfoErr
						}
						return c.Get(ctx, key, obj, opts...)
					},
				})
			}
			fakeClient := builder.Build()
			gatewayWebhookUnderTest = &gatewayValidator{
				Client:          fakeClient,
				agentInfoReader: fakeClient,
				decoder:         decoder,
				namespace:       "antrea-multicluster",
			}

			response := gatewayWebhookUnderTest.Handle(context.Background(), tt.req)
			assert.Equal(t, tt.isAllowed, response.Allowed)
		})
	}
}
