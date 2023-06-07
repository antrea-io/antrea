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
	j "encoding/json"
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
	mcsv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
)

var clusterClaimWebhookUnderTest *clusterClaimValidator

func TestWebhookClusterClaimEvents(t *testing.T) {
	validClusterClaim1 := &mcsv1alpha2.ClusterClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "mcs1",
			Name:      "id.k8s.io",
		},
		Value: "east",
	}
	validClusterClaim2 := &mcsv1alpha2.ClusterClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "mcs1",
			Name:      "clusterset.k8s.io",
		},
		Value: "clusterset",
	}
	validClusterClaim3 := &mcsv1alpha2.ClusterClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "mcs1",
			Name:      "id.k8s.io",
		},
		Value: "north",
	}

	invalidClusterClaim := &mcsv1alpha2.ClusterClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "mcs1",
			Name:      "invalid",
		},
		Value: "clusterclaim",
	}

	validClusterClaim1Updated := &mcsv1alpha2.ClusterClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "mcs1",
			Name:      "id.k8s.io",
		},
		Value: "east-1",
	}

	existingClusterSetList := &mcsv1alpha1.ClusterSetList{
		Items: []mcsv1alpha1.ClusterSet{
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "mcs1",
					Name:      "clusterset",
				},
				Spec: mcsv1alpha1.ClusterSetSpec{
					Leaders: []mcsv1alpha1.MemberCluster{
						{
							ClusterID: "leader1",
						}},
					Members: []mcsv1alpha1.MemberCluster{
						{
							ClusterID:      "east",
							ServiceAccount: "east-access-sa",
						},
						{
							ClusterID:      "west",
							ServiceAccount: "west-access-sa",
						},
					},
					Namespace: "mcs1",
				},
			},
		},
	}

	validCC1, _ := j.Marshal(validClusterClaim1)
	validCC2, _ := j.Marshal(validClusterClaim2)
	validCC3, _ := j.Marshal(validClusterClaim3)
	invalidCC, _ := j.Marshal(invalidClusterClaim)
	validCC1Updated, _ := j.Marshal(validClusterClaim1Updated)

	validCC1Req := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			UID: "07e52e8d-4513-11e9-a716-42010a800270",
			Kind: metav1.GroupVersionKind{
				Group:   "multicluster.crd.antrea.io",
				Version: "v1alpha2",
				Kind:    "ClusterClaim",
			},
			Resource: metav1.GroupVersionResource{
				Group:    "multicluster.crd.antrea.io",
				Version:  "v1alpha2",
				Resource: "ClusterClaims",
			},
			Name:      "id.k8s.io",
			Namespace: "mcs1",
			Operation: v1.Create,
			Object: runtime.RawExtension{
				Raw: validCC1,
			},
		},
	}
	invalidCCReq := validCC1Req.DeepCopy()
	invalidCCReq.Name = "invalid"
	invalidCCReq.Object.Raw = invalidCC

	updatedCC1Req := validCC1Req.DeepCopy()
	updatedCC1Req.Operation = v1.Update
	updatedCC1Req.OldObject.Raw = validCC1Updated

	deleteCC1Req := validCC1Req.DeepCopy()
	deleteCC1Req.Operation = v1.Delete
	deleteCC1Req.OldObject.Raw = validCC1

	deleteCC2Req := validCC1Req.DeepCopy()
	deleteCC2Req.Operation = v1.Delete
	deleteCC2Req.Name = "clusterset.k8s.io"
	deleteCC2Req.OldObject.Raw = validCC2

	deleteCC3Req := validCC1Req.DeepCopy()
	deleteCC3Req.Operation = v1.Delete
	deleteCC3Req.OldObject.Raw = validCC3

	tests := []struct {
		name                 string
		req                  admission.Request
		existingClusterClaim *mcsv1alpha2.ClusterClaim
		newClusterClaim      *mcsv1alpha2.ClusterClaim
		isAllowed            bool
	}{
		{
			name:      "create a new ClusterClaim",
			req:       validCC1Req,
			isAllowed: true,
		},
		{
			name:      "create an invalid ClusterClaim",
			req:       admission.Request{AdmissionRequest: *invalidCCReq},
			isAllowed: false,
		},
		{
			name:                 "update a new ClusterClaim with value change",
			existingClusterClaim: validClusterClaim1,
			newClusterClaim:      validClusterClaim1Updated,
			req:                  admission.Request{AdmissionRequest: *updatedCC1Req},
			isAllowed:            false,
		},
		{
			name:      "delete a ClusterClaim which is referred by a ClusterSet's member",
			req:       admission.Request{AdmissionRequest: *deleteCC1Req},
			isAllowed: false,
		},
		{
			name:      "delete a ClusterClaim which is referred by a ClusterSet",
			req:       admission.Request{AdmissionRequest: *deleteCC2Req},
			isAllowed: false,
		},
		{
			name:      "delete a ClusterClaim successfully",
			req:       admission.Request{AdmissionRequest: *deleteCC3Req},
			isAllowed: true,
		},
	}

	newScheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(newScheme))
	utilruntime.Must(k8smcsv1alpha1.AddToScheme(newScheme))
	utilruntime.Must(mcsv1alpha1.AddToScheme(newScheme))
	utilruntime.Must(mcsv1alpha2.AddToScheme(newScheme))
	decoder, err := admission.NewDecoder(newScheme)
	if err != nil {
		klog.ErrorS(err, "Error constructing a decoder")
	}

	for _, tt := range tests {
		fakeClient := fake.NewClientBuilder().WithScheme(newScheme).WithLists(existingClusterSetList).Build()
		if tt.existingClusterClaim != nil {
			fakeClient = fake.NewClientBuilder().WithScheme(newScheme).WithObjects(tt.existingClusterClaim).
				WithLists(existingClusterSetList).Build()
		}
		clusterClaimWebhookUnderTest = &clusterClaimValidator{
			Client:    fakeClient,
			namespace: "mcs1"}
		clusterClaimWebhookUnderTest.InjectDecoder(decoder)

		t.Run(tt.name, func(t *testing.T) {
			response := clusterClaimWebhookUnderTest.Handle(context.Background(), tt.req)
			assert.Equal(t, tt.isAllowed, response.Allowed)
		})
	}
}
