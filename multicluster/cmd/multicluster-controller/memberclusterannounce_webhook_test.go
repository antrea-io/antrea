/*
Copyright 2021 Antrea Authors.

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
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	mcv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	mcv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
)

var mcaWebhookUnderTest *memberClusterAnnounceValidator

func TestMemberClusterAnnounceWebhook(t *testing.T) {
	existingClusterSet := &mcv1alpha2.ClusterSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "mcs1",
			Name:      "clusterset1",
		},
		Spec: mcv1alpha2.ClusterSetSpec{
			Leaders: []mcv1alpha2.LeaderClusterInfo{
				{
					ClusterID: "leader1",
				}},
			Namespace: "mcs-A",
		},
	}
	existingServiceAccounts := &corev1.ServiceAccountList{
		Items: []corev1.ServiceAccount{
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "mcs1",
					Name:      "east-access-sa",
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "mcs1",
					Name:      "west-access-sa",
				},
			},
		},
	}

	mca := &mcv1alpha1.MemberClusterAnnounce{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "member-announce-from-east",
			Namespace: "mcs1",
		},
		ClusterID:       "east",
		ClusterSetID:    "clusterset1",
		LeaderClusterID: "leader1",
	}

	oldmca := mca.DeepCopy()
	oldmca.ClusterSetID = "old-clusterset"

	mcafromAnotherClusterSet := &mcv1alpha1.MemberClusterAnnounce{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "member-announce-from-north",
			Namespace: "mcs1",
		},
		ClusterID:       "north",
		ClusterSetID:    "another-clusterset",
		LeaderClusterID: "leader1",
	}

	mcaDifferentLeader := &mcv1alpha1.MemberClusterAnnounce{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "member-announce-from-north",
			Namespace: "mcs1",
		},
		ClusterID:       "north",
		ClusterSetID:    "clusterset1",
		LeaderClusterID: "different-leader",
	}

	mcaMarshaled, _ := j.Marshal(mca)
	oldmcaMarshaled, _ := j.Marshal(oldmca)
	mcaAnotherMarshaled, _ := j.Marshal(mcafromAnotherClusterSet)
	mcaDifferentLeaderMarshaled, _ := j.Marshal(mcaDifferentLeader)

	userInfo := authenticationv1.UserInfo{
		Username: "system:serviceaccount:mcs1:east-access-sa",
		UID:      "4842eb60-68e3-4e38-adad-3abfd6117241",
		Groups: []string{
			"system:serviceaccounts",
			"system:serviceaccounts:mcs1",
			"system:authenticated",
		},
	}

	reqAllow := admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			UID: "07e52e8d-4513-11e9-a716-42010a800270",
			Kind: metav1.GroupVersionKind{
				Group:   "multicluster.crd.antrea.io",
				Version: "v1alpha1",
				Kind:    "MemberClusterAnnounce",
			},
			Resource: metav1.GroupVersionResource{
				Group:    "multicluster.crd.antrea.io",
				Version:  "v1alpha1",
				Resource: "memberclusterannounces",
			},
			Name:      "member-announce-from-east",
			Namespace: "mcs1",
			Operation: v1.Create,
			Object: runtime.RawExtension{
				Raw: mcaMarshaled,
			},
			UserInfo: userInfo,
		},
	}

	reqAllowCopy := reqAllow.DeepCopy()
	reqDenyAnother := admission.Request{
		AdmissionRequest: *reqAllowCopy,
	}
	reqDenyAnother.Name = "member-announce-from-north"
	reqDenyAnother.Object = runtime.RawExtension{
		Raw: mcaAnotherMarshaled,
	}

	reqDenyAnotherCopy := reqDenyAnother.DeepCopy()
	reqDenyDifferentLeader := admission.Request{
		AdmissionRequest: *reqDenyAnotherCopy,
	}
	reqDenyDifferentLeader.Object = runtime.RawExtension{
		Raw: mcaDifferentLeaderMarshaled,
	}

	reqDenyUnknownSA := admission.Request{
		AdmissionRequest: *reqAllowCopy,
	}
	reqDenyUnknownSA.UserInfo = authenticationv1.UserInfo{
		Username: "system:serviceaccount:mcs1:unknown-access-sa",
		UID:      "4842eb60-68e3-4e38-adad-3abfd6117241",
		Groups: []string{
			"system:serviceaccounts",
			"system:serviceaccounts:mcs1",
			"system:authenticated",
		},
	}

	reqDenyUpdateClusterSetID := admission.Request{
		AdmissionRequest: *reqAllowCopy,
	}
	reqDenyUpdateClusterSetID.OldObject = runtime.RawExtension{
		Raw: oldmcaMarshaled,
	}
	reqDenyUpdateClusterSetID.Operation = v1.Update

	reqDenyNoClusterSet := admission.Request{
		AdmissionRequest: *reqAllowCopy,
	}
	reqDelete := admission.Request{
		AdmissionRequest: *reqAllowCopy,
	}
	reqDelete.Operation = v1.Delete

	reqInvalidUser := admission.Request{
		AdmissionRequest: *reqAllowCopy,
	}
	reqInvalidUser.UserInfo = authenticationv1.UserInfo{
		Username: "system:user",
		UID:      "4842eb60-68e3-4e38-adad-3abfd6117241",
		Groups: []string{
			"system:authenticated",
		},
	}

	tests := []struct {
		name               string
		existingClusterSet *mcv1alpha2.ClusterSet
		req                admission.Request
		isAllowed          bool
	}{
		{
			name:               "Allow MemberClusterAnnounce creation",
			existingClusterSet: existingClusterSet,
			req:                reqAllow,
			isAllowed:          true,
		},
		{
			name:               "Deny MemberClusterAnnounce creation for another ClusterSet",
			existingClusterSet: existingClusterSet,
			req:                reqDenyAnother,
			isAllowed:          false,
		},
		{
			name:               "Deny MemberClusterAnnounce creation with different Leader ID",
			existingClusterSet: existingClusterSet,
			req:                reqDenyDifferentLeader,
			isAllowed:          false,
		},
		{
			name:               "Deny MemberClusterAnnounce creation with unknown ServiceAccount",
			existingClusterSet: existingClusterSet,
			req:                reqDenyUnknownSA,
			isAllowed:          false,
		},
		{
			name:      "Deny MemberClusterAnnounce creation when no ClusterSet found",
			req:       reqDenyNoClusterSet,
			isAllowed: false,
		},
		{
			name:               "Deny MemberClusterAnnounce update with ClusterSet ID change",
			existingClusterSet: existingClusterSet,
			req:                reqDenyUpdateClusterSetID,
			isAllowed:          false,
		},
		{
			name:               "Allow MemberClusterAnnounce delete",
			existingClusterSet: existingClusterSet,
			req:                reqDelete,
			isAllowed:          true,
		},
		{
			name:               "Deny MemberClusterAnnounce creation with invalid user info",
			existingClusterSet: existingClusterSet,
			req:                reqInvalidUser,
			isAllowed:          false,
		},
	}

	decoder := admission.NewDecoder(common.TestScheme)
	for _, tt := range tests {
		fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects().WithLists(existingServiceAccounts).Build()
		if tt.existingClusterSet != nil {
			fakeClient = fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(existingClusterSet).WithLists(existingServiceAccounts).Build()
		}
		mcaWebhookUnderTest = &memberClusterAnnounceValidator{
			Client:    fakeClient,
			decoder:   decoder,
			namespace: "mcs1",
		}
		t.Run(tt.name, func(t *testing.T) {
			response := mcaWebhookUnderTest.Handle(context.Background(), tt.req)
			assert.Equal(t, tt.isAllowed, response.Allowed)
		})
	}

}
