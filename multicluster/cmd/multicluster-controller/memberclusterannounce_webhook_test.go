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
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
	k8smcsv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
)

var mcaWebhookUnderTest *memberClusterAnnounceValidator

func setup() {
	existingClusterSet := &mcsv1alpha1.ClusterSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "mcs1",
			Name:      "clusterset1",
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

	newScheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(newScheme))
	utilruntime.Must(k8smcsv1alpha1.AddToScheme(newScheme))
	utilruntime.Must(mcsv1alpha1.AddToScheme(newScheme))
	fakeClient := fake.NewClientBuilder().WithScheme(newScheme).WithObjects(existingClusterSet).WithLists(existingServiceAccounts).Build()

	mcaWebhookUnderTest = &memberClusterAnnounceValidator{
		Client:    fakeClient,
		namespace: "mcs1"}

	decoder, err := admission.NewDecoder(newScheme)
	if err != nil {
		klog.ErrorS(err, "Error constructing a decoder")
	}

	mcaWebhookUnderTest.InjectDecoder(decoder)
}

func TestWebhookAllow(t *testing.T) {
	setup()

	mca := &mcsv1alpha1.MemberClusterAnnounce{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "member-announce-from-east",
			Namespace: "mcs1",
		},
		ClusterID:       "east",
		ClusterSetID:    "clusterset1",
		LeaderClusterID: "leader1",
	}
	b, _ := j.Marshal(mca)

	req := admission.Request{
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
				Raw: b,
			},
			UserInfo: authenticationv1.UserInfo{
				Username: "system:serviceaccount:mcs1:east-access-sa",
				UID:      "4842eb60-68e3-4e38-adad-3abfd6117241",
				Groups: []string{
					"system:serviceaccounts",
					"system:serviceaccounts:mcs1",
					"system:authenticated",
				},
			},
		},
	}

	response := mcaWebhookUnderTest.Handle(context.Background(), req)
	assert.Equal(t, true, response.Allowed)
}

func TestWebhookJoinAllow(t *testing.T) {
	setup()

	mca := &mcsv1alpha1.MemberClusterAnnounce{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "member-announce-from-south",
			Namespace: "mcs1",
		},
		ClusterID:       "south",
		ClusterSetID:    "clusterset1",
		LeaderClusterID: "leader1",
	}
	b, _ := j.Marshal(mca)

	req := admission.Request{
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
			Name:      "member-announce-from-south",
			Namespace: "mcs1",
			Operation: v1.Create,
			Object: runtime.RawExtension{
				Raw: b,
			},
			UserInfo: authenticationv1.UserInfo{
				Username: "system:serviceaccount:mcs1:east-access-sa",
				UID:      "4842eb60-68e3-4e38-adad-3abfd6117241",
				Groups: []string{
					"system:serviceaccounts",
					"system:serviceaccounts:mcs1",
					"system:authenticated",
				},
			},
		},
	}

	response := mcaWebhookUnderTest.Handle(context.Background(), req)
	assert.Equal(t, true, response.Allowed)
}

func TestWebhookDeniedDifferentClusterSet(t *testing.T) {
	setup()

	mca := &mcsv1alpha1.MemberClusterAnnounce{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "member-announce-from-north",
			Namespace: "mcs1",
		},
		ClusterID:       "north",
		ClusterSetID:    "another-clusterset",
		LeaderClusterID: "leader1",
	}
	b, _ := j.Marshal(mca)

	req := admission.Request{
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
			Name:      "member-announce-from-north",
			Namespace: "mcs1",
			Operation: v1.Create,
			Object: runtime.RawExtension{
				Raw: b,
			},
			UserInfo: authenticationv1.UserInfo{
				Username: "system:serviceaccount:mcs1:east-access-sa",
				UID:      "4842eb60-68e3-4e38-adad-3abfd6117241",
				Groups: []string{
					"system:serviceaccounts",
					"system:serviceaccounts:mcs1",
					"system:authenticated",
				},
			},
		},
	}

	response := mcaWebhookUnderTest.Handle(context.Background(), req)
	assert.Equal(t, false, response.Allowed)
}

func TestWebhookDeniedDifferentLeaderCluster(t *testing.T) {
	setup()

	mca := &mcsv1alpha1.MemberClusterAnnounce{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "member-announce-from-north",
			Namespace: "mcs1",
		},
		ClusterID:       "north",
		ClusterSetID:    "clusterset1",
		LeaderClusterID: "different-leader",
	}
	b, _ := j.Marshal(mca)

	req := admission.Request{
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
			Name:      "member-announce-from-north",
			Namespace: "mcs1",
			Operation: v1.Create,
			Object: runtime.RawExtension{
				Raw: b,
			},
			UserInfo: authenticationv1.UserInfo{
				Username: "system:serviceaccount:mcs1:east-access-sa",
				UID:      "4842eb60-68e3-4e38-adad-3abfd6117241",
				Groups: []string{
					"system:serviceaccounts",
					"system:serviceaccounts:mcs1",
					"system:authenticated",
				},
			},
		},
	}

	response := mcaWebhookUnderTest.Handle(context.Background(), req)
	assert.Equal(t, false, response.Allowed)
}

func TestWebhookDeniedUnknownServiceAccount(t *testing.T) {
	setup()

	mca := &mcsv1alpha1.MemberClusterAnnounce{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "member-announce-from-south",
			Namespace: "mcs1",
		},
		ClusterID:       "south",
		ClusterSetID:    "clusterset1",
		LeaderClusterID: "leader1",
	}
	b, _ := j.Marshal(mca)

	req := admission.Request{
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
			Name:      "member-announce-from-south",
			Namespace: "mcs1",
			Operation: v1.Create,
			Object: runtime.RawExtension{
				Raw: b,
			},
			UserInfo: authenticationv1.UserInfo{
				Username: "system:serviceaccount:mcs1:unknown-access-sa",
				UID:      "4842eb60-68e3-4e38-adad-3abfd6117241",
				Groups: []string{
					"system:serviceaccounts",
					"system:serviceaccounts:mcs1",
					"system:authenticated",
				},
			},
		},
	}

	response := mcaWebhookUnderTest.Handle(context.Background(), req)
	assert.Equal(t, false, response.Allowed)
}

func TestUpdateClusterSetID(t *testing.T) {
	setup()

	mca := &mcsv1alpha1.MemberClusterAnnounce{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "member-announce-from-south",
			Namespace: "mcs1",
		},
		ClusterID:       "south",
		ClusterSetID:    "clusterset-changed",
		LeaderClusterID: "leader1",
	}
	oldMca := &mcsv1alpha1.MemberClusterAnnounce{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "member-announce-from-south",
			Namespace: "mcs1",
		},
		ClusterID:       "south",
		ClusterSetID:    "clusterset",
		LeaderClusterID: "leader1",
	}
	b, _ := j.Marshal(mca)
	old, _ := j.Marshal(oldMca)

	req := admission.Request{
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
			Name:      "member-announce-from-south",
			Namespace: "mcs1",
			Operation: v1.Update,
			Object: runtime.RawExtension{
				Raw: b,
			},
			OldObject: runtime.RawExtension{
				Raw: old,
			},
			UserInfo: authenticationv1.UserInfo{
				Username: "system:serviceaccount:mcs1:east-access-sa",
				UID:      "4842eb60-68e3-4e38-adad-3abfd6117241",
				Groups: []string{
					"system:serviceaccounts",
					"system:serviceaccounts:mcs1",
					"system:authenticated",
				},
			},
		},
	}

	response := mcaWebhookUnderTest.Handle(context.Background(), req)
	assert.Equal(t, false, response.Allowed)
}
