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

	"antrea.io/antrea/v2/multicluster/apis/multicluster/constants"
	mcv1alpha1 "antrea.io/antrea/v2/multicluster/apis/multicluster/v1alpha1"
	mcv1alpha2 "antrea.io/antrea/v2/multicluster/apis/multicluster/v1alpha2"
	"antrea.io/antrea/v2/multicluster/controllers/multicluster/common"
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
					Annotations: map[string]string{
						"multicluster.antrea.io/cluster-id": "east",
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "mcs1",
					Name:      "west-access-sa",
					Annotations: map[string]string{
						"multicluster.antrea.io/cluster-id": "west",
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "mcs1",
					Name:      "north-access-sa",
					Annotations: map[string]string{
						"multicluster.antrea.io/cluster-id": "north",
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "mcs1",
					Name:      "south-access-sa",
				},
			},
			// Exists so that the Namespace controller case below is not allowed
			// merely because its ServiceAccount cannot be found: in a real cluster
			// the lookup fails with Forbidden, not NotFound.
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "kube-system",
					Name:      "namespace-controller",
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

	mcaSpoofed := &mcv1alpha1.MemberClusterAnnounce{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "member-announce-from-west",
			Namespace: "mcs1",
		},
		ClusterID:       "west",
		ClusterSetID:    "clusterset1",
		LeaderClusterID: "leader1",
	}
	mcaSpoofedMarshaled, _ := j.Marshal(mcaSpoofed)

	userInfo := authenticationv1.UserInfo{
		Username: "system:serviceaccount:mcs1:east-access-sa",
		UID:      "4842eb60-68e3-4e38-adad-3abfd6117241",
		Groups: []string{
			"system:serviceaccounts",
			"system:serviceaccounts:mcs1",
			"system:authenticated",
		},
	}

	east1UserInfo := authenticationv1.UserInfo{
		Username: "system:serviceaccount:mcs1:east1-access-sa",
		UID:      "4842eb60-68e3-4e38-adad-3abfd6117241",
		Groups: []string{
			"system:serviceaccounts",
			"system:serviceaccounts:mcs1",
			"system:authenticated",
		},
	}

	// A bound ServiceAccount set that contains a dash-delimited prefix pair
	// ("east" vs "east-1"), used to exercise the deny at announce time.
	pairServiceAccounts := &corev1.ServiceAccountList{
		Items: []corev1.ServiceAccount{
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "mcs1",
					Name:      "east-access-sa",
					Annotations: map[string]string{
						constants.ServiceAccountClusterIDAnnotation: "east",
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "mcs1",
					Name:      "east1-access-sa",
					Annotations: map[string]string{
						constants.ServiceAccountClusterIDAnnotation: "east-1",
					},
				},
			},
		},
	}

	mcaEast1 := &mcv1alpha1.MemberClusterAnnounce{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "member-announce-from-east-1",
			Namespace: "mcs1",
		},
		ClusterID:       "east-1",
		ClusterSetID:    "clusterset1",
		LeaderClusterID: "leader1",
	}
	mcaEast1Marshaled, _ := j.Marshal(mcaEast1)

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
	reqDenyAnother.UserInfo.Username = "system:serviceaccount:mcs1:north-access-sa"

	reqDenyAnotherCopy := reqDenyAnother.DeepCopy()
	reqDenyDifferentLeader := admission.Request{
		AdmissionRequest: *reqDenyAnotherCopy,
	}
	reqDenyDifferentLeader.Object = runtime.RawExtension{
		Raw: mcaDifferentLeaderMarshaled,
	}
	reqDenyDifferentLeader.UserInfo.Username = "system:serviceaccount:mcs1:north-access-sa"

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

	reqDenySpoofed := admission.Request{
		AdmissionRequest: *reqAllowCopy,
	}
	reqDenySpoofed.Name = "member-announce-from-west"
	reqDenySpoofed.Object = runtime.RawExtension{
		Raw: mcaSpoofedMarshaled,
	}

	reqDenyUpdateClusterSetID := admission.Request{
		AdmissionRequest: *reqAllowCopy,
	}
	reqDenyUpdateClusterSetID.OldObject = runtime.RawExtension{
		Raw: oldmcaMarshaled,
	}
	reqDenyUpdateClusterSetID.Operation = v1.Update

	reqDenyUpdateClusterID := admission.Request{
		AdmissionRequest: *reqAllowCopy,
	}
	oldmcaClusterID := mca.DeepCopy()
	oldmcaClusterID.ClusterID = "old-cluster-id"
	oldmcaClusterIDMarshaled, _ := j.Marshal(oldmcaClusterID)
	reqDenyUpdateClusterID.OldObject = runtime.RawExtension{
		Raw: oldmcaClusterIDMarshaled,
	}
	reqDenyUpdateClusterID.Operation = v1.Update

	reqDenyNoAnnotation := admission.Request{
		AdmissionRequest: *reqAllowCopy,
	}
	reqDenyNoAnnotation.UserInfo = authenticationv1.UserInfo{
		Username: "system:serviceaccount:mcs1:south-access-sa",
		UID:      "4842eb60-68e3-4e38-adad-3abfd6117241",
		Groups: []string{
			"system:serviceaccounts",
			"system:serviceaccounts:mcs1",
			"system:authenticated",
		},
	}

	reqDenyWrongName := admission.Request{
		AdmissionRequest: *reqAllowCopy,
	}
	reqDenyWrongName.Name = "member-announce-from-wrong"
	mcaWrongName := mca.DeepCopy()
	mcaWrongName.Name = "member-announce-from-wrong"
	mcaWrongNameMarshaled, _ := j.Marshal(mcaWrongName)
	reqDenyWrongName.Object = runtime.RawExtension{
		Raw: mcaWrongNameMarshaled,
	}

	reqDenyNoClusterSet := admission.Request{
		AdmissionRequest: *reqAllowCopy,
	}
	reqDelete := admission.Request{
		AdmissionRequest: *reqAllowCopy,
	}
	reqDelete.Operation = v1.Delete
	reqDelete.Object = runtime.RawExtension{}
	reqDelete.OldObject = runtime.RawExtension{
		Raw: mcaMarshaled,
	}

	reqDenyUpdatePeer := admission.Request{
		AdmissionRequest: *reqAllowCopy,
	}
	reqDenyUpdatePeer.Operation = v1.Update
	reqDenyUpdatePeer.Object = runtime.RawExtension{
		Raw: mcaSpoofedMarshaled,
	}
	reqDenyUpdatePeer.OldObject = runtime.RawExtension{
		Raw: mcaSpoofedMarshaled,
	}

	reqDenyDeletePeer := admission.Request{
		AdmissionRequest: *reqAllowCopy,
	}
	reqDenyDeletePeer.Operation = v1.Delete
	reqDenyDeletePeer.Object = runtime.RawExtension{}
	reqDenyDeletePeer.OldObject = runtime.RawExtension{
		Raw: mcaSpoofedMarshaled,
	}

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

	controllerUserInfo := authenticationv1.UserInfo{
		Username: "system:serviceaccount:mcs1:antrea-mc-controller",
		UID:      "4842eb60-68e3-4e38-adad-3abfd6117241",
		Groups: []string{
			"system:serviceaccounts",
			"system:serviceaccounts:mcs1",
			"system:authenticated",
		},
	}

	reqControllerUpdate := admission.Request{
		AdmissionRequest: *reqAllowCopy,
	}
	reqControllerUpdate.UserInfo = controllerUserInfo
	reqControllerUpdate.Operation = v1.Update
	reqControllerUpdate.OldObject = runtime.RawExtension{
		Raw: mcaMarshaled,
	}

	// The same ServiceAccount name in another Namespace must not be exempted:
	// the Namespace is part of the identity.
	reqControllerOtherNSUpdate := admission.Request{AdmissionRequest: reqControllerUpdate.AdmissionRequest}
	reqControllerOtherNSUpdate.UserInfo.Username = "system:serviceaccount:kube-system:antrea-mc-controller"

	// The Namespace controller deletes every object in a Namespace being torn
	// down; it must be allowed to delete MemberClusterAnnounces even though it
	// is not a member ServiceAccount in the leader Namespace.
	reqNamespaceControllerDelete := admission.Request{
		AdmissionRequest: *reqAllowCopy,
	}
	reqNamespaceControllerDelete.Operation = v1.Delete
	reqNamespaceControllerDelete.Object = runtime.RawExtension{}
	reqNamespaceControllerDelete.OldObject = runtime.RawExtension{
		Raw: mcaMarshaled,
	}
	reqNamespaceControllerDelete.UserInfo = authenticationv1.UserInfo{
		Username: "system:serviceaccount:kube-system:namespace-controller",
		UID:      "4842eb60-68e3-4e38-adad-3abfd6117241",
		Groups: []string{
			"system:serviceaccounts",
			"system:serviceaccounts:kube-system",
			"system:authenticated",
		},
	}

	reqOtherNSCreate := admission.Request{
		AdmissionRequest: *reqAllowCopy,
	}
	reqOtherNSCreate.UserInfo = authenticationv1.UserInfo{
		Username: "system:serviceaccount:kube-system:any-sa",
		UID:      "4842eb60-68e3-4e38-adad-3abfd6117241",
		Groups: []string{
			"system:serviceaccounts",
			"system:serviceaccounts:kube-system",
			"system:authenticated",
		},
	}

	reqAdminDelete := admission.Request{
		AdmissionRequest: *reqAllowCopy,
	}
	reqAdminDelete.Operation = v1.Delete
	reqAdminDelete.Object = runtime.RawExtension{}
	reqAdminDelete.OldObject = runtime.RawExtension{
		Raw: mcaMarshaled,
	}
	reqAdminDelete.UserInfo = authenticationv1.UserInfo{
		Username: "kubernetes-admin",
		UID:      "4842eb60-68e3-4e38-adad-3abfd6117241",
		Groups: []string{
			"system:masters",
			"system:authenticated",
		},
	}

	reqGCDelete := admission.Request{
		AdmissionRequest: *reqAllowCopy,
	}
	reqGCDelete.Operation = v1.Delete
	reqGCDelete.Object = runtime.RawExtension{}
	reqGCDelete.OldObject = runtime.RawExtension{
		Raw: mcaMarshaled,
	}
	reqGCDelete.UserInfo = authenticationv1.UserInfo{
		Username: "system:serviceaccount:kube-system:generic-garbage-collector",
		UID:      "4842eb60-68e3-4e38-adad-3abfd6117241",
		Groups: []string{
			"system:serviceaccounts",
			"system:serviceaccounts:kube-system",
			"system:authenticated",
		},
	}

	// "east" announcing while "east-1" is already bound: the new member is the
	// shorter ID of the pair.
	reqDenyPrefixPair := admission.Request{
		AdmissionRequest: *reqAllowCopy,
	}

	// "east-1" announcing while "east" is already bound: the new member is the
	// longer ID of the pair.
	reqDenyPrefixPairEast1 := admission.Request{
		AdmissionRequest: *reqAllowCopy,
	}
	reqDenyPrefixPairEast1.Name = "member-announce-from-east-1"
	reqDenyPrefixPairEast1.Object = runtime.RawExtension{
		Raw: mcaEast1Marshaled,
	}
	reqDenyPrefixPairEast1.UserInfo = east1UserInfo

	tests := []struct {
		name               string
		existingClusterSet *mcv1alpha2.ClusterSet
		saList             *corev1.ServiceAccountList
		req                admission.Request
		isAllowed          bool
		expectedMsg        string
	}{
		{
			name:               "Allow MemberClusterAnnounce creation",
			existingClusterSet: existingClusterSet,
			req:                reqAllow,
			isAllowed:          true,
			expectedMsg:        "",
		},
		{
			name:               "Deny MemberClusterAnnounce creation for another ClusterSet",
			existingClusterSet: existingClusterSet,
			req:                reqDenyAnother,
			isAllowed:          false,
			expectedMsg:        "Unknown ClusterSet ID",
		},
		{
			name:               "Deny MemberClusterAnnounce creation with different Leader ID",
			existingClusterSet: existingClusterSet,
			req:                reqDenyDifferentLeader,
			isAllowed:          false,
			expectedMsg:        "Leader cluster ID in the MemberClusterAnnounce does not match that in the ClusterSet",
		},
		{
			name:               "Deny MemberClusterAnnounce creation with unknown ServiceAccount",
			existingClusterSet: existingClusterSet,
			req:                reqDenyUnknownSA,
			isAllowed:          false,
			expectedMsg:        "not found",
		},
		{
			name:               "Deny MemberClusterAnnounce creation with spoofed ClusterID",
			existingClusterSet: existingClusterSet,
			req:                reqDenySpoofed,
			isAllowed:          false,
			expectedMsg:        "is not permitted for ServiceAccount",
		},
		{
			name:        "Deny MemberClusterAnnounce creation when no ClusterSet found",
			req:         reqDenyNoClusterSet,
			isAllowed:   false,
			expectedMsg: "no ClusterSet found in Namespace",
		},
		{
			name:               "Deny MemberClusterAnnounce update with ClusterSet ID change",
			existingClusterSet: existingClusterSet,
			req:                reqDenyUpdateClusterSetID,
			isAllowed:          false,
			expectedMsg:        "ClusterSet ID or Leader Cluster ID cannot be changed",
		},
		{
			name:               "Deny MemberClusterAnnounce update with ClusterID change",
			existingClusterSet: existingClusterSet,
			req:                reqDenyUpdateClusterID,
			isAllowed:          false,
			expectedMsg:        "ClusterID cannot be changed",
		},
		{
			name:               "Deny MemberClusterAnnounce creation with no annotation on ServiceAccount",
			existingClusterSet: existingClusterSet,
			req:                reqDenyNoAnnotation,
			isAllowed:          false,
			expectedMsg:        "is not permitted for ServiceAccount",
		},
		{
			name:               "Deny MemberClusterAnnounce creation with wrong name",
			existingClusterSet: existingClusterSet,
			req:                reqDenyWrongName,
			isAllowed:          false,
			expectedMsg:        "MemberClusterAnnounce name must be",
		},
		{
			name:               "Allow MemberClusterAnnounce delete",
			existingClusterSet: existingClusterSet,
			req:                reqDelete,
			isAllowed:          true,
			expectedMsg:        "",
		},
		{
			name:               "Deny MemberClusterAnnounce creation with invalid user info",
			existingClusterSet: existingClusterSet,
			req:                reqInvalidUser,
			isAllowed:          false,
			expectedMsg:        "Username must be in the form",
		},
		{
			name:               "Deny MemberClusterAnnounce update of peer",
			existingClusterSet: existingClusterSet,
			req:                reqDenyUpdatePeer,
			isAllowed:          false,
			expectedMsg:        "is not permitted for ServiceAccount",
		},
		{
			name:               "Deny MemberClusterAnnounce delete of peer",
			existingClusterSet: existingClusterSet,
			req:                reqDenyDeletePeer,
			isAllowed:          false,
			expectedMsg:        "is not permitted for ServiceAccount",
		},
		{
			name:               "Allow MemberClusterAnnounce update by leader controller ServiceAccount",
			existingClusterSet: existingClusterSet,
			req:                reqControllerUpdate,
			isAllowed:          true,
			expectedMsg:        "",
		},
		{
			name:               "Deny MemberClusterAnnounce update by controller ServiceAccount from another Namespace",
			existingClusterSet: existingClusterSet,
			req:                reqControllerOtherNSUpdate,
			isAllowed:          false,
			expectedMsg:        "is not in Namespace",
		},
		{
			name:               "Deny MemberClusterAnnounce creation by ServiceAccount from another Namespace",
			existingClusterSet: existingClusterSet,
			req:                reqOtherNSCreate,
			isAllowed:          false,
			expectedMsg:        "is not in Namespace",
		},
		{
			name:               "Allow MemberClusterAnnounce delete by Namespace controller",
			existingClusterSet: existingClusterSet,
			req:                reqNamespaceControllerDelete,
			isAllowed:          true,
			expectedMsg:        "",
		},
		{
			name:               "Allow MemberClusterAnnounce delete by non-ServiceAccount user",
			existingClusterSet: existingClusterSet,
			req:                reqAdminDelete,
			isAllowed:          true,
			expectedMsg:        "",
		},
		{
			name:               "Allow MemberClusterAnnounce delete by ServiceAccount from another Namespace",
			existingClusterSet: existingClusterSet,
			req:                reqGCDelete,
			isAllowed:          true,
			expectedMsg:        "",
		},
		{
			name:               "Deny MemberClusterAnnounce creation with prefix-conflicting ClusterID",
			existingClusterSet: existingClusterSet,
			saList:             pairServiceAccounts,
			req:                reqDenyPrefixPair,
			isAllowed:          false,
			expectedMsg:        "conflicts with an existing member's ClusterID",
		},
		{
			name:               "Deny MemberClusterAnnounce creation with prefix-conflicting ClusterID (longer ID)",
			existingClusterSet: existingClusterSet,
			saList:             pairServiceAccounts,
			req:                reqDenyPrefixPairEast1,
			isAllowed:          false,
			expectedMsg:        "conflicts with an existing member's ClusterID",
		},
	}

	decoder := admission.NewDecoder(common.TestScheme)
	for _, tt := range tests {
		saList := tt.saList
		if saList == nil {
			saList = existingServiceAccounts
		}
		fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects().WithLists(saList).Build()
		if tt.existingClusterSet != nil {
			fakeClient = fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(existingClusterSet).WithLists(saList).Build()
		}
		mcaWebhookUnderTest = &memberClusterAnnounceValidator{
			Client:    fakeClient,
			decoder:   decoder,
			namespace: "mcs1",
			saName:    "antrea-mc-controller",
		}
		t.Run(tt.name, func(t *testing.T) {
			response := mcaWebhookUnderTest.Handle(context.Background(), tt.req)
			assert.Equal(t, tt.isAllowed, response.Allowed)
			if !tt.isAllowed && tt.expectedMsg != "" {
				assert.Contains(t, response.Result.Message, tt.expectedMsg)
			}
		})
	}

}
