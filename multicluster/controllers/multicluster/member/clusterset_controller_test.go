// Copyright 2022 Antrea Authors.
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

package member

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	mcv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	mcv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
	"antrea.io/antrea/multicluster/controllers/multicluster/commonarea"
	"antrea.io/antrea/multicluster/test/mocks"
)

func TestMemberClusterDelete(t *testing.T) {
	existingMemberClusterAnnounce := &mcv1alpha1.MemberClusterAnnounce{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  "default",
			Name:       "member-announce-from-cluster-a",
			Generation: 1,
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects().Build()
	fakeRemoteClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(existingMemberClusterAnnounce).Build()
	commonArea := commonarea.NewFakeRemoteCommonArea(fakeRemoteClient, "leader-cluster", common.LocalClusterID, "default", nil)

	reconciler := MemberClusterSetReconciler{
		Client:           fakeClient,
		remoteCommonArea: commonArea,
		clusterSetID:     common.ClusterSetID("clusterset1"),
	}

	// Delete a different ClusterSet.
	if _, err := reconciler.Reconcile(common.TestCtx, reconcile.Request{
		NamespacedName: types.NamespacedName{
			Namespace: "default",
			Name:      "clusterset2",
		}}); err != nil {
		t.Errorf("Member ClusterSet Reconciler should handle delete event successfully but got error = %v", err)
	} else {
		memberClusterAnnounce := &mcv1alpha1.MemberClusterAnnounce{}
		err := fakeRemoteClient.Get(common.TestCtx, types.NamespacedName{
			Namespace: "default",
			Name:      "member-announce-from-cluster-a",
		}, memberClusterAnnounce)
		if err != nil {
			if apierrors.IsNotFound(err) {
				t.Errorf("Member ClusterSet Reconciler should not remove MemberClusterAnnounce")
			} else {
				t.Errorf("Get MemberClusterAnnounce returned error = %v", err)
			}
		}
	}

	// Delete the current ClusterSet.
	if _, err := reconciler.Reconcile(common.TestCtx, reconcile.Request{
		NamespacedName: types.NamespacedName{
			Namespace: "default",
			Name:      "clusterset1",
		}}); err != nil {
		t.Errorf("Member ClusterSet Reconciler should handle delete event successfully but got error = %v", err)
	} else {
		memberClusterAnnounce := &mcv1alpha1.MemberClusterAnnounce{}
		err := fakeRemoteClient.Get(common.TestCtx, types.NamespacedName{
			Namespace: "default",
			Name:      "member-announce-from-cluster-a",
		}, memberClusterAnnounce)
		if err == nil {
			t.Errorf("Member ClusterSet Reconciler should remove MemberClusterAnnounce but not")
		} else if !apierrors.IsNotFound(err) {
			t.Errorf("Get MemberClusterAnnounce returned error = %v", err)
		}
	}
}

func TestMemberClusterStatus(t *testing.T) {
	existingClusterSet := &mcv1alpha2.ClusterSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  "mcs1",
			Name:       "clusterset1",
			Generation: 1,
		},
		Spec: mcv1alpha2.ClusterSetSpec{
			Leaders: []mcv1alpha2.LeaderClusterInfo{
				{
					ClusterID: "leader1",
				}},
			Namespace: "mcs1",
		},
		Status: mcv1alpha2.ClusterSetStatus{
			ObservedGeneration: 1,
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(existingClusterSet).WithStatusSubresource(existingClusterSet).Build()
	fakeRemoteClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(existingClusterSet).WithStatusSubresource(existingClusterSet).Build()
	conditions := []mcv1alpha2.ClusterCondition{
		{
			Message: "Member Connected",
			Reason:  "Connected",
			Status:  v1.ConditionTrue,
			Type:    mcv1alpha2.ClusterReady,
		},
		{
			Status: v1.ConditionTrue,
			Type:   mcv1alpha2.ClusterIsLeader,
		},
	}
	expectedStatusNoCondition := mcv1alpha2.ClusterSetStatus{
		ObservedGeneration: 1,
		TotalClusters:      1,
		ReadyClusters:      0,
		Conditions: []mcv1alpha2.ClusterSetCondition{
			{
				Message: "Disconnected from leader",
				Status:  v1.ConditionFalse,
				Type:    mcv1alpha2.ClusterSetReady,
			},
		},
		ClusterStatuses: []mcv1alpha2.ClusterStatus{
			{
				ClusterID:  "leader1",
				Conditions: []mcv1alpha2.ClusterCondition{},
			},
		},
	}
	expectedStatusWithCondition := mcv1alpha2.ClusterSetStatus{
		ObservedGeneration: 1,
		TotalClusters:      1,
		ReadyClusters:      1,
		Conditions: []mcv1alpha2.ClusterSetCondition{
			{
				Status: v1.ConditionTrue,
				Type:   mcv1alpha2.ClusterSetReady,
			},
		},
		ClusterStatuses: []mcv1alpha2.ClusterStatus{
			{
				ClusterID: "leader1",
				Conditions: []mcv1alpha2.ClusterCondition{
					{
						Status:  v1.ConditionTrue,
						Type:    mcv1alpha2.ClusterReady,
						Message: "Member Connected",
						Reason:  "Connected",
					},
					{
						Status: v1.ConditionTrue,
						Type:   mcv1alpha2.ClusterIsLeader,
					},
				},
			},
		},
	}

	tests := []struct {
		name           string
		conditions     []mcv1alpha2.ClusterCondition
		expectedStatus mcv1alpha2.ClusterSetStatus
	}{
		{
			name:           "with no conditions",
			conditions:     nil,
			expectedStatus: expectedStatusNoCondition,
		},
		{
			name:           "with conditions",
			conditions:     conditions,
			expectedStatus: expectedStatusWithCondition,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			commonArea := commonarea.NewFakeRemoteCommonArea(fakeRemoteClient, "leader1", common.LocalClusterID, "mcs1", tt.conditions)
			reconciler := MemberClusterSetReconciler{
				Client:           fakeClient,
				remoteCommonArea: commonArea,
				clusterSetID:     "clusterset1",
				clusterID:        "east",
				namespace:        "mcs1",
			}
			reconciler.updateStatus()
			clusterSet := &mcv1alpha2.ClusterSet{}

			err := fakeClient.Get(context.TODO(), types.NamespacedName{Name: "clusterset1", Namespace: "mcs1"}, clusterSet)
			assert.Equal(t, nil, err)
			assert.Equal(t, tt.expectedStatus.ObservedGeneration, clusterSet.Status.ObservedGeneration)
			assert.Equal(t, tt.expectedStatus.TotalClusters, clusterSet.Status.TotalClusters)
			assert.Equal(t, tt.expectedStatus.ReadyClusters, clusterSet.Status.ReadyClusters)
			assert.Equal(t, tt.expectedStatus.Conditions[0].Message, clusterSet.Status.Conditions[0].Message)
			assert.Equal(t, tt.expectedStatus.Conditions[0].Type, clusterSet.Status.Conditions[0].Type)
			assert.Equal(t, tt.expectedStatus.Conditions[0].Status, clusterSet.Status.Conditions[0].Status)
			assert.Equal(t, tt.expectedStatus.ClusterStatuses[0].ClusterID, clusterSet.Status.ClusterStatuses[0].ClusterID)
			if tt.conditions != nil {
				assert.Equal(t, tt.expectedStatus.ClusterStatuses[0].Conditions[0].Status, clusterSet.Status.ClusterStatuses[0].Conditions[0].Status)
				assert.Equal(t, tt.expectedStatus.ClusterStatuses[0].Conditions[0].Type, clusterSet.Status.ClusterStatuses[0].Conditions[0].Type)
				assert.Equal(t, tt.expectedStatus.ClusterStatuses[0].Conditions[0].Message, clusterSet.Status.ClusterStatuses[0].Conditions[0].Message)
				assert.Equal(t, tt.expectedStatus.ClusterStatuses[0].Conditions[0].Reason, clusterSet.Status.ClusterStatuses[0].Conditions[0].Reason)
				assert.Equal(t, tt.expectedStatus.ClusterStatuses[0].Conditions[1].Status, clusterSet.Status.ClusterStatuses[0].Conditions[1].Status)
				assert.Equal(t, tt.expectedStatus.ClusterStatuses[0].Conditions[1].Type, clusterSet.Status.ClusterStatuses[0].Conditions[1].Type)
			}
		})
	}
}

func TestMemberCreateOrUpdateRemoteCommonArea(t *testing.T) {
	existingSecret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "mcs1",
			Name:      "membertoken",
		},
		Data: map[string][]byte{
			"ca.crt": []byte(`12345`),
			"token":  []byte(`12345`)},
	}
	existingClusterSet := &mcv1alpha2.ClusterSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  "mcs1",
			Name:       "clusterset1",
			Generation: 1,
		},
		Spec: mcv1alpha2.ClusterSetSpec{
			Leaders: []mcv1alpha2.LeaderClusterInfo{
				{
					ClusterID: "leader1",
					Secret:    "membertoken",
				}},
			Namespace: "mcs1",
		},
		Status: mcv1alpha2.ClusterSetStatus{
			ObservedGeneration: 1,
		},
	}
	expectedInstalledLeader := leaderClusterInfo{
		clusterID:  "leader1",
		secretName: "membertoken",
	}
	fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(existingClusterSet, existingSecret).Build()
	fakeRemoteClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(existingClusterSet, existingSecret).Build()
	commonArea := commonarea.NewFakeRemoteCommonArea(fakeRemoteClient, "leader1", common.LocalClusterID, "mcs1", nil)
	reconciler := MemberClusterSetReconciler{
		Client:                       fakeClient,
		remoteCommonArea:             commonArea,
		clusterSetID:                 "clusterset1",
		clusterID:                    "east",
		enableStretchedNetworkPolicy: true,
	}
	mockCtrl := gomock.NewController(t)
	mockManager := mocks.NewMockManager(mockCtrl)
	getRemoteConfigAndClient = commonarea.FuncGetFakeRemoteConfigAndClient(mockManager)

	err := reconciler.createRemoteCommonArea(existingClusterSet)
	assert.Equal(t, nil, err)
	assert.Equal(t, expectedInstalledLeader, reconciler.installedLeader)
}

func TestMemberClusterSetAddWithoutClusterID(t *testing.T) {
	existingSecret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "mcs1",
			Name:      "membertoken",
		},
		Data: map[string][]byte{
			"ca.crt": []byte(`12345`),
			"token":  []byte(`12345`)},
	}
	clusterSetWithoutClusterID := &mcv1alpha2.ClusterSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  "mcs1",
			Name:       "clusterset1",
			Generation: 1,
		},
		Spec: mcv1alpha2.ClusterSetSpec{
			Leaders: []mcv1alpha2.LeaderClusterInfo{
				{
					ClusterID: "leader1",
					Secret:    "membertoken",
				}},
			Namespace: "mcs1",
		},
	}
	clusterClaim := &mcv1alpha2.ClusterClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "mcs1",
			Name:      "id.k8s.io",
		},
		Value: "member1",
	}

	tests := []struct {
		name      string
		clusterID common.ClusterID
	}{
		{
			name: "create a new ClusterSet without a clusterID",
		},
		{
			name:      "with non-empty clusterID",
			clusterID: common.ClusterID("cluster-a"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(clusterSetWithoutClusterID, clusterClaim, existingSecret).Build()

			mockCtrl := gomock.NewController(t)
			mockManager := mocks.NewMockManager(mockCtrl)
			getRemoteConfigAndClient = commonarea.FuncGetFakeRemoteConfigAndClient(mockManager)

			reconciler := MemberClusterSetReconciler{
				Client:                   fakeClient,
				clusterCalimCRDAvailable: true,
				commonAreaCreationCh:     make(chan struct{}),
			}
			go func() {
				<-reconciler.commonAreaCreationCh
			}()
			if tt.clusterID != "" {
				fakeRemoteClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects().Build()
				commonArea := commonarea.NewFakeRemoteCommonArea(fakeRemoteClient, "leader1", "clusterset1", "mcs1", nil)
				reconciler.remoteCommonArea = commonArea
				reconciler.clusterID = tt.clusterID
			}

			if _, err := reconciler.Reconcile(common.TestCtx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Namespace: "mcs1",
					Name:      "clusterset1",
				},
			}); err != nil {
				t.Errorf("Member ClusterSet Reconciler should handle add event successfully but got error = %v", err)
			} else {
				assert.Equal(t, nil, err)
				assert.Equal(t, "clusterset1", string(reconciler.clusterSetID))
				assert.Equal(t, "member1", string(reconciler.clusterID))

				clusterSet := &mcv1alpha2.ClusterSet{}
				err = fakeClient.Get(context.TODO(), types.NamespacedName{Name: "clusterset1", Namespace: "mcs1"}, clusterSet)
				assert.Equal(t, nil, err)
				assert.Equal(t, "member1", clusterSet.Spec.ClusterID)
			}
		})
	}
}
