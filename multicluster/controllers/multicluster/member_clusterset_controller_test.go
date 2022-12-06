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

package multicluster

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/commonarea"
)

func TestMemberClusterDelete(t *testing.T) {
	existingMemberClusterAnnounce := &mcsv1alpha1.MemberClusterAnnounce{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  "default",
			Name:       "member-announce-from-cluster-a",
			Generation: 1,
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects().Build()
	fakeRemoteClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingMemberClusterAnnounce).Build()
	commonArea := commonarea.NewFakeRemoteCommonArea(fakeRemoteClient, "leader-cluster", localClusterID, "default", nil)

	reconciler := MemberClusterSetReconciler{
		Client:           fakeClient,
		remoteCommonArea: commonArea,
	}
	if _, err := reconciler.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{
			Namespace: "default",
			Name:      "clusterset1",
		}}); err != nil {
		t.Errorf("Member ClusterSet Reconciler should handle delete event successfully but got error = %v", err)
	} else {
		memberClusterAnnounce := &mcsv1alpha1.MemberClusterAnnounce{}
		err := fakeClient.Get(ctx, types.NamespacedName{
			Namespace: "default",
			Name:      "member-announce-from-cluster-a",
		}, memberClusterAnnounce)
		if !apierrors.IsNotFound(err) {
			t.Errorf("Member ClusterSet Reconciler should remove MemberClusterAnnounce successfully but got error = %v", err)
		}
	}
}

func TestMemberClusterStatus(t *testing.T) {
	existingClusterSet := &mcsv1alpha1.ClusterSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  "mcs1",
			Name:       "clusterset1",
			Generation: 1,
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
		Status: mcsv1alpha1.ClusterSetStatus{
			ObservedGeneration: 1,
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingClusterSet).Build()
	fakeRemoteClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingClusterSet).Build()
	conditions := []mcsv1alpha1.ClusterCondition{
		{
			Message: "Member Connected",
			Reason:  "Connected",
			Status:  v1.ConditionTrue,
			Type:    mcsv1alpha1.ClusterReady,
		},
		{
			Status: v1.ConditionTrue,
			Type:   mcsv1alpha1.ClusterIsLeader,
		},
	}
	expectedStatusNoCondition := mcsv1alpha1.ClusterSetStatus{
		ObservedGeneration: 1,
		TotalClusters:      2,
		ReadyClusters:      0,
		Conditions: []mcsv1alpha1.ClusterSetCondition{
			{
				Message: "Disconnected from leader",
				Status:  v1.ConditionFalse,
				Type:    mcsv1alpha1.ClusterSetReady,
			},
		},
		ClusterStatuses: []mcsv1alpha1.ClusterStatus{
			{
				ClusterID:  "leader1",
				Conditions: []mcsv1alpha1.ClusterCondition{},
			},
		},
	}
	expectedStatusWithCondition := mcsv1alpha1.ClusterSetStatus{
		ObservedGeneration: 1,
		TotalClusters:      2,
		ReadyClusters:      1,
		Conditions: []mcsv1alpha1.ClusterSetCondition{
			{
				Status: v1.ConditionTrue,
				Type:   mcsv1alpha1.ClusterSetReady,
			},
		},
		ClusterStatuses: []mcsv1alpha1.ClusterStatus{
			{
				ClusterID: "leader1",
				Conditions: []mcsv1alpha1.ClusterCondition{
					{
						Status:  v1.ConditionTrue,
						Type:    mcsv1alpha1.ClusterReady,
						Message: "Member Connected",
						Reason:  "Connected",
					},
					{
						Status: v1.ConditionTrue,
						Type:   mcsv1alpha1.ClusterIsLeader,
					},
				},
			},
		},
	}

	tests := []struct {
		name           string
		conditions     []mcsv1alpha1.ClusterCondition
		expectedStatus mcsv1alpha1.ClusterSetStatus
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
			commonArea := commonarea.NewFakeRemoteCommonArea(fakeRemoteClient, "leader1", localClusterID, "mcs1", tt.conditions)
			reconciler := MemberClusterSetReconciler{
				Client:           fakeClient,
				remoteCommonArea: commonArea,
				clusterSetConfig: existingClusterSet,
				clusterSetID:     "clusterset1",
				clusterID:        "east",
			}

			reconciler.updateStatus()
			clusterSet := &mcsv1alpha1.ClusterSet{}

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
	existingClusterSet := &mcsv1alpha1.ClusterSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  "mcs1",
			Name:       "clusterset1",
			Generation: 1,
		},
		Spec: mcsv1alpha1.ClusterSetSpec{
			Leaders: []mcsv1alpha1.MemberCluster{
				{
					ClusterID: "leader1",
					Secret:    "membertoken",
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
		Status: mcsv1alpha1.ClusterSetStatus{
			ObservedGeneration: 1,
		},
	}
	expectedInstalledLeader := leaderClusterInfo{
		clusterID:  "leader1",
		secretName: "membertoken",
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingClusterSet, existingSecret).Build()
	fakeRemoteClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingClusterSet, existingSecret).Build()
	commonArea := commonarea.NewFakeRemoteCommonArea(fakeRemoteClient, "leader1", localClusterID, "mcs1", nil)
	reconciler := MemberClusterSetReconciler{
		Client:           fakeClient,
		remoteCommonArea: commonArea,
		clusterSetConfig: existingClusterSet,
		clusterSetID:     "clusterset1",
		clusterID:        "east",
	}

	getRemoteConfigAndClient = commonarea.GetFakeRemoteConfigAndClient

	err := reconciler.createOrUpdateRemoteCommonArea(existingClusterSet)
	assert.Equal(t, nil, err)
	assert.Equal(t, expectedInstalledLeader, reconciler.installedLeader)
}
