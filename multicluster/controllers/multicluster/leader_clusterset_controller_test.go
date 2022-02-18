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
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
)

var (
	fakeRemoteClient                    client.Client
	leaderClusterSetReconcilerUnderTest LeaderClusterSetReconciler
	mockStatusManager                   *MockMemberClusterStatusManager
)

func TestLeaderClusterSetAdd(t *testing.T) {
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
	}
	existingClusterClaimList := &mcsv1alpha1.ClusterClaimList{
		Items: []mcsv1alpha1.ClusterClaim{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "clustersetid",
					Namespace: "mcs1",
				},
				Name:  mcsv1alpha1.WellKnownClusterClaimClusterSet,
				Value: "clusterset1",
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "clusterid",
					Namespace: "mcs1",
				},
				Name:  mcsv1alpha1.WellKnownClusterClaimID,
				Value: "leader1",
			},
		},
	}

	scheme := runtime.NewScheme()
	mcsv1alpha1.AddToScheme(scheme)
	fakeRemoteClient = fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(existingClusterSet, &existingClusterClaimList.Items[0], &existingClusterClaimList.Items[1]).
		Build()

	mockCtrl := gomock.NewController(t)
	mockStatusManager = NewMockMemberClusterStatusManager(mockCtrl)
	leaderClusterSetReconcilerUnderTest = LeaderClusterSetReconciler{
		Client:        fakeRemoteClient,
		Scheme:        scheme,
		StatusManager: mockStatusManager,
	}

	mockStatusManager.EXPECT().AddMember(common.ClusterID("east"))
	mockStatusManager.EXPECT().AddMember(common.ClusterID("west"))

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: "mcs1",
			Name:      "clusterset1",
		},
	}
	_, err := leaderClusterSetReconcilerUnderTest.Reconcile(context.TODO(), req)
	assert.Equal(t, nil, err)

	assert.Equal(t, "clusterset1", string(leaderClusterSetReconcilerUnderTest.clusterSetID))
	assert.Equal(t, "leader1", string(leaderClusterSetReconcilerUnderTest.clusterID))
}

func TestLeaderClusterSetUpdate(t *testing.T) {
	TestLeaderClusterSetAdd(t)
	clusterSet := &mcsv1alpha1.ClusterSet{}
	err := fakeRemoteClient.Get(context.TODO(), types.NamespacedName{Name: "clusterset1", Namespace: "mcs1"}, clusterSet)
	assert.Equal(t, nil, err)

	clusterSet.Spec = mcsv1alpha1.ClusterSetSpec{
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
				ClusterID:      "north",
				ServiceAccount: "north-access-sa",
			},
		},
		Namespace: "mcs1",
	}
	err = fakeRemoteClient.Update(context.TODO(), clusterSet)
	assert.Equal(t, nil, err)

	mockStatusManager.EXPECT().AddMember(common.ClusterID("north"))
	mockStatusManager.EXPECT().RemoveMember(common.ClusterID("west"))

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "clusterset1",
			Namespace: "mcs1",
		},
	}
	_, err = leaderClusterSetReconcilerUnderTest.Reconcile(context.Background(), req)
	assert.Equal(t, nil, err)
}

func TestLeaderClusterSetDelete(t *testing.T) {
	TestLeaderClusterSetAdd(t)
	clusterSet := &mcsv1alpha1.ClusterSet{}
	err := fakeRemoteClient.Get(context.TODO(), types.NamespacedName{Name: "clusterset1", Namespace: "mcs1"}, clusterSet)
	assert.Equal(t, nil, err)

	err = fakeRemoteClient.Delete(context.TODO(), clusterSet)
	assert.Equal(t, nil, err)

	mockStatusManager.EXPECT().RemoveMember(common.ClusterID("east"))
	mockStatusManager.EXPECT().RemoveMember(common.ClusterID("west"))

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "clusterset1",
			Namespace: "mcs1",
		},
	}
	_, err = leaderClusterSetReconcilerUnderTest.Reconcile(context.Background(), req)
	assert.Equal(t, nil, err)
}

func TestLeaderClusterStatus(t *testing.T) {
	TestLeaderClusterSetAdd(t)

	eventTime := time.Date(2021, 12, 12, 12, 12, 12, 0, time.Local)
	metaTime := metav1.Time{Time: eventTime}

	statues := []mcsv1alpha1.ClusterStatus{
		{
			ClusterID: "east",
			Conditions: []mcsv1alpha1.ClusterCondition{
				{
					LastTransitionTime: metaTime,
					Message:            "Member created",
					Reason:             "NeverConnected",
					Status:             v1.ConditionUnknown,
					Type:               mcsv1alpha1.ClusterReady,
				},
				{
					LastTransitionTime: metaTime,
					Message:            "Member created",
					Reason:             "NeverConnected",
					Status:             v1.ConditionFalse,
					Type:               mcsv1alpha1.ClusterImportsResources,
				},
			},
		},
		{
			ClusterID: "west",
			Conditions: []mcsv1alpha1.ClusterCondition{
				{
					LastTransitionTime: metaTime,
					Status:             v1.ConditionTrue,
					Type:               mcsv1alpha1.ClusterReady,
				},
				{
					LastTransitionTime: metaTime,
					Message:            "Local leader cluster is the elected leader of member: west",
					Reason:             "ElectedLeader",
					Status:             v1.ConditionFalse,
					Type:               mcsv1alpha1.ClusterImportsResources,
				},
			},
		},
	}

	mockStatusManager.EXPECT().GetMemberClusterStatuses().Return(statues).Times(1)

	leaderClusterSetReconcilerUnderTest.updateStatus()

	clusterSet := &mcsv1alpha1.ClusterSet{}
	err := fakeRemoteClient.Get(context.TODO(), types.NamespacedName{Name: "clusterset1", Namespace: "mcs1"}, clusterSet)
	assert.Equal(t, nil, err)

	actualStatus := clusterSet.Status
	expectedStatus := mcsv1alpha1.ClusterSetStatus{
		ObservedGeneration: 1,
		TotalClusters:      3,
		ClusterStatuses:    statues,
		Conditions: []mcsv1alpha1.ClusterSetCondition{
			{
				Reason: "NoReadyCluster",
				Status: v1.ConditionFalse,
				Type:   mcsv1alpha1.ClusterSetReady,
			},
		},
	}

	klog.V(2).InfoS("Test result", "Actual", actualStatus, "Expected", expectedStatus)

	assert.Equal(t, expectedStatus.ObservedGeneration, actualStatus.ObservedGeneration)
	assert.Equal(t, expectedStatus.TotalClusters, actualStatus.TotalClusters)
	assert.Equal(t, expectedStatus.ClusterStatuses, actualStatus.ClusterStatuses)
	assert.Equal(t, 1, len(actualStatus.Conditions))
	assert.Equal(t, expectedStatus.Conditions[0].Type, actualStatus.Conditions[0].Type)
	assert.Equal(t, expectedStatus.Conditions[0].Reason, actualStatus.Conditions[0].Reason)
	assert.Equal(t, expectedStatus.Conditions[0].Status, actualStatus.Conditions[0].Status)
	assert.Equal(t, expectedStatus.Conditions[0].Message, actualStatus.Conditions[0].Message)
}
