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

package leader

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	mcv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
)

var (
	eventTime = time.Date(2021, 12, 12, 12, 12, 12, 0, time.Local)
	metaTime  = metav1.Time{Time: eventTime}
	statuses  = []mcv1alpha2.ClusterStatus{
		{
			ClusterID: "east",
			Conditions: []mcv1alpha2.ClusterCondition{
				{
					LastTransitionTime: metaTime,
					Message:            "Member Connected",
					Reason:             "Connected",
					Status:             v1.ConditionTrue,
					Type:               mcv1alpha2.ClusterReady,
				},
			},
		},
		{
			ClusterID: "west",
			Conditions: []mcv1alpha2.ClusterCondition{
				{
					LastTransitionTime: metaTime,
					Message:            "Member Connected",
					Reason:             "Disconnected",
					Status:             v1.ConditionFalse,
					Type:               mcv1alpha2.ClusterReady,
				},
			},
		},
	}
	existingClusterSet = &mcv1alpha2.ClusterSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  "mcs1",
			Name:       "clusterset1",
			Generation: 1,
		},
		Spec: mcv1alpha2.ClusterSetSpec{
			ClusterID: "leader1",
			Leaders: []mcv1alpha2.LeaderClusterInfo{
				{
					ClusterID: "leader1",
				}},
			Namespace: "mcs1",
		},
	}
)

func createMockClients(t *testing.T, objects ...client.Object) (client.Client, *MockMemberClusterStatusManager) {
	fakeRemoteClient := fake.NewClientBuilder().WithScheme(common.TestScheme).
		WithObjects(objects...).WithStatusSubresource(objects...).Build()

	mockCtrl := gomock.NewController(t)
	mockStatusManager := NewMockMemberClusterStatusManager(mockCtrl)
	return fakeRemoteClient, mockStatusManager
}

func TestLeaderClusterSetAdd(t *testing.T) {
	fakeRemoteClient, mockStatusManager := createMockClients(t, existingClusterSet)
	leaderClusterSetReconcilerUnderTest := NewLeaderClusterSetReconciler(
		fakeRemoteClient, "mcs1", false, mockStatusManager)
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

func TestLeaderClusterSetAddWithoutClusterID(t *testing.T) {
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
				}},
			Namespace: "mcs1",
		},
	}
	clusterClaim := &mcv1alpha2.ClusterClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "mcs1",
			Name:      "id.k8s.io",
		},
		Value: "leader1",
	}
	fakeRemoteClient, mockStatusManager := createMockClients(t, clusterSetWithoutClusterID, clusterClaim)
	leaderClusterSetReconcilerUnderTest := NewLeaderClusterSetReconciler(
		fakeRemoteClient, "mcs1", true, mockStatusManager)
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

	clusterSet := &mcv1alpha2.ClusterSet{}
	err = fakeRemoteClient.Get(context.TODO(), types.NamespacedName{Name: "clusterset1", Namespace: "mcs1"}, clusterSet)
	assert.Equal(t, nil, err)
	assert.Equal(t, "leader1", clusterSet.Spec.ClusterID)
}

func TestLeaderClusterSetUpdate(t *testing.T) {
	fakeRemoteClient, mockStatusManager := createMockClients(t, existingClusterSet)
	leaderClusterSetReconcilerUnderTest := NewLeaderClusterSetReconciler(
		fakeRemoteClient, "mcs1", false, mockStatusManager)
	leaderClusterSetReconcilerUnderTest.clusterID = common.ClusterID(existingClusterSet.Spec.ClusterID)

	clusterSet := &mcv1alpha2.ClusterSet{}
	err := fakeRemoteClient.Get(context.TODO(), types.NamespacedName{Name: "clusterset1", Namespace: "mcs1"}, clusterSet)
	assert.Equal(t, nil, err)

	clusterSet.Spec = mcv1alpha2.ClusterSetSpec{
		Leaders: []mcv1alpha2.LeaderClusterInfo{
			{
				ClusterID: "leader1",
			}},
		Namespace: "mcs1",
	}
	err = fakeRemoteClient.Update(context.TODO(), clusterSet)
	assert.Equal(t, nil, err)

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
	fakeRemoteClient, mockStatusManager := createMockClients(t, existingClusterSet)
	leaderClusterSetReconcilerUnderTest := NewLeaderClusterSetReconciler(
		fakeRemoteClient, "mcs1", false, mockStatusManager)
	leaderClusterSetReconcilerUnderTest.clusterID = common.ClusterID(existingClusterSet.Spec.ClusterID)
	leaderClusterSetReconcilerUnderTest.clusterSetID = common.ClusterSetID(existingClusterSet.Name)

	clusterSet := &mcv1alpha2.ClusterSet{}
	err := fakeRemoteClient.Get(context.TODO(), types.NamespacedName{Name: "clusterset1", Namespace: "mcs1"}, clusterSet)
	assert.Equal(t, nil, err)

	err = fakeRemoteClient.Delete(context.TODO(), clusterSet)
	assert.Equal(t, nil, err)

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "clusterset1",
			Namespace: "mcs1",
		},
	}
	_, err = leaderClusterSetReconcilerUnderTest.Reconcile(context.Background(), req)
	assert.Equal(t, nil, err)
	assert.Equal(t, common.InvalidClusterID, leaderClusterSetReconcilerUnderTest.clusterID)
	assert.Equal(t, common.InvalidClusterSetID, leaderClusterSetReconcilerUnderTest.clusterSetID)
}

func TestLeaderClusterStatus(t *testing.T) {
	fakeRemoteClient, mockStatusManager := createMockClients(t, existingClusterSet)
	leaderClusterSetReconcilerUnderTest := NewLeaderClusterSetReconciler(
		fakeRemoteClient, "mcs1", false, mockStatusManager)
	leaderClusterSetReconcilerUnderTest.clusterID = common.ClusterID(existingClusterSet.Spec.ClusterID)
	leaderClusterSetReconcilerUnderTest.clusterSetID = common.ClusterSetID(existingClusterSet.Name)

	mockStatusManager.EXPECT().GetMemberClusterStatuses().Return(statuses).Times(1)
	leaderClusterSetReconcilerUnderTest.updateStatus()

	clusterSet := &mcv1alpha2.ClusterSet{}
	err := fakeRemoteClient.Get(context.TODO(), types.NamespacedName{Name: "clusterset1", Namespace: "mcs1"}, clusterSet)
	assert.Equal(t, nil, err)

	actualStatus := clusterSet.Status
	expectedStatus := mcv1alpha2.ClusterSetStatus{
		ObservedGeneration: 1,
		TotalClusters:      2,
		ClusterStatuses:    statuses,
		Conditions: []mcv1alpha2.ClusterSetCondition{
			{
				Reason: "NoReadyCluster",
				Status: v1.ConditionFalse,
				Type:   mcv1alpha2.ClusterSetReady,
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
