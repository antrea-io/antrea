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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	mcsv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
)

var (
	mcaTestFakeRemoteClient                  client.Client
	memberClusterAnnounceReconcilerUnderTest *MemberClusterAnnounceReconciler
)

func setup() {
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
	existingClusterClaimList := &mcsv1alpha2.ClusterClaimList{
		Items: []mcsv1alpha2.ClusterClaim{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      mcsv1alpha2.WellKnownClusterClaimClusterSet,
					Namespace: "mcs1",
				},
				Value: "clusterset1",
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      mcsv1alpha2.WellKnownClusterClaimID,
					Namespace: "mcs1",
				},
				Value: "leader1",
			},
		},
	}

	scheme := runtime.NewScheme()
	mcsv1alpha1.AddToScheme(scheme)
	mcsv1alpha2.AddToScheme(scheme)
	mcaTestFakeRemoteClient = fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(existingClusterSet, &existingClusterClaimList.Items[0], &existingClusterClaimList.Items[1]).
		Build()

	memberClusterAnnounceReconcilerUnderTest = NewMemberClusterAnnounceReconciler(
		mcaTestFakeRemoteClient, scheme)
}

func TestAddMemberToClusterSet(t *testing.T) {
	setup()

	memberCluster := &mcsv1alpha1.MemberClusterAnnounce{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "member-announce-from-south",
			Namespace: "mcs1",
		},
		ClusterSetID: "clusterset1",
		ClusterID:    "south",
	}

	err := memberClusterAnnounceReconcilerUnderTest.addMemberToClusterSet(memberCluster)
	assert.Equal(t, nil, err)

	clusterSet := &mcsv1alpha1.ClusterSet{}
	err = mcaTestFakeRemoteClient.Get(context.TODO(), types.NamespacedName{Namespace: "mcs1", Name: "clusterset1"}, clusterSet)
	assert.Equal(t, nil, err)
	assert.Equal(t, 3, len(clusterSet.Spec.Members))
}

func TestRemoveMemberCluster(t *testing.T) {
	setup()

	memberCluster := &mcsv1alpha1.MemberClusterAnnounce{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "member-announce-from-east",
			Namespace: "mcs1",
		},
		ClusterSetID: "clusterset1",
		ClusterID:    "east",
	}
	err := memberClusterAnnounceReconcilerUnderTest.removeMemberFromClusterSet(memberCluster)
	assert.Equal(t, nil, err)
}

func TestRemoveMemberClusterNotExist(t *testing.T) {
	setup()

	memberCluster := &mcsv1alpha1.MemberClusterAnnounce{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "member-announce-from-not-exist",
			Namespace: "mcs1",
		},
		ClusterSetID: "clusterset1",
		ClusterID:    "not-exist",
	}
	err := memberClusterAnnounceReconcilerUnderTest.removeMemberFromClusterSet(memberCluster)

	assert.Equal(t, nil, err)
}

func TestStatusAfterAdd(t *testing.T) {
	setup()

	memberClusterAnnounceReconcilerUnderTest.addOrUpdateMemberStatus("east")

	expectedStatus := mcsv1alpha1.ClusterStatus{
		ClusterID: "east",
		Conditions: []mcsv1alpha1.ClusterCondition{
			{
				Type:    "Ready",
				Status:  "True",
				Message: "Member Connected",
				Reason:  "Connected",
			},
		},
	}

	actualStatus := memberClusterAnnounceReconcilerUnderTest.GetMemberClusterStatuses()
	assert.Equal(t, 1, len(actualStatus))
	verifyStatus(t, expectedStatus, actualStatus[0])
}

func TestStatusAfterDelete(t *testing.T) {
	setup()
	memberClusterAnnounceReconcilerUnderTest.addOrUpdateMemberStatus("east")
	memberClusterAnnounceReconcilerUnderTest.removeMemberStatus("east")

	actualStatus := memberClusterAnnounceReconcilerUnderTest.GetMemberClusterStatuses()
	assert.Equal(t, 0, len(actualStatus))
}

func TestStatusAfterReconcile(t *testing.T) {
	TestStatusAfterAdd(t)

	mca := mcsv1alpha1.MemberClusterAnnounce{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "memberclusterannounce-east",
			Namespace: "mcs1",
		},
		ClusterID:       "east",
		ClusterSetID:    "clusterset1",
		LeaderClusterID: "leader1",
	}
	err := mcaTestFakeRemoteClient.Create(context.TODO(), &mca, &client.CreateOptions{})
	assert.Equal(t, nil, err)

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: "mcs1",
			Name:      "member-announce-from-east",
		},
	}
	memberClusterAnnounceReconcilerUnderTest.Reconcile(context.Background(), req)

	expectedStatus := mcsv1alpha1.ClusterStatus{
		ClusterID: "east",
		Conditions: []mcsv1alpha1.ClusterCondition{
			{
				Type:   "Ready",
				Status: "True",
				Reason: "Connected",
			},
		},
	}

	memberClusterAnnounceReconcilerUnderTest.processMCSStatus()
	actualStatus := memberClusterAnnounceReconcilerUnderTest.GetMemberClusterStatuses()
	klog.V(2).InfoS("Received", "actual", actualStatus, "expected", expectedStatus)
	assert.Equal(t, 1, len(actualStatus))
	verifyStatus(t, expectedStatus, actualStatus[0])
}

func TestStatusAfterReconcileAndTimeout(t *testing.T) {
	TestStatusAfterAdd(t)

	mca := mcsv1alpha1.MemberClusterAnnounce{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "member-announce-from-east",
			Namespace: "mcs1",
		},
		ClusterID:       "east",
		ClusterSetID:    "clusterset1",
		LeaderClusterID: "leader1",
	}
	err := mcaTestFakeRemoteClient.Create(context.TODO(), &mca, &client.CreateOptions{})
	assert.Equal(t, nil, err)

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: "mcs1",
			Name:      "member-announce-from-east",
		},
	}
	memberClusterAnnounceReconcilerUnderTest.Reconcile(context.Background(), req)

	expectedStatus := mcsv1alpha1.ClusterStatus{
		ClusterID: "east",
		Conditions: []mcsv1alpha1.ClusterCondition{
			{
				Type:    "Ready",
				Status:  "False",
				Message: "No MemberClusterAnnounce update after",
				Reason:  "Disconnected",
			},
		},
	}

	ConnectionTimeout = 1 * time.Second
	time.Sleep(2 * time.Second)
	memberClusterAnnounceReconcilerUnderTest.processMCSStatus()
	actualStatus := memberClusterAnnounceReconcilerUnderTest.GetMemberClusterStatuses()
	klog.V(2).InfoS("Received", "actual", actualStatus, "expected", expectedStatus)
	assert.Equal(t, 1, len(actualStatus))
	verifyStatus(t, expectedStatus, actualStatus[0])
	ConnectionTimeout = 3 * TimerInterval
}

func verifyStatus(t *testing.T, expected mcsv1alpha1.ClusterStatus, actual mcsv1alpha1.ClusterStatus) {
	assert.Equal(t, expected.ClusterID, actual.ClusterID)
	assert.Equal(t, len(expected.Conditions), len(actual.Conditions))
	verfiedConditions := 0
	for _, condition := range expected.Conditions {
		for _, actualCondition := range actual.Conditions {
			if condition.Type == actualCondition.Type {
				assert.Equal(t, condition.Status, actualCondition.Status)
				assert.Contains(t, actualCondition.Message, condition.Message)
				assert.Equal(t, condition.Reason, actualCondition.Reason)
				verfiedConditions += 1
			}
		}
	}
	assert.Equal(t, len(expected.Conditions), verfiedConditions)
}
