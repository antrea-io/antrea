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
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	mcv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	mcv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
)

var (
	mcaTestFakeRemoteClient                  client.Client
	memberClusterAnnounceReconcilerUnderTest *MemberClusterAnnounceReconciler
)

func setup() {
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
	}

	mcaTestFakeRemoteClient = fake.NewClientBuilder().WithScheme(common.TestScheme).
		WithObjects(existingClusterSet).
		Build()

	memberClusterAnnounceReconcilerUnderTest = NewMemberClusterAnnounceReconciler(
		mcaTestFakeRemoteClient, common.TestScheme)
}

func TestStatusAfterAdd(t *testing.T) {
	setup()

	memberClusterAnnounceReconcilerUnderTest.addOrUpdateMemberStatus("east")

	expectedStatus := mcv1alpha2.ClusterStatus{
		ClusterID: "east",
		Conditions: []mcv1alpha2.ClusterCondition{
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

	mca := mcv1alpha1.MemberClusterAnnounce{
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

	expectedStatus := mcv1alpha2.ClusterStatus{
		ClusterID: "east",
		Conditions: []mcv1alpha2.ClusterCondition{
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

	mca := mcv1alpha1.MemberClusterAnnounce{
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

	expectedStatus := mcv1alpha2.ClusterStatus{
		ClusterID: "east",
		Conditions: []mcv1alpha2.ClusterCondition{
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

func verifyStatus(t *testing.T, expected mcv1alpha2.ClusterStatus, actual mcv1alpha2.ClusterStatus) {
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
