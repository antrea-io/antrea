package multicluster

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
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
	mcaTestFakeRemoteClient = fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(existingClusterSet, &existingClusterClaimList.Items[0], &existingClusterClaimList.Items[1]).
		Build()

	memberClusterAnnounceReconcilerUnderTest = NewMemberClusterAnnounceReconciler(
		mcaTestFakeRemoteClient, scheme)
}

func TestStatusAfterAdd(t *testing.T) {
	setup()

	memberClusterAnnounceReconcilerUnderTest.AddMember("east")

	expectedStatus := mcsv1alpha1.ClusterStatus{
		ClusterID: "east",
		Conditions: []mcsv1alpha1.ClusterCondition{
			{
				Type:    "Ready",
				Status:  "Unknown",
				Message: "Member created",
				Reason:  "NeverConnected",
			},
			{
				Type:    "ImportsResources",
				Status:  "False",
				Message: "Member created",
				Reason:  "NeverConnected",
			},
		},
	}

	//[]multiclusterv1alpha1.ClusterStatus
	status := memberClusterAnnounceReconcilerUnderTest.GetMemberClusterStatuses()
	assert.Equal(t, 1, len(status))
	verifyStatus(t, expectedStatus, status[0])
}

func TestStatusAfterReconcile(t *testing.T) {
	TestStatusAfterAdd(t)

	mca := mcsv1alpha1.MemberClusterAnnounce{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "memberclusterannounce-east",
			Namespace: "mcs1",
		},
		ClusterID:    "east",
		ClusterSetID: "clusterset1",
	}
	err := mcaTestFakeRemoteClient.Create(context.TODO(), &mca, &client.CreateOptions{})
	assert.Equal(t, nil, err)

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: "mcs1",
			Name:      "memberclusterannounce-east",
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
			{
				Type:    "ImportsResources",
				Status:  "Unknown",
				Message: "Leader has not been elected yet",
			},
		},
	}

	memberClusterAnnounceReconcilerUnderTest.processMCSStatus()
	status := memberClusterAnnounceReconcilerUnderTest.GetMemberClusterStatuses()
	klog.V(2).InfoS("Received", "actual", status, "expected", expectedStatus)
	assert.Equal(t, 1, len(status))
	verifyStatus(t, expectedStatus, status[0])
}

func TestStatusAfterLeaderElection(t *testing.T) {
	TestStatusAfterReconcile(t)

	mca := &mcsv1alpha1.MemberClusterAnnounce{}
	err := mcaTestFakeRemoteClient.Get(context.TODO(), types.NamespacedName{Name: "memberclusterannounce-east", Namespace: "mcs1"}, mca)
	assert.Equal(t, nil, err)
	mca.LeaderClusterID = "leader1"
	err = mcaTestFakeRemoteClient.Update(context.TODO(), mca, &client.UpdateOptions{})
	assert.Equal(t, nil, err)

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: "mcs1",
			Name:      "memberclusterannounce-east",
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
			{
				Type:    "ImportsResources",
				Status:  "True",
				Message: "Local cluster is the elected leader of member: east",
				Reason:  "ElectedLeader",
			},
		},
	}

	memberClusterAnnounceReconcilerUnderTest.processMCSStatus()
	status := memberClusterAnnounceReconcilerUnderTest.GetMemberClusterStatuses()
	klog.V(2).InfoS("Received", "actual", status, "expected", expectedStatus)
	assert.Equal(t, 1, len(status))
	verifyStatus(t, expectedStatus, status[0])
}

func TestStatusInNonLeaderCase(t *testing.T) {
	TestStatusAfterReconcile(t)

	mca := &mcsv1alpha1.MemberClusterAnnounce{}
	err := mcaTestFakeRemoteClient.Get(context.TODO(), types.NamespacedName{Name: "memberclusterannounce-east", Namespace: "mcs1"}, mca)
	assert.Equal(t, nil, err)
	mca.LeaderClusterID = "leader2"
	err = mcaTestFakeRemoteClient.Update(context.TODO(), mca, &client.UpdateOptions{})
	assert.Equal(t, nil, err)

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: "mcs1",
			Name:      "memberclusterannounce-east",
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
			{
				Type:    "ImportsResources",
				Status:  "False",
				Message: "Local cluster is not the elected leader of member: east",
				Reason:  "NotElectedLeader",
			},
		},
	}

	memberClusterAnnounceReconcilerUnderTest.processMCSStatus()
	status := memberClusterAnnounceReconcilerUnderTest.GetMemberClusterStatuses()
	klog.V(2).InfoS("Received", "actual", status, "expected", expectedStatus)
	assert.Equal(t, 1, len(status))
	verifyStatus(t, expectedStatus, status[0])
}

func verifyStatus(t *testing.T, expected mcsv1alpha1.ClusterStatus, actual mcsv1alpha1.ClusterStatus) {
	assert.Equal(t, expected.ClusterID, actual.ClusterID)
	assert.Equal(t, len(expected.Conditions), len(actual.Conditions))
	verfiedConditions := 0
	for _, condition := range expected.Conditions {
		for _, actualCondition := range actual.Conditions {
			if condition.Type == actualCondition.Type {
				assert.Equal(t, condition.Status, actualCondition.Status)
				assert.Equal(t, condition.Message, actualCondition.Message)
				assert.Equal(t, condition.Reason, actualCondition.Reason)
				verfiedConditions += 1
			}
		}
	}
	assert.Equal(t, len(expected.Conditions), verfiedConditions)
}
