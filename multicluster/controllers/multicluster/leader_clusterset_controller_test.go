package multicluster

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
)

var (
	fakeRemoteClient                    client.Client
	leaderClusterSetReconcilerUnderTest LeaderClusterSetReconciler
)

func TestLeaderClusterSetAdd(t *testing.T) {
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

	leaderClusterSetReconcilerUnderTest = LeaderClusterSetReconciler{
		Client: fakeRemoteClient,
		Scheme: scheme,
	}

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

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name:      "clusterset1",
			Namespace: "mcs1",
		},
	}
	_, err = leaderClusterSetReconcilerUnderTest.Reconcile(context.Background(), req)
	assert.Equal(t, nil, err)
}
