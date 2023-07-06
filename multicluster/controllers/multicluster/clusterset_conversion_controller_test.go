/*
Copyright 2023 Antrea Authors.

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

package multicluster

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	mcv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
)

func TestConversion(t *testing.T) {
	ns := "default"
	clusterSetID := "test-clusterset"
	clusterID := "cluster-a"
	clusterSetWithoutIDs := &mcv1alpha2.ClusterSet{
		ObjectMeta: v1.ObjectMeta{
			Namespace: ns,
			Name:      clusterSetID,
		},
		Spec: mcv1alpha2.ClusterSetSpec{
			Leaders: []mcv1alpha2.LeaderClusterInfo{
				{ClusterID: clusterID},
			},
		},
	}
	mismatchedClusterSet := &mcv1alpha2.ClusterSet{
		ObjectMeta: v1.ObjectMeta{
			Namespace: ns,
			Name:      "cluster-set",
		},
		Spec: mcv1alpha2.ClusterSetSpec{
			Leaders: []mcv1alpha2.LeaderClusterInfo{
				{ClusterID: clusterID},
			},
		},
	}
	clusterSetWithIDs := &mcv1alpha2.ClusterSet{
		ObjectMeta: v1.ObjectMeta{
			Namespace: ns,
			Name:      clusterSetID,
		},
		Spec: mcv1alpha2.ClusterSetSpec{
			ClusterID: "existing-cluster-id",
			Leaders: []mcv1alpha2.LeaderClusterInfo{
				{ClusterID: clusterID},
			},
		},
	}

	clusterClaim1 := mcv1alpha2.ClusterClaim{
		ObjectMeta: v1.ObjectMeta{
			Namespace: ns,
			Name:      "id.k8s.io",
		},
		Value: clusterID,
	}
	clusterClaim2 := mcv1alpha2.ClusterClaim{
		ObjectMeta: v1.ObjectMeta{
			Namespace: ns,
			Name:      "clusterset.k8s.io",
		},
		Value: clusterSetID,
	}
	clusterClaim3 := mcv1alpha2.ClusterClaim{
		ObjectMeta: v1.ObjectMeta{
			Namespace: ns,
			Name:      "clusterset.k8s.io",
		},
		Value: "test-clusterset-1",
	}
	ctx := context.TODO()

	tests := []struct {
		name                 string
		existClusterSets     mcv1alpha2.ClusterSetList
		existClusterClaims   mcv1alpha2.ClusterClaimList
		expectedClusterID    string
		expectedClusterSetID string
	}{
		{
			name:               "empty ClusterSet list",
			existClusterSets:   mcv1alpha2.ClusterSetList{},
			existClusterClaims: mcv1alpha2.ClusterClaimList{},
		},
		{
			name: "empty ClusterClaim list",
			existClusterSets: mcv1alpha2.ClusterSetList{
				Items: []mcv1alpha2.ClusterSet{*clusterSetWithoutIDs},
			},
			existClusterClaims:   mcv1alpha2.ClusterClaimList{},
			expectedClusterSetID: clusterSetID,
		},
		{
			name: "convert IDs in ClusterClaims to ClusterSet",
			existClusterSets: mcv1alpha2.ClusterSetList{
				Items: []mcv1alpha2.ClusterSet{*clusterSetWithoutIDs},
			},
			existClusterClaims: mcv1alpha2.ClusterClaimList{
				Items: []mcv1alpha2.ClusterClaim{
					clusterClaim1,
					clusterClaim2,
				},
			},
			expectedClusterID:    clusterID,
			expectedClusterSetID: clusterSetID,
		},
		{
			name: "create a new ClusterSet when the existing ClusterSet's name mismatch clusterSetID",
			existClusterSets: mcv1alpha2.ClusterSetList{
				Items: []mcv1alpha2.ClusterSet{*mismatchedClusterSet},
			},
			existClusterClaims: mcv1alpha2.ClusterClaimList{
				Items: []mcv1alpha2.ClusterClaim{
					clusterClaim1,
					clusterClaim3,
				},
			},
			expectedClusterID:    clusterID,
			expectedClusterSetID: clusterClaim3.Value,
		},
		{
			name: "skip converting when ClusterSet contains IDs",
			existClusterSets: mcv1alpha2.ClusterSetList{
				Items: []mcv1alpha2.ClusterSet{*clusterSetWithIDs},
			},
			existClusterClaims: mcv1alpha2.ClusterClaimList{
				Items: []mcv1alpha2.ClusterClaim{
					clusterClaim1,
					clusterClaim2,
				},
			},
			expectedClusterID:    "existing-cluster-id",
			expectedClusterSetID: clusterSetID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithLists(&tt.existClusterSets, &tt.existClusterClaims).Build()
			controller := NewClusterSetConversionController(
				fakeClient,
				common.TestScheme,
				ns,
			)
			err := controller.conversion()
			assert.NoError(t, err)
			if len(tt.existClusterSets.Items) > 0 {
				actualClusterSet := &mcv1alpha2.ClusterSet{}
				err = fakeClient.Get(ctx, types.NamespacedName{
					Namespace: ns,
					Name:      tt.expectedClusterSetID}, actualClusterSet)
				if err != nil {
					t.Errorf("Error running conversion() %v", err)
				}
				assert.Equal(t, tt.expectedClusterID, actualClusterSet.Spec.ClusterID)
			}
		})
	}
}
