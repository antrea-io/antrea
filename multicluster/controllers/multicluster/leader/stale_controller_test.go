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

package leader

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	mcv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	mcv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
	"antrea.io/antrea/multicluster/controllers/multicluster/commonarea"
)

func TestReconcile(t *testing.T) {
	resExport1 := mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "cluster-1-svc",
		},
		Spec: mcv1alpha1.ResourceExportSpec{
			ClusterID: "cluster-1",
		},
	}
	resExport2 := mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "cluster-1-ep",
		},
		Spec: mcv1alpha1.ResourceExportSpec{
			ClusterID: "cluster-1",
		},
	}
	resExport3 := mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "cluster-2-ep",
		},
		Spec: mcv1alpha1.ResourceExportSpec{
			ClusterID: "cluster-2",
		},
	}
	resExportsList := &mcv1alpha1.ResourceExportList{
		Items: []mcv1alpha1.ResourceExport{
			resExport1,
			resExport2,
			resExport3,
		},
	}
	now := metav1.Now()
	memberClusterAnnounce1 := &mcv1alpha1.MemberClusterAnnounce{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "member-announce-from-cluster-1",
			Namespace:         "default",
			DeletionTimestamp: &now,
			Finalizers:        []string{"test-membercluster-announce-finalizer"},
		},
		ClusterID: "cluster-1",
	}
	memberClusterAnnounce2 := &mcv1alpha1.MemberClusterAnnounce{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "member-announce-from-cluster-2",
			Namespace: "default",
		},
		ClusterID: "cluster-2",
	}

	tests := []struct {
		name                          string
		memberAnnounceName            string
		expectedResExportsSize        int
		expectedErr                   error
		existingMemberAnnounce        *mcv1alpha1.MemberClusterAnnounce
		existingResExports            *mcv1alpha1.ResourceExportList
		getResourceExportsByClusterID func(c *StaleResCleanupController, ctx context.Context, clusterID string) ([]mcv1alpha1.ResourceExport, error)
	}{
		{
			name:                   "MemberClusterAnnounce deleted",
			memberAnnounceName:     memberClusterAnnounce1.Name,
			existingMemberAnnounce: memberClusterAnnounce1,
			existingResExports:     resExportsList,
			getResourceExportsByClusterID: func(c *StaleResCleanupController, ctx context.Context, clusterID string) ([]mcv1alpha1.ResourceExport, error) {
				return []mcv1alpha1.ResourceExport{resExport1, resExport2}, nil
			},
			expectedResExportsSize: 1,
		},
		{
			name:                   "MemberClusterAnnounce exists",
			memberAnnounceName:     memberClusterAnnounce2.Name,
			existingMemberAnnounce: memberClusterAnnounce2,
			existingResExports:     resExportsList,
			expectedResExportsSize: 3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getResourceExportsByClusterIDFunc = tt.getResourceExportsByClusterID
			defer func() {
				getResourceExportsByClusterIDFunc = getResourceExportsByClusterID
			}()
			fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithLists(tt.existingResExports).
				WithObjects(tt.existingMemberAnnounce).WithStatusSubresource(tt.existingMemberAnnounce).Build()
			c := NewStaleResCleanupController(fakeClient, common.TestScheme)
			ctx := context.Background()
			_, err := c.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Namespace: "default",
					Name:      tt.memberAnnounceName,
				},
			})
			if tt.expectedErr == nil {
				require.NoError(t, err)
			} else {
				assert.Equal(t, tt.expectedErr, err.Error())
			}
			latestResExports := &mcv1alpha1.ResourceExportList{}
			err = fakeClient.List(ctx, latestResExports)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedResExportsSize, len(latestResExports.Items))
		})
	}
}

func TestStaleController_CleanUpMemberClusterAnnounces(t *testing.T) {
	tests := []struct {
		name                              string
		memberClusterAnnounceList         *mcv1alpha1.MemberClusterAnnounceList
		clusterSet                        *mcv1alpha2.ClusterSetList
		exceptMemberClusterAnnounceNumber int
	}{
		{
			name:                              "no MemberClusterAnnounce to clean up when there is no resource",
			clusterSet:                        &mcv1alpha2.ClusterSetList{},
			memberClusterAnnounceList:         &mcv1alpha1.MemberClusterAnnounceList{},
			exceptMemberClusterAnnounceNumber: 0,
		},
		{
			name:                              "no MemberClusterAnnounce to clean up when the resource has a valid update time",
			exceptMemberClusterAnnounceNumber: 1,
			clusterSet: &mcv1alpha2.ClusterSetList{
				Items: []mcv1alpha2.ClusterSet{
					{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "default",
							Name:      "clusterset",
						},
						Spec: mcv1alpha2.ClusterSetSpec{},
					},
				},
			},
			memberClusterAnnounceList: &mcv1alpha1.MemberClusterAnnounceList{
				Items: []mcv1alpha1.MemberClusterAnnounce{
					{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "default",
							Name:      "member-cluster-from-cluster-a",
							Annotations: map[string]string{
								commonarea.TimestampAnnotationKey: time.Now().Format(time.RFC3339),
							},
						},
						ClusterID: "cluster-a",
					},
				},
			},
		},
		{
			name:                              "clean up outdated MemberClusterAnnounce",
			exceptMemberClusterAnnounceNumber: 1,
			clusterSet: &mcv1alpha2.ClusterSetList{
				Items: []mcv1alpha2.ClusterSet{
					{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "default",
							Name:      "clusterset",
						},
						Spec: mcv1alpha2.ClusterSetSpec{},
					},
				},
			},
			memberClusterAnnounceList: &mcv1alpha1.MemberClusterAnnounceList{
				Items: []mcv1alpha1.MemberClusterAnnounce{
					{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "default",
							Name:      "member-cluster-from-cluster-a",
							Annotations: map[string]string{
								commonarea.TimestampAnnotationKey: time.Now().Format(time.RFC3339),
							},
						},
						ClusterID: "cluster-a",
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "default",
							Name:      "member-cluster-from-cluster-outdated",
							Annotations: map[string]string{
								commonarea.TimestampAnnotationKey: time.Now().Add(-memberClusterAnnounceStaleTime - 1).Format(time.RFC3339),
							},
						},
						ClusterID: "cluster-outdated",
					},
				},
			},
		},
	}
	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithLists(tt.memberClusterAnnounceList).WithLists(tt.clusterSet).Build()
			c := NewStaleResCleanupController(fakeClient, common.TestScheme)
			c.cleanUpExpiredMemberClusterAnnounces(ctx)

			memberClusterAnnounceList := &mcv1alpha1.MemberClusterAnnounceList{}
			if err := fakeClient.List(context.TODO(), memberClusterAnnounceList, &client.ListOptions{}); err != nil {
				t.Errorf("Should list MemberClusterAnnounce successfully but got err = %v", err)
			}

			assert.Equal(t, tt.exceptMemberClusterAnnounceNumber, len(memberClusterAnnounceList.Items))
		})
	}
}
