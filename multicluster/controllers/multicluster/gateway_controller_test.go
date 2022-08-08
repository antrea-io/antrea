/*
Copyright 2022 Antrea Authors.

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
	"fmt"
	"reflect"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
	"antrea.io/antrea/multicluster/controllers/multicluster/commonarea"
)

var (
	serviceCIDR = "10.96.0.0/12"
	clusterID   = "cluster-a"

	gw1CreationTime = metav1.NewTime(time.Now())
	gw2CreationTime = metav1.NewTime(time.Now().Add(10 * time.Minute))

	gwNode1 = mcsv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "node-1",
			Namespace:         "default",
			CreationTimestamp: gw1CreationTime,
		},
		GatewayIP:  "10.10.10.10",
		InternalIP: "172.11.10.1",
	}
	gwNode2 = mcsv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "node-2",
			Namespace:         "default",
			CreationTimestamp: gw2CreationTime,
		},
		GatewayIP:  "10.8.8.8",
		InternalIP: "172.11.10.1",
	}
	existingResExport = &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cluster-a-clusterinfo",
			Namespace: leaderNamespace,
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Name:      clusterID,
			Namespace: "default",
			Kind:      common.ClusterInfoKind,
			ClusterInfo: &mcsv1alpha1.ClusterInfo{
				ServiceCIDR: serviceCIDR,
				ClusterID:   clusterID,
				GatewayInfos: []mcsv1alpha1.GatewayInfo{
					{
						GatewayIP: "10.10.10.10",
					},
				},
			},
		},
	}
	existingResExport2 = &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cluster-a-clusterinfo",
			Namespace: leaderNamespace,
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Name:      clusterID,
			Namespace: "default",
			Kind:      common.ClusterInfoKind,
			ClusterInfo: &mcsv1alpha1.ClusterInfo{
				ServiceCIDR: serviceCIDR,
				ClusterID:   clusterID,
				GatewayInfos: []mcsv1alpha1.GatewayInfo{
					{
						GatewayIP: "101.101.101.101",
					},
				},
			},
		},
	}
)

func TestGatewayReconciler(t *testing.T) {
	gwNode1New := gwNode1
	gwNode1New.GatewayIP = "10.10.10.12"

	tests := []struct {
		name           string
		te             mcsv1alpha1.Gateway
		namespacedName types.NamespacedName
		gateway        []mcsv1alpha1.Gateway
		resExport      *mcsv1alpha1.ResourceExport
		expectedInfo   []mcsv1alpha1.GatewayInfo
		isDelete       bool
	}{
		{
			name: "create a ResourceExport successfully",
			namespacedName: types.NamespacedName{
				Namespace: "default",
				Name:      "node-1",
			},
			gateway: []mcsv1alpha1.Gateway{
				gwNode1,
			},
			resExport: existingResExport,
			expectedInfo: []mcsv1alpha1.GatewayInfo{
				{
					GatewayIP: "10.10.10.10",
				},
			},
		},
		{
			name: "update a ResourceExport successfully by creating a new Gateway",
			namespacedName: types.NamespacedName{
				Namespace: "default",
				Name:      "node-2",
			},
			gateway: []mcsv1alpha1.Gateway{
				gwNode1, gwNode2,
			},
			resExport: existingResExport,
			expectedInfo: []mcsv1alpha1.GatewayInfo{
				{
					GatewayIP: "10.8.8.8",
				},
			},
		},
		{
			name: "update a ResourceExport successfully by deleting a Gateway",
			namespacedName: types.NamespacedName{
				Namespace: "default",
				Name:      "node-2",
			},
			gateway: []mcsv1alpha1.Gateway{
				gwNode1,
			},
			resExport: existingResExport2,
			expectedInfo: []mcsv1alpha1.GatewayInfo{
				{
					GatewayIP: "10.10.10.10",
				},
			},
		},
		{
			name: "update a ResourceExport successfully by updating an existing Gateway",
			namespacedName: types.NamespacedName{
				Namespace: "default",
				Name:      "node-1",
			},
			gateway: []mcsv1alpha1.Gateway{
				gwNode1New,
			},
			resExport: existingResExport,
			expectedInfo: []mcsv1alpha1.GatewayInfo{
				{
					GatewayIP: "10.10.10.12",
				},
			},
		},
		{
			name: "delete a ResourceExport successfully by deleting an existing Gateway",
			namespacedName: types.NamespacedName{
				Namespace: "default",
				Name:      "node-1",
			},
			resExport: existingResExport,
			isDelete:  true,
		},
	}

	for _, tt := range tests {
		var obj []client.Object
		for _, n := range tt.gateway {
			node := n
			obj = append(obj, &node)
		}
		fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(obj...).Build()
		fakeRemoteClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects().Build()
		if tt.resExport != nil {
			fakeRemoteClient = fake.NewClientBuilder().WithScheme(scheme).WithObjects(tt.resExport).Build()
		}
		commonArea := commonarea.NewFakeRemoteCommonArea(fakeRemoteClient, "leader-cluster", localClusterID, leaderNamespace)
		mcReconciler := NewMemberClusterSetReconciler(fakeClient, scheme, "default")
		mcReconciler.SetRemoteCommonArea(commonArea)
		commonAreaGatter := mcReconciler
		r := NewGatewayReconciler(fakeClient, scheme, "default", "10.96.0.0/12", commonAreaGatter)
		t.Run(tt.name, func(t *testing.T) {
			req := ctrl.Request{NamespacedName: tt.namespacedName}
			if _, err := r.Reconcile(ctx, req); err != nil {
				t.Errorf("Gateway Reconciler should handle ResourceExports events successfully but got error = %v", err)
			} else {
				gws := &mcsv1alpha1.GatewayList{}
				_ = fakeClient.List(ctx, gws, &client.ListOptions{})
				fmt.Printf("output list: %v", gws)
				ciExport := mcsv1alpha1.ResourceExport{}
				ciExportName := types.NamespacedName{
					Namespace: leaderNamespace,
					Name:      newClusterInfoResourceExportName(localClusterID),
				}
				err := fakeRemoteClient.Get(ctx, ciExportName, &ciExport)
				if err == nil {
					if !reflect.DeepEqual(ciExport.Spec.ClusterInfo.GatewayInfos, tt.expectedInfo) {
						t.Errorf("Expected GatewayInfos are %v but got %v", tt.expectedInfo, ciExport.Spec.ClusterInfo.GatewayInfos)
					}
				} else {
					if tt.isDelete {
						if !apierrors.IsNotFound(err) {
							t.Errorf("Gateway Reconciler expects not found error but got error = %v", err)
						}
					} else {
						t.Errorf("Expected a ClusterInfo kind of ResourceExport but got error = %v", err)
					}
				}
			}
		})
	}
}
