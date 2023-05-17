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

package member

import (
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"antrea.io/antrea/multicluster/apis/multicluster/constants"
	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
	"antrea.io/antrea/multicluster/controllers/multicluster/commonarea"
)

var (
	serviceCIDR = "10.96.0.0/12"
	clusterID   = "cluster-a"

	gw1CreationTime = metav1.NewTime(time.Now())

	gwNode1 = mcsv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "node-1",
			Namespace:         "default",
			CreationTimestamp: gw1CreationTime,
		},
		GatewayIP:  "10.10.10.10",
		InternalIP: "172.11.10.1",
	}

	existingResExport = &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cluster-a-clusterinfo",
			Namespace: common.LeaderNamespace,
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Name:      clusterID,
			Namespace: "default",
			Kind:      constants.ClusterInfoKind,
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
)

func TestGatewayReconciler(t *testing.T) {
	gwNode1New := gwNode1
	gwNode1New.GatewayIP = "10.10.10.12"
	staleExistingResExport := existingResExport.DeepCopy()
	staleExistingResExport.DeletionTimestamp = &metav1.Time{Time: time.Now()}
	tests := []struct {
		name           string
		namespacedName types.NamespacedName
		gateway        []mcsv1alpha1.Gateway
		resExport      *mcsv1alpha1.ResourceExport
		expectedInfo   []mcsv1alpha1.GatewayInfo
		expectedErr    string
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
			expectedInfo: []mcsv1alpha1.GatewayInfo{
				{
					GatewayIP: "10.10.10.10",
				},
			},
		},
		{
			name: "error creating a ResourceExport when existing ResourceExport is being deleted",
			namespacedName: types.NamespacedName{
				Namespace: "default",
				Name:      "node-1",
			},
			gateway: []mcsv1alpha1.Gateway{
				gwNode1,
			},
			resExport:   staleExistingResExport,
			expectedErr: "resourceexports.multicluster.crd.antrea.io \"cluster-a-clusterinfo\" already exists",
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
		fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(obj...).Build()
		fakeRemoteClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects().Build()
		if tt.resExport != nil {
			fakeRemoteClient = fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(tt.resExport).Build()
		}
		commonArea := commonarea.NewFakeRemoteCommonArea(fakeRemoteClient, "leader-cluster", common.LocalClusterID, common.LeaderNamespace, nil)
		mcReconciler := NewMemberClusterSetReconciler(fakeClient, common.TestScheme, "default", false)
		mcReconciler.SetRemoteCommonArea(commonArea)
		commonAreaGatter := mcReconciler
		r := NewGatewayReconciler(fakeClient, common.TestScheme, "default", []string{"10.200.1.1/16"}, commonAreaGatter)
		t.Run(tt.name, func(t *testing.T) {
			req := ctrl.Request{NamespacedName: tt.namespacedName}
			if _, err := r.Reconcile(common.TestCtx, req); err != nil {
				if tt.expectedErr != "" {
					assert.Equal(t, tt.expectedErr, err.Error())
				} else {
					t.Errorf("Gateway Reconciler should handle ResourceExports events successfully but got error = %v", err)
				}
			} else {
				ciExport := mcsv1alpha1.ResourceExport{}
				ciExportName := types.NamespacedName{
					Namespace: common.LeaderNamespace,
					Name:      common.NewClusterInfoResourceExportName(common.LocalClusterID),
				}
				err := fakeRemoteClient.Get(common.TestCtx, ciExportName, &ciExport)
				if tt.isDelete && !apierrors.IsNotFound(err) {
					t.Errorf("Gateway Reconciler expects not found error but got error = %v", err)
				}
				if err == nil && !reflect.DeepEqual(ciExport.Spec.ClusterInfo.GatewayInfos, tt.expectedInfo) {
					t.Errorf("Expected GatewayInfos are %v but got %v", tt.expectedInfo, ciExport.Spec.ClusterInfo.GatewayInfos)
				}
				if !tt.isDelete && apierrors.IsNotFound(err) {
					t.Errorf("Expected a ClusterInfo kind of ResourceExport but got error = %v", err)
				}
			}
		})
	}
}

func TestGetClusterInfo(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects().Build()
	r := NewGatewayReconciler(fakeClient, common.TestScheme, "default", []string{"10.200.1.1/16"}, nil)
	gw := &mcsv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name: "gw",
		},
		ServiceCIDR: "10.100.0.0/16",
		GatewayIP:   "10.10.1.1",
		InternalIP:  "10.10.1.1",
		WireGuard: &mcsv1alpha1.WireGuardInfo{
			PublicKey: "key",
		},
	}
	expectedClusterInfo := &mcsv1alpha1.ClusterInfo{
		GatewayInfos: []mcsv1alpha1.GatewayInfo{
			{
				GatewayIP: "10.10.1.1",
			},
		},
		ServiceCIDR: "10.100.0.0/16",
		PodCIDRs:    []string{"10.200.1.1/16"},
		WireGuard: &mcsv1alpha1.WireGuardInfo{
			PublicKey: "key",
		},
	}

	assert.Equal(t, expectedClusterInfo, r.getClusterInfo(gw))
}
