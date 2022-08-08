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

package commonarea

import (
	"reflect"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
)

func TestResourceImportReconciler_handleClusterInfo(t *testing.T) {
	clusterAInfo := mcsv1alpha1.ClusterInfo{
		ClusterID:   "cluster-a",
		ServiceCIDR: "10.10.1.0/16",
		GatewayInfos: []mcsv1alpha1.GatewayInfo{
			{
				GatewayIP: "172.168.10.11",
			},
		},
	}
	clusterBInfo := mcsv1alpha1.ClusterInfo{
		ClusterID:   "cluster-b",
		ServiceCIDR: "10.10.1.0/16",
		GatewayInfos: []mcsv1alpha1.GatewayInfo{
			{
				GatewayIP: "17.16.10.10",
			},
		},
	}
	clusterBInfoNew := clusterBInfo
	clusterBInfoNew.GatewayInfos = []mcsv1alpha1.GatewayInfo{
		{
			GatewayIP: "17.16.10.10",
		},
		{
			GatewayIP: "17.16.11.11",
		},
	}
	ciResImportA := &mcsv1alpha1.ResourceImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "cluster-a-default-clusterinfo",
		},
		Spec: mcsv1alpha1.ResourceImportSpec{
			Kind:        common.ClusterInfoKind,
			Name:        "node-1",
			Namespace:   "default",
			ClusterInfo: &clusterAInfo,
		},
	}
	ciResImportB := &mcsv1alpha1.ResourceImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "cluster-b-default-clusterinfo",
		},
		Spec: mcsv1alpha1.ResourceImportSpec{
			Kind:        common.ClusterInfoKind,
			Name:        "node-2",
			Namespace:   "default",
			ClusterInfo: &clusterBInfoNew,
		},
	}
	ciResImportC := &mcsv1alpha1.ResourceImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "cluster-c-default-clusterinfo",
		},
		Spec: mcsv1alpha1.ResourceImportSpec{
			Kind:      common.ClusterInfoKind,
			Name:      "node-3",
			Namespace: "default",
		},
	}
	ciImportA := mcsv1alpha1.ClusterInfoImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "cluster-a-default-clusterinfo",
		},
		Spec: clusterAInfo,
	}
	ciImportB := mcsv1alpha1.ClusterInfoImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "cluster-b-default-clusterinfo",
		},
		Spec: clusterBInfo,
	}
	ciImportC := mcsv1alpha1.ClusterInfoImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "cluster-c-default-clusterinfo",
		},
		Spec: mcsv1alpha1.ClusterInfo{
			ClusterID:   "cluster-c",
			ServiceCIDR: "10.10.1.0/16",
			GatewayInfos: []mcsv1alpha1.GatewayInfo{
				{
					GatewayIP: "172.168.10.11",
				},
			},
		},
	}

	tests := []struct {
		name                string
		existingCIResImport *mcsv1alpha1.ResourceImport
		existingCIImport    *mcsv1alpha1.ClusterInfoImport
		expectedCIImport    *mcsv1alpha1.ClusterInfoImport
		isDelete            bool
	}{
		{
			name:                "create ClusterInfoImport successfully",
			existingCIResImport: ciResImportA,
			expectedCIImport:    &ciImportA,
		},
		{
			name:                "update ClusterInfoImport successfully",
			existingCIResImport: ciResImportB,
			existingCIImport:    &ciImportB,
			expectedCIImport: &mcsv1alpha1.ClusterInfoImport{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "cluster-b-default-clusterinfo",
				},
				Spec: clusterBInfoNew,
			},
		},
		{
			name:                "delete ClusterInfoImport successfully",
			existingCIResImport: ciResImportC,
			existingCIImport:    &ciImportC,
			isDelete:            true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects().Build()
			if tt.existingCIImport != nil {
				fakeClient = fake.NewClientBuilder().WithScheme(scheme).WithObjects(tt.existingCIImport).Build()
			}
			fakeRemoteClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tt.existingCIResImport).Build()
			if tt.isDelete {
				fakeRemoteClient = fake.NewClientBuilder().WithScheme(scheme).WithObjects().Build()
			}
			remoteCluster := NewFakeRemoteCommonArea(fakeRemoteClient, "leader-cluster", "cluster-d", "default")
			r := NewResourceImportReconciler(fakeClient, scheme, fakeClient, "cluster-d", "default", remoteCluster)
			if tt.isDelete {
				r.installedResImports.Add(*ciResImportC)
			}
			ciResImportName := types.NamespacedName{
				Namespace: tt.existingCIResImport.Namespace,
				Name:      tt.existingCIResImport.Name,
			}
			req := ctrl.Request{NamespacedName: ciResImportName}

			if _, err := r.Reconcile(ctx, req); err != nil {
				t.Errorf("ClusterInfo Importer should handle ResourceImport events successfully but got error = %v", err)
			} else {
				gotCIImp := &mcsv1alpha1.ClusterInfoImport{}
				err := fakeClient.Get(ctx, ciResImportName, gotCIImp)
				isNotFound := apierrors.IsNotFound(err)
				if err != nil {
					if tt.expectedCIImport == nil && !isNotFound {
						t.Errorf("Expected to get not found error but got error = %v", err)
					}
					if tt.expectedCIImport != nil && isNotFound {
						t.Errorf("Expected to get ClusterInfoImport %v but got not found error = %v", tt.expectedCIImport, err)
					}
				} else if tt.expectedCIImport != nil {
					if !reflect.DeepEqual(tt.expectedCIImport.Spec, gotCIImp.Spec) {
						t.Errorf("Expected ClusterInfoImport %v but got %v", tt.expectedCIImport.Spec, gotCIImp.Spec)
					}
				}
			}
		})
	}

}
