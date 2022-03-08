/*
Copyright 2021 Antrea Authors.

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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	k8smcsv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
	"antrea.io/antrea/multicluster/controllers/multicluster/commonarea"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

func TestStaleController_CleanupService(t *testing.T) {
	localClusterID = "cluster-a"
	remoteMgr := commonarea.NewRemoteCommonAreaManager("test-clusterset", common.ClusterID(localClusterID))
	go remoteMgr.Start()

	mcSvcNginx := svcNginx.DeepCopy()
	mcSvcNginx.Name = "antrea-mc-nginx"
	mcSvcNginx.Annotations = map[string]string{common.AntreaMCServiceAnnotation: "true"}
	mcSvcNonNginx := svcNginx.DeepCopy()
	mcSvcNginx.Name = "antrea-mc-non-nginx"
	mcSvcNonNginx.Annotations = map[string]string{common.AntreaMCServiceAnnotation: "true"}
	mcSvcImpNginx := k8smcsv1alpha1.ServiceImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "nginx",
		},
	}
	mcSvcImpNonNginx := k8smcsv1alpha1.ServiceImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "non-nginx",
		},
	}
	svcResImport := mcsv1alpha1.ResourceImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "default-non-nginx-service",
		},
		Spec: mcsv1alpha1.ResourceImportSpec{
			Name:      "non-nginx",
			Namespace: "default",
			Kind:      common.ServiceKind,
		},
	}
	tests := []struct {
		name            string
		existSvcList    *corev1.ServiceList
		existSvcImpList *k8smcsv1alpha1.ServiceImportList
		existResImpList *mcsv1alpha1.ResourceImportList
		wantErr         bool
	}{
		{
			name: "clean up MC Serivce and ServiceImport successfully",
			existSvcList: &corev1.ServiceList{
				Items: []corev1.Service{*mcSvcNginx, *mcSvcNonNginx},
			},
			existSvcImpList: &k8smcsv1alpha1.ServiceImportList{
				Items: []k8smcsv1alpha1.ServiceImport{
					mcSvcImpNginx, mcSvcImpNonNginx,
				},
			},
			existResImpList: &mcsv1alpha1.ResourceImportList{
				Items: []mcsv1alpha1.ResourceImport{
					svcResImport,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithLists(tt.existSvcList, tt.existSvcImpList).Build()
			fakeRemoteClient := fake.NewClientBuilder().WithScheme(scheme).WithLists(tt.existResImpList).Build()
			_ = commonarea.NewFakeRemoteCommonArea(scheme, &remoteMgr, fakeRemoteClient, "leader-cluster", "default")

			c := NewStaleController(fakeClient, scheme, &remoteMgr)
			if err := c.cleanup(); err != nil {
				t.Errorf("StaleController.cleanup() should clean up all stale Service and ServiceImport but got err = %v", err)
			}
			ctx := context.TODO()
			svcList := &corev1.ServiceList{}
			err := fakeClient.List(ctx, svcList, &client.ListOptions{})
			svcLen := len(svcList.Items)
			if err == nil {
				if svcLen != 1 {
					t.Errorf("Should only one valid Service left but got %v", svcLen)
				}
			} else {
				t.Errorf("Should list Service successfully but got err = %v", err)
			}
			svImpList := &k8smcsv1alpha1.ServiceImportList{}
			err = fakeClient.List(ctx, svImpList, &client.ListOptions{})
			svcImpLen := len(svImpList.Items)
			if err == nil {
				if svcImpLen != 1 {
					t.Errorf("Should only one valid ServiceImport left but got %v", svcImpLen)
				}
			} else {
				t.Errorf("Should list ServiceImport successfully but got err = %v", err)
			}
		})
	}
}

func TestStaleController_CleanupACNP(t *testing.T) {
	localClusterID = "cluster-a"
	remoteMgr := commonarea.NewRemoteCommonAreaManager("test-clusterset", common.ClusterID(localClusterID))
	go remoteMgr.Start()

	acnpImportName := "acnp-for-isolation"
	acnpResImportName := leaderNamespace + "-" + acnpImportName
	acnpResImport := mcsv1alpha1.ResourceImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      acnpResImportName,
		},
		Spec: mcsv1alpha1.ResourceImportSpec{
			Name: acnpImportName,
			Kind: common.AntreaClusterNetworkPolicyKind,
			ClusterNetworkPolicy: &v1alpha1.ClusterNetworkPolicySpec{
				Tier:     "securityops",
				Priority: 1.0,
				AppliedTo: []v1alpha1.NetworkPolicyPeer{
					{NamespaceSelector: &metav1.LabelSelector{}},
				},
			},
		},
	}
	acnp1 := v1alpha1.ClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:        common.AntreaMCSPrefix + acnpImportName,
			Annotations: map[string]string{common.AntreaMCACNPAnnotation: "true"},
		},
	}
	acnp2 := v1alpha1.ClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:        common.AntreaMCSPrefix + "some-deleted-resimp",
			Annotations: map[string]string{common.AntreaMCACNPAnnotation: "true"},
		},
	}
	acnp3 := v1alpha1.ClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "non-mcs-acnp",
		},
	}
	tests := []struct {
		name                  string
		existingACNPList      *v1alpha1.ClusterNetworkPolicyList
		existResImpList       *mcsv1alpha1.ResourceImportList
		expectedACNPRemaining sets.String
	}{
		{
			name: "cleanup stale ACNP",
			existingACNPList: &v1alpha1.ClusterNetworkPolicyList{
				Items: []v1alpha1.ClusterNetworkPolicy{
					acnp1, acnp2, acnp3,
				},
			},
			existResImpList: &mcsv1alpha1.ResourceImportList{
				Items: []mcsv1alpha1.ResourceImport{
					acnpResImport,
				},
			},
			expectedACNPRemaining: sets.NewString(common.AntreaMCSPrefix+acnpImportName, "non-mcs-acnp"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithLists(tt.existingACNPList).Build()
			fakeRemoteClient := fake.NewClientBuilder().WithScheme(scheme).WithLists(tt.existResImpList).Build()
			_ = commonarea.NewFakeRemoteCommonArea(scheme, &remoteMgr, fakeRemoteClient, "leader-cluster", "default")

			c := NewStaleController(fakeClient, scheme, &remoteMgr)
			if err := c.cleanup(); err != nil {
				t.Errorf("StaleController.cleanup() should clean up all stale ACNPs but got err = %v", err)
			}
			ctx := context.TODO()
			acnpList := &v1alpha1.ClusterNetworkPolicyList{}
			if err := fakeClient.List(ctx, acnpList, &client.ListOptions{}); err != nil {
				t.Errorf("Error when listing the ACNPs after cleanup")
			}
			acnpRemaining := sets.NewString()
			for _, acnp := range acnpList.Items {
				acnpRemaining.Insert(acnp.Name)
			}
			if !acnpRemaining.Equal(tt.expectedACNPRemaining) {
				t.Errorf("Unexpected stale ACNP cleanup result. Expected: %v, Actual: %v", tt.expectedACNPRemaining, acnpRemaining)
			}
		})
	}
}

func TestStaleController_CleanupResourceExport(t *testing.T) {
	localClusterID = "cluster-a"
	remoteMgr := commonarea.NewRemoteCommonAreaManager("test-clusterset", common.ClusterID(localClusterID))
	go remoteMgr.Start()

	svcExpNginx := k8smcsv1alpha1.ServiceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "nginx",
		},
	}
	toDeleteSvcResExport := mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "cluster-a-default-tobedeleted-service",
			Labels: map[string]string{
				common.SourceClusterID: "cluster-a",
			},
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Name:      "tobedeleted",
			Namespace: "default",
		},
	}
	toKeepSvcResExport := mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "cluster-a-default-nginx-service",
			Labels: map[string]string{
				common.SourceClusterID: "cluster-a",
			},
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Name:      "nginx",
			Namespace: "default",
		},
	}
	svcResExportFromOther := mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "cluster-b-default-nginx-service",
			Labels: map[string]string{
				common.SourceClusterID: "cluster-b",
			},
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Name:      "nginx",
			Namespace: "default",
		},
	}
	tests := []struct {
		name            string
		existSvcList    *corev1.ServiceList
		existSvcExpList *k8smcsv1alpha1.ServiceExportList
		existResExpList *mcsv1alpha1.ResourceExportList
		wantErr         bool
	}{
		{
			name: "clean up ResourceExport successfully",
			existSvcExpList: &k8smcsv1alpha1.ServiceExportList{
				Items: []k8smcsv1alpha1.ServiceExport{
					svcExpNginx,
				},
			},
			existResExpList: &mcsv1alpha1.ResourceExportList{
				Items: []mcsv1alpha1.ResourceExport{
					toDeleteSvcResExport,
					toKeepSvcResExport,
					svcResExportFromOther,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithLists(tt.existSvcExpList).Build()
			fakeRemoteClient := fake.NewClientBuilder().WithScheme(scheme).WithLists(tt.existResExpList).Build()
			_ = commonarea.NewFakeRemoteCommonArea(scheme, &remoteMgr, fakeRemoteClient, "leader-cluster", "default")

			c := NewStaleController(fakeClient, scheme, &remoteMgr)
			if err := c.cleanup(); err != nil {
				t.Errorf("StaleController.cleanup() should clean up all stale ResourceExports but got err = %v", err)
			}
			ctx := context.TODO()
			svcResExpList := &mcsv1alpha1.ResourceExportList{}
			err := fakeRemoteClient.List(ctx, svcResExpList, &client.ListOptions{})
			resExpLen := len(svcResExpList.Items)
			if err == nil {
				if resExpLen != 2 {
					for _, re := range svcResExpList.Items {
						klog.Infof("left resourceexport %v", re)
					}
					t.Errorf("Should only two valid ResourceExports left but got %v", resExpLen)
				}
			} else {
				t.Errorf("Should list ResourceExport successfully but got err = %v", err)
			}
		})
	}
}
