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
	"time"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	k8smcsv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
	"antrea.io/antrea/multicluster/controllers/multicluster/commonarea"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

func TestStaleController_CleanupService(t *testing.T) {
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
			Kind:      common.ServiceImportKind,
		},
	}
	tests := []struct {
		name               string
		existSvcList       *corev1.ServiceList
		existSvcImpList    *k8smcsv1alpha1.ServiceImportList
		existingResImpList *mcsv1alpha1.ResourceImportList
		wantErr            bool
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
			existingResImpList: &mcsv1alpha1.ResourceImportList{
				Items: []mcsv1alpha1.ResourceImport{
					svcResImport,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithLists(tt.existSvcList, tt.existSvcImpList).Build()
			fakeRemoteClient := fake.NewClientBuilder().WithScheme(scheme).WithLists(tt.existingResImpList).Build()
			commonArea := commonarea.NewFakeRemoteCommonArea(fakeRemoteClient, "leader-cluster", localClusterID, "default")
			mcReconciler := NewMemberClusterSetReconciler(fakeClient, scheme, "default")
			mcReconciler.SetRemoteCommonArea(commonArea)
			c := NewStaleResCleanupController(fakeClient, scheme, "default", mcReconciler, MemberCluster)
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
		existingResImpList    *mcsv1alpha1.ResourceImportList
		expectedACNPRemaining sets.String
	}{
		{
			name: "cleanup stale ACNP",
			existingACNPList: &v1alpha1.ClusterNetworkPolicyList{
				Items: []v1alpha1.ClusterNetworkPolicy{
					acnp1, acnp2, acnp3,
				},
			},
			existingResImpList: &mcsv1alpha1.ResourceImportList{
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
			fakeRemoteClient := fake.NewClientBuilder().WithScheme(scheme).WithLists(tt.existingResImpList).Build()
			commonArea := commonarea.NewFakeRemoteCommonArea(fakeRemoteClient, "leader-cluster", localClusterID, "default")

			mcReconciler := NewMemberClusterSetReconciler(fakeClient, scheme, "default")
			mcReconciler.SetRemoteCommonArea(commonArea)
			c := NewStaleResCleanupController(fakeClient, scheme, "default", mcReconciler, MemberCluster)
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
	svcExpNginx := k8smcsv1alpha1.ServiceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "keep-nginx",
		},
	}
	toDeleteSvcResExport := mcsv1alpha1.ResourceExport{
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
			Kind:      common.ServiceKind,
		},
	}
	toDeleteEPResExport := mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "cluster-a-default-nginx-endpoint",
			Labels: map[string]string{
				common.SourceClusterID: "cluster-a",
			},
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Name:      "nginx",
			Namespace: "default",
			Kind:      common.EndpointsKind,
		},
	}
	toDeleteCIResExport := mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "cluster-a-clusterinfo",
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Name:      "tobedeleted",
			Namespace: "default",
			ClusterID: "cluster-a",
			Kind:      common.ClusterInfoKind,
		},
	}
	toKeepSvcResExport := mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "cluster-a-default-keep-nginx-service",
			Labels: map[string]string{
				common.SourceClusterID: "cluster-a",
			},
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Name:      "keep-nginx",
			Namespace: "default",
			Kind:      common.ServiceKind,
		},
	}

	svcResExportFromOtherCluster := mcsv1alpha1.ResourceExport{
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
			Kind:      common.ServiceKind,
		},
	}
	existingNamespaces := &corev1.NamespaceList{
		Items: []corev1.Namespace{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-ns",
					Labels: map[string]string{
						"purpose": "test",
					},
				},
			},
		},
	}
	existingPods := &corev1.PodList{
		Items: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-ns",
					Name:      "test-pod",
					Labels: map[string]string{
						"app": "web",
					},
				},
			},
		},
	}
	labelNormalizedExist := "namespace:kubernetes.io/metadata.name=test-ns,purpose=test&pod:app=web"
	labelNormalizedNonExist := "namespace:kubernetes.io/metadata.name=test-ns,purpose=test&pod:app=db"
	toKeepLabelResExport := mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "cluster-a-" + common.HashLabelIdentity(labelNormalizedExist),
			Labels: map[string]string{
				common.SourceKind:      common.LabelIdentityKind,
				common.SourceClusterID: "cluster-a",
			},
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Kind: common.LabelIdentityKind,
			LabelIdentity: &mcsv1alpha1.LabelIdentityExport{
				NormalizedLabel: labelNormalizedExist,
			},
		},
	}
	toDeleteLabelResExport := mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "cluster-a-" + common.HashLabelIdentity(labelNormalizedNonExist),
			Labels: map[string]string{
				common.SourceKind:      common.LabelIdentityKind,
				common.SourceClusterID: "cluster-a",
			},
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			Kind: common.LabelIdentityKind,
			LabelIdentity: &mcsv1alpha1.LabelIdentityExport{
				NormalizedLabel: labelNormalizedNonExist,
			},
		},
	}
	tests := []struct {
		name                   string
		existSvcList           *corev1.ServiceList
		existPodList           *corev1.PodList
		existNamespaceList     *corev1.NamespaceList
		existLabelIdentityList *mcsv1alpha1.LabelIdentityList
		existSvcExpList        *k8smcsv1alpha1.ServiceExportList
		existResExpList        *mcsv1alpha1.ResourceExportList
		wantErr                bool
	}{
		{
			name:               "clean up ResourceExport successfully",
			existNamespaceList: existingNamespaces,
			existPodList:       existingPods,
			existSvcExpList: &k8smcsv1alpha1.ServiceExportList{
				Items: []k8smcsv1alpha1.ServiceExport{
					svcExpNginx,
				},
			},
			existResExpList: &mcsv1alpha1.ResourceExportList{
				Items: []mcsv1alpha1.ResourceExport{
					toDeleteSvcResExport,
					toDeleteEPResExport,
					toDeleteCIResExport,
					toKeepSvcResExport,
					toKeepLabelResExport,
					toDeleteLabelResExport,
					svcResExportFromOtherCluster,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithLists(tt.existSvcExpList, tt.existPodList, tt.existNamespaceList).Build()
			fakeRemoteClient := fake.NewClientBuilder().WithScheme(scheme).WithLists(tt.existResExpList).Build()
			commonArea := commonarea.NewFakeRemoteCommonArea(fakeRemoteClient, "leader-cluster", localClusterID, "default")

			mcReconciler := NewMemberClusterSetReconciler(fakeClient, scheme, "default")
			mcReconciler.SetRemoteCommonArea(commonArea)
			c := NewStaleResCleanupController(fakeClient, scheme, "default", mcReconciler, MemberCluster)
			if err := c.cleanup(); err != nil {
				t.Errorf("StaleController.cleanup() should clean up all stale ResourceExports but got err = %v", err)
			}
			resExpList := &mcsv1alpha1.ResourceExportList{}
			err := fakeRemoteClient.List(context.TODO(), resExpList, &client.ListOptions{})
			resExpLen := len(resExpList.Items)
			if err == nil {
				if resExpLen != 3 {
					t.Errorf("Should only THREE valid ResourceExports left but got %v", resExpLen)
				}
			} else {
				t.Errorf("Should list ResourceExport successfully but got err = %v", err)
			}
		})
	}
}

func TestStaleController_CleanupClusterInfoImport(t *testing.T) {
	ci := mcsv1alpha1.ClusterInfo{
		ClusterID:   "cluster-a",
		ServiceCIDR: "10.10.1.0/16",
	}
	ciResImportA := mcsv1alpha1.ResourceImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "antrea-mcs",
			Name:      "cluster-a-default-clusterinfo",
		},
		Spec: mcsv1alpha1.ResourceImportSpec{
			Kind:        common.ClusterInfoKind,
			Name:        "node-1",
			Namespace:   "default",
			ClusterInfo: &ci,
		},
	}
	ciImportA := mcsv1alpha1.ClusterInfoImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "cluster-a-default-clusterinfo",
		},
		Spec: ci,
	}
	ciImportB := mcsv1alpha1.ClusterInfoImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "cluster-b-default-clusterinfo",
		},
		Spec: ci,
	}
	tests := []struct {
		name               string
		existCIImpList     *mcsv1alpha1.ClusterInfoImportList
		existingResImpList *mcsv1alpha1.ResourceImportList
		wantErr            bool
	}{
		{
			name: "clean up ClusterInfoImport successfully",
			existCIImpList: &mcsv1alpha1.ClusterInfoImportList{
				Items: []mcsv1alpha1.ClusterInfoImport{
					ciImportA, ciImportB,
				},
			},
			existingResImpList: &mcsv1alpha1.ResourceImportList{
				Items: []mcsv1alpha1.ResourceImport{
					ciResImportA,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithLists(tt.existCIImpList).Build()
			fakeRemoteClient := fake.NewClientBuilder().WithScheme(scheme).WithLists(tt.existingResImpList).Build()
			commonarea := commonarea.NewFakeRemoteCommonArea(fakeRemoteClient, "leader-cluster", localClusterID, "antrea-mcs")

			mcReconciler := NewMemberClusterSetReconciler(fakeClient, scheme, "default")
			mcReconciler.SetRemoteCommonArea(commonarea)
			c := NewStaleResCleanupController(fakeClient, scheme, "default", mcReconciler, MemberCluster)
			if err := c.cleanup(); err != nil {
				t.Errorf("StaleController.cleanup() should clean up all stale ClusterInfoImport but got err = %v", err)
			}
			ctx := context.TODO()
			ciImpList := &mcsv1alpha1.ClusterInfoImportList{}
			err := fakeClient.List(ctx, ciImpList, &client.ListOptions{})
			ciImpLen := len(ciImpList.Items)
			if err == nil {
				if ciImpLen != 1 {
					t.Errorf("Should only one valid ClusterInfoImport left but got %v", ciImpLen)
				}
			} else {
				t.Errorf("Should list ClusterInfoImport successfully but got err = %v", err)
			}
		})
	}
}

func TestStaleController_CleanupMemberClusterAnnounce(t *testing.T) {
	tests := []struct {
		name                              string
		memberClusterAnnounceList         *mcsv1alpha1.MemberClusterAnnounceList
		clusterSet                        *mcsv1alpha1.ClusterSetList
		exceptMemberClusterAnnounceNumber int
	}{
		{
			name:                              "no MemberClusterAnnounce to clean up when there is no resource",
			clusterSet:                        &mcsv1alpha1.ClusterSetList{},
			memberClusterAnnounceList:         &mcsv1alpha1.MemberClusterAnnounceList{},
			exceptMemberClusterAnnounceNumber: 0,
		},
		{
			name:                              "no MemberClusterAnnounce to clean up when the resource has a valid update time",
			exceptMemberClusterAnnounceNumber: 1,
			clusterSet: &mcsv1alpha1.ClusterSetList{
				Items: []mcsv1alpha1.ClusterSet{
					{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "default",
							Name:      "clusterset",
						},
						Spec: mcsv1alpha1.ClusterSetSpec{
							Members: []mcsv1alpha1.MemberCluster{
								{
									ClusterID: "cluster-a",
								},
							},
						},
					},
				},
			},
			memberClusterAnnounceList: &mcsv1alpha1.MemberClusterAnnounceList{
				Items: []mcsv1alpha1.MemberClusterAnnounce{
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
			clusterSet: &mcsv1alpha1.ClusterSetList{
				Items: []mcsv1alpha1.ClusterSet{
					{
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "default",
							Name:      "clusterset",
						},
						Spec: mcsv1alpha1.ClusterSetSpec{
							Members: []mcsv1alpha1.MemberCluster{
								{
									ClusterID: "cluster-a",
								},
								{
									ClusterID: "cluster-outdated",
								},
							},
						},
					},
				},
			},
			memberClusterAnnounceList: &mcsv1alpha1.MemberClusterAnnounceList{
				Items: []mcsv1alpha1.MemberClusterAnnounce{
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
								commonarea.TimestampAnnotationKey: time.Now().Add(-1 * time.Hour).Format(time.RFC3339),
							},
						},
						ClusterID: "cluster-outdated",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithLists(tt.memberClusterAnnounceList).WithLists(tt.clusterSet).Build()

			mcReconciler := NewMemberClusterSetReconciler(fakeClient, scheme, "default")
			c := NewStaleResCleanupController(fakeClient, scheme, "default", mcReconciler, LeaderCluster)
			assert.Equal(t, nil, c.cleanup())

			memberClusterAnnounceList := &mcsv1alpha1.MemberClusterAnnounceList{}
			if err := fakeClient.List(context.TODO(), memberClusterAnnounceList, &client.ListOptions{}); err != nil {
				t.Errorf("Should list MemberClusterAnnounce successfully but got err = %v", err)
			}

			assert.Equal(t, tt.exceptMemberClusterAnnounceNumber, len(memberClusterAnnounceList.Items))
		})
	}
}

func TestStaleController_CleanupLabelIdentites(t *testing.T) {
	normalizedLabelA := "namespace:kubernetes.io/metadata.name=test&pod:app=client"
	normalizedLabelB := "namespace:kubernetes.io/metadata.name=test&pod:app=db"
	labelHashA := common.HashLabelIdentity(normalizedLabelA)
	labelHashB := common.HashLabelIdentity(normalizedLabelB)
	labelIdentityA := mcsv1alpha1.LabelIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name: labelHashA,
		},
		Spec: mcsv1alpha1.LabelIdentitySpec{
			Label: normalizedLabelA,
			ID:    1,
		},
	}
	resImpA := mcsv1alpha1.ResourceImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "antrea-mcs",
			Name:      labelHashA,
		},
		Spec: mcsv1alpha1.ResourceImportSpec{
			Kind: common.LabelIdentityKind,
			LabelIdentity: &mcsv1alpha1.LabelIdentitySpec{
				Label: normalizedLabelA,
				ID:    1,
			},
		},
	}
	labelIdentityB := mcsv1alpha1.LabelIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name: labelHashB,
		},
		Spec: mcsv1alpha1.LabelIdentitySpec{
			Label: normalizedLabelB,
			ID:    2,
		},
	}
	tests := []struct {
		name                   string
		existLabelIdentityList *mcsv1alpha1.LabelIdentityList
		existingResImpList     *mcsv1alpha1.ResourceImportList
		wantErr                bool
	}{
		{
			name: "clean up LabelIdentities successfully",
			existLabelIdentityList: &mcsv1alpha1.LabelIdentityList{
				Items: []mcsv1alpha1.LabelIdentity{
					labelIdentityA, labelIdentityB,
				},
			},
			existingResImpList: &mcsv1alpha1.ResourceImportList{
				Items: []mcsv1alpha1.ResourceImport{
					resImpA,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithLists(tt.existLabelIdentityList).Build()
			fakeRemoteClient := fake.NewClientBuilder().WithScheme(scheme).WithLists(tt.existingResImpList).Build()
			ca := commonarea.NewFakeRemoteCommonArea(fakeRemoteClient, "leader-cluster", localClusterID, "antrea-mcs")

			mcReconciler := NewMemberClusterSetReconciler(fakeClient, scheme, "default")
			mcReconciler.SetRemoteCommonArea(ca)
			c := NewStaleResCleanupController(fakeClient, scheme, "default", mcReconciler, MemberCluster)
			if err := c.cleanup(); err != nil {
				t.Errorf("StaleController.cleanup() should clean up all stale LabelIdentities but got err = %v", err)
			}
			ctx := context.TODO()
			labelList := &mcsv1alpha1.LabelIdentityList{}
			err := fakeClient.List(ctx, labelList, &client.ListOptions{})
			labelListLen := len(labelList.Items)
			if err == nil {
				if labelListLen != 1 {
					t.Errorf("Should only one valid LabelIdentity left but got %v", labelListLen)
				}
			} else {
				t.Errorf("Should list LabelIdentity successfully but got err = %v", err)
			}
		})
	}
}
