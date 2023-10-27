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

package member

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	k8smcv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	"antrea.io/antrea/multicluster/apis/multicluster/constants"
	mcv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	mcv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
	"antrea.io/antrea/multicluster/controllers/multicluster/commonarea"
	"antrea.io/antrea/pkg/apis/crd/v1beta1"
)

var clusterSet = &mcv1alpha2.ClusterSet{
	ObjectMeta: metav1.ObjectMeta{
		Namespace: "default",
		Name:      "test-cluster",
	},
}

func TestStaleController_CleanUpService(t *testing.T) {
	mcSvcNginx := common.SvcNginx.DeepCopy()
	mcSvcNginx.Name = "antrea-mc-nginx"
	mcSvcNginx.Annotations = map[string]string{common.AntreaMCServiceAnnotation: "true"}
	mcSvcNonNginx := common.SvcNginx.DeepCopy()
	mcSvcNginx.Name = "antrea-mc-non-nginx"
	mcSvcNonNginx.Annotations = map[string]string{common.AntreaMCServiceAnnotation: "true"}
	mcSvcImpNginx := k8smcv1alpha1.ServiceImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "nginx",
		},
	}
	mcSvcImpNonNginx := k8smcv1alpha1.ServiceImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "non-nginx",
		},
	}
	svcResImport := mcv1alpha1.ResourceImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "default-non-nginx-service",
		},
		Spec: mcv1alpha1.ResourceImportSpec{
			Name:      "non-nginx",
			Namespace: "default",
			Kind:      constants.ServiceImportKind,
		},
	}
	tests := []struct {
		name               string
		existSvcList       *corev1.ServiceList
		existSvcImpList    *k8smcv1alpha1.ServiceImportList
		existingResImpList *mcv1alpha1.ResourceImportList
		wantErr            bool
	}{
		{
			name: "clean up MC Serivce and ServiceImport successfully",
			existSvcList: &corev1.ServiceList{
				Items: []corev1.Service{*mcSvcNginx, *mcSvcNonNginx},
			},
			existSvcImpList: &k8smcv1alpha1.ServiceImportList{
				Items: []k8smcv1alpha1.ServiceImport{
					mcSvcImpNginx, mcSvcImpNonNginx,
				},
			},
			existingResImpList: &mcv1alpha1.ResourceImportList{
				Items: []mcv1alpha1.ResourceImport{
					svcResImport,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(clusterSet).
				WithLists(tt.existSvcList, tt.existSvcImpList).Build()
			fakeRemoteClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithLists(tt.existingResImpList).Build()
			commonArea := commonarea.NewFakeRemoteCommonArea(fakeRemoteClient, "leader-cluster", common.LocalClusterID, "default", nil)
			mcReconciler := NewMemberClusterSetReconciler(fakeClient, common.TestScheme, "default", false, false, make(chan struct{}))
			mcReconciler.SetRemoteCommonArea(commonArea)
			c := NewStaleResCleanupController(fakeClient, common.TestScheme, make(chan struct{}), "default", mcReconciler)
			if err := c.cleanUpStaleResources(ctx); err != nil {
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
			svImpList := &k8smcv1alpha1.ServiceImportList{}
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

func TestStaleController_CleanUpACNP(t *testing.T) {
	acnpImportName := "acnp-for-isolation"
	acnpResImportName := common.LeaderNamespace + "-" + acnpImportName
	acnpResImport := mcv1alpha1.ResourceImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      acnpResImportName,
		},
		Spec: mcv1alpha1.ResourceImportSpec{
			Name: acnpImportName,
			Kind: constants.AntreaClusterNetworkPolicyKind,
			ClusterNetworkPolicy: &v1beta1.ClusterNetworkPolicySpec{
				Tier:     "securityops",
				Priority: 1.0,
				AppliedTo: []v1beta1.AppliedTo{
					{NamespaceSelector: &metav1.LabelSelector{}},
				},
			},
		},
	}
	acnp1 := v1beta1.ClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:        common.AntreaMCSPrefix + acnpImportName,
			Annotations: map[string]string{common.AntreaMCACNPAnnotation: "true"},
		},
	}
	acnp2 := v1beta1.ClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:        common.AntreaMCSPrefix + "some-deleted-resimp",
			Annotations: map[string]string{common.AntreaMCACNPAnnotation: "true"},
		},
	}
	acnp3 := v1beta1.ClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "non-mcs-acnp",
		},
	}
	tests := []struct {
		name                  string
		existingACNPList      *v1beta1.ClusterNetworkPolicyList
		existingResImpList    *mcv1alpha1.ResourceImportList
		expectedACNPRemaining sets.Set[string]
	}{
		{
			name: "cleanup stale ACNP",
			existingACNPList: &v1beta1.ClusterNetworkPolicyList{
				Items: []v1beta1.ClusterNetworkPolicy{
					acnp1, acnp2, acnp3,
				},
			},
			existingResImpList: &mcv1alpha1.ResourceImportList{
				Items: []mcv1alpha1.ResourceImport{
					acnpResImport,
				},
			},
			expectedACNPRemaining: sets.New[string](common.AntreaMCSPrefix+acnpImportName, "non-mcs-acnp"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(clusterSet).WithLists(tt.existingACNPList).Build()
			fakeRemoteClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithLists(tt.existingResImpList).Build()
			commonArea := commonarea.NewFakeRemoteCommonArea(fakeRemoteClient, "leader-cluster", common.LocalClusterID, "default", nil)

			mcReconciler := NewMemberClusterSetReconciler(fakeClient, common.TestScheme, "default", false, false, make(chan struct{}))
			mcReconciler.SetRemoteCommonArea(commonArea)
			c := NewStaleResCleanupController(fakeClient, common.TestScheme, make(chan struct{}), "default", mcReconciler)
			if err := c.cleanUpStaleResources(ctx); err != nil {
				t.Errorf("StaleController.cleanup() should clean up all stale ACNPs but got err = %v", err)
			}
			ctx := context.TODO()
			acnpList := &v1beta1.ClusterNetworkPolicyList{}
			if err := fakeClient.List(ctx, acnpList, &client.ListOptions{}); err != nil {
				t.Errorf("Error when listing the ACNPs after cleanup")
			}
			acnpRemaining := sets.New[string]()
			for _, acnp := range acnpList.Items {
				acnpRemaining.Insert(acnp.Name)
			}
			if !acnpRemaining.Equal(tt.expectedACNPRemaining) {
				t.Errorf("Unexpected stale ACNP cleanup result. Expected: %v, Actual: %v", tt.expectedACNPRemaining, acnpRemaining)
			}
		})
	}
}

func TestStaleController_CleanUpResourceExports(t *testing.T) {
	svcExpNginx := k8smcv1alpha1.ServiceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "keep-nginx",
		},
	}
	toDeleteSvcResExport := mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "cluster-a-default-nginx-service",
			Labels: map[string]string{
				constants.SourceClusterID: "cluster-a",
			},
		},
		Spec: mcv1alpha1.ResourceExportSpec{
			Name:      "nginx",
			Namespace: "default",
			Kind:      constants.ServiceKind,
		},
	}
	toDeleteEPResExport := mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "cluster-a-default-nginx-endpoint",
			Labels: map[string]string{
				constants.SourceClusterID: "cluster-a",
			},
		},
		Spec: mcv1alpha1.ResourceExportSpec{
			Name:      "nginx",
			Namespace: "default",
			Kind:      constants.EndpointsKind,
		},
	}
	toDeleteCIResExport := mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "cluster-a-clusterinfo",
		},
		Spec: mcv1alpha1.ResourceExportSpec{
			Name:      "tobedeleted",
			Namespace: "default",
			ClusterID: "cluster-a",
			Kind:      constants.ClusterInfoKind,
		},
	}
	toKeepSvcResExport := mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "cluster-a-default-keep-nginx-service",
			Labels: map[string]string{
				constants.SourceClusterID: "cluster-a",
			},
		},
		Spec: mcv1alpha1.ResourceExportSpec{
			Name:      "keep-nginx",
			Namespace: "default",
			Kind:      constants.ServiceKind,
		},
	}

	svcResExportFromOtherCluster := mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "cluster-b-default-nginx-service",
			Labels: map[string]string{
				constants.SourceClusterID: "cluster-b",
			},
		},
		Spec: mcv1alpha1.ResourceExportSpec{
			Name:      "nginx",
			Namespace: "default",
			Kind:      constants.ServiceKind,
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
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-ns",
					Name:      "test-pod-empty-labels",
				},
			},
		},
	}
	labelNormalizedExist := "ns:kubernetes.io/metadata.name=test-ns,purpose=test&pod:app=web"
	labelNormalizedNonExist := "ns:kubernetes.io/metadata.name=test-ns,purpose=test&pod:app=db"
	labelNormalizedEmptyLabels := "ns:kubernetes.io/metadata.name=test-ns,purpose=test&pod:"
	labelNormalizedEmptyLabelsStale := "ns:kubernetes.io/metadata.name=test-ns,purpose=test&pod:<none>"
	toKeepLabelResExport := mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "cluster-a-" + common.HashLabelIdentity(labelNormalizedExist),
			Labels: map[string]string{
				constants.SourceKind:      constants.LabelIdentityKind,
				constants.SourceClusterID: "cluster-a",
			},
		},
		Spec: mcv1alpha1.ResourceExportSpec{
			Kind: constants.LabelIdentityKind,
			LabelIdentity: &mcv1alpha1.LabelIdentityExport{
				NormalizedLabel: labelNormalizedExist,
			},
		},
	}
	toKeepLabelResExportEmptyLabels := mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "cluster-a-" + common.HashLabelIdentity(labelNormalizedEmptyLabels),
			Labels: map[string]string{
				constants.SourceKind:      constants.LabelIdentityKind,
				constants.SourceClusterID: "cluster-a",
			},
		},
		Spec: mcv1alpha1.ResourceExportSpec{
			Kind: constants.LabelIdentityKind,
			LabelIdentity: &mcv1alpha1.LabelIdentityExport{
				NormalizedLabel: labelNormalizedEmptyLabels,
			},
		},
	}
	toDeleteLabelResExport := mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "cluster-a-" + common.HashLabelIdentity(labelNormalizedNonExist),
			Labels: map[string]string{
				constants.SourceKind:      constants.LabelIdentityKind,
				constants.SourceClusterID: "cluster-a",
			},
		},
		Spec: mcv1alpha1.ResourceExportSpec{
			Kind: constants.LabelIdentityKind,
			LabelIdentity: &mcv1alpha1.LabelIdentityExport{
				NormalizedLabel: labelNormalizedNonExist,
			},
		},
	}
	toDeleteLabelResExportEmptyLabels := mcv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "cluster-a-" + common.HashLabelIdentity(labelNormalizedEmptyLabelsStale),
			Labels: map[string]string{
				constants.SourceKind:      constants.LabelIdentityKind,
				constants.SourceClusterID: "cluster-a",
			},
		},
		Spec: mcv1alpha1.ResourceExportSpec{
			Kind: constants.LabelIdentityKind,
			LabelIdentity: &mcv1alpha1.LabelIdentityExport{
				NormalizedLabel: labelNormalizedEmptyLabelsStale,
			},
		},
	}
	tests := []struct {
		name                   string
		existSvcList           *corev1.ServiceList
		existPodList           *corev1.PodList
		existNamespaceList     *corev1.NamespaceList
		existLabelIdentityList *mcv1alpha1.LabelIdentityList
		existSvcExpList        *k8smcv1alpha1.ServiceExportList
		existResExpList        *mcv1alpha1.ResourceExportList
		wantErr                bool
	}{
		{
			name:               "clean up ResourceExport successfully",
			existNamespaceList: existingNamespaces,
			existPodList:       existingPods,
			existSvcExpList: &k8smcv1alpha1.ServiceExportList{
				Items: []k8smcv1alpha1.ServiceExport{
					svcExpNginx,
				},
			},
			existResExpList: &mcv1alpha1.ResourceExportList{
				Items: []mcv1alpha1.ResourceExport{
					toDeleteSvcResExport,
					toDeleteEPResExport,
					toDeleteCIResExport,
					toKeepSvcResExport,
					toKeepLabelResExport,
					toDeleteLabelResExport,
					toKeepLabelResExportEmptyLabels,
					toDeleteLabelResExportEmptyLabels,
					svcResExportFromOtherCluster,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(clusterSet).
				WithLists(tt.existSvcExpList, tt.existPodList, tt.existNamespaceList).Build()
			fakeRemoteClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithLists(tt.existResExpList).Build()
			commonArea := commonarea.NewFakeRemoteCommonArea(fakeRemoteClient, "leader-cluster", common.LocalClusterID, "default", nil)

			mcReconciler := NewMemberClusterSetReconciler(fakeClient, common.TestScheme, "default", false, false, make(chan struct{}))
			mcReconciler.SetRemoteCommonArea(commonArea)
			c := NewStaleResCleanupController(fakeClient, common.TestScheme, make(chan struct{}), "default", mcReconciler)
			if err := c.cleanUpStaleResources(ctx); err != nil {
				t.Errorf("StaleController.cleanup() should clean up all stale ResourceExports but got err = %v", err)
			}
			resExpList := &mcv1alpha1.ResourceExportList{}
			err := fakeRemoteClient.List(context.TODO(), resExpList, &client.ListOptions{})
			resExpLen := len(resExpList.Items)
			if err == nil {
				if resExpLen != 4 {
					t.Errorf("Should only FOUR valid ResourceExports left but got %v", resExpLen)
				}
			} else {
				t.Errorf("Should list ResourceExport successfully but got err = %v", err)
			}
		})
	}
}

func TestStaleController_CleanUpClusterInfoImports(t *testing.T) {
	ci := mcv1alpha1.ClusterInfo{
		ClusterID:   "cluster-a",
		ServiceCIDR: "10.10.1.0/16",
	}
	ciResImportA := mcv1alpha1.ResourceImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "antrea-mcs",
			Name:      "cluster-a-default-clusterinfo",
		},
		Spec: mcv1alpha1.ResourceImportSpec{
			Kind:        constants.ClusterInfoKind,
			Name:        "node-1",
			Namespace:   "default",
			ClusterInfo: &ci,
		},
	}
	ciImportA := mcv1alpha1.ClusterInfoImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "cluster-a-default-clusterinfo",
		},
		Spec: ci,
	}
	ciImportB := mcv1alpha1.ClusterInfoImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "cluster-b-default-clusterinfo",
		},
		Spec: ci,
	}
	tests := []struct {
		name               string
		existCIImpList     *mcv1alpha1.ClusterInfoImportList
		existingResImpList *mcv1alpha1.ResourceImportList
		wantErr            bool
	}{
		{
			name: "clean up ClusterInfoImport successfully",
			existCIImpList: &mcv1alpha1.ClusterInfoImportList{
				Items: []mcv1alpha1.ClusterInfoImport{
					ciImportA, ciImportB,
				},
			},
			existingResImpList: &mcv1alpha1.ResourceImportList{
				Items: []mcv1alpha1.ResourceImport{
					ciResImportA,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(clusterSet).WithLists(tt.existCIImpList).Build()
			fakeRemoteClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithLists(tt.existingResImpList).Build()
			commonarea := commonarea.NewFakeRemoteCommonArea(fakeRemoteClient, "leader-cluster", common.LocalClusterID, "antrea-mcs", nil)

			mcReconciler := NewMemberClusterSetReconciler(fakeClient, common.TestScheme, "default", false, false, make(chan struct{}))
			mcReconciler.SetRemoteCommonArea(commonarea)
			c := NewStaleResCleanupController(fakeClient, common.TestScheme, make(chan struct{}), "default", mcReconciler)
			if err := c.cleanUpStaleResources(ctx); err != nil {
				t.Errorf("StaleController.cleanup() should clean up all stale ClusterInfoImport but got err = %v", err)
			}
			ctx := context.TODO()
			ciImpList := &mcv1alpha1.ClusterInfoImportList{}
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

func TestStaleController_CleanUpLabelIdentites(t *testing.T) {
	normalizedLabelA := "namespace:kubernetes.io/metadata.name=test&pod:app=client"
	normalizedLabelB := "namespace:kubernetes.io/metadata.name=test&pod:app=db"
	labelHashA := common.HashLabelIdentity(normalizedLabelA)
	labelHashB := common.HashLabelIdentity(normalizedLabelB)
	labelIdentityA := mcv1alpha1.LabelIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name: labelHashA,
		},
		Spec: mcv1alpha1.LabelIdentitySpec{
			Label: normalizedLabelA,
			ID:    1,
		},
	}
	resImpA := mcv1alpha1.ResourceImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "antrea-mcs",
			Name:      labelHashA,
		},
		Spec: mcv1alpha1.ResourceImportSpec{
			Kind: constants.LabelIdentityKind,
			LabelIdentity: &mcv1alpha1.LabelIdentitySpec{
				Label: normalizedLabelA,
				ID:    1,
			},
		},
	}
	labelIdentityB := mcv1alpha1.LabelIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name: labelHashB,
		},
		Spec: mcv1alpha1.LabelIdentitySpec{
			Label: normalizedLabelB,
			ID:    2,
		},
	}
	tests := []struct {
		name                   string
		existLabelIdentityList *mcv1alpha1.LabelIdentityList
		existingResImpList     *mcv1alpha1.ResourceImportList
		wantErr                bool
	}{
		{
			name: "clean up LabelIdentities successfully",
			existLabelIdentityList: &mcv1alpha1.LabelIdentityList{
				Items: []mcv1alpha1.LabelIdentity{
					labelIdentityA, labelIdentityB,
				},
			},
			existingResImpList: &mcv1alpha1.ResourceImportList{
				Items: []mcv1alpha1.ResourceImport{
					resImpA,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(clusterSet).WithLists(tt.existLabelIdentityList).Build()
			fakeRemoteClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithLists(tt.existingResImpList).Build()
			ca := commonarea.NewFakeRemoteCommonArea(fakeRemoteClient, "leader-cluster", common.LocalClusterID, "antrea-mcs", nil)

			mcReconciler := NewMemberClusterSetReconciler(fakeClient, common.TestScheme, "default", false, false, make(chan struct{}))
			mcReconciler.SetRemoteCommonArea(ca)
			c := NewStaleResCleanupController(fakeClient, common.TestScheme, make(chan struct{}), "default", mcReconciler)
			if err := c.cleanUpStaleResources(ctx); err != nil {
				t.Errorf("StaleController.cleanup() should clean up all stale LabelIdentities but got err = %v", err)
			}
			ctx := context.TODO()
			labelList := &mcv1alpha1.LabelIdentityList{}
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

func TestStaleController_CleanupAllWithEmptyClusterSet(t *testing.T) {
	fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).Build()
	fakeRemoteClient := fake.NewClientBuilder().WithScheme(common.TestScheme).Build()
	commonarea := commonarea.NewFakeRemoteCommonArea(fakeRemoteClient, "leader-cluster", common.LocalClusterID, "antrea-mcs", nil)

	mcReconciler := NewMemberClusterSetReconciler(fakeClient, common.TestScheme, "default", false, false, make(chan struct{}))
	mcReconciler.SetRemoteCommonArea(commonarea)
	c := NewStaleResCleanupController(fakeClient, common.TestScheme, make(chan struct{}), "default", mcReconciler)
	if err := c.CleanUp(ctx); err != nil {
		t.Errorf("StaleController.cleanup() should clean up all stale resources but got err = %v", err)
	}
}

func TestCleanUpMCServiceAndServiceImport(t *testing.T) {
	existingSVCs := &corev1.ServiceList{
		Items: []corev1.Service{
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "svc-a",
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "antrea-mc-svc-b",
				},
			},
		},
	}
	existingSVCImports := &k8smcv1alpha1.ServiceImportList{
		Items: []k8smcv1alpha1.ServiceImport{
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "svc-b",
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithLists(existingSVCImports, existingSVCs).Build()
	ctx := context.Background()
	err := cleanUpMCServicesAndServiceImports(ctx, fakeClient)
	require.NoError(t, err)
	actualSvcList := &corev1.ServiceList{}
	err = fakeClient.List(ctx, actualSvcList)
	require.NoError(t, err)
	assert.Equal(t, 1, len(actualSvcList.Items))

	actualSvcImpList := &k8smcv1alpha1.ServiceImportList{}
	err = fakeClient.List(ctx, actualSvcImpList)
	require.NoError(t, err)
	assert.Equal(t, 0, len(actualSvcImpList.Items))
}

func TestCleanUpReplicatedACNP(t *testing.T) {
	acnpList := &v1beta1.ClusterNetworkPolicyList{
		Items: []v1beta1.ClusterNetworkPolicy{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-1",
					Annotations: map[string]string{
						common.AntreaMCACNPAnnotation: "true",
					},
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "acnp-2",
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithLists(acnpList).Build()
	ctx := context.Background()
	err := cleanUpReplicatedACNPs(ctx, fakeClient)
	require.NoError(t, err)

	actualACNPList := &v1beta1.ClusterNetworkPolicyList{}
	err = fakeClient.List(ctx, actualACNPList, &client.ListOptions{})
	require.NoError(t, err)
	assert.Equal(t, 1, len(actualACNPList.Items))
}

func TestCleanUpLabelIdentities(t *testing.T) {
	labelIdentityList := &mcv1alpha1.LabelIdentityList{
		Items: []mcv1alpha1.LabelIdentity{
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "labelidt-1",
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "labelidt-2",
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithLists(labelIdentityList).Build()
	ctx := context.Background()
	err := cleanUpLabelIdentities(ctx, fakeClient)
	require.NoError(t, err)

	actualIdtList := &mcv1alpha1.LabelIdentityList{}
	err = fakeClient.List(ctx, actualIdtList, &client.ListOptions{})
	require.NoError(t, err)
	assert.Equal(t, 0, len(actualIdtList.Items))
}

func TestCleanUpClusterInfoImport(t *testing.T) {
	ciImpList := &mcv1alpha1.ClusterInfoImportList{
		Items: []mcv1alpha1.ClusterInfoImport{
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "cluster-1-import",
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "cluster-2-import",
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithLists(ciImpList).Build()
	ctx := context.Background()
	err := cleanUpClusterInfoImports(ctx, fakeClient)
	require.NoError(t, err)

	actualCIImpList := &mcv1alpha1.ClusterInfoImportList{}
	err = fakeClient.List(ctx, actualCIImpList, &client.ListOptions{})
	require.NoError(t, err)
	assert.Equal(t, 0, len(actualCIImpList.Items))
}

func TestCleanUpGateway(t *testing.T) {
	gwList := &mcv1alpha1.GatewayList{
		Items: []mcv1alpha1.Gateway{
			{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "gw-1",
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithLists(gwList).Build()
	ctx := context.Background()
	err := cleanUpGateways(ctx, fakeClient)
	require.NoError(t, err)

	actualGWList := &mcv1alpha1.ClusterInfoImportList{}
	err = fakeClient.List(ctx, actualGWList, &client.ListOptions{})
	require.NoError(t, err)
	assert.Equal(t, 0, len(actualGWList.Items))
}
