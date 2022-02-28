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

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

var (
	acnpImportName    = "acnp-for-isolation"
	acnpResImportName = leaderNamespace + "-" + acnpImportName

	acnpImpReq = ctrl.Request{NamespacedName: types.NamespacedName{
		Namespace: leaderNamespace,
		Name:      acnpResImportName,
	}}
	acnpImpNoMatchingTierReq = ctrl.Request{NamespacedName: types.NamespacedName{
		Namespace: leaderNamespace,
		Name:      "default-acnp-no-matching-tier",
	}}

	allowAction     = v1alpha1.RuleActionAllow
	dropAction      = v1alpha1.RuleActionDrop
	securityOpsTier = &v1alpha1.Tier{
		ObjectMeta: metav1.ObjectMeta{
			Name: "securityops",
		},
		Spec: v1alpha1.TierSpec{
			Priority:    int32(100),
			Description: "[READ-ONLY]: System generated SecurityOps Tier",
		},
	}
	acnpResImport = &mcsv1alpha1.ResourceImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: leaderNamespace,
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
				Ingress: []v1alpha1.Rule{
					{
						Action: &dropAction,
						From: []v1alpha1.NetworkPolicyPeer{
							{
								Namespaces: &v1alpha1.PeerNamespaces{
									Match: v1alpha1.NamespaceMatchSelf,
								},
							},
						},
					},
				},
			},
		},
	}
	acnpResImportNoMatchingTier = &mcsv1alpha1.ResourceImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: leaderNamespace,
			Name:      "default-acnp-no-matching-tier",
		},
		Spec: mcsv1alpha1.ResourceImportSpec{
			Name: "acnp-no-matching-tier",
			Kind: common.AntreaClusterNetworkPolicyKind,
			ClusterNetworkPolicy: &v1alpha1.ClusterNetworkPolicySpec{
				Tier:     "somerandomtier",
				Priority: 1.0,
				AppliedTo: []v1alpha1.NetworkPolicyPeer{
					{NamespaceSelector: &metav1.LabelSelector{}},
				},
			},
		},
	}
)

func TestResourceImportReconciler_handleCopySpanACNPCreateEvent(t *testing.T) {
	remoteMgr := NewRemoteCommonAreaManager("test-clusterset", common.ClusterID(localClusterID))
	go remoteMgr.Start()
	defer remoteMgr.Stop()

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(securityOpsTier).Build()
	fakeRemoteClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(acnpResImport, acnpResImportNoMatchingTier).Build()
	remoteCluster := NewFakeRemoteCommonArea(scheme, &remoteMgr, fakeRemoteClient, "leader-cluster", "default")

	tests := []struct {
		name            string
		acnpImportName  string
		req             ctrl.Request
		expectedSuccess bool
	}{
		{
			name:            "import ACNP of pre-defined tiers",
			acnpImportName:  acnpImportName,
			req:             acnpImpReq,
			expectedSuccess: true,
		},
		{
			name:            "import ACNP of non-existing tier",
			acnpImportName:  "acnp-no-matching-tier",
			req:             acnpImpNoMatchingTierReq,
			expectedSuccess: false,
		},
	}
	r := NewResourceImportReconciler(fakeClient, scheme, fakeClient, localClusterID, remoteCluster)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := r.Reconcile(ctx, tt.req); err != nil {
				if err != nil {
					t.Errorf("ResourceImport Reconciler should handle ACNP create event successfully but got error = %v", err)
				}
			} else {
				acnp := &v1alpha1.ClusterNetworkPolicy{}
				err := fakeClient.Get(ctx, types.NamespacedName{Namespace: "", Name: common.AntreaMCSPrefix + tt.acnpImportName}, acnp)
				if tt.expectedSuccess && err != nil {
					t.Errorf("ResourceImport Reconciler should import an ACNP successfully but got error = %v", err)
				} else if !tt.expectedSuccess && (err == nil || !apierrors.IsNotFound(err)) {
					t.Errorf("ResourceImport Reconciler should not import an ACNP whose Tier does not exist in current cluster. Expected NotFound error. Actual err = %v", err)
				}
				acnpImport := &mcsv1alpha1.ACNPImport{}
				if err := fakeClient.Get(ctx, types.NamespacedName{Namespace: "", Name: tt.acnpImportName}, acnpImport); err != nil {
					t.Errorf("ResourceImport Reconciler should create ACNPImport for ACNP type resouc")
				}
				status := acnpImport.Status.Conditions
				if len(status) > 0 && status[0].Type == mcsv1alpha1.ACNPImportRealizable {
					if tt.expectedSuccess && status[0].Status != corev1.ConditionTrue {
						t.Errorf("ACNPImport %v realizable status should be True but is %v instead", acnpImportName, status[0].Status)
					} else if !tt.expectedSuccess && status[0].Status != corev1.ConditionFalse {
						t.Errorf("ACNPImport %v realizable status should be False but is %v instead", acnpImportName, status[0].Status)
					}
				} else {
					t.Errorf("No realizable status provided for ACNPImport %v", acnpImportName)
				}
			}
		})
	}
}

func TestResourceImportReconciler_handleCopySpanACNPDeleteEvent(t *testing.T) {
	remoteMgr := NewRemoteCommonAreaManager("test-clusterset", common.ClusterID(localClusterID))
	go remoteMgr.Start()
	defer remoteMgr.Stop()

	existingACNP := &v1alpha1.ClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: common.AntreaMCSPrefix + acnpImportName,
		},
	}
	existingACNPImport := &mcsv1alpha1.ACNPImport{
		ObjectMeta: metav1.ObjectMeta{
			Name: acnpImportName,
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingACNP, existingACNPImport).Build()
	fakeRemoteClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	remoteCluster := NewFakeRemoteCommonArea(scheme, &remoteMgr, fakeRemoteClient, "leader-cluster", "default")

	r := NewResourceImportReconciler(fakeClient, scheme, fakeClient, localClusterID, remoteCluster)
	r.installedResImports.Add(*acnpResImport)

	if _, err := r.Reconcile(ctx, acnpImpReq); err != nil {
		t.Errorf("ResourceImport Reconciler should handle ACNP ResourceImport delete event successfully but got error = %v", err)
	}
	acnp := &v1alpha1.ClusterNetworkPolicy{}
	if err := fakeClient.Get(ctx, types.NamespacedName{Namespace: "", Name: common.AntreaMCSPrefix + acnpImportName}, acnp); !apierrors.IsNotFound(err) {
		t.Errorf("ResourceImport Reconciler should delete ACNP successfully but got error = %v", err)
	}
	acnpImport := &mcsv1alpha1.ACNPImport{}
	if err := fakeClient.Get(ctx, types.NamespacedName{Namespace: "", Name: acnpImportName}, acnpImport); !apierrors.IsNotFound(err) {
		t.Errorf("ResourceImport Reconciler should delete ACNPImport successfully but got error = %v", err)
	}
}

func TestResourceImportReconciler_handleCopySpanACNPUpdateEvent(t *testing.T) {
	remoteMgr := NewRemoteCommonAreaManager("test-clusterset", common.ClusterID(localClusterID))
	go remoteMgr.Start()
	defer remoteMgr.Stop()

	existingACNP1 := &v1alpha1.ClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:        common.AntreaMCSPrefix + acnpImportName,
			Annotations: map[string]string{common.AntreaMCACNPAnnotation: "true"},
		},
		Spec: v1alpha1.ClusterNetworkPolicySpec{
			Tier:     "securityops",
			Priority: 1.0,
			AppliedTo: []v1alpha1.NetworkPolicyPeer{
				{NamespaceSelector: &metav1.LabelSelector{}},
			},
			Ingress: []v1alpha1.Rule{
				{
					Action: &allowAction,
					From: []v1alpha1.NetworkPolicyPeer{
						{
							Namespaces: &v1alpha1.PeerNamespaces{
								Match: v1alpha1.NamespaceMatchSelf,
							},
						},
					},
				},
			},
		},
	}
	existingACNPImport1 := &mcsv1alpha1.ACNPImport{
		ObjectMeta: metav1.ObjectMeta{
			Name: acnpImportName,
		},
		Status: mcsv1alpha1.ACNPImportStatus{
			Conditions: []mcsv1alpha1.ACNPImportCondition{
				{
					Type:   mcsv1alpha1.ACNPImportRealizable,
					Status: corev1.ConditionTrue,
				},
			},
		},
	}
	existingACNPImport2 := &mcsv1alpha1.ACNPImport{
		ObjectMeta: metav1.ObjectMeta{
			Name: "acnp-no-matching-tier",
		},
		Status: mcsv1alpha1.ACNPImportStatus{
			Conditions: []mcsv1alpha1.ACNPImportCondition{
				{
					Type:   mcsv1alpha1.ACNPImportRealizable,
					Status: corev1.ConditionFalse,
				},
			},
		},
	}
	updatedResImport2 := &mcsv1alpha1.ResourceImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: leaderNamespace,
			Name:      "default-acnp-no-matching-tier",
		},
		Spec: mcsv1alpha1.ResourceImportSpec{
			Name: "acnp-no-matching-tier",
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
	existingACNP3 := &v1alpha1.ClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:        common.AntreaMCSPrefix + "valid-updated-to-no-valid",
			Annotations: map[string]string{common.AntreaMCACNPAnnotation: "true"},
		},
		Spec: v1alpha1.ClusterNetworkPolicySpec{
			Tier:     "securityops",
			Priority: 1.0,
			AppliedTo: []v1alpha1.NetworkPolicyPeer{
				{NamespaceSelector: &metav1.LabelSelector{}},
			},
		},
	}
	existingACNPImport3 := &mcsv1alpha1.ACNPImport{
		ObjectMeta: metav1.ObjectMeta{
			Name: "valid-updated-to-no-valid",
		},
		Status: mcsv1alpha1.ACNPImportStatus{
			Conditions: []mcsv1alpha1.ACNPImportCondition{
				{
					Type:   mcsv1alpha1.ACNPImportRealizable,
					Status: corev1.ConditionTrue,
				},
			},
		},
	}
	updatedResImport3 := &mcsv1alpha1.ResourceImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: leaderNamespace,
			Name:      "default-valid-updated-to-no-valid",
		},
		Spec: mcsv1alpha1.ResourceImportSpec{
			Name: acnpImportName,
			Kind: common.AntreaClusterNetworkPolicyKind,
			ClusterNetworkPolicy: &v1alpha1.ClusterNetworkPolicySpec{
				Tier:     "somerandomtier",
				Priority: 1.0,
				AppliedTo: []v1alpha1.NetworkPolicyPeer{
					{NamespaceSelector: &metav1.LabelSelector{}},
				},
			},
		},
	}
	acnpImp3Req := ctrl.Request{NamespacedName: types.NamespacedName{
		Namespace: leaderNamespace,
		Name:      "default-valid-updated-to-no-valid",
	}}
	acnpImp4Req := ctrl.Request{NamespacedName: types.NamespacedName{
		Namespace: leaderNamespace,
		Name:      "default-name-conflict",
	}}
	existingACNP4 := &v1alpha1.ClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: common.AntreaMCSPrefix + "name-conflict",
		},
		Spec: v1alpha1.ClusterNetworkPolicySpec{
			Tier:     "securityops",
			Priority: 1.0,
			AppliedTo: []v1alpha1.NetworkPolicyPeer{
				{NamespaceSelector: &metav1.LabelSelector{}},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingACNP1, existingACNPImport1, existingACNPImport2,
		existingACNP3, existingACNPImport3, existingACNP4, securityOpsTier).Build()
	fakeRemoteClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(acnpResImport, updatedResImport2, updatedResImport3).Build()
	remoteCluster := NewFakeRemoteCommonArea(scheme, &remoteMgr, fakeRemoteClient, "leader-cluster", "default")

	r := NewResourceImportReconciler(fakeClient, scheme, fakeClient, localClusterID, remoteCluster)
	r.installedResImports.Add(*acnpResImport)
	r.installedResImports.Add(*acnpResImportNoMatchingTier)
	r.installedResImports.Add(*updatedResImport3)

	tests := []struct {
		name                    string
		acnpImportName          string
		req                     ctrl.Request
		expectErr               bool
		expectImportSuccess     bool
		expectedUpdatedACNPSpec *v1alpha1.ClusterNetworkPolicySpec
	}{
		{
			name:                    "update acnp spec",
			acnpImportName:          acnpImportName,
			req:                     acnpImpReq,
			expectErr:               false,
			expectImportSuccess:     true,
			expectedUpdatedACNPSpec: acnpResImport.Spec.ClusterNetworkPolicy,
		},
		{
			name:                    "imported acnp missing tier update to valid tier",
			acnpImportName:          "acnp-no-matching-tier",
			req:                     acnpImpNoMatchingTierReq,
			expectErr:               false,
			expectImportSuccess:     true,
			expectedUpdatedACNPSpec: updatedResImport2.Spec.ClusterNetworkPolicy,
		},
		{
			name:                    "valid imported acnp update to missing tier",
			req:                     acnpImp3Req,
			acnpImportName:          "valid-updated-to-no-valid",
			expectErr:               false,
			expectImportSuccess:     false,
			expectedUpdatedACNPSpec: nil,
		},
		{
			name:                    "name conflict with existing acnp",
			req:                     acnpImp4Req,
			acnpImportName:          "name-conflict",
			expectErr:               true,
			expectImportSuccess:     false,
			expectedUpdatedACNPSpec: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := r.Reconcile(ctx, tt.req); err != nil {
				if tt.expectErr {
					assert.Contains(t, err.Error(), "conflicts with existing one")
				} else {
					t.Errorf("ResourceImport Reconciler should handle update event successfully but got error = %v", err)
				}
			} else {
				if tt.expectedUpdatedACNPSpec != nil {
					acnp := &v1alpha1.ClusterNetworkPolicy{}
					err := fakeClient.Get(ctx, types.NamespacedName{Namespace: "", Name: common.AntreaMCSPrefix + tt.acnpImportName}, acnp)
					if tt.expectImportSuccess && err != nil {
						t.Errorf("ResourceImport Reconciler should import an ACNP successfully but got error = %v", err)
					} else if !tt.expectImportSuccess && (err == nil || !apierrors.IsNotFound(err)) {
						t.Errorf("ResourceImport Reconciler should not import an ACNP whose Tier does not exist in current cluster. Expected NotFound error. Actual err = %v", err)
					} else if !reflect.DeepEqual(acnp.Spec, *tt.expectedUpdatedACNPSpec) {
						t.Errorf("ACNP spec was not updated successfully")
					}
				}
			}
		})
	}
}
