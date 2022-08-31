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
)

var (
	resImpNamespacedName = types.NamespacedName{
		Name:      "label-identity-app-client",
		Namespace: "default",
	}

	labelIdentityResImp1 = &mcsv1alpha1.ResourceImport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      resImpNamespacedName.Name,
			Namespace: resImpNamespacedName.Namespace,
		},
		Spec: mcsv1alpha1.ResourceImportSpec{
			LabelIdentity: &mcsv1alpha1.LabelIdentitySpec{
				Label: "ns:kubernetes.io/metadata.name=ns&pod:app=client",
				ID:    uint32(1),
			},
		},
	}

	labelIdentityResImp2 = &mcsv1alpha1.ResourceImport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      resImpNamespacedName.Name,
			Namespace: resImpNamespacedName.Namespace,
		},
		Spec: mcsv1alpha1.ResourceImportSpec{
			LabelIdentity: &mcsv1alpha1.LabelIdentitySpec{
				Label: "ns:kubernetes.io/metadata.name=ns&pod:app=client",
				ID:    uint32(2),
			},
		},
	}

	labelIdentity1 = &mcsv1alpha1.LabelIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name: resImpNamespacedName.Name,
		},
		Spec: mcsv1alpha1.LabelIdentitySpec{
			Label: "ns:kubernetes.io/metadata.name=ns&pod:app=client",
			ID:    uint32(1),
		},
	}

	labelIdentity2 = &mcsv1alpha1.LabelIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name: resImpNamespacedName.Name,
		},
		Spec: mcsv1alpha1.LabelIdentitySpec{
			Label: "ns:kubernetes.io/metadata.name=ns&pod:app=client",
			ID:    uint32(2),
		},
	}
)

func TestLabelIdentityResourceImportReconclie(t *testing.T) {
	tests := []struct {
		name                    string
		existLabelIdentity      *mcsv1alpha1.LabelIdentity
		existResImp             *mcsv1alpha1.ResourceImport
		resImportNamespacedName types.NamespacedName
		expLabelIdentity        *mcsv1alpha1.LabelIdentitySpec
		isDeleted               bool
	}{
		{
			"create LabelIdentity",
			&mcsv1alpha1.LabelIdentity{},
			labelIdentityResImp1,
			resImpNamespacedName,
			&labelIdentity1.Spec,
			false,
		},
		{
			"update LabelIdentity",
			labelIdentity1,
			labelIdentityResImp2,
			resImpNamespacedName,
			&labelIdentity2.Spec,
			false,
		},
		{
			"delete LabelIdentity",
			labelIdentity1,
			labelIdentityResImp1,
			resImpNamespacedName,
			&mcsv1alpha1.LabelIdentitySpec{},
			true,
		},
	}

	for _, tt := range tests {
		fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tt.existLabelIdentity).Build()
		fakeRemoteClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tt.existResImp).Build()
		remoteCluster := NewFakeRemoteCommonArea(fakeRemoteClient, "leader-cluster", localClusterID, "default")
		r := NewLabelIdentityResourceImportReconciler(fakeClient, scheme, fakeClient, localClusterID, "default", remoteCluster)
		if tt.isDeleted {
			r.remoteCommonArea.Delete(ctx, tt.existResImp)
		}

		resImpReq := ctrl.Request{NamespacedName: tt.resImportNamespacedName}
		if _, err := r.Reconcile(ctx, resImpReq); err != nil {
			t.Errorf("LabelIdentityResourceImport Reconciler should handle LabelIdentity event successfully but got error = %v", err)
		} else {
			actLabelIdentity := &mcsv1alpha1.LabelIdentity{}
			err := fakeClient.Get(ctx, types.NamespacedName{Namespace: "", Name: tt.resImportNamespacedName.Name}, actLabelIdentity)
			if err == nil {
				if !reflect.DeepEqual(*tt.expLabelIdentity, actLabelIdentity.Spec) {
					t.Errorf("LabelIdentityResourceImport Reconciler imported a LabelIdentity incorrectly. Exp: %v, Act: %v", *tt.expLabelIdentity, actLabelIdentity.Spec)
				}
			} else {
				if tt.isDeleted {
					if !apierrors.IsNotFound(err) {
						t.Errorf("LabelIdentityResourceImport Reconciler expects not found error but got error = %v", err)
					}
				} else {
					t.Errorf("Expected a LabelIdentity but got error = %v", err)
				}
			}
		}
	}
}
