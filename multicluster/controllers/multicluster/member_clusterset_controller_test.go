// Copyright 2022 Antrea Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package multicluster

import (
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/commonarea"
)

func TestMemberClusterDelete(t *testing.T) {
	existingMemberClusterAnnounce := &mcsv1alpha1.MemberClusterAnnounce{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  "default",
			Name:       "member-announce-from-cluster-a",
			Generation: 1,
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects().Build()
	fakeRemoteClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingMemberClusterAnnounce).Build()
	commonArea := commonarea.NewFakeRemoteCommonArea(fakeRemoteClient, "leader-cluster", localClusterID, "default")

	reconciler := MemberClusterSetReconciler{
		Client:           fakeClient,
		remoteCommonArea: commonArea,
	}
	if _, err := reconciler.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{
			Namespace: "default",
			Name:      "clusterset1",
		}}); err != nil {
		t.Errorf("Member ClusterSet Reconciler should handle delete event successfully but got error = %v", err)
	} else {
		memberClusterAnnounce := &mcsv1alpha1.MemberClusterAnnounce{}
		err := fakeClient.Get(ctx, types.NamespacedName{
			Namespace: "default",
			Name:      "member-announce-from-cluster-a",
		}, memberClusterAnnounce)
		if !apierrors.IsNotFound(err) {
			t.Errorf("Member ClusterSet Reconciler should remove MemberClusterAnnounce successfully but got error = %v", err)
		}
	}
}
