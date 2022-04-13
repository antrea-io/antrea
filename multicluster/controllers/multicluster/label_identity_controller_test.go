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
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/commonarea"
)

const (
	addEvent = iota
	updateEvent
	deleteEvent
)

var (
	ns = &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ns",
			Labels: map[string]string{
				"kubernetes.io/metadata.name": "ns",
			},
		},
	}
	newNS = &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ns",
			Labels: map[string]string{
				"kubernetes.io/metadata.name": "ns",
				"level":                       "admin",
			},
		},
	}

	pod = &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "ns",
			Name:      "pod",
			Labels: map[string]string{
				"app": "client",
			},
		},
	}

	newPod = &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "ns",
			Name:      "pod",
			Labels: map[string]string{
				"app": "db",
			},
		},
	}

	normalizedLabelDB    = "ns:kubernetes.io/metadata.name=ns&pod:app=db"
	normalizedLabelAdmin = "ns:kubernetes.io/metadata.name=ns,level=admin&pod:app=client"

	podNamespacedName = &types.NamespacedName{Namespace: "ns", Name: "pod"}
	nsNamespacedName  = &types.NamespacedName{Namespace: "", Name: "ns"}
)

func TestLabelIdentityReconciler(t *testing.T) {
	tests := []struct {
		name                 string
		existPod             *v1.Pod
		existNS              *v1.Namespace
		newPod               *v1.Pod
		newNS                *v1.Namespace
		podNamespacedName    *types.NamespacedName
		nsNamespaceName      *types.NamespacedName
		expNormalizedLabel   string
		expLabelsToPodsCache map[string]sets.String
		expPodLabelCache     map[string]string
		event                int
	}{
		{
			"pod add event",
			pod,
			ns,
			nil,
			nil,
			podNamespacedName,
			nil,
			normalizedLabel,
			map[string]sets.String{normalizedLabel: sets.NewString(podNamespacedName.String())},
			map[string]string{podNamespacedName.String(): normalizedLabel},
			addEvent,
		},
		{
			"pod update event",
			pod,
			ns,
			newPod,
			nil,
			podNamespacedName,
			nil,
			normalizedLabelDB,
			map[string]sets.String{normalizedLabelDB: sets.NewString(podNamespacedName.String())},
			map[string]string{podNamespacedName.String(): normalizedLabelDB},
			updateEvent,
		},
		{
			"pod delete event",
			pod,
			ns,
			nil,
			nil,
			podNamespacedName,
			nil,
			"",
			map[string]sets.String{},
			map[string]string{},
			deleteEvent,
		},
		{
			"ns update event",
			pod,
			ns,
			nil,
			newNS,
			nil,
			nsNamespacedName,
			normalizedLabelAdmin,
			map[string]sets.String{normalizedLabelAdmin: sets.NewString(podNamespacedName.String())},
			map[string]string{podNamespacedName.String(): normalizedLabelAdmin},
			updateEvent,
		},
	}

	for _, tt := range tests {
		fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tt.existPod, tt.existNS).Build()
		fakeRemoteClient := fake.NewClientBuilder().WithScheme(scheme).Build()
		commonArea := commonarea.NewFakeRemoteCommonArea(fakeRemoteClient, "leader-cluster", localClusterID, leaderNamespace)
		mcReconciler := NewMemberClusterSetReconciler(fakeClient, scheme, "default")
		mcReconciler.SetRemoteCommonArea(commonArea)
		r := NewLabelIdentityReconciler(fakeClient, scheme, mcReconciler)

		var req ctrl.Request
		if tt.podNamespacedName != nil {
			req = ctrl.Request{NamespacedName: *tt.podNamespacedName}
		} else {
			req = ctrl.Request{NamespacedName: *tt.nsNamespaceName}
		}
		if _, err := r.Reconcile(ctx, req); err != nil {
			t.Errorf("LabelIdentity Reconciler got error during reconciling. error = %v", err)
			continue
		}

		if tt.event == updateEvent {
			if tt.newPod != nil {
				r.Client.Update(ctx, tt.newPod, &client.UpdateOptions{})
			} else {
				r.Client.Update(ctx, tt.newNS, &client.UpdateOptions{})
			}
			if _, err := r.Reconcile(ctx, req); err != nil {
				t.Errorf("LabelIdentity Reconciler got error during reconciling. error = %v", err)
				continue
			}
		} else if tt.event == deleteEvent {
			r.Client.Delete(ctx, tt.existPod, &client.DeleteOptions{})
			if _, err := r.Reconcile(ctx, req); err != nil {
				t.Errorf("LabelIdentity Reconciler got error during reconciling. error = %v", err)
				continue
			}
		}

		if !reflect.DeepEqual(r.labelToPodsCache, tt.expLabelsToPodsCache) {
			t.Errorf("Unexpected labelToPodsCache in LabelIdentity Reconciler in step %s. Exp: %s, Act: %s", tt.name, tt.expLabelsToPodsCache, r.labelToPodsCache)
		}
		if !reflect.DeepEqual(r.podLabelCache, tt.expPodLabelCache) {
			t.Errorf("Unexpected podLabelCache in LabelIdentity Reconciler in step %s. Exp: %s, Act: %s", tt.name, tt.expPodLabelCache, r.podLabelCache)
		}

		actLabelIdentityExport := &mcsv1alpha1.ResourceExport{}
		err := commonArea.Get(ctx, types.NamespacedName{Namespace: commonArea.GetNamespace(), Name: getResourceExportNameForLabelIdentity(localClusterID, tt.expNormalizedLabel)}, actLabelIdentityExport)
		if err == nil {
			if actLabelIdentityExport.Spec.LabelIdentity.NormalizedLabel != tt.expNormalizedLabel {
				t.Errorf("LabelIdentity Reconciler create LabelIdentity kind of ResourceExport incorrectly. ExpLabel:%s, ActLabel:%s", tt.expNormalizedLabel, actLabelIdentityExport.Spec.LabelIdentity.NormalizedLabel)
			}
		} else {
			if tt.event == deleteEvent {
				if !apierrors.IsNotFound(err) {
					t.Errorf("LabelIdentity Reconciler expects not found error but got error = %v", err)
				}
			} else {
				t.Errorf("Expected a LabelIdentity kind of ResourceExport but got error = %v", err)
			}
		}
	}
}

func TestNamespaceMapFunc(t *testing.T) {
	ns := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-ns",
		},
	}
	expReq := []reconcile.Request{
		{
			NamespacedName: types.NamespacedName{
				Name: "test-ns",
			},
		},
	}
	actualReq := namespaceMapFunc(ns)
	assert.ElementsMatch(t, expReq, actualReq)
}
