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
	"time"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
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
			Name: "test-ns",
			Labels: map[string]string{
				"kubernetes.io/metadata.name": "test-ns",
			},
		},
	}
	podA = &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test-ns",
			Name:      "pod-a",
			Labels: map[string]string{
				"app": "client",
			},
		},
	}
	newPodA = &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test-ns",
			Name:      "pod-a",
			Labels: map[string]string{
				"app": "db",
			},
		},
	}
	podB = &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test-ns",
			Name:      "pod-b",
			Labels: map[string]string{
				"app": "client",
			},
		},
	}
	podC = &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test-ns",
			Name:      "pod-c",
			Labels: map[string]string{
				"app": "web",
			},
		},
	}

	normalizedLabelDB  = "ns:kubernetes.io/metadata.name=test-ns&pod:app=db"
	podANamespacedName = &types.NamespacedName{Namespace: "test-ns", Name: "pod-a"}
	podBNamespacedName = &types.NamespacedName{Namespace: "test-ns", Name: "pod-b"}
	podCNamespacedName = &types.NamespacedName{Namespace: "test-ns", Name: "pod-c"}
	podAName           = podANamespacedName.String()
	podBName           = podBNamespacedName.String()
)

func TestLabelIdentityReconciler(t *testing.T) {
	tests := []struct {
		name                 string
		existingPods         *v1.PodList
		podEvent             *v1.Pod
		podNamespaceName     *types.NamespacedName
		eventType            int
		expLabelsQueued      bool
		expNormalizedLabels  []string
		expLabelsToPodsCache map[string]sets.String
		expPodLabelCache     map[string]string
	}{
		{
			name:                 "pod add event",
			existingPods:         &v1.PodList{Items: []v1.Pod{}},
			podEvent:             podA,
			podNamespaceName:     podANamespacedName,
			eventType:            addEvent,
			expLabelsQueued:      true,
			expNormalizedLabels:  []string{normalizedLabel},
			expLabelsToPodsCache: map[string]sets.String{normalizedLabel: sets.NewString(podAName)},
			expPodLabelCache:     map[string]string{podANamespacedName.String(): normalizedLabel},
		},
		{
			name:                 "pod add event existing label",
			existingPods:         &v1.PodList{Items: []v1.Pod{*podA}},
			podEvent:             podB,
			podNamespaceName:     podBNamespacedName,
			eventType:            addEvent,
			expLabelsQueued:      false,
			expNormalizedLabels:  []string{normalizedLabel},
			expLabelsToPodsCache: map[string]sets.String{normalizedLabel: sets.NewString(podAName, podBName)},
			expPodLabelCache:     map[string]string{podAName: normalizedLabel, podBName: normalizedLabel},
		},
		{
			name:                 "pod update event",
			existingPods:         &v1.PodList{Items: []v1.Pod{*podA}},
			podEvent:             newPodA,
			podNamespaceName:     podANamespacedName,
			eventType:            updateEvent,
			expLabelsQueued:      true,
			expNormalizedLabels:  []string{normalizedLabelDB},
			expLabelsToPodsCache: map[string]sets.String{normalizedLabelDB: sets.NewString(podAName)},
			expPodLabelCache:     map[string]string{podAName: normalizedLabelDB},
		},
		{
			name:                 "pod delete event stale label",
			existingPods:         &v1.PodList{Items: []v1.Pod{*podA}},
			podEvent:             podA,
			podNamespaceName:     podANamespacedName,
			eventType:            deleteEvent,
			expLabelsQueued:      true,
			expNormalizedLabels:  []string{},
			expLabelsToPodsCache: map[string]sets.String{},
			expPodLabelCache:     map[string]string{},
		},
		{
			name:                 "pod delete event no stale label",
			existingPods:         &v1.PodList{Items: []v1.Pod{*podA, *podB}},
			podEvent:             podB,
			podNamespaceName:     podBNamespacedName,
			eventType:            deleteEvent,
			expLabelsQueued:      false,
			expNormalizedLabels:  []string{normalizedLabel},
			expLabelsToPodsCache: map[string]sets.String{normalizedLabel: sets.NewString(podAName)},
			expPodLabelCache:     map[string]string{podAName: normalizedLabel},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stopCh := make(chan struct{})
			defer close(stopCh)

			fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithLists(tt.existingPods).WithObjects(ns).Build()
			fakeRemoteClient := fake.NewClientBuilder().WithScheme(scheme).Build()
			commonArea := commonarea.NewFakeRemoteCommonArea(fakeRemoteClient, "leader-cluster", localClusterID, leaderNamespace)
			mcReconciler := NewMemberClusterSetReconciler(fakeClient, scheme, "default")
			mcReconciler.SetRemoteCommonArea(commonArea)
			r := NewLabelIdentityReconciler(fakeClient, scheme, mcReconciler)
			go r.Run(stopCh)

			for _, p := range tt.existingPods.Items {
				req := ctrl.Request{
					NamespacedName: types.NamespacedName{
						Namespace: p.Namespace,
						Name:      p.Name,
					},
				}
				_, err := r.Reconcile(ctx, req)
				assert.NoError(t, err, "LabelIdentity Reconciler got error during reconciling initial Pod events")
			}
			time.Sleep(10 * time.Millisecond)
			assert.Equalf(t, r.labelQueue.Len(), 0, "LabelIdentity Reconciler failed to process label ResourceExport for existing Pods")
			switch tt.eventType {
			case addEvent:
				tt.podEvent.ResourceVersion = ""
				r.Client.Create(ctx, tt.podEvent, &client.CreateOptions{})
			case updateEvent:
				r.Client.Update(ctx, tt.podEvent, &client.UpdateOptions{})
			case deleteEvent:
				r.Client.Delete(ctx, tt.podEvent, &client.DeleteOptions{})
			}
			var err error
			req := ctrl.Request{NamespacedName: *tt.podNamespaceName}

			_, err = r.Reconcile(ctx, req)
			assert.NoError(t, err, "LabelIdentity Reconciler got error during reconciling Pod event")

			if !reflect.DeepEqual(r.labelToPodsCache, tt.expLabelsToPodsCache) {
				t.Errorf("Unexpected labelToPodsCache in LabelIdentity Reconciler. Exp: %s, Act: %s", tt.expLabelsToPodsCache, r.labelToPodsCache)
			}
			if !reflect.DeepEqual(r.podLabelCache, tt.expPodLabelCache) {
				t.Errorf("Unexpected podLabelCache in LabelIdentity Reconciler. Exp: %s, Act: %s", tt.expPodLabelCache, r.podLabelCache)
			}
			time.Sleep(10 * time.Millisecond)
			assert.Equalf(t, r.labelQueue.Len(), 0, "LabelIdentity Reconciler failed to process label ResourceExport for testcase Pod")
			actLabelIdentityResourceExports := &mcsv1alpha1.ResourceExportList{}
			err = commonArea.List(ctx, actLabelIdentityResourceExports)
			assert.NoError(t, err, "Failed to list ResourceExports after reconciliation")
			var actNormalizedLabels []string
			for _, re := range actLabelIdentityResourceExports.Items {
				if re.Spec.LabelIdentity != nil {
					actNormalizedLabels = append(actNormalizedLabels, re.Spec.LabelIdentity.NormalizedLabel)
				}
			}
			assert.ElementsMatchf(t, tt.expNormalizedLabels, actNormalizedLabels,
				"Unexpected LabelIdentity ResourceExports, expect ResourceExports for labels: %s, actual: %s", tt.expNormalizedLabels, actNormalizedLabels)
		})
	}
}

func TestNamespaceMapFunc(t *testing.T) {
	expReq := []reconcile.Request{
		{
			NamespacedName: *podANamespacedName,
		},
		{
			NamespacedName: *podCNamespacedName,
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(podA, podC, ns).Build()
	fakeRemoteClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	commonArea := commonarea.NewFakeRemoteCommonArea(fakeRemoteClient, "leader-cluster", localClusterID, leaderNamespace)
	mcReconciler := NewMemberClusterSetReconciler(fakeClient, scheme, "default")
	mcReconciler.SetRemoteCommonArea(commonArea)

	r := NewLabelIdentityReconciler(fakeClient, scheme, mcReconciler)
	actualReq := r.namespaceMapFunc(ns)
	assert.ElementsMatch(t, expReq, actualReq)
}

func TestGetNormalizedLabel(t *testing.T) {
	tests := []struct {
		name               string
		namespace          string
		podLabels          map[string]string
		nsLabels           map[string]string
		expNormalizedLabel string
	}{
		{
			"regular Pod",
			"test-ns",
			map[string]string{"purpose": "test"},
			map[string]string{v1.LabelMetadataName: "test-ns"},
			"ns:kubernetes.io/metadata.name=test-ns&pod:purpose=test",
		},
		{
			"no Namespace default name label",
			"test-ns",
			map[string]string{"purpose": "test"},
			map[string]string{"region": "west"},
			"ns:kubernetes.io/metadata.name=test-ns,region=west&pod:purpose=test",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			normalizedLabel := getNormalizedLabel(tt.nsLabels, tt.podLabels, tt.namespace)
			assert.Equal(t, tt.expNormalizedLabel, normalizedLabel)
		})
	}
}
