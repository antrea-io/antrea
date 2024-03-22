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
	"context"
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
	mcv1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
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

	normalizedLabel   = "ns:kubernetes.io/metadata.name=test-ns&pod:app=client"
	normalizedLabelDB = "ns:kubernetes.io/metadata.name=test-ns&pod:app=db"

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
		expLabelsToPodsCache map[string]sets.Set[string]
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
			expLabelsToPodsCache: map[string]sets.Set[string]{normalizedLabel: sets.New[string](podAName)},
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
			expLabelsToPodsCache: map[string]sets.Set[string]{normalizedLabel: sets.New[string](podAName, podBName)},
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
			expLabelsToPodsCache: map[string]sets.Set[string]{normalizedLabelDB: sets.New[string](podAName)},
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
			expLabelsToPodsCache: map[string]sets.Set[string]{},
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
			expLabelsToPodsCache: map[string]sets.Set[string]{normalizedLabel: sets.New[string](podAName)},
			expPodLabelCache:     map[string]string{podAName: normalizedLabel},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stopCh := make(chan struct{})
			defer close(stopCh)

			fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithLists(tt.existingPods).WithObjects(ns).Build()
			fakeRemoteClient := fake.NewClientBuilder().WithScheme(common.TestScheme).Build()
			commonArea := commonarea.NewFakeRemoteCommonArea(fakeRemoteClient, "leader-cluster", common.LocalClusterID, common.LeaderNamespace, nil)
			mcReconciler := NewMemberClusterSetReconciler(fakeClient, common.TestScheme, "default", true, false, make(chan struct{}))
			mcReconciler.SetRemoteCommonArea(commonArea)
			r := NewLabelIdentityReconciler(fakeClient, common.TestScheme, mcReconciler, "default")
			go r.Run(stopCh)

			for _, p := range tt.existingPods.Items {
				req := ctrl.Request{
					NamespacedName: types.NamespacedName{
						Namespace: p.Namespace,
						Name:      p.Name,
					},
				}
				_, err := r.Reconcile(common.TestCtx, req)
				assert.NoError(t, err, "LabelIdentity Reconciler got error during reconciling initial Pod events")
			}
			time.Sleep(10 * time.Millisecond)
			assert.Equalf(t, r.labelQueue.Len(), 0, "LabelIdentity Reconciler failed to process label ResourceExport for existing Pods")
			switch tt.eventType {
			case addEvent:
				tt.podEvent.ResourceVersion = ""
				r.Client.Create(common.TestCtx, tt.podEvent, &client.CreateOptions{})
			case updateEvent:
				r.Client.Update(common.TestCtx, tt.podEvent, &client.UpdateOptions{})
			case deleteEvent:
				r.Client.Delete(common.TestCtx, tt.podEvent, &client.DeleteOptions{})
			}
			var err error
			req := ctrl.Request{NamespacedName: *tt.podNamespaceName}

			_, err = r.Reconcile(common.TestCtx, req)
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
			err = commonArea.List(common.TestCtx, actLabelIdentityResourceExports)
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
	fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(podA, podC, ns).Build()
	fakeRemoteClient := fake.NewClientBuilder().WithScheme(common.TestScheme).Build()
	commonArea := commonarea.NewFakeRemoteCommonArea(fakeRemoteClient, "leader-cluster", common.LocalClusterID, common.LeaderNamespace, nil)
	mcReconciler := NewMemberClusterSetReconciler(fakeClient, common.TestScheme, "default", true, false, make(chan struct{}))
	mcReconciler.SetRemoteCommonArea(commonArea)

	r := NewLabelIdentityReconciler(fakeClient, common.TestScheme, mcReconciler, "default")
	actualReq := r.namespaceMapFunc(context.Background(), ns)
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
		{
			"no Pod label",
			"test-ns",
			map[string]string{},
			map[string]string{"region": "west"},
			"ns:kubernetes.io/metadata.name=test-ns,region=west&pod:",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			normalizedLabel := GetNormalizedLabel(tt.nsLabels, tt.podLabels, tt.namespace)
			assert.Equal(t, tt.expNormalizedLabel, normalizedLabel)
		})
	}
}

func TestClusterSetMapFunc_LabelIdentity(t *testing.T) {
	clusterSet := &mcv1alpha2.ClusterSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "clusterset-test",
		},
		Status: mcv1alpha2.ClusterSetStatus{
			Conditions: []mcv1alpha2.ClusterSetCondition{
				{
					Status: v1.ConditionTrue,
					Type:   mcv1alpha2.ClusterSetReady,
				},
			},
		},
	}
	clusterSet2 := &mcv1alpha2.ClusterSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "clusterset-test-stale",
		},
	}
	pod1 := v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "pod1",
		},
	}
	pod2 := v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "kube-system",
			Name:      "pod2",
		},
	}
	pods := &v1.PodList{
		Items: []v1.Pod{
			pod1, pod2,
		},
	}
	expectedReqs := []reconcile.Request{
		{
			NamespacedName: types.NamespacedName{
				Name:      pod1.GetName(),
				Namespace: pod1.GetNamespace(),
			},
		},
		{
			NamespacedName: types.NamespacedName{
				Name:      pod2.GetName(),
				Namespace: pod2.GetNamespace(),
			},
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithObjects(clusterSet).WithLists(pods).Build()
	r := NewLabelIdentityReconciler(fakeClient, common.TestScheme, nil, clusterSet.Namespace)
	requests := r.clusterSetMapFunc(context.Background(), clusterSet)
	assert.Equal(t, expectedReqs, requests)

	r = NewLabelIdentityReconciler(fakeClient, common.TestScheme, nil, "mismatch_ns")
	requests = r.clusterSetMapFunc(context.Background(), clusterSet)
	assert.Equal(t, []reconcile.Request{}, requests)

	// non-existing ClusterSet
	r = NewLabelIdentityReconciler(fakeClient, common.TestScheme, nil, "default")
	r.labelToPodsCache["label"] = sets.New[string]("default/nginx")
	r.podLabelCache["default/nginx"] = "label"
	requests = r.clusterSetMapFunc(context.Background(), clusterSet2)
	assert.Equal(t, []reconcile.Request{}, requests)
	assert.Equal(t, 0, len(r.labelToPodsCache))
	assert.Equal(t, 0, len(r.labelToPodsCache))
}
