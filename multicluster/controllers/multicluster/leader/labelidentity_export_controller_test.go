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

package leader

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	mcsv1alpha1 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha1"
	"antrea.io/antrea/multicluster/controllers/multicluster/common"
)

var (
	normalizedLabel = "ns:kubernetes.io/metadata.name=test-ns&pod:app=client"
	labelHash       = common.HashLabelIdentity(normalizedLabel)

	resExpNamespacedName = types.NamespacedName{
		Namespace: common.LeaderNamespace,
		Name:      common.LocalClusterID + "-" + labelHash,
	}

	labelIdentityResExp = &mcsv1alpha1.ResourceExport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: common.LeaderNamespace,
			Name:      common.LocalClusterID + "-" + labelHash,
		},
		Spec: mcsv1alpha1.ResourceExportSpec{
			ClusterID: common.LocalClusterID,
			LabelIdentity: &mcsv1alpha1.LabelIdentityExport{
				NormalizedLabel: normalizedLabel,
			},
		},
	}
	labelIdentityResImp = &mcsv1alpha1.ResourceImport{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: common.LeaderNamespace,
			Name:      labelHash,
		},
		Spec: mcsv1alpha1.ResourceImportSpec{
			ClusterIDs: []string{common.LocalClusterID},
			LabelIdentity: &mcsv1alpha1.LabelIdentitySpec{
				Label: normalizedLabel,
				ID:    1,
			},
		},
	}

	clusterBID                   = "cluster-b"
	resExpNamespacedNameClusterB = types.NamespacedName{
		Namespace: "cluster-b-namespace",
		Name:      clusterBID + "-" + labelHash,
	}
)

func TestLabelIdentityResourceExportReconclie(t *testing.T) {
	tests := []struct {
		name                     string
		existingResExp           *mcsv1alpha1.ResourceExportList
		existingResImp           *mcsv1alpha1.ResourceImportList
		resExpNamespacedName     types.NamespacedName
		expNormalizedLabel       string
		originalLabelsToClusters map[string]sets.Set[string]
		originalClusterToLabels  map[string]sets.Set[string]
		expLabelsToClusters      map[string]sets.Set[string]
		expClusterToLabels       map[string]sets.Set[string]
		expLabelResImpDeleted    bool
	}{
		{
			name: "create LabelIdentity kind of ResImp",
			existingResExp: &mcsv1alpha1.ResourceExportList{
				Items: []mcsv1alpha1.ResourceExport{*labelIdentityResExp},
			},
			existingResImp:        &mcsv1alpha1.ResourceImportList{},
			resExpNamespacedName:  resExpNamespacedName,
			expNormalizedLabel:    normalizedLabel,
			expLabelsToClusters:   map[string]sets.Set[string]{labelHash: sets.New[string](common.LocalClusterID)},
			expClusterToLabels:    map[string]sets.Set[string]{common.LocalClusterID: sets.New[string](labelHash)},
			expLabelResImpDeleted: false,
		},
		{
			name: "LabelIdentity kind of ResImp already exist",
			existingResExp: &mcsv1alpha1.ResourceExportList{
				Items: []mcsv1alpha1.ResourceExport{*labelIdentityResExp},
			},
			existingResImp: &mcsv1alpha1.ResourceImportList{
				Items: []mcsv1alpha1.ResourceImport{*labelIdentityResImp},
			},
			resExpNamespacedName:  resExpNamespacedName,
			expNormalizedLabel:    normalizedLabel,
			expLabelsToClusters:   map[string]sets.Set[string]{labelHash: sets.New[string](common.LocalClusterID)},
			expClusterToLabels:    map[string]sets.Set[string]{common.LocalClusterID: sets.New[string](labelHash)},
			expLabelResImpDeleted: false,
		},
		{
			name: "ResExport delete LabelIdentity not stale in ClusterSet",
			existingResExp: &mcsv1alpha1.ResourceExportList{
				Items: []mcsv1alpha1.ResourceExport{*labelIdentityResExp},
			},
			existingResImp: &mcsv1alpha1.ResourceImportList{
				Items: []mcsv1alpha1.ResourceImport{*labelIdentityResImp},
			},
			resExpNamespacedName:     resExpNamespacedNameClusterB,
			expNormalizedLabel:       normalizedLabel,
			originalLabelsToClusters: map[string]sets.Set[string]{labelHash: sets.New[string](common.LocalClusterID, clusterBID)},
			originalClusterToLabels:  map[string]sets.Set[string]{common.LocalClusterID: sets.New[string](labelHash), clusterBID: sets.New[string](labelHash)},
			expLabelsToClusters:      map[string]sets.Set[string]{labelHash: sets.New[string](common.LocalClusterID)},
			expClusterToLabels:       map[string]sets.Set[string]{common.LocalClusterID: sets.New[string](labelHash), clusterBID: sets.New[string]()},
			expLabelResImpDeleted:    false,
		},
		{
			name:           "delete LabelIdentity kind of ResImp",
			existingResExp: &mcsv1alpha1.ResourceExportList{},
			existingResImp: &mcsv1alpha1.ResourceImportList{
				Items: []mcsv1alpha1.ResourceImport{*labelIdentityResImp},
			},
			resExpNamespacedName:     resExpNamespacedName,
			expNormalizedLabel:       "",
			originalLabelsToClusters: map[string]sets.Set[string]{labelHash: sets.New[string](common.LocalClusterID)},
			originalClusterToLabels:  map[string]sets.Set[string]{common.LocalClusterID: sets.New[string](labelHash)},
			expLabelsToClusters:      map[string]sets.Set[string]{},
			expClusterToLabels:       map[string]sets.Set[string]{common.LocalClusterID: sets.New[string]()},
			expLabelResImpDeleted:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stopCh := make(chan struct{})
			defer close(stopCh)

			fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithLists(tt.existingResExp, tt.existingResImp).Build()
			r := NewLabelIdentityExportReconciler(fakeClient, common.TestScheme, common.LeaderNamespace)
			if len(tt.originalLabelsToClusters) > 0 {
				r.clusterToLabels = tt.originalClusterToLabels
				r.labelsToClusters = tt.originalLabelsToClusters
			}
			go r.Run(stopCh)
			resExpReq := ctrl.Request{NamespacedName: tt.resExpNamespacedName}
			if _, err := r.Reconcile(common.TestCtx, resExpReq); err != nil {
				t.Errorf("LabelIdentityExport Reconciler got error during reconciling. error = %v", err)
			}

			if !reflect.DeepEqual(r.labelsToClusters, tt.expLabelsToClusters) {
				t.Errorf("LabelIdentityExport Reconciler yield incorrect labelsToClusters. Exp: %s, Act: %s", tt.expLabelsToClusters, r.labelsToClusters)
			}
			if !reflect.DeepEqual(r.clusterToLabels, tt.expClusterToLabels) {
				t.Errorf("LabelIdentityExport Reconciler yield incorrect clusterToLabels. Exp: %s, Act: %s", tt.expClusterToLabels, r.clusterToLabels)
			}

			time.Sleep(100 * time.Millisecond)
			actLabelIdentityResImp := &mcsv1alpha1.ResourceImport{}
			lastIdx := strings.LastIndex(tt.resExpNamespacedName.Name, "-")
			parsedLabelHash := tt.resExpNamespacedName.Name[lastIdx+1:]
			err := fakeClient.Get(common.TestCtx, types.NamespacedName{Namespace: "default", Name: parsedLabelHash}, actLabelIdentityResImp)
			assert.Equalf(t, tt.expLabelResImpDeleted, apierrors.IsNotFound(err), "Unexpected error status when getting LabelIdentity kind of ResourceImport: %v", err)
			if tt.expNormalizedLabel != "" {
				actualLabel := actLabelIdentityResImp.Spec.LabelIdentity.Label
				assert.Equalf(t, tt.expNormalizedLabel, actualLabel, "Unexpected normalized label in ResourceImport. Exp: %s, Act: %s", tt.expNormalizedLabel, actualLabel)
			}
		})
	}
}

func TestConcurrentProcessLabelForResourceImport(t *testing.T) {
	existingResImpList := &mcsv1alpha1.ResourceImportList{
		Items: []mcsv1alpha1.ResourceImport{*labelIdentityResImp},
	}
	stopCh := make(chan struct{})
	defer close(stopCh)
	fakeClient := fake.NewClientBuilder().WithScheme(common.TestScheme).WithLists(existingResImpList).Build()
	r := NewLabelIdentityExportReconciler(fakeClient, common.TestScheme, common.LeaderNamespace)
	r.hashToLabels = map[string]string{
		labelHash: normalizedLabel,
	}
	r.labelQueue.Add(labelHash)
	for i := 2; i <= 40; i++ {
		l := normalizedLabel + strconv.Itoa(i)
		lHash := common.HashLabelIdentity(l)
		r.labelQueue.Add(lHash)
		// Simulate 20 LabelIdentity ResourceImport add events and 20 delete events
		if i <= 20 {
			// When label hash is present in the reconciler, it means the corresponding
			// ResourceExport exists.
			r.hashToLabels[lHash] = l
		}
	}
	// Mock the state of the reconciler where id 1 was allocated for labelHash
	r.labelsToID.Store(labelHash, uint32(1))
	r.allocator.setAllocated(1)
	// Spin off more workers to bump up concurrency
	r.numWorkers = common.DefaultWorkerCount * 2
	go r.Run(stopCh)

	// The ResourceImport corresponding to label 21-40 should be deleted as the mocked hashToLabels
	// map indicates its ResourceExport has been deleted. ResourceImport for label1 should not change
	// and ResourceImport for label 2-20 should be created.
	assert.Eventually(t, func() bool {
		actLabelIdentityResImpList := &mcsv1alpha1.ResourceImportList{}
		fakeClient.List(common.TestCtx, actLabelIdentityResImpList)
		if len(actLabelIdentityResImpList.Items) != 20 {
			return false
		}
		for _, resImp := range actLabelIdentityResImpList.Items {
			id, ok := r.labelsToID.Load(resImp.Name)
			assert.Truef(t, ok, "ResourceImport's label hash should be stored")
			assert.Equalf(t, id, resImp.Spec.LabelIdentity.ID, "Cached ID for label should match")
		}
		return true
	}, time.Millisecond*200, time.Millisecond*10, "Unexpected number of ResourceImport after test is executed")
}

func TestIDAllocatorBasic(t *testing.T) {
	testSteps := []struct {
		op                        string
		idExpectedOrReleasing     uint32
		expectedAvailableReuseIDs int
		expectErr                 bool
	}{
		{
			"allocate",
			1,
			0,
			false,
		},
		{
			"allocate",
			2,
			0,
			false,
		},
		{
			"allocate",
			3,
			0,
			false,
		},
		{
			"release",
			2,
			1,
			false,
		},
		{
			"release",
			1,
			2,
			false,
		},
		{
			"allocate",
			1,
			1,
			false,
		},
		{
			"allocate",
			2,
			0,
			false,
		},
		{
			"allocate",
			0,
			0,
			true,
		},
	}
	idAllocator := newIDAllocator(1, 3)
	for _, step := range testSteps {
		if step.op == "allocate" {
			id, err := idAllocator.allocate()
			if step.expectErr && err == nil {
				t.Errorf("Expect id allocation to fail because the pool is exhausted, but got id %d", id)
			} else if !step.expectErr && err != nil {
				t.Errorf("Expect allocation to succeed but got err %v", err)
			}
			if id != step.idExpectedOrReleasing {
				t.Errorf("ID allocated is not expected, expect %d, got %d", step.expectedAvailableReuseIDs, id)
			}
		} else {
			idAllocator.release(step.idExpectedOrReleasing)
		}
		if idAllocator.releasedIDs.Len() != step.expectedAvailableReuseIDs {
			t.Errorf("Unexpected number of IDs available for reuse")
		}
	}
}

func TestIDAllocatorWithPreAllocation(t *testing.T) {
	testSteps := []struct {
		op                        string
		id                        uint32
		expectedAvailableReuseIDs int
		expectedPreAllocatedIDs   int
		expectErr                 bool
	}{
		{
			"setAllocated",
			4,
			0,
			1,
			false,
		},
		{
			"setAllocated",
			1,
			0,
			2,
			false,
		},
		{
			"setAllocated",
			2,
			0,
			3,
			false,
		},
		{
			"allocate",
			3,
			0,
			3,
			false,
		},
		{
			"setAllocated",
			3,
			0,
			3,
			true,
		},
		{
			"release",
			2,
			1,
			2,
			false,
		},
		{
			"allocate",
			2,
			0,
			2,
			false,
		},
		{
			"allocate",
			0,
			0,
			2,
			true,
		},
	}
	idAllocator := newIDAllocator(1, 4)
	for _, step := range testSteps {
		switch step.op {
		case "setAllocated":
			err := idAllocator.setAllocated(step.id)
			if step.expectErr && err == nil {
				t.Errorf("Expect setting id allocated to fail but succeeded")
			} else if !step.expectErr && err != nil {
				t.Errorf("Expect set allocation to succeed but got err %v", err)
			}
		case "allocate":
			id, err := idAllocator.allocate()
			if step.expectErr && err == nil {
				t.Errorf("Expect id allocation to fail because the pool is exhausted, but got id %d", id)
			}
			if id != step.id {
				t.Errorf("ID allocated is not expected, expect %d, got %d", step.id, id)
			}
		case "release":
			idAllocator.release(step.id)
		}
		if idAllocator.previouslyAllocatedIDs.Len() != step.expectedPreAllocatedIDs {
			t.Errorf("Unexpected number of pre-allocated IDs on step %s %d, expect: %d actual: %d",
				step.op, step.id, step.expectedPreAllocatedIDs, idAllocator.previouslyAllocatedIDs.Len())
		}
		if idAllocator.releasedIDs.Len() != step.expectedAvailableReuseIDs {
			t.Errorf("Unexpected number of IDs available for reuse on step %s %d, expect: %d actual: %d",
				step.op, step.id, step.expectedAvailableReuseIDs, idAllocator.releasedIDs.Len())
		}
	}
}
