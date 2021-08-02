// Copyright 2021 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package e2e

import (
	"fmt"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	crdv1alpha2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	legacycorev1alpha2 "antrea.io/antrea/pkg/legacyapis/core/v1alpha2"
)

func testLegacyInvalidCGIPBlockWithPodSelector(t *testing.T) {
	invalidErr := fmt.Errorf("clustergroup created with ipblock and podSelector")
	cgName := "ipb-pod"
	pSel := &metav1.LabelSelector{MatchLabels: map[string]string{"pod": "x"}}
	cidr := "10.0.0.10/32"
	ipb := &crdv1alpha1.IPBlock{CIDR: cidr}
	cg := &legacycorev1alpha2.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: cgName,
		},
		Spec: crdv1alpha2.GroupSpec{
			PodSelector: pSel,
			IPBlock:     ipb,
		},
	}
	if _, err := k8sUtils.CreateOrUpdateLegacyCG(cg); err == nil {
		// Above creation of CG must fail as it is an invalid spec.
		failOnError(invalidErr, t)
	}
}

func testLegacyInvalidCGIPBlockWithNSSelector(t *testing.T) {
	invalidErr := fmt.Errorf("clustergroup created with ipblock and namespaceSelector")
	cgName := "ipb-ns"
	nSel := &metav1.LabelSelector{MatchLabels: map[string]string{"ns": "y"}}
	cidr := "10.0.0.10/32"
	ipb := &crdv1alpha1.IPBlock{CIDR: cidr}
	cg := &legacycorev1alpha2.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: cgName,
		},
		Spec: crdv1alpha2.GroupSpec{
			NamespaceSelector: nSel,
			IPBlock:           ipb,
		},
	}
	if _, err := k8sUtils.CreateOrUpdateLegacyCG(cg); err == nil {
		// Above creation of CG must fail as it is an invalid spec.
		failOnError(invalidErr, t)
	}
}

func testLegacyInvalidCGServiceRefWithPodSelector(t *testing.T) {
	invalidErr := fmt.Errorf("clustergroup created with serviceReference and podSelector")
	cgName := "svcref-pod-selector"
	pSel := &metav1.LabelSelector{MatchLabels: map[string]string{"pod": "x"}}
	svcRef := &crdv1alpha2.ServiceReference{
		Namespace: "y",
		Name:      "test-svc",
	}
	cg := &legacycorev1alpha2.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: cgName,
		},
		Spec: crdv1alpha2.GroupSpec{
			PodSelector:      pSel,
			ServiceReference: svcRef,
		},
	}
	if _, err := k8sUtils.CreateOrUpdateLegacyCG(cg); err == nil {
		// Above creation of CG must fail as it is an invalid spec.
		failOnError(invalidErr, t)
	}
}

func testLegacyInvalidCGServiceRefWithNSSelector(t *testing.T) {
	invalidErr := fmt.Errorf("clustergroup created with serviceReference and namespaceSelector")
	cgName := "svcref-ns-selector"
	nSel := &metav1.LabelSelector{MatchLabels: map[string]string{"ns": "y"}}
	svcRef := &crdv1alpha2.ServiceReference{
		Namespace: "y",
		Name:      "test-svc",
	}
	cg := &legacycorev1alpha2.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: cgName,
		},
		Spec: crdv1alpha2.GroupSpec{
			NamespaceSelector: nSel,
			ServiceReference:  svcRef,
		},
	}
	if _, err := k8sUtils.CreateOrUpdateLegacyCG(cg); err == nil {
		// Above creation of CG must fail as it is an invalid spec.
		failOnError(invalidErr, t)
	}
}

func testLegacyInvalidCGServiceRefWithIPBlock(t *testing.T) {
	invalidErr := fmt.Errorf("clustergroup created with ipblock and namespaceSelector")
	cgName := "ipb-svcref"
	cidr := "10.0.0.10/32"
	ipb := &crdv1alpha1.IPBlock{CIDR: cidr}
	svcRef := &crdv1alpha2.ServiceReference{
		Namespace: "y",
		Name:      "test-svc",
	}
	cg := &legacycorev1alpha2.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: cgName,
		},
		Spec: crdv1alpha2.GroupSpec{
			ServiceReference: svcRef,
			IPBlock:          ipb,
		},
	}
	if _, err := k8sUtils.CreateOrUpdateLegacyCG(cg); err == nil {
		// Above creation of CG must fail as it is an invalid spec.
		failOnError(invalidErr, t)
	}
}

func createLegacyChildCGForTest(t *testing.T) {
	cg := &legacycorev1alpha2.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: testChildCGName,
		},
		Spec: crdv1alpha2.GroupSpec{
			PodSelector: &metav1.LabelSelector{},
		},
	}
	if _, err := k8sUtils.CreateOrUpdateLegacyCG(cg); err != nil {
		failOnError(err, t)
	}
}

func cleanupLegacyChildCGForTest(t *testing.T) {
	if err := k8sUtils.DeleteLegacyCG(testChildCGName); err != nil {
		failOnError(err, t)
	}
}

func testLegacyInvalidCGChildGroupWithPodSelector(t *testing.T) {
	invalidErr := fmt.Errorf("clustergroup created with childGroups and podSelector")
	cgName := "child-group-pod-selector"
	pSel := &metav1.LabelSelector{MatchLabels: map[string]string{"pod": "x"}}
	cg := &legacycorev1alpha2.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: cgName,
		},
		Spec: crdv1alpha2.GroupSpec{
			PodSelector: pSel,
			ChildGroups: []crdv1alpha2.ClusterGroupReference{crdv1alpha2.ClusterGroupReference(testChildCGName)},
		},
	}
	if _, err := k8sUtils.CreateOrUpdateLegacyCG(cg); err == nil {
		// Above creation of CG must fail as it is an invalid spec.
		failOnError(invalidErr, t)
	}
}

func testLegacyInvalidCGChildGroupWithServiceReference(t *testing.T) {
	invalidErr := fmt.Errorf("clustergroup created with childGroups and ServiceReference")
	cgName := "child-group-svcref"
	svcRef := &crdv1alpha2.ServiceReference{
		Namespace: "y",
		Name:      "test-svc",
	}
	cg := &legacycorev1alpha2.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: cgName,
		},
		Spec: crdv1alpha2.GroupSpec{
			ServiceReference: svcRef,
			ChildGroups:      []crdv1alpha2.ClusterGroupReference{crdv1alpha2.ClusterGroupReference(testChildCGName)},
		},
	}
	if _, err := k8sUtils.CreateOrUpdateLegacyCG(cg); err == nil {
		// Above creation of CG must fail as it is an invalid spec.
		failOnError(invalidErr, t)
	}
}

func testLegacyInvalidCGMaxNestedLevel(t *testing.T) {
	invalidErr := fmt.Errorf("clustergroup created with childGroup which has childGroups itself")
	cgName1, cgName2 := "cg-nested-1", "cg-nested-2"
	cg1 := &legacycorev1alpha2.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: cgName1},
		Spec: crdv1alpha2.GroupSpec{
			ChildGroups: []crdv1alpha2.ClusterGroupReference{crdv1alpha2.ClusterGroupReference(testChildCGName)},
		},
	}
	if _, err := k8sUtils.CreateOrUpdateLegacyCG(cg1); err != nil {
		// Above creation of CG must succeed as it is a valid spec.
		failOnError(err, t)
	}
	cg2 := &legacycorev1alpha2.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: cgName2},
		Spec: crdv1alpha2.GroupSpec{
			ChildGroups: []crdv1alpha2.ClusterGroupReference{crdv1alpha2.ClusterGroupReference(cgName1)},
		},
	}
	if _, err := k8sUtils.CreateOrUpdateLegacyCG(cg2); err == nil {
		// Above creation of CG must fail as it is an invalid spec.
		failOnError(invalidErr, t)
	}
	// cleanup cg-nested-1
	if err := k8sUtils.DeleteLegacyCG(cgName1); err != nil {
		failOnError(err, t)
	}
}

// TestLegacyClusterGroup is the top-level test which contains all subtests for
// LegacyClusterGroup related test cases so they can share setup, teardown.
func TestLegacyClusterGroup(t *testing.T) {
	skipIfProviderIs(t, "kind", "This test is for legacy API groups and is almost the same as new API groups'.")
	skipIfHasWindowsNodes(t)
	skipIfAntreaPolicyDisabled(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
	initialize(t, data)

	t.Run("TestLegacyGroupClusterGroupValidate", func(t *testing.T) {
		t.Run("Case=LegacyIPBlockWithPodSelectorDenied", func(t *testing.T) { testLegacyInvalidCGIPBlockWithPodSelector(t) })
		t.Run("Case=LegacyIPBlockWithNamespaceSelectorDenied", func(t *testing.T) { testLegacyInvalidCGIPBlockWithNSSelector(t) })
		t.Run("Case=LegacyServiceRefWithPodSelectorDenied", func(t *testing.T) { testLegacyInvalidCGServiceRefWithPodSelector(t) })
		t.Run("Case=LegacyServiceRefWithNamespaceSelectorDenied", func(t *testing.T) { testLegacyInvalidCGServiceRefWithNSSelector(t) })
		t.Run("Case=LegacyServiceRefWithIPBlockDenied", func(t *testing.T) { testLegacyInvalidCGServiceRefWithIPBlock(t) })
	})

	t.Run("TestLegacyGroupClusterGroupValidateChildGroup", func(t *testing.T) {
		createLegacyChildCGForTest(t)
		t.Run("Case=LegacyChildGroupWithPodSelectorDenied", func(t *testing.T) { testLegacyInvalidCGChildGroupWithPodSelector(t) })
		t.Run("Case=LegacyChildGroupWithPodServiceReferenceDenied", func(t *testing.T) { testLegacyInvalidCGChildGroupWithServiceReference(t) })
		t.Run("Case=LegacyChildGroupExceedMaxNestedLevel", func(t *testing.T) { testLegacyInvalidCGMaxNestedLevel(t) })
		cleanupLegacyChildCGForTest(t)
	})

	k8sUtils.LegacyCleanup(namespaces) // clean up all cluster-scope resources, including CGs
}
