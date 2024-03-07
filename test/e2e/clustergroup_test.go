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
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
)

func testInvalidCGIPBlockWithPodSelector(t *testing.T) {
	invalidErr := fmt.Errorf("clustergroup created with ipblock and podSelector")
	cgName := "ipb-pod"
	pSel := &metav1.LabelSelector{MatchLabels: map[string]string{"pod": "x"}}
	cidr := "10.0.0.10/32"
	ipb := []crdv1beta1.IPBlock{{CIDR: cidr}}
	cg := &crdv1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: cgName,
		},
		Spec: crdv1beta1.GroupSpec{
			PodSelector: pSel,
			IPBlocks:    ipb,
		},
	}
	if _, err := k8sUtils.CreateOrUpdateCG(cg); err == nil {
		// Above creation of CG must fail as it is an invalid spec.
		failOnError(invalidErr, t)
	}
}

func testInvalidCGIPBlockWithNSSelector(t *testing.T) {
	invalidErr := fmt.Errorf("clustergroup created with ipblock and namespaceSelector")
	cgName := "ipb-ns"
	nSel := &metav1.LabelSelector{MatchLabels: map[string]string{"ns": getNS("y")}}
	cidr := "10.0.0.10/32"
	ipb := []crdv1beta1.IPBlock{{CIDR: cidr}}
	cg := &crdv1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: cgName,
		},
		Spec: crdv1beta1.GroupSpec{
			NamespaceSelector: nSel,
			IPBlocks:          ipb,
		},
	}
	if _, err := k8sUtils.CreateOrUpdateCG(cg); err == nil {
		// Above creation of CG must fail as it is an invalid spec.
		failOnError(invalidErr, t)
	}
}

func testInvalidCGServiceRefWithPodSelector(t *testing.T) {
	invalidErr := fmt.Errorf("clustergroup created with serviceReference and podSelector")
	cgName := "svcref-pod-selector"
	pSel := &metav1.LabelSelector{MatchLabels: map[string]string{"pod": "x"}}
	svcRef := &crdv1beta1.NamespacedName{
		Namespace: getNS("y"),
		Name:      "test-svc",
	}
	cg := &crdv1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: cgName,
		},
		Spec: crdv1beta1.GroupSpec{
			PodSelector:      pSel,
			ServiceReference: svcRef,
		},
	}
	if _, err := k8sUtils.CreateOrUpdateCG(cg); err == nil {
		// Above creation of CG must fail as it is an invalid spec.
		failOnError(invalidErr, t)
	}
}

func testInvalidCGServiceRefWithNSSelector(t *testing.T) {
	invalidErr := fmt.Errorf("clustergroup created with serviceReference and namespaceSelector")
	cgName := "svcref-ns-selector"
	nSel := &metav1.LabelSelector{MatchLabels: map[string]string{"ns": getNS("y")}}
	svcRef := &crdv1beta1.NamespacedName{
		Namespace: getNS("y"),
		Name:      "test-svc",
	}
	cg := &crdv1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: cgName,
		},
		Spec: crdv1beta1.GroupSpec{
			NamespaceSelector: nSel,
			ServiceReference:  svcRef,
		},
	}
	if _, err := k8sUtils.CreateOrUpdateCG(cg); err == nil {
		// Above creation of CG must fail as it is an invalid spec.
		failOnError(invalidErr, t)
	}
}

func testInvalidCGServiceRefWithIPBlock(t *testing.T) {
	invalidErr := fmt.Errorf("clustergroup created with ipblock and namespaceSelector")
	cgName := "ipb-svcref"
	cidr := "10.0.0.10/32"
	ipb := []crdv1beta1.IPBlock{{CIDR: cidr}}
	svcRef := &crdv1beta1.NamespacedName{
		Namespace: getNS("y"),
		Name:      "test-svc",
	}
	cg := &crdv1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: cgName,
		},
		Spec: crdv1beta1.GroupSpec{
			ServiceReference: svcRef,
			IPBlocks:         ipb,
		},
	}
	if _, err := k8sUtils.CreateOrUpdateCG(cg); err == nil {
		// Above creation of CG must fail as it is an invalid spec.
		failOnError(invalidErr, t)
	}
}

var testChildCGName = "test-child-cg"

func createChildCGForTest(t *testing.T) {
	cg := &crdv1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: testChildCGName,
		},
		Spec: crdv1beta1.GroupSpec{
			PodSelector: &metav1.LabelSelector{},
		},
	}
	if _, err := k8sUtils.CreateOrUpdateCG(cg); err != nil {
		failOnError(err, t)
	}
}

func cleanupChildCGForTest(t *testing.T) {
	if err := k8sUtils.DeleteCG(testChildCGName); err != nil {
		failOnError(err, t)
	}
}

func testInvalidCGChildGroupWithPodSelector(t *testing.T) {
	invalidErr := fmt.Errorf("clustergroup created with childGroups and podSelector")
	cgName := "child-group-pod-selector"
	pSel := &metav1.LabelSelector{MatchLabels: map[string]string{"pod": "x"}}
	cg := &crdv1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: cgName,
		},
		Spec: crdv1beta1.GroupSpec{
			PodSelector: pSel,
			ChildGroups: []crdv1beta1.ClusterGroupReference{crdv1beta1.ClusterGroupReference(testChildCGName)},
		},
	}
	if _, err := k8sUtils.CreateOrUpdateCG(cg); err == nil {
		// Above creation of CG must fail as it is an invalid spec.
		failOnError(invalidErr, t)
	}
}

func testInvalidCGChildGroupWithServiceReference(t *testing.T) {
	invalidErr := fmt.Errorf("clustergroup created with childGroups and ServiceReference")
	cgName := "child-group-svcref"
	svcRef := &crdv1beta1.NamespacedName{
		Namespace: getNS("y"),
		Name:      "test-svc",
	}
	cg := &crdv1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: cgName,
		},
		Spec: crdv1beta1.GroupSpec{
			ServiceReference: svcRef,
			ChildGroups:      []crdv1beta1.ClusterGroupReference{crdv1beta1.ClusterGroupReference(testChildCGName)},
		},
	}
	if _, err := k8sUtils.CreateOrUpdateCG(cg); err == nil {
		// Above creation of CG must fail as it is an invalid spec.
		failOnError(invalidErr, t)
	}
}

func testInvalidCGMaxNestedLevel(t *testing.T) {
	invalidErr := fmt.Errorf("clustergroup created with childGroup which has childGroups itself")
	cgName1, cgName2 := "cg-nested-1", "cg-nested-2"
	cg1 := &crdv1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: cgName1},
		Spec: crdv1beta1.GroupSpec{
			ChildGroups: []crdv1beta1.ClusterGroupReference{crdv1beta1.ClusterGroupReference(testChildCGName)},
		},
	}
	cg2 := &crdv1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: cgName2},
		Spec: crdv1beta1.GroupSpec{
			ChildGroups: []crdv1beta1.ClusterGroupReference{crdv1beta1.ClusterGroupReference(cgName1)},
		},
	}
	// Try to create cg-nested-1 first and then cg-nested-2.
	// The creation of cg-nested-2 should fail as it breaks the max nested level
	if _, err := k8sUtils.CreateOrUpdateCG(cg1); err != nil {
		// Above creation of CG must succeed as it is a valid spec.
		failOnError(err, t)
	}
	if _, err := k8sUtils.CreateOrUpdateCG(cg2); err == nil {
		// Above creation of CG must fail as cg-nested-2 cannot have cg-nested-1 as childGroup.
		failOnError(invalidErr, t)
	}
	// cleanup cg-nested-1
	if err := k8sUtils.DeleteCG(cgName1); err != nil {
		failOnError(err, t)
	}
	// Try to create cg-nested-2 first and then cg-nested-1.
	// The creation of cg-nested-1 should fail as it breaks the max nested level
	if _, err := k8sUtils.CreateOrUpdateCG(cg2); err != nil {
		// Above creation of CG must succeed as it is a valid spec.
		failOnError(err, t)
	}
	if _, err := k8sUtils.CreateOrUpdateCG(cg1); err == nil {
		// Above creation of CG must fail as cg-nested-2 cannot have cg-nested-1 as childGroup.
		failOnError(invalidErr, t)
	}
	// cleanup cg-nested-2
	if err := k8sUtils.DeleteCG(cgName2); err != nil {
		failOnError(err, t)
	}
}

func getRealizationStatus(cg *crdv1beta1.ClusterGroup) v1.ConditionStatus {
	conds := cg.Status.Conditions
	for _, cond := range conds {
		if cond.Type == crdv1beta1.GroupMembersComputed && cond.Status == v1.ConditionTrue {
			return v1.ConditionTrue
		}
	}
	return v1.ConditionFalse
}

func testClusterGroupRealizationStatus(t *testing.T) {
	invalidErr1 := fmt.Errorf("clustergroup with child groups should only be considered realized when all its child groups are realized")
	invalidErr2 := fmt.Errorf("clustergroup with selectors or serviceRef should be realized once processed")
	childCG1Returned, _ := k8sUtils.GetCG(testChildCGName)
	// test-child-cg should be considered realized as soon as its synced.
	if getRealizationStatus(childCG1Returned) != v1.ConditionTrue {
		failOnError(invalidErr2, t)
	}
	cgParent := &crdv1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: "parent-cg"},
		Spec: crdv1beta1.GroupSpec{
			ChildGroups: []crdv1beta1.ClusterGroupReference{
				crdv1beta1.ClusterGroupReference(testChildCGName),
				crdv1beta1.ClusterGroupReference("child-cg-2"),
			},
		},
	}
	if _, err := k8sUtils.CreateOrUpdateCG(cgParent); err != nil {
		// Above creation of CG must succeed as it is a valid spec.
		failOnError(err, t)
	}
	time.Sleep(networkPolicyDelay / 2)
	cgParentReturned, _ := k8sUtils.GetCG("parent-cg")
	// cgParent should not be considered realized yet since child-cg-2 is not yet created.
	if getRealizationStatus(cgParentReturned) != v1.ConditionFalse {
		failOnError(invalidErr1, t)
	}
	cgChild2 := &crdv1beta1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: "child-cg-2",
		},
		Spec: crdv1beta1.GroupSpec{
			IPBlocks: []crdv1beta1.IPBlock{
				{CIDR: "192.168.2.0/24"},
			},
		},
	}
	if _, err := k8sUtils.CreateOrUpdateCG(cgChild2); err != nil {
		// Above creation of CG must succeed as it is a valid spec.
		failOnError(err, t)
	}
	time.Sleep(networkPolicyDelay / 2)
	childCG2Returned, _ := k8sUtils.GetCG("child-cg-2")
	// child-cg-2 should be considered realized as soon as its synced.
	if getRealizationStatus(childCG2Returned) != v1.ConditionTrue {
		failOnError(invalidErr2, t)
	}
	cgParentReturned, _ = k8sUtils.GetCG("parent-cg")
	// cgParent should now be considered realized.
	if getRealizationStatus(cgParentReturned) != v1.ConditionTrue {
		failOnError(invalidErr1, t)
	}

}

func TestClusterGroup(t *testing.T) {
	skipIfHasWindowsNodes(t)
	skipIfAntreaPolicyDisabled(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	initialize(t, data, nil)

	t.Run("TestGroupClusterGroupValidate", func(t *testing.T) {
		t.Run("Case=IPBlockWithPodSelectorDenied", func(t *testing.T) { testInvalidCGIPBlockWithPodSelector(t) })
		t.Run("Case=IPBlockWithNamespaceSelectorDenied", func(t *testing.T) { testInvalidCGIPBlockWithNSSelector(t) })
		t.Run("Case=ServiceRefWithPodSelectorDenied", func(t *testing.T) { testInvalidCGServiceRefWithPodSelector(t) })
		t.Run("Case=ServiceRefWithNamespaceSelectorDenied", func(t *testing.T) { testInvalidCGServiceRefWithNSSelector(t) })
		t.Run("Case=ServiceRefWithIPBlockDenied", func(t *testing.T) { testInvalidCGServiceRefWithIPBlock(t) })
	})
	t.Run("TestGroupClusterGroupValidateChildGroup", func(t *testing.T) {
		createChildCGForTest(t)
		t.Run("Case=ChildGroupWithPodSelectorDenied", func(t *testing.T) { testInvalidCGChildGroupWithPodSelector(t) })
		t.Run("Case=ChildGroupWithPodServiceReferenceDenied", func(t *testing.T) { testInvalidCGChildGroupWithServiceReference(t) })
		t.Run("Case=ChildGroupExceedMaxNestedLevel", func(t *testing.T) { testInvalidCGMaxNestedLevel(t) })
		t.Run("Case=ClusterGroupRealizationStatusWithChildGroups", func(t *testing.T) { testClusterGroupRealizationStatus(t) })
		cleanupChildCGForTest(t)
	})
	k8sUtils.Cleanup(namespaces) // clean up all cluster-scope resources, including CGs
}
