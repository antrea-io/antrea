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

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	crdv1alpha2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	crdv1alpha3 "antrea.io/antrea/pkg/apis/crd/v1alpha3"
)

func testInvalidCGIPBlockWithPodSelector(t *testing.T) {
	invalidErr := fmt.Errorf("clustergroup created with ipblock and podSelector")
	cgName := "ipb-pod"
	pSel := &metav1.LabelSelector{MatchLabels: map[string]string{"pod": "x"}}
	cidr := "10.0.0.10/32"
	ipb := []crdv1alpha1.IPBlock{{CIDR: cidr}}
	cg := &crdv1alpha3.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: cgName,
		},
		Spec: crdv1alpha3.GroupSpec{
			PodSelector: pSel,
			IPBlocks:    ipb,
		},
	}
	if _, err := k8sUtils.CreateOrUpdateV1Alpha3CG(cg); err == nil {
		// Above creation of CG must fail as it is an invalid spec.
		failOnError(invalidErr, t)
	}
}

func testInvalidCGIPBlockWithNSSelector(t *testing.T) {
	invalidErr := fmt.Errorf("clustergroup created with ipblock and namespaceSelector")
	cgName := "ipb-ns"
	nSel := &metav1.LabelSelector{MatchLabels: map[string]string{"ns": "y"}}
	cidr := "10.0.0.10/32"
	ipb := []crdv1alpha1.IPBlock{{CIDR: cidr}}
	cg := &crdv1alpha3.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: cgName,
		},
		Spec: crdv1alpha3.GroupSpec{
			NamespaceSelector: nSel,
			IPBlocks:          ipb,
		},
	}
	if _, err := k8sUtils.CreateOrUpdateV1Alpha3CG(cg); err == nil {
		// Above creation of CG must fail as it is an invalid spec.
		failOnError(invalidErr, t)
	}
}

func testInvalidCGIPBlockWithIPBlocks(t *testing.T) {
	invalidErr := fmt.Errorf("clustergroup created with ipBlock and ipBlocks")
	cgName := "ipb-ipbs"
	cidr := "10.0.0.10/32"
	cidr2 := "10.0.0.20/32"
	ipb := &crdv1alpha1.IPBlock{CIDR: cidr}
	ipbs := []crdv1alpha1.IPBlock{{CIDR: cidr2}}
	cg := &crdv1alpha2.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: cgName,
		},
		Spec: crdv1alpha2.GroupSpec{
			IPBlocks: ipbs,
			IPBlock:  ipb,
		},
	}
	if _, err := k8sUtils.CreateOrUpdateV1Alpha2CG(cg); err == nil {
		// Above creation of CG must fail as it is an invalid spec.
		failOnError(invalidErr, t)
	}
}

func testInvalidCGServiceRefWithPodSelector(t *testing.T) {
	invalidErr := fmt.Errorf("clustergroup created with serviceReference and podSelector")
	cgName := "svcref-pod-selector"
	pSel := &metav1.LabelSelector{MatchLabels: map[string]string{"pod": "x"}}
	svcRef := &crdv1alpha3.ServiceReference{
		Namespace: "y",
		Name:      "test-svc",
	}
	cg := &crdv1alpha3.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: cgName,
		},
		Spec: crdv1alpha3.GroupSpec{
			PodSelector:      pSel,
			ServiceReference: svcRef,
		},
	}
	if _, err := k8sUtils.CreateOrUpdateV1Alpha3CG(cg); err == nil {
		// Above creation of CG must fail as it is an invalid spec.
		failOnError(invalidErr, t)
	}
}

func testInvalidCGServiceRefWithNSSelector(t *testing.T) {
	invalidErr := fmt.Errorf("clustergroup created with serviceReference and namespaceSelector")
	cgName := "svcref-ns-selector"
	nSel := &metav1.LabelSelector{MatchLabels: map[string]string{"ns": "y"}}
	svcRef := &crdv1alpha3.ServiceReference{
		Namespace: "y",
		Name:      "test-svc",
	}
	cg := &crdv1alpha3.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: cgName,
		},
		Spec: crdv1alpha3.GroupSpec{
			NamespaceSelector: nSel,
			ServiceReference:  svcRef,
		},
	}
	if _, err := k8sUtils.CreateOrUpdateV1Alpha3CG(cg); err == nil {
		// Above creation of CG must fail as it is an invalid spec.
		failOnError(invalidErr, t)
	}
}

func testInvalidCGServiceRefWithIPBlock(t *testing.T) {
	invalidErr := fmt.Errorf("clustergroup created with ipblock and namespaceSelector")
	cgName := "ipb-svcref"
	cidr := "10.0.0.10/32"
	ipb := []crdv1alpha1.IPBlock{{CIDR: cidr}}
	svcRef := &crdv1alpha3.ServiceReference{
		Namespace: "y",
		Name:      "test-svc",
	}
	cg := &crdv1alpha3.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: cgName,
		},
		Spec: crdv1alpha3.GroupSpec{
			ServiceReference: svcRef,
			IPBlocks:         ipb,
		},
	}
	if _, err := k8sUtils.CreateOrUpdateV1Alpha3CG(cg); err == nil {
		// Above creation of CG must fail as it is an invalid spec.
		failOnError(invalidErr, t)
	}
}

var testChildCGName = "test-child-cg"

func createChildCGForTest(t *testing.T) {
	cg := &crdv1alpha3.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: testChildCGName,
		},
		Spec: crdv1alpha3.GroupSpec{
			PodSelector: &metav1.LabelSelector{},
		},
	}
	if _, err := k8sUtils.CreateOrUpdateV1Alpha3CG(cg); err != nil {
		failOnError(err, t)
	}
}

func cleanupChildCGForTest(t *testing.T) {
	if err := k8sUtils.DeleteV1Alpha3CG(testChildCGName); err != nil {
		failOnError(err, t)
	}
}

func testInvalidCGChildGroupWithPodSelector(t *testing.T) {
	invalidErr := fmt.Errorf("clustergroup created with childGroups and podSelector")
	cgName := "child-group-pod-selector"
	pSel := &metav1.LabelSelector{MatchLabels: map[string]string{"pod": "x"}}
	cg := &crdv1alpha3.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: cgName,
		},
		Spec: crdv1alpha3.GroupSpec{
			PodSelector: pSel,
			ChildGroups: []crdv1alpha3.ClusterGroupReference{crdv1alpha3.ClusterGroupReference(testChildCGName)},
		},
	}
	if _, err := k8sUtils.CreateOrUpdateV1Alpha3CG(cg); err == nil {
		// Above creation of CG must fail as it is an invalid spec.
		failOnError(invalidErr, t)
	}
}

func testInvalidCGChildGroupWithServiceReference(t *testing.T) {
	invalidErr := fmt.Errorf("clustergroup created with childGroups and ServiceReference")
	cgName := "child-group-svcref"
	svcRef := &crdv1alpha3.ServiceReference{
		Namespace: "y",
		Name:      "test-svc",
	}
	cg := &crdv1alpha3.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: cgName,
		},
		Spec: crdv1alpha3.GroupSpec{
			ServiceReference: svcRef,
			ChildGroups:      []crdv1alpha3.ClusterGroupReference{crdv1alpha3.ClusterGroupReference(testChildCGName)},
		},
	}
	if _, err := k8sUtils.CreateOrUpdateV1Alpha3CG(cg); err == nil {
		// Above creation of CG must fail as it is an invalid spec.
		failOnError(invalidErr, t)
	}
}

func testInvalidCGMaxNestedLevel(t *testing.T) {
	invalidErr := fmt.Errorf("clustergroup created with childGroup which has childGroups itself")
	cgName1, cgName2 := "cg-nested-1", "cg-nested-2"
	cg1 := &crdv1alpha3.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: cgName1},
		Spec: crdv1alpha3.GroupSpec{
			ChildGroups: []crdv1alpha3.ClusterGroupReference{crdv1alpha3.ClusterGroupReference(testChildCGName)},
		},
	}
	cg2 := &crdv1alpha3.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: cgName2},
		Spec: crdv1alpha3.GroupSpec{
			ChildGroups: []crdv1alpha3.ClusterGroupReference{crdv1alpha3.ClusterGroupReference(cgName1)},
		},
	}
	// Try to create cg-nested-1 first and then cg-nested-2.
	// The creation of cg-nested-2 should fail as it breaks the max nested level
	if _, err := k8sUtils.CreateOrUpdateV1Alpha3CG(cg1); err != nil {
		// Above creation of CG must succeed as it is a valid spec.
		failOnError(err, t)
	}
	if _, err := k8sUtils.CreateOrUpdateV1Alpha3CG(cg2); err == nil {
		// Above creation of CG must fail as cg-nested-2 cannot have cg-nested-1 as childGroup.
		failOnError(invalidErr, t)
	}
	// cleanup cg-nested-1
	if err := k8sUtils.DeleteV1Alpha3CG(cgName1); err != nil {
		failOnError(err, t)
	}
	// Try to create cg-nested-2 first and then cg-nested-1.
	// The creation of cg-nested-1 should fail as it breaks the max nested level
	if _, err := k8sUtils.CreateOrUpdateV1Alpha3CG(cg2); err != nil {
		// Above creation of CG must succeed as it is a valid spec.
		failOnError(err, t)
	}
	if _, err := k8sUtils.CreateOrUpdateV1Alpha3CG(cg1); err == nil {
		// Above creation of CG must fail as cg-nested-2 cannot have cg-nested-1 as childGroup.
		failOnError(invalidErr, t)
	}
	// cleanup cg-nested-2
	if err := k8sUtils.DeleteV1Alpha3CG(cgName2); err != nil {
		failOnError(err, t)
	}
}

func testClusterGroupConversionV1A2AndV1A3(t *testing.T) {
	cgName1, cgName2 := "cg-v1a2", "cg-v1a3"
	ipb1 := crdv1alpha1.IPBlock{
		CIDR: "192.168.1.0/24",
	}
	ipb2 := crdv1alpha1.IPBlock{
		CIDR: "192.168.2.0/24",
	}
	cg1 := &crdv1alpha2.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: cgName1},
		Spec: crdv1alpha2.GroupSpec{
			IPBlock: &ipb1,
		},
	}
	cg2 := &crdv1alpha3.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{Name: cgName2},
		Spec: crdv1alpha3.GroupSpec{
			IPBlocks: []crdv1alpha1.IPBlock{
				ipb1,
				ipb2,
			},
		},
	}
	if _, err := k8sUtils.CreateOrUpdateV1Alpha2CG(cg1); err != nil {
		// Above creation of CG must succeed as it is a valid spec.
		failOnError(err, t)
	}
	// Get v1alpha3 version of ClusterGroup, which was created as v1alpha2
	cg1Returned, err := k8sUtils.GetV1Alpha3CG(cgName1)
	if err != nil {
		failOnError(err, t)
	}
	assert.ElementsMatch(t, cg1Returned.Spec.IPBlocks, []crdv1alpha1.IPBlock{ipb1})
	if _, err := k8sUtils.CreateOrUpdateV1Alpha3CG(cg2); err != nil {
		// Above creation of CG must succeed as it is a valid spec.
		failOnError(err, t)
	}
	// Get v1alpha2 version of ClusterGroup, which was created as v1alpha3
	cg2Returned, err := k8sUtils.GetV1Alpha2CG(cgName2)
	if err != nil {
		failOnError(err, t)
	}
	assert.ElementsMatch(t, cg2Returned.Spec.IPBlocks, []crdv1alpha1.IPBlock{ipb1, ipb2})
}

func TestClusterGroup(t *testing.T) {
	skipIfHasWindowsNodes(t)
	skipIfAntreaPolicyDisabled(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
	initialize(t, data)

	t.Run("TestGroupClusterGroupValidate", func(t *testing.T) {
		t.Run("Case=IPBlockWithPodSelectorDenied", func(t *testing.T) { testInvalidCGIPBlockWithPodSelector(t) })
		t.Run("Case=IPBlockWithNamespaceSelectorDenied", func(t *testing.T) { testInvalidCGIPBlockWithNSSelector(t) })
		t.Run("Case=IPBlockWithIPBlocksDenied", func(t *testing.T) { testInvalidCGIPBlockWithIPBlocks(t) })
		t.Run("Case=ServiceRefWithPodSelectorDenied", func(t *testing.T) { testInvalidCGServiceRefWithPodSelector(t) })
		t.Run("Case=ServiceRefWithNamespaceSelectorDenied", func(t *testing.T) { testInvalidCGServiceRefWithNSSelector(t) })
		t.Run("Case=ServiceRefWithIPBlockDenied", func(t *testing.T) { testInvalidCGServiceRefWithIPBlock(t) })
	})
	t.Run("TestGroupClusterGroupValidateChildGroup", func(t *testing.T) {
		createChildCGForTest(t)
		t.Run("Case=ChildGroupWithPodSelectorDenied", func(t *testing.T) { testInvalidCGChildGroupWithPodSelector(t) })
		t.Run("Case=ChildGroupWithPodServiceReferenceDenied", func(t *testing.T) { testInvalidCGChildGroupWithServiceReference(t) })
		t.Run("Case=ChildGroupExceedMaxNestedLevel", func(t *testing.T) { testInvalidCGMaxNestedLevel(t) })
		cleanupChildCGForTest(t)
	})
	t.Run("TestGroupClusterGroupConversion", func(t *testing.T) {
		t.Run("Case=ConvertBetweenV1A2AndV1A3", func(t *testing.T) { testClusterGroupConversionV1A2AndV1A3(t) })
	})
	k8sUtils.Cleanup(namespaces) // clean up all cluster-scope resources, including CGs
}
