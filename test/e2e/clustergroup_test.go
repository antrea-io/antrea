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

	corev1a1 "github.com/vmware-tanzu/antrea/pkg/apis/core/v1alpha2"
	secv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/security/v1alpha1"
)

func testInvalidCGIPBlockWithPodSelector(t *testing.T) {
	invalidErr := fmt.Errorf("clustergroup created with ipblock and podSelector")
	cgName := "ipb-pod"
	pSel := &metav1.LabelSelector{MatchLabels: map[string]string{"pod": "x"}}
	cidr := "10.0.0.10/32"
	ipb := &secv1alpha1.IPBlock{CIDR: cidr}
	cg := &corev1a1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: cgName,
		},
		Spec: corev1a1.GroupSpec{
			PodSelector: pSel,
			IPBlock:     ipb,
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
	nSel := &metav1.LabelSelector{MatchLabels: map[string]string{"ns": "y"}}
	cidr := "10.0.0.10/32"
	ipb := &secv1alpha1.IPBlock{CIDR: cidr}
	cg := &corev1a1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: cgName,
		},
		Spec: corev1a1.GroupSpec{
			NamespaceSelector: nSel,
			IPBlock:           ipb,
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
	svcRef := &corev1a1.ServiceReference{
		Namespace: "y",
		Name:      "test-svc",
	}
	cg := &corev1a1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: cgName,
		},
		Spec: corev1a1.GroupSpec{
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
	nSel := &metav1.LabelSelector{MatchLabels: map[string]string{"ns": "y"}}
	svcRef := &corev1a1.ServiceReference{
		Namespace: "y",
		Name:      "test-svc",
	}
	cg := &corev1a1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: cgName,
		},
		Spec: corev1a1.GroupSpec{
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
	ipb := &secv1alpha1.IPBlock{CIDR: cidr}
	svcRef := &corev1a1.ServiceReference{
		Namespace: "y",
		Name:      "test-svc",
	}
	cg := &corev1a1.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: cgName,
		},
		Spec: corev1a1.GroupSpec{
			ServiceReference: svcRef,
			IPBlock:          ipb,
		},
	}
	if _, err := k8sUtils.CreateOrUpdateCG(cg); err == nil {
		// Above creation of CG must fail as it is an invalid spec.
		failOnError(invalidErr, t)
	}
}

func TestClusterGroup(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
	skipIfAntreaPolicyDisabled(t, data)
	initialize(t, data)

	t.Run("TestGroupClusterGroupValidate", func(t *testing.T) {
		t.Run("Case=IPBlockWithPodSelectorDenied", func(t *testing.T) { testInvalidCGIPBlockWithPodSelector(t) })
		t.Run("Case=IPBlockWithNamespaceSelectorDenied", func(t *testing.T) { testInvalidCGIPBlockWithNSSelector(t) })
		t.Run("Case=ServiceRefWithPodSelectorDenied", func(t *testing.T) { testInvalidCGServiceRefWithPodSelector(t) })
		t.Run("Case=ServiceRefWithNamespaceSelectorDenied", func(t *testing.T) { testInvalidCGServiceRefWithNSSelector(t) })
		t.Run("Case=ServiceRefWithIPBlockDenied", func(t *testing.T) { testInvalidCGServiceRefWithIPBlock(t) })
	})
	failOnError(k8sUtils.CleanCGs(), t)
}
