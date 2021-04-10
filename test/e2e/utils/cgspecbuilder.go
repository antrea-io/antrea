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

package utils

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	crdv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/crd/v1alpha1"
	crdv1alpha2 "github.com/vmware-tanzu/antrea/pkg/apis/crd/v1alpha2"
	legacycorev1alpha2 "github.com/vmware-tanzu/antrea/pkg/legacyapis/core/v1alpha2"
)

type ClusterGroupSpecBuilder struct {
	Spec crdv1alpha2.GroupSpec
	Name string
}

func (b *ClusterGroupSpecBuilder) Get() *crdv1alpha2.ClusterGroup {
	return &crdv1alpha2.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: b.Name,
		},
		Spec: b.Spec,
	}
}

func (b *ClusterGroupSpecBuilder) GetLegacy() *legacycorev1alpha2.ClusterGroup {
	return &legacycorev1alpha2.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: b.Name,
		},
		Spec: b.Spec,
	}
}

func (b *ClusterGroupSpecBuilder) SetName(name string) *ClusterGroupSpecBuilder {
	b.Name = name
	return b
}

func (b *ClusterGroupSpecBuilder) SetPodSelector(podSelector map[string]string, podSelectorMatchExp []metav1.LabelSelectorRequirement) *ClusterGroupSpecBuilder {
	var ps *metav1.LabelSelector
	if podSelector != nil {
		ps = &metav1.LabelSelector{
			MatchLabels: podSelector,
		}
		if podSelectorMatchExp != nil {
			ps.MatchExpressions = podSelectorMatchExp
		}
	}
	b.Spec.PodSelector = ps
	return b
}

func (b *ClusterGroupSpecBuilder) SetNamespaceSelector(nsSelector map[string]string, nsSelectorMatchExp []metav1.LabelSelectorRequirement) *ClusterGroupSpecBuilder {
	var ns *metav1.LabelSelector
	if nsSelector != nil {
		ns = &metav1.LabelSelector{
			MatchLabels: nsSelector,
		}
		if nsSelectorMatchExp != nil {
			ns.MatchExpressions = nsSelectorMatchExp
		}
	}
	b.Spec.NamespaceSelector = ns
	return b
}

func (b *ClusterGroupSpecBuilder) SetIPBlocks(ipBlocks []crdv1alpha1.IPBlock) *ClusterGroupSpecBuilder {
	b.Spec.IPBlocks = ipBlocks
	return b
}

func (b *ClusterGroupSpecBuilder) SetServiceReference(svcNS, svcName string) *ClusterGroupSpecBuilder {
	svcRef := &crdv1alpha2.ServiceReference{
		Namespace: svcNS,
		Name:      svcName,
	}
	b.Spec.ServiceReference = svcRef
	return b
}

func (b *ClusterGroupSpecBuilder) SetChildGroups(cgs []string) *ClusterGroupSpecBuilder {
	var childGroups []crdv1alpha2.ClusterGroupReference
	for _, c := range cgs {
		childGroups = append(childGroups, crdv1alpha2.ClusterGroupReference(c))
	}
	b.Spec.ChildGroups = childGroups
	return b
}
