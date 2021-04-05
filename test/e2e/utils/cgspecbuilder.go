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

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	crdv1alpha2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	crdv1alpha3 "antrea.io/antrea/pkg/apis/crd/v1alpha3"
	legacycorev1alpha2 "antrea.io/antrea/pkg/legacyapis/core/v1alpha2"
)

type ClusterGroupV1Alpha2SpecBuilder struct {
	Spec crdv1alpha2.GroupSpec
	Name string
}

func (b *ClusterGroupV1Alpha2SpecBuilder) Get() *crdv1alpha2.ClusterGroup {
	return &crdv1alpha2.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: b.Name,
		},
		Spec: b.Spec,
	}
}

func (b *ClusterGroupV1Alpha2SpecBuilder) GetLegacy() *legacycorev1alpha2.ClusterGroup {
	return &legacycorev1alpha2.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: b.Name,
		},
		Spec: b.Spec,
	}
}

func (b *ClusterGroupV1Alpha2SpecBuilder) SetName(name string) *ClusterGroupV1Alpha2SpecBuilder {
	b.Name = name
	return b
}

func (b *ClusterGroupV1Alpha2SpecBuilder) SetPodSelector(podSelector map[string]string, podSelectorMatchExp []metav1.LabelSelectorRequirement) *ClusterGroupV1Alpha2SpecBuilder {
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

func (b *ClusterGroupV1Alpha2SpecBuilder) SetNamespaceSelector(nsSelector map[string]string, nsSelectorMatchExp []metav1.LabelSelectorRequirement) *ClusterGroupV1Alpha2SpecBuilder {
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

func (b *ClusterGroupV1Alpha2SpecBuilder) SetIPBlock(ipb *crdv1alpha1.IPBlock) *ClusterGroupV1Alpha2SpecBuilder {
	b.Spec.IPBlock = ipb
	return b
}

func (b *ClusterGroupV1Alpha2SpecBuilder) SetIPBlocks(ipBlocks []crdv1alpha1.IPBlock) *ClusterGroupV1Alpha2SpecBuilder {
	b.Spec.IPBlocks = ipBlocks
	return b
}

func (b *ClusterGroupV1Alpha2SpecBuilder) SetServiceReference(svcNS, svcName string) *ClusterGroupV1Alpha2SpecBuilder {
	svcRef := &crdv1alpha2.ServiceReference{
		Namespace: svcNS,
		Name:      svcName,
	}
	b.Spec.ServiceReference = svcRef
	return b
}

func (b *ClusterGroupV1Alpha2SpecBuilder) SetChildGroups(cgs []string) *ClusterGroupV1Alpha2SpecBuilder {
	var childGroups []crdv1alpha2.ClusterGroupReference
	for _, c := range cgs {
		childGroups = append(childGroups, crdv1alpha2.ClusterGroupReference(c))
	}
	b.Spec.ChildGroups = childGroups
	return b
}

// ClusterGroupV1Alpha3SpecBuilder builds a core/v1alpha3 ClusterGroup object.
type ClusterGroupV1Alpha3SpecBuilder struct {
	Spec crdv1alpha3.GroupSpec
	Name string
}

func (b *ClusterGroupV1Alpha3SpecBuilder) Get() *crdv1alpha3.ClusterGroup {
	return &crdv1alpha3.ClusterGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: b.Name,
		},
		Spec: b.Spec,
	}
}

func (b *ClusterGroupV1Alpha3SpecBuilder) SetName(name string) *ClusterGroupV1Alpha3SpecBuilder {
	b.Name = name
	return b
}

func (b *ClusterGroupV1Alpha3SpecBuilder) SetPodSelector(podSelector map[string]string, podSelectorMatchExp []metav1.LabelSelectorRequirement) *ClusterGroupV1Alpha3SpecBuilder {
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

func (b *ClusterGroupV1Alpha3SpecBuilder) SetNamespaceSelector(nsSelector map[string]string, nsSelectorMatchExp []metav1.LabelSelectorRequirement) *ClusterGroupV1Alpha3SpecBuilder {
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

func (b *ClusterGroupV1Alpha3SpecBuilder) SetIPBlocks(ipBlocks []crdv1alpha1.IPBlock) *ClusterGroupV1Alpha3SpecBuilder {
	b.Spec.IPBlocks = ipBlocks
	return b
}

func (b *ClusterGroupV1Alpha3SpecBuilder) SetServiceReference(svcNS, svcName string) *ClusterGroupV1Alpha3SpecBuilder {
	svcRef := &crdv1alpha3.ServiceReference{
		Namespace: svcNS,
		Name:      svcName,
	}
	b.Spec.ServiceReference = svcRef
	return b
}

func (b *ClusterGroupV1Alpha3SpecBuilder) SetChildGroups(cgs []string) *ClusterGroupV1Alpha3SpecBuilder {
	var childGroups []crdv1alpha3.ClusterGroupReference
	for _, c := range cgs {
		childGroups = append(childGroups, crdv1alpha3.ClusterGroupReference(c))
	}
	b.Spec.ChildGroups = childGroups
	return b
}
