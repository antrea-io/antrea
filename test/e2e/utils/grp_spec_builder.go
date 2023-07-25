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

	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
)

// GroupSpecBuilder builds a Group object.
type GroupSpecBuilder struct {
	Spec      crdv1beta1.GroupSpec
	Name      string
	Namespace string
}

func (b *GroupSpecBuilder) Get() *crdv1beta1.Group {
	return &crdv1beta1.Group{
		ObjectMeta: metav1.ObjectMeta{
			Name:      b.Name,
			Namespace: b.Namespace,
		},
		Spec: b.Spec,
	}
}

func (b *GroupSpecBuilder) SetName(name string) *GroupSpecBuilder {
	b.Name = name
	return b
}

func (b *GroupSpecBuilder) SetNamespace(namespace string) *GroupSpecBuilder {
	b.Namespace = namespace
	return b
}

func (b *GroupSpecBuilder) SetPodSelector(podSelector map[string]string, podSelectorMatchExp []metav1.LabelSelectorRequirement) *GroupSpecBuilder {
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

func (b *GroupSpecBuilder) SetNamespaceSelector(nsSelector map[string]string, nsSelectorMatchExp []metav1.LabelSelectorRequirement) *GroupSpecBuilder {
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

func (b *GroupSpecBuilder) SetIPBlocks(ipBlocks []crdv1beta1.IPBlock) *GroupSpecBuilder {
	b.Spec.IPBlocks = ipBlocks
	return b
}

func (b *GroupSpecBuilder) SetServiceReference(svcNS, svcName string) *GroupSpecBuilder {
	svcRef := &crdv1beta1.NamespacedName{
		Namespace: svcNS,
		Name:      svcName,
	}
	b.Spec.ServiceReference = svcRef
	return b
}

func (b *GroupSpecBuilder) SetChildGroups(cgs []string) *GroupSpecBuilder {
	var childGroups []crdv1beta1.ClusterGroupReference
	for _, c := range cgs {
		childGroups = append(childGroups, crdv1beta1.ClusterGroupReference(c))
	}
	b.Spec.ChildGroups = childGroups
	return b
}
