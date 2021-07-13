// Copyright 2020 Antrea Authors
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
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	legacysecv1alpha1 "antrea.io/antrea/pkg/legacyapis/security/v1alpha1"
)

type AntreaNetworkPolicySpecBuilder struct {
	Spec      crdv1alpha1.NetworkPolicySpec
	Name      string
	Namespace string
}

type ANPAppliedToSpec struct {
	PodSelector         map[string]string
	PodSelectorMatchExp []metav1.LabelSelectorRequirement
}

func (b *AntreaNetworkPolicySpecBuilder) Get() *crdv1alpha1.NetworkPolicy {
	if b.Spec.Ingress == nil {
		b.Spec.Ingress = []crdv1alpha1.Rule{}
	}
	if b.Spec.Egress == nil {
		b.Spec.Egress = []crdv1alpha1.Rule{}
	}
	return &crdv1alpha1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      b.Name,
			Namespace: b.Namespace,
		},
		Spec: b.Spec,
	}
}

func (b *AntreaNetworkPolicySpecBuilder) GetLegacy() *legacysecv1alpha1.NetworkPolicy {
	if b.Spec.Ingress == nil {
		b.Spec.Ingress = []crdv1alpha1.Rule{}
	}
	if b.Spec.Egress == nil {
		b.Spec.Egress = []crdv1alpha1.Rule{}
	}
	return &legacysecv1alpha1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      b.Name,
			Namespace: b.Namespace,
		},
		Spec: b.Spec,
	}
}

func (b *AntreaNetworkPolicySpecBuilder) SetName(namespace string, name string) *AntreaNetworkPolicySpecBuilder {
	b.Name = name
	b.Namespace = namespace
	return b
}

func (b *AntreaNetworkPolicySpecBuilder) SetPriority(p float64) *AntreaNetworkPolicySpecBuilder {
	b.Spec.Priority = p
	return b
}

func (b *AntreaNetworkPolicySpecBuilder) SetTier(tier string) *AntreaNetworkPolicySpecBuilder {
	b.Spec.Tier = tier
	return b
}

func (b *AntreaNetworkPolicySpecBuilder) SetAppliedToGroup(specs []ANPAppliedToSpec) *AntreaNetworkPolicySpecBuilder {
	for _, spec := range specs {
		appliedToPeer := b.GetAppliedToPeer(spec.PodSelector, spec.PodSelectorMatchExp)
		b.Spec.AppliedTo = append(b.Spec.AppliedTo, appliedToPeer)
	}
	return b
}

func (b *AntreaNetworkPolicySpecBuilder) GetAppliedToPeer(podSelector map[string]string,
	podSelectorMatchExp []metav1.LabelSelectorRequirement) crdv1alpha1.NetworkPolicyPeer {
	var ps *metav1.LabelSelector
	if len(podSelector) > 0 || len(podSelectorMatchExp) > 0 {
		ps = &metav1.LabelSelector{
			MatchLabels:      podSelector,
			MatchExpressions: podSelectorMatchExp,
		}
	}
	return crdv1alpha1.NetworkPolicyPeer{
		PodSelector: ps,
	}
}

func (b *AntreaNetworkPolicySpecBuilder) AddIngress(protoc v1.Protocol,
	port *int32, portName *string, endPort *int32, cidr *string,
	podSelector map[string]string, nsSelector map[string]string,
	podSelectorMatchExp []metav1.LabelSelectorRequirement, nsSelectorMatchExp []metav1.LabelSelectorRequirement,
	ruleAppliedToSpecs []ANPAppliedToSpec, action crdv1alpha1.RuleAction, name string) *AntreaNetworkPolicySpecBuilder {

	var ps, ns *metav1.LabelSelector
	var appliedTos []crdv1alpha1.NetworkPolicyPeer
	if b.Spec.Ingress == nil {
		b.Spec.Ingress = []crdv1alpha1.Rule{}
	}

	if len(podSelector) > 0 || len(podSelectorMatchExp) > 0 {
		ps = &metav1.LabelSelector{
			MatchLabels:      podSelector,
			MatchExpressions: podSelectorMatchExp,
		}
	}
	if len(nsSelector) > 0 || len(nsSelectorMatchExp) > 0 {
		ns = &metav1.LabelSelector{
			MatchLabels:      nsSelector,
			MatchExpressions: nsSelectorMatchExp,
		}
	}
	var ipBlock *crdv1alpha1.IPBlock
	if cidr != nil {
		ipBlock = &crdv1alpha1.IPBlock{
			CIDR: *cidr,
		}
	}
	for _, at := range ruleAppliedToSpecs {
		appliedTos = append(appliedTos, b.GetAppliedToPeer(at.PodSelector, at.PodSelectorMatchExp))
	}
	// An empty From/To in ANP rules evaluates to match all addresses.
	policyPeer := make([]crdv1alpha1.NetworkPolicyPeer, 0)
	if ps != nil || ns != nil || ipBlock != nil {
		policyPeer = []crdv1alpha1.NetworkPolicyPeer{{
			PodSelector:       ps,
			NamespaceSelector: ns,
			IPBlock:           ipBlock,
		}}
	}

	var ports []crdv1alpha1.NetworkPolicyPort
	if port != nil && portName != nil {
		panic("specify portname or port, not both")
	}
	if portName != nil {
		ports = []crdv1alpha1.NetworkPolicyPort{
			{
				Port:     &intstr.IntOrString{Type: intstr.String, StrVal: *portName},
				Protocol: &protoc,
			},
		}
	}
	if port != nil || endPort != nil {
		var pVal *intstr.IntOrString
		if port != nil {
			pVal = &intstr.IntOrString{IntVal: *port}
		}
		ports = []crdv1alpha1.NetworkPolicyPort{
			{
				Port:     pVal,
				EndPort:  endPort,
				Protocol: &protoc,
			},
		}
	}

	newRule := crdv1alpha1.Rule{
		From:      policyPeer,
		Ports:     ports,
		Action:    &action,
		Name:      name,
		AppliedTo: appliedTos,
	}
	b.Spec.Ingress = append(b.Spec.Ingress, newRule)
	return b
}

func (b *AntreaNetworkPolicySpecBuilder) AddEgress(protoc v1.Protocol,
	port *int32, portName *string, endPort *int32, cidr *string,
	podSelector map[string]string, nsSelector map[string]string,
	podSelectorMatchExp []metav1.LabelSelectorRequirement, nsSelectorMatchExp []metav1.LabelSelectorRequirement,
	ruleAppliedToSpecs []ANPAppliedToSpec, action crdv1alpha1.RuleAction, name string) *AntreaNetworkPolicySpecBuilder {

	// For simplicity, we just reuse the Ingress code here.  The underlying data model for ingress/egress is identical
	// With the exception of calling the rule `To` vs. `From`.
	c := &AntreaNetworkPolicySpecBuilder{}
	c.AddIngress(protoc, port, portName, endPort, cidr, podSelector, nsSelector,
		podSelectorMatchExp, nsSelectorMatchExp, ruleAppliedToSpecs, action, name)
	theRule := c.Get().Spec.Ingress[0]

	b.Spec.Egress = append(b.Spec.Egress, crdv1alpha1.Rule{
		To:        theRule.From,
		Ports:     theRule.Ports,
		Action:    theRule.Action,
		Name:      theRule.Name,
		AppliedTo: theRule.AppliedTo,
	})
	return b
}

func (b *AntreaNetworkPolicySpecBuilder) AddEgressLogging() *AntreaNetworkPolicySpecBuilder {
	for i, e := range b.Spec.Egress {
		e.EnableLogging = true
		b.Spec.Egress[i] = e
	}
	return b
}
