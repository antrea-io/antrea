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

	secv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/security/v1alpha1"
)

type AntreaNetworkPolicySpecBuilder struct {
	Spec      secv1alpha1.NetworkPolicySpec
	Name      string
	Namespace string
}

type ANPAppliedToSpec struct {
	PodSelector         map[string]string
	PodSelectorMatchExp []metav1.LabelSelectorRequirement
}

func (b *AntreaNetworkPolicySpecBuilder) Get() *secv1alpha1.NetworkPolicy {
	if b.Spec.Ingress == nil {
		b.Spec.Ingress = []secv1alpha1.Rule{}
	}
	if b.Spec.Egress == nil {
		b.Spec.Egress = []secv1alpha1.Rule{}
	}
	return &secv1alpha1.NetworkPolicy{
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
	podSelectorMatchExp []metav1.LabelSelectorRequirement) secv1alpha1.NetworkPolicyPeer {
	var ps *metav1.LabelSelector
	if podSelector != nil {
		ps = &metav1.LabelSelector{
			MatchLabels: podSelector,
		}
		if podSelectorMatchExp != nil {
			ps.MatchExpressions = podSelectorMatchExp
		}
	}
	if podSelectorMatchExp != nil {
		ps = &metav1.LabelSelector{
			MatchExpressions: podSelectorMatchExp,
		}
	}
	return secv1alpha1.NetworkPolicyPeer{
		PodSelector: ps,
	}
}

func (b *AntreaNetworkPolicySpecBuilder) AddIngress(protoc v1.Protocol,
	port *int, portName *string, endPort *int32, cidr *string,
	podSelector map[string]string, nsSelector map[string]string,
	podSelectorMatchExp []metav1.LabelSelectorRequirement, nsSelectorMatchExp []metav1.LabelSelectorRequirement,
	ruleAppliedToSpecs []ANPAppliedToSpec, action secv1alpha1.RuleAction, name string) *AntreaNetworkPolicySpecBuilder {

	var ps, ns *metav1.LabelSelector
	var appliedTos []secv1alpha1.NetworkPolicyPeer
	if b.Spec.Ingress == nil {
		b.Spec.Ingress = []secv1alpha1.Rule{}
	}

	if podSelector != nil {
		ps = &metav1.LabelSelector{
			MatchLabels: podSelector,
		}
		if podSelectorMatchExp != nil {
			ps.MatchExpressions = podSelectorMatchExp
		}
	}
	if podSelectorMatchExp != nil {
		ps = &metav1.LabelSelector{
			MatchExpressions: podSelectorMatchExp,
		}
	}
	if nsSelector != nil {
		ns = &metav1.LabelSelector{
			MatchLabels: nsSelector,
		}
		if nsSelectorMatchExp != nil {
			ns.MatchExpressions = nsSelectorMatchExp
		}
	}
	if nsSelectorMatchExp != nil {
		ns = &metav1.LabelSelector{
			MatchExpressions: nsSelectorMatchExp,
		}
	}
	var ipBlock *secv1alpha1.IPBlock
	if cidr != nil {
		ipBlock = &secv1alpha1.IPBlock{
			CIDR: *cidr,
		}
	}
	for _, at := range ruleAppliedToSpecs {
		appliedTos = append(appliedTos, b.GetAppliedToPeer(at.PodSelector, at.PodSelectorMatchExp))
	}
	var policyPeer []secv1alpha1.NetworkPolicyPeer
	if ps != nil || ns != nil || ipBlock != nil {
		policyPeer = []secv1alpha1.NetworkPolicyPeer{{
			PodSelector:       ps,
			NamespaceSelector: ns,
			IPBlock:           ipBlock,
		}}
	}

	var ports []secv1alpha1.NetworkPolicyPort
	if port != nil && portName != nil {
		panic("specify portname or port, not both")
	}
	if portName != nil {
		ports = []secv1alpha1.NetworkPolicyPort{
			{
				Port:     &intstr.IntOrString{Type: intstr.String, StrVal: *portName},
				Protocol: &protoc,
			},
		}
	}
	if port != nil || endPort != nil {
		var pVal *intstr.IntOrString
		if port != nil {
			pVal = &intstr.IntOrString{IntVal: int32(*port)}
		}
		ports = []secv1alpha1.NetworkPolicyPort{
			{
				Port:     pVal,
				EndPort:  endPort,
				Protocol: &protoc,
			},
		}
	}

	newRule := secv1alpha1.Rule{
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
	port *int, portName *string, endPort *int32, cidr *string,
	podSelector map[string]string, nsSelector map[string]string,
	podSelectorMatchExp []metav1.LabelSelectorRequirement, nsSelectorMatchExp []metav1.LabelSelectorRequirement,
	ruleAppliedToSpecs []ANPAppliedToSpec, action secv1alpha1.RuleAction, name string) *AntreaNetworkPolicySpecBuilder {

	// For simplicity, we just reuse the Ingress code here.  The underlying data model for ingress/egress is identical
	// With the exception of calling the rule `To` vs. `From`.
	c := &AntreaNetworkPolicySpecBuilder{}
	c.AddIngress(protoc, port, portName, endPort, cidr, podSelector, nsSelector,
		podSelectorMatchExp, nsSelectorMatchExp, ruleAppliedToSpecs, action, name)
	theRule := c.Get().Spec.Ingress[0]

	b.Spec.Egress = append(b.Spec.Egress, secv1alpha1.Rule{
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
