// Copyright 2025 Antrea Authors
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

<<<<<<< HEAD
	crdv1beta1 "antrea.io/antrea/apis/pkg/apis/crd/v1beta1"
=======
	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
>>>>>>> origin/main
)

type RuleBuilder interface {
	GetIngress() crdv1beta1.Rule
	GetEgress() crdv1beta1.Rule
}

type BaseRuleBuilder struct {
	Protoc               AntreaPolicyProtocol
	Port                 *int32
	PortName             *string
	EndPort              *int32
	ICMPType             *int32
	ICMPCode             *int32
	IGMPType             *int32
	GroupAddress         *string
	PodSelector          map[string]string
	NSSelector           map[string]string
	PodSelectorMatchExp  []metav1.LabelSelectorRequirement
	NodeSelectorMatchExp []metav1.LabelSelectorRequirement
	NSSelectorMatchExp   []metav1.LabelSelectorRequirement
	Action               crdv1beta1.RuleAction
	Name                 string
	SelfNS               bool
	SrcPort              *int32
	SrcEndPort           *int32
	IPBlock              *crdv1beta1.IPBlock
}

type ACNPRuleBuilder struct {
	BaseRuleBuilder
	NodeSelector     map[string]string
	Namespaces       *crdv1beta1.PeerNamespaces
	AppliedToSpecs   []ACNPAppliedToSpec
	ServiceAccount   *crdv1beta1.NamespacedName
	RuleClusterGroup string
}

type ANNPRuleBuilder struct {
	BaseRuleBuilder
	L7Protocols        []crdv1beta1.L7Protocol
	RuleGroup          string
	EESelector         map[string]string
	EESelectorMatchExp []metav1.LabelSelectorRequirement
	AppliedToSpecs     []ANNPAppliedToSpec
}

func toEgress(ingressRule crdv1beta1.Rule) crdv1beta1.Rule {
	ingressRule.To = ingressRule.From
	ingressRule.From = nil
	return ingressRule
}

func (rb ANNPRuleBuilder) GetEgress() crdv1beta1.Rule {
	return toEgress(rb.GetIngress())
}

func (rb ANNPRuleBuilder) GetIngress() crdv1beta1.Rule {
	var ees *metav1.LabelSelector

	ps := rb.generatePodSelector()
	ns := rb.generateNSSelector()

	if len(rb.EESelector) > 0 || len(rb.EESelectorMatchExp) > 0 {
		ees = &metav1.LabelSelector{
			MatchLabels:      rb.EESelector,
			MatchExpressions: rb.EESelectorMatchExp,
		}
	}
	// An empty From/To in ANNP rules evaluates to match all addresses.
	policyPeer := make([]crdv1beta1.NetworkPolicyPeer, 0)
	if ps != nil || ns != nil || rb.IPBlock != nil || rb.RuleGroup != "" || ees != nil {
		policyPeer = []crdv1beta1.NetworkPolicyPeer{{
			PodSelector:            ps,
			NamespaceSelector:      ns,
			ExternalEntitySelector: ees,
			IPBlock:                rb.IPBlock,
			Group:                  rb.RuleGroup,
		}}
	}
	ports, protocols := GenPortsOrProtocols(rb.BaseRuleBuilder)

	var appliedTos []crdv1beta1.AppliedTo
	for _, at := range rb.AppliedToSpecs {
		appliedTos = append(appliedTos, ANNPGetAppliedToPeer(at.PodSelector, at.PodSelectorMatchExp, at.ExternalEntitySelector, at.ExternalEntitySelectorMatchExp, at.Group))
	}

	return crdv1beta1.Rule{
		From:        policyPeer,
		Ports:       ports,
		Protocols:   protocols,
		L7Protocols: rb.L7Protocols,
		Action:      &rb.Action,
		Name:        rb.Name,
		AppliedTo:   appliedTos,
	}
}

func (rb ACNPRuleBuilder) GetIngress() crdv1beta1.Rule {
	var nodeSel *metav1.LabelSelector
	var appliedTos []crdv1beta1.AppliedTo
	podSel := rb.generatePodSelector()

	if rb.NodeSelector != nil || rb.NodeSelectorMatchExp != nil {
		nodeSel = &metav1.LabelSelector{
			MatchLabels:      rb.NodeSelector,
			MatchExpressions: rb.NodeSelectorMatchExp,
		}
	}

	nsSel := rb.generateNSSelector()
	for _, at := range rb.AppliedToSpecs {
		appliedTos = append(appliedTos, ACNPGetAppliedToPeer(at.PodSelector,
			at.NodeSelector,
			at.NSSelector,
			at.PodSelectorMatchExp,
			at.NodeSelectorMatchExp,
			at.NSSelectorMatchExp,
			at.Group,
			at.Service))
	}

	matchSelf := crdv1beta1.NamespaceMatchSelf
	if rb.SelfNS {
		rb.Namespaces = &crdv1beta1.PeerNamespaces{
			Match: matchSelf,
		}
	}
	// An empty From/To in ACNP rules evaluates to match all addresses.
	policyPeer := make([]crdv1beta1.NetworkPolicyPeer, 0)
	if podSel != nil || nodeSel != nil || nsSel != nil || rb.Namespaces != nil || rb.IPBlock != nil || rb.RuleClusterGroup != "" || rb.ServiceAccount != nil {
		policyPeer = []crdv1beta1.NetworkPolicyPeer{{
			PodSelector:       podSel,
			NodeSelector:      nodeSel,
			NamespaceSelector: nsSel,
			Namespaces:        rb.Namespaces,
			IPBlock:           rb.IPBlock,
			Group:             rb.RuleClusterGroup,
			ServiceAccount:    rb.ServiceAccount,
		}}
	}
	ports, protocols := GenPortsOrProtocols(rb.BaseRuleBuilder)
	return crdv1beta1.Rule{
		From:      policyPeer,
		Ports:     ports,
		Protocols: protocols,
		Action:    &rb.Action,
		Name:      rb.Name,
		AppliedTo: appliedTos,
	}
}

func (rb ACNPRuleBuilder) GetEgress() crdv1beta1.Rule {
	return toEgress(rb.GetIngress())
}

func (rb BaseRuleBuilder) generatePodSelector() (podSel *metav1.LabelSelector) {
	if rb.PodSelector != nil || rb.PodSelectorMatchExp != nil {
		podSel = &metav1.LabelSelector{
			MatchLabels:      rb.PodSelector,
			MatchExpressions: rb.PodSelectorMatchExp,
		}
	}
	return podSel
}

func (rb BaseRuleBuilder) generateNSSelector() (nsSel *metav1.LabelSelector) {
	if rb.NSSelector != nil || rb.NSSelectorMatchExp != nil {
		nsSel = &metav1.LabelSelector{
			MatchLabels:      rb.NSSelector,
			MatchExpressions: rb.NSSelectorMatchExp,
		}
	}
	return nsSel
}
