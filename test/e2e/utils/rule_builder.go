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

	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
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
	IcmpType             *int32
	IcmpCode             *int32
	IgmpType             *int32
	GroupAddress         *string
	PodSelector          map[string]string
	NsSelector           map[string]string
	PodSelectorMatchExp  []metav1.LabelSelectorRequirement
	NodeSelectorMatchExp []metav1.LabelSelectorRequirement
	NsSelectorMatchExp   []metav1.LabelSelectorRequirement
	Action               crdv1beta1.RuleAction
	Name                 string
	SelfNS               bool
	SrcPort              *int32
	SrcEndPort           *int32
}

type CNPRuleBuilder struct {
	BaseRuleBuilder
	IpBlock            *crdv1beta1.IPBlock
	NodeSelector       map[string]string
	Namespaces         *crdv1beta1.PeerNamespaces
	RuleAppliedToSpecs []ACNPAppliedToSpec
	ServiceAccount     *crdv1beta1.NamespacedName
	RuleClusterGroup   string
}

type ANPRuleBuilder struct {
	BaseRuleBuilder
	L7Protocols           []crdv1beta1.L7Protocol
	RuleGroup             string
	Cidr                  *string
	EeSelector            map[string]string
	EeSelectorMatchExp    []metav1.LabelSelectorRequirement
	ANPRuleAppliedToSpecs []ANNPAppliedToSpec
}

func toEgress(ingressRule crdv1beta1.Rule) crdv1beta1.Rule {
	ingressRule.To = ingressRule.From
	ingressRule.From = nil
	return ingressRule
}

func (rb ANPRuleBuilder) GetEgress() crdv1beta1.Rule {
	return toEgress(rb.GetIngress())
}

func (rb ANPRuleBuilder) GetIngress() crdv1beta1.Rule {
	var ees *metav1.LabelSelector

	ps := rb.generatePodSelector()
	ns := rb.generateNsSelector()

	if len(rb.EeSelector) > 0 || len(rb.EeSelectorMatchExp) > 0 {
		ees = &metav1.LabelSelector{
			MatchLabels:      rb.EeSelector,
			MatchExpressions: rb.EeSelectorMatchExp,
		}
	}
	var ipBlock *crdv1beta1.IPBlock
	if rb.Cidr != nil {
		ipBlock = &crdv1beta1.IPBlock{
			CIDR: *rb.Cidr,
		}
	}
	// An empty From/To in ANNP rules evaluates to match all addresses.
	policyPeer := make([]crdv1beta1.NetworkPolicyPeer, 0)
	if ps != nil || ns != nil || ipBlock != nil || rb.RuleGroup != "" || ees != nil {
		policyPeer = []crdv1beta1.NetworkPolicyPeer{{
			PodSelector:            ps,
			NamespaceSelector:      ns,
			ExternalEntitySelector: ees,
			IPBlock:                ipBlock,
			Group:                  rb.RuleGroup,
		}}
	}
	ports, protocols := GenPortsOrProtocols(rb.BaseRuleBuilder)

	var appliedTos []crdv1beta1.AppliedTo
	for _, at := range rb.ANPRuleAppliedToSpecs {
		appliedTos = append(appliedTos, ANPGetAppliedToPeer(at.PodSelector, at.PodSelectorMatchExp, at.ExternalEntitySelector, at.ExternalEntitySelectorMatchExp, at.Group))
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

func (rb CNPRuleBuilder) GetIngress() crdv1beta1.Rule {
	var nodeSel *metav1.LabelSelector
	var appliedTos []crdv1beta1.AppliedTo
	podSel := rb.generatePodSelector()

	if rb.NodeSelector != nil || rb.NodeSelectorMatchExp != nil {
		nodeSel = &metav1.LabelSelector{
			MatchLabels:      rb.NodeSelector,
			MatchExpressions: rb.NodeSelectorMatchExp,
		}
	}

	nsSel := rb.generateNsSelector()
	for _, at := range rb.RuleAppliedToSpecs {
		appliedTos = append(appliedTos, CNPGetAppliedToPeer(at.PodSelector,
			at.NodeSelector,
			at.NSSelector,
			at.PodSelectorMatchExp,
			at.NodeSelectorMatchExp,
			at.NSSelectorMatchExp,
			at.Group,
			at.Service))
	}

	matchSelf := crdv1beta1.NamespaceMatchSelf
	if rb.SelfNS == true {
		rb.Namespaces = &crdv1beta1.PeerNamespaces{
			Match: matchSelf,
		}
	}
	// An empty From/To in ACNP rules evaluates to match all addresses.
	policyPeer := make([]crdv1beta1.NetworkPolicyPeer, 0)
	if podSel != nil || nodeSel != nil || nsSel != nil || rb.Namespaces != nil || rb.IpBlock != nil || rb.RuleClusterGroup != "" || rb.ServiceAccount != nil {
		policyPeer = []crdv1beta1.NetworkPolicyPeer{{
			PodSelector:       podSel,
			NodeSelector:      nodeSel,
			NamespaceSelector: nsSel,
			Namespaces:        rb.Namespaces,
			IPBlock:           rb.IpBlock,
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

func (rb CNPRuleBuilder) GetEgress() crdv1beta1.Rule {
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

func (rb BaseRuleBuilder) generateNsSelector() (nsSel *metav1.LabelSelector) {
	if rb.NsSelector != nil || rb.NsSelectorMatchExp != nil {
		nsSel = &metav1.LabelSelector{
			MatchLabels:      rb.NsSelector,
			MatchExpressions: rb.NsSelectorMatchExp,
		}
	}
	return nsSel
}
