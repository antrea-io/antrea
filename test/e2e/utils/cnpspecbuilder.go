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
)

type ClusterNetworkPolicySpecBuilder struct {
	Spec crdv1alpha1.ClusterNetworkPolicySpec
	Name string
}

type ACNPAppliedToSpec struct {
	PodSelector         map[string]string
	NSSelector          map[string]string
	PodSelectorMatchExp []metav1.LabelSelectorRequirement
	NSSelectorMatchExp  []metav1.LabelSelectorRequirement
	Group               string
}

func (b *ClusterNetworkPolicySpecBuilder) Get() *crdv1alpha1.ClusterNetworkPolicy {
	if b.Spec.Ingress == nil {
		b.Spec.Ingress = []crdv1alpha1.Rule{}
	}
	if b.Spec.Egress == nil {
		b.Spec.Egress = []crdv1alpha1.Rule{}
	}
	return &crdv1alpha1.ClusterNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: b.Name,
		},
		Spec: b.Spec,
	}
}

func (b *ClusterNetworkPolicySpecBuilder) SetName(name string) *ClusterNetworkPolicySpecBuilder {
	b.Name = name
	return b
}

func (b *ClusterNetworkPolicySpecBuilder) SetPriority(p float64) *ClusterNetworkPolicySpecBuilder {
	b.Spec.Priority = p
	return b
}

func (b *ClusterNetworkPolicySpecBuilder) SetTier(tier string) *ClusterNetworkPolicySpecBuilder {
	b.Spec.Tier = tier
	return b
}

func (b *ClusterNetworkPolicySpecBuilder) SetAppliedToGroup(specs []ACNPAppliedToSpec) *ClusterNetworkPolicySpecBuilder {
	for _, spec := range specs {
		appliedToPeer := b.GetAppliedToPeer(spec.PodSelector, spec.NSSelector, spec.PodSelectorMatchExp, spec.NSSelectorMatchExp, spec.Group)
		b.Spec.AppliedTo = append(b.Spec.AppliedTo, appliedToPeer)
	}
	return b
}

func (b *ClusterNetworkPolicySpecBuilder) GetAppliedToPeer(podSelector map[string]string,
	nsSelector map[string]string,
	podSelectorMatchExp []metav1.LabelSelectorRequirement,
	nsSelectorMatchExp []metav1.LabelSelectorRequirement,
	appliedToCG string) crdv1alpha1.NetworkPolicyPeer {

	var ps *metav1.LabelSelector
	var ns *metav1.LabelSelector

	if podSelector != nil || podSelectorMatchExp != nil {
		ps = &metav1.LabelSelector{
			MatchLabels:      podSelector,
			MatchExpressions: podSelectorMatchExp,
		}
	}
	if nsSelector != nil || nsSelectorMatchExp != nil {
		ns = &metav1.LabelSelector{
			MatchLabels:      nsSelector,
			MatchExpressions: nsSelectorMatchExp,
		}
	}
	peer := crdv1alpha1.NetworkPolicyPeer{
		PodSelector:       ps,
		NamespaceSelector: ns,
	}
	if appliedToCG != "" {
		peer.Group = appliedToCG
	}
	return peer
}

func (b *ClusterNetworkPolicySpecBuilder) AddIngress(protoc v1.Protocol,
	port *int32, portName *string, endPort *int32, cidr *string,
	podSelector map[string]string, nsSelector map[string]string,
	podSelectorMatchExp []metav1.LabelSelectorRequirement, nsSelectorMatchExp []metav1.LabelSelectorRequirement, selfNS bool,
	ruleAppliedToSpecs []ACNPAppliedToSpec, action crdv1alpha1.RuleAction, ruleClusterGroup, name string) *ClusterNetworkPolicySpecBuilder {

	var pSel *metav1.LabelSelector
	var nSel *metav1.LabelSelector
	var ns *crdv1alpha1.PeerNamespaces
	var appliedTos []crdv1alpha1.NetworkPolicyPeer
	matchSelf := crdv1alpha1.NamespaceMatchSelf

	if b.Spec.Ingress == nil {
		b.Spec.Ingress = []crdv1alpha1.Rule{}
	}

	if podSelector != nil || podSelectorMatchExp != nil {
		pSel = &metav1.LabelSelector{
			MatchLabels:      podSelector,
			MatchExpressions: podSelectorMatchExp,
		}
	}
	if nsSelector != nil || nsSelectorMatchExp != nil {
		nSel = &metav1.LabelSelector{
			MatchLabels:      nsSelector,
			MatchExpressions: nsSelectorMatchExp,
		}
	}
	if selfNS == true {
		ns = &crdv1alpha1.PeerNamespaces{
			Match: matchSelf,
		}
	}
	var ipBlock *crdv1alpha1.IPBlock
	if cidr != nil {
		ipBlock = &crdv1alpha1.IPBlock{
			CIDR: *cidr,
		}
	}
	for _, at := range ruleAppliedToSpecs {
		appliedTos = append(appliedTos, b.GetAppliedToPeer(at.PodSelector, at.NSSelector, at.PodSelectorMatchExp, at.NSSelectorMatchExp, at.Group))
	}
	// An empty From/To in ACNP rules evaluates to match all addresses.
	policyPeer := make([]crdv1alpha1.NetworkPolicyPeer, 0)
	if pSel != nil || nSel != nil || ns != nil || ipBlock != nil || ruleClusterGroup != "" {
		policyPeer = []crdv1alpha1.NetworkPolicyPeer{{
			PodSelector:       pSel,
			NamespaceSelector: nSel,
			Namespaces:        ns,
			IPBlock:           ipBlock,
			Group:             ruleClusterGroup,
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

func (b *ClusterNetworkPolicySpecBuilder) AddEgress(protoc v1.Protocol,
	port *int32, portName *string, endPort *int32, cidr *string,
	podSelector map[string]string, nsSelector map[string]string,
	podSelectorMatchExp []metav1.LabelSelectorRequirement, nsSelectorMatchExp []metav1.LabelSelectorRequirement, selfNS bool,
	ruleAppliedToSpecs []ACNPAppliedToSpec, action crdv1alpha1.RuleAction, ruleClusterGroup, name string) *ClusterNetworkPolicySpecBuilder {

	// For simplicity, we just reuse the Ingress code here.  The underlying data model for ingress/egress is identical
	// With the exception of calling the rule `To` vs. `From`.
	c := &ClusterNetworkPolicySpecBuilder{}
	c.AddIngress(protoc, port, portName, endPort, cidr, podSelector, nsSelector,
		podSelectorMatchExp, nsSelectorMatchExp, selfNS, ruleAppliedToSpecs, action, ruleClusterGroup, name)
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

func (b *ClusterNetworkPolicySpecBuilder) AddFQDNRule(fqdn string,
	protoc v1.Protocol, port *int32, portName *string, endPort *int32, name string,
	ruleAppliedToSpecs []ACNPAppliedToSpec, action crdv1alpha1.RuleAction) *ClusterNetworkPolicySpecBuilder {
	var appliedTos []crdv1alpha1.NetworkPolicyPeer
	for _, at := range ruleAppliedToSpecs {
		appliedTos = append(appliedTos, b.GetAppliedToPeer(at.PodSelector, at.NSSelector, at.PodSelectorMatchExp, at.NSSelectorMatchExp, at.Group))
	}
	policyPeer := []crdv1alpha1.NetworkPolicyPeer{{FQDN: fqdn}}
	var ports []crdv1alpha1.NetworkPolicyPort
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
		To:        policyPeer,
		Ports:     ports,
		Action:    &action,
		Name:      name,
		AppliedTo: appliedTos,
	}
	b.Spec.Egress = append(b.Spec.Egress, newRule)
	return b
}

func (b *ClusterNetworkPolicySpecBuilder) AddToServicesRule(svcRefs []crdv1alpha1.ServiceReference,
	name string, ruleAppliedToSpecs []ACNPAppliedToSpec, action crdv1alpha1.RuleAction) *ClusterNetworkPolicySpecBuilder {
	var appliedTos []crdv1alpha1.NetworkPolicyPeer
	for _, at := range ruleAppliedToSpecs {
		appliedTos = append(appliedTos, b.GetAppliedToPeer(at.PodSelector, at.NSSelector, at.PodSelectorMatchExp, at.NSSelectorMatchExp, at.Group))
	}
	newRule := crdv1alpha1.Rule{
		To:         make([]crdv1alpha1.NetworkPolicyPeer, 0),
		ToServices: svcRefs,
		Action:     &action,
		Name:       name,
		AppliedTo:  appliedTos,
	}
	b.Spec.Egress = append(b.Spec.Egress, newRule)
	return b
}

// AddEgressDNS mutates the nth policy rule to allow DNS, convenience method
func (b *ClusterNetworkPolicySpecBuilder) WithEgressDNS() *ClusterNetworkPolicySpecBuilder {
	protocolUDP := v1.ProtocolUDP
	route53 := crdv1alpha1.NetworkPolicyPort{
		Protocol: &protocolUDP,
		Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 53},
	}

	for i, e := range b.Spec.Egress {
		e.Ports = append(e.Ports, route53)
		b.Spec.Egress[i] = e
	}
	return b
}

func (b *ClusterNetworkPolicySpecBuilder) AddEgressLogging() *ClusterNetworkPolicySpecBuilder {
	for i, e := range b.Spec.Egress {
		e.EnableLogging = true
		b.Spec.Egress[i] = e
	}
	return b
}
