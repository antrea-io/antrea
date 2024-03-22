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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
)

type ClusterNetworkPolicySpecBuilder struct {
	Spec crdv1beta1.ClusterNetworkPolicySpec
	Name string
}

type ACNPAppliedToSpec struct {
	PodSelector          map[string]string
	NodeSelector         map[string]string
	NSSelector           map[string]string
	PodSelectorMatchExp  []metav1.LabelSelectorRequirement
	NodeSelectorMatchExp []metav1.LabelSelectorRequirement
	NSSelectorMatchExp   []metav1.LabelSelectorRequirement
	Group                string
	Service              *crdv1beta1.NamespacedName
}

func (b *ClusterNetworkPolicySpecBuilder) Get() *crdv1beta1.ClusterNetworkPolicy {
	if b.Spec.Ingress == nil {
		b.Spec.Ingress = []crdv1beta1.Rule{}
	}
	if b.Spec.Egress == nil {
		b.Spec.Egress = []crdv1beta1.Rule{}
	}
	return &crdv1beta1.ClusterNetworkPolicy{
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
		appliedToPeer := b.GetAppliedToPeer(spec.PodSelector,
			spec.NodeSelector,
			spec.NSSelector,
			spec.PodSelectorMatchExp,
			spec.NodeSelectorMatchExp,
			spec.NSSelectorMatchExp,
			spec.Group,
			spec.Service)
		b.Spec.AppliedTo = append(b.Spec.AppliedTo, appliedToPeer)
	}
	return b
}

func (b *ClusterNetworkPolicySpecBuilder) GetAppliedToPeer(podSelector map[string]string,
	nodeSelector map[string]string,
	nsSelector map[string]string,
	podSelectorMatchExp []metav1.LabelSelectorRequirement,
	nodeSelectorMatchExp []metav1.LabelSelectorRequirement,
	nsSelectorMatchExp []metav1.LabelSelectorRequirement,
	appliedToCG string,
	service *crdv1beta1.NamespacedName) crdv1beta1.AppliedTo {

	var podSel *metav1.LabelSelector
	var nodeSel *metav1.LabelSelector
	var nsSel *metav1.LabelSelector

	if podSelector != nil || podSelectorMatchExp != nil {
		podSel = &metav1.LabelSelector{
			MatchLabels:      podSelector,
			MatchExpressions: podSelectorMatchExp,
		}
	}
	if nodeSelector != nil || nodeSelectorMatchExp != nil {
		nodeSel = &metav1.LabelSelector{
			MatchLabels:      nodeSelector,
			MatchExpressions: nodeSelectorMatchExp,
		}
	}
	if nsSelector != nil || nsSelectorMatchExp != nil {
		nsSel = &metav1.LabelSelector{
			MatchLabels:      nsSelector,
			MatchExpressions: nsSelectorMatchExp,
		}
	}
	peer := crdv1beta1.AppliedTo{
		PodSelector:       podSel,
		NodeSelector:      nodeSel,
		NamespaceSelector: nsSel,
	}
	if appliedToCG != "" {
		peer.Group = appliedToCG
	}
	if service != nil {
		peer.Service = service
	}
	return peer
}

func (b *ClusterNetworkPolicySpecBuilder) AddIngress(protoc AntreaPolicyProtocol,
	port *int32, portName *string, endPort, icmpType, icmpCode, igmpType *int32,
	groupAddress, cidr *string, podSelector map[string]string, nodeSelector map[string]string, nsSelector map[string]string,
	podSelectorMatchExp []metav1.LabelSelectorRequirement, nodeSelectorMatchExp []metav1.LabelSelectorRequirement, nsSelectorMatchExp []metav1.LabelSelectorRequirement, namespaces *crdv1beta1.PeerNamespaces,
	ruleAppliedToSpecs []ACNPAppliedToSpec, action crdv1beta1.RuleAction, ruleClusterGroup, name string, serviceAccount *crdv1beta1.NamespacedName) *ClusterNetworkPolicySpecBuilder {

	var podSel *metav1.LabelSelector
	var nodeSel *metav1.LabelSelector
	var nsSel *metav1.LabelSelector
	var appliedTos []crdv1beta1.AppliedTo

	if b.Spec.Ingress == nil {
		b.Spec.Ingress = []crdv1beta1.Rule{}
	}

	if podSelector != nil || podSelectorMatchExp != nil {
		podSel = &metav1.LabelSelector{
			MatchLabels:      podSelector,
			MatchExpressions: podSelectorMatchExp,
		}
	}
	if nodeSelector != nil || nodeSelectorMatchExp != nil {
		nodeSel = &metav1.LabelSelector{
			MatchLabels:      nodeSelector,
			MatchExpressions: nodeSelectorMatchExp,
		}
	}
	if nsSelector != nil || nsSelectorMatchExp != nil {
		nsSel = &metav1.LabelSelector{
			MatchLabels:      nsSelector,
			MatchExpressions: nsSelectorMatchExp,
		}
	}
	var ipBlock *crdv1beta1.IPBlock
	if cidr != nil {
		ipBlock = &crdv1beta1.IPBlock{
			CIDR: *cidr,
		}
	}
	for _, at := range ruleAppliedToSpecs {
		appliedTos = append(appliedTos, b.GetAppliedToPeer(at.PodSelector,
			at.NodeSelector,
			at.NSSelector,
			at.PodSelectorMatchExp,
			at.NodeSelectorMatchExp,
			at.NSSelectorMatchExp,
			at.Group,
			at.Service))
	}
	// An empty From/To in ACNP rules evaluates to match all addresses.
	policyPeer := make([]crdv1beta1.NetworkPolicyPeer, 0)
	if podSel != nil || nodeSel != nil || nsSel != nil || namespaces != nil || ipBlock != nil || ruleClusterGroup != "" || serviceAccount != nil {
		policyPeer = []crdv1beta1.NetworkPolicyPeer{{
			PodSelector:       podSel,
			NodeSelector:      nodeSel,
			NamespaceSelector: nsSel,
			Namespaces:        namespaces,
			IPBlock:           ipBlock,
			Group:             ruleClusterGroup,
			ServiceAccount:    serviceAccount,
		}}
	}
	ports, protocols := GenPortsOrProtocols(protoc, port, portName, endPort, nil, nil, icmpType, icmpCode, igmpType, groupAddress)
	newRule := crdv1beta1.Rule{
		From:      policyPeer,
		Ports:     ports,
		Protocols: protocols,
		Action:    &action,
		Name:      name,
		AppliedTo: appliedTos,
	}
	b.Spec.Ingress = append(b.Spec.Ingress, newRule)
	return b
}

// TODO: added new function to avoid merge conflicts. Unify this function with 'addIngress' when
//
//	all conflicting PRs are merged.
func (b *ClusterNetworkPolicySpecBuilder) AddIngressForSrcPort(protoc AntreaPolicyProtocol,
	port, endPort, srcPort, endSrcPort, icmpType, icmpCode, igmpType *int32,
	groupAddress, cidr *string, podSelector map[string]string, nodeSelector map[string]string, nsSelector map[string]string,
	podSelectorMatchExp []metav1.LabelSelectorRequirement, nodeSelectorMatchExp []metav1.LabelSelectorRequirement, nsSelectorMatchExp []metav1.LabelSelectorRequirement, selfNS bool,
	ruleAppliedToSpecs []ACNPAppliedToSpec, action crdv1beta1.RuleAction, ruleClusterGroup, name string, serviceAccount *crdv1beta1.NamespacedName) *ClusterNetworkPolicySpecBuilder {

	var podSel *metav1.LabelSelector
	var nodeSel *metav1.LabelSelector
	var nsSel *metav1.LabelSelector
	var ns *crdv1beta1.PeerNamespaces
	var appliedTos []crdv1beta1.AppliedTo
	matchSelf := crdv1beta1.NamespaceMatchSelf

	if b.Spec.Ingress == nil {
		b.Spec.Ingress = []crdv1beta1.Rule{}
	}

	if podSelector != nil || podSelectorMatchExp != nil {
		podSel = &metav1.LabelSelector{
			MatchLabels:      podSelector,
			MatchExpressions: podSelectorMatchExp,
		}
	}
	if nodeSelector != nil || nodeSelectorMatchExp != nil {
		nodeSel = &metav1.LabelSelector{
			MatchLabels:      nodeSelector,
			MatchExpressions: nodeSelectorMatchExp,
		}
	}
	if nsSelector != nil || nsSelectorMatchExp != nil {
		nsSel = &metav1.LabelSelector{
			MatchLabels:      nsSelector,
			MatchExpressions: nsSelectorMatchExp,
		}
	}
	if selfNS == true {
		ns = &crdv1beta1.PeerNamespaces{
			Match: matchSelf,
		}
	}
	var ipBlock *crdv1beta1.IPBlock
	if cidr != nil {
		ipBlock = &crdv1beta1.IPBlock{
			CIDR: *cidr,
		}
	}
	for _, at := range ruleAppliedToSpecs {
		appliedTos = append(appliedTos, b.GetAppliedToPeer(at.PodSelector,
			at.NodeSelector,
			at.NSSelector,
			at.PodSelectorMatchExp,
			at.NodeSelectorMatchExp,
			at.NSSelectorMatchExp,
			at.Group,
			at.Service))
	}
	// An empty From/To in ACNP rules evaluates to match all addresses.
	policyPeer := make([]crdv1beta1.NetworkPolicyPeer, 0)
	if podSel != nil || nodeSel != nil || nsSel != nil || ns != nil || ipBlock != nil || ruleClusterGroup != "" || serviceAccount != nil {
		policyPeer = []crdv1beta1.NetworkPolicyPeer{{
			PodSelector:       podSel,
			NodeSelector:      nodeSel,
			NamespaceSelector: nsSel,
			Namespaces:        ns,
			IPBlock:           ipBlock,
			Group:             ruleClusterGroup,
			ServiceAccount:    serviceAccount,
		}}
	}
	ports, protocols := GenPortsOrProtocols(protoc, port, nil, endPort, srcPort, endSrcPort, icmpType, icmpCode, igmpType, groupAddress)
	newRule := crdv1beta1.Rule{
		From:      policyPeer,
		Ports:     ports,
		Protocols: protocols,
		Action:    &action,
		Name:      name,
		AppliedTo: appliedTos,
	}
	b.Spec.Ingress = append(b.Spec.Ingress, newRule)
	return b
}

func (b *ClusterNetworkPolicySpecBuilder) AddEgress(protoc AntreaPolicyProtocol,
	port *int32, portName *string, endPort, icmpType, icmpCode, igmpType *int32,
	groupAddress, cidr *string, podSelector map[string]string, nodeSelector map[string]string, nsSelector map[string]string,
	podSelectorMatchExp []metav1.LabelSelectorRequirement, nodeSelectorMatchExp []metav1.LabelSelectorRequirement, nsSelectorMatchExp []metav1.LabelSelectorRequirement, namespaces *crdv1beta1.PeerNamespaces,
	ruleAppliedToSpecs []ACNPAppliedToSpec, action crdv1beta1.RuleAction, ruleClusterGroup, name string, serviceAccount *crdv1beta1.NamespacedName) *ClusterNetworkPolicySpecBuilder {

	// For simplicity, we just reuse the Ingress code here.  The underlying data model for ingress/egress is identical
	// With the exception of calling the rule `To` vs. `From`.
	c := &ClusterNetworkPolicySpecBuilder{}
	c.AddIngress(protoc, port, portName, endPort, icmpType, icmpCode, igmpType, groupAddress, cidr, podSelector, nodeSelector, nsSelector,
		podSelectorMatchExp, nodeSelectorMatchExp, nsSelectorMatchExp, namespaces, ruleAppliedToSpecs, action, ruleClusterGroup, name, serviceAccount)
	theRule := c.Get().Spec.Ingress[0]

	b.Spec.Egress = append(b.Spec.Egress, crdv1beta1.Rule{
		To:        theRule.From,
		Ports:     theRule.Ports,
		Action:    theRule.Action,
		Name:      theRule.Name,
		AppliedTo: theRule.AppliedTo,
	})
	return b
}

func (b *ClusterNetworkPolicySpecBuilder) AddNodeSelectorRule(nodeSelector *metav1.LabelSelector, protoc AntreaPolicyProtocol, port *int32, name string,
	ruleAppliedToSpecs []ACNPAppliedToSpec, action crdv1beta1.RuleAction, isEgress bool) *ClusterNetworkPolicySpecBuilder {
	var appliedTos []crdv1beta1.AppliedTo
	for _, at := range ruleAppliedToSpecs {
		appliedTos = append(appliedTos, b.GetAppliedToPeer(at.PodSelector,
			at.NodeSelector,
			at.NSSelector,
			at.PodSelectorMatchExp,
			at.NodeSelectorMatchExp,
			at.NSSelectorMatchExp,
			at.Group,
			at.Service))
	}
	policyPeer := []crdv1beta1.NetworkPolicyPeer{{NodeSelector: nodeSelector}}
	k8sProtocol, _ := AntreaPolicyProtocolToK8sProtocol(protoc)
	newRule := crdv1beta1.Rule{
		Ports: []crdv1beta1.NetworkPolicyPort{
			{Protocol: &k8sProtocol, Port: &intstr.IntOrString{IntVal: *port}},
		},
		Action:    &action,
		Name:      name,
		AppliedTo: appliedTos,
	}
	if isEgress {
		newRule.To = policyPeer
		b.Spec.Egress = append(b.Spec.Egress, newRule)
	} else {
		newRule.From = policyPeer
		b.Spec.Ingress = append(b.Spec.Ingress, newRule)
	}
	return b
}

func (b *ClusterNetworkPolicySpecBuilder) AddFQDNRule(fqdn string,
	protoc AntreaPolicyProtocol, port *int32, portName *string, endPort *int32, name string,
	ruleAppliedToSpecs []ACNPAppliedToSpec, action crdv1beta1.RuleAction) *ClusterNetworkPolicySpecBuilder {
	var appliedTos []crdv1beta1.AppliedTo
	for _, at := range ruleAppliedToSpecs {
		appliedTos = append(appliedTos, b.GetAppliedToPeer(at.PodSelector,
			at.NodeSelector,
			at.NSSelector,
			at.PodSelectorMatchExp,
			at.NodeSelectorMatchExp,
			at.NSSelectorMatchExp,
			at.Group,
			at.Service))
	}
	policyPeer := []crdv1beta1.NetworkPolicyPeer{{FQDN: fqdn}}
	ports, _ := GenPortsOrProtocols(protoc, port, portName, endPort, nil, nil, nil, nil, nil, nil)
	newRule := crdv1beta1.Rule{
		To:        policyPeer,
		Ports:     ports,
		Action:    &action,
		Name:      name,
		AppliedTo: appliedTos,
	}
	b.Spec.Egress = append(b.Spec.Egress, newRule)
	return b
}

func (b *ClusterNetworkPolicySpecBuilder) AddToServicesRule(svcRefs []crdv1beta1.PeerService,
	name string, ruleAppliedToSpecs []ACNPAppliedToSpec, action crdv1beta1.RuleAction) *ClusterNetworkPolicySpecBuilder {
	var appliedTos []crdv1beta1.AppliedTo
	for _, at := range ruleAppliedToSpecs {
		appliedTos = append(appliedTos, b.GetAppliedToPeer(at.PodSelector,
			at.NodeSelector,
			at.NSSelector,
			at.PodSelectorMatchExp,
			at.NodeSelectorMatchExp,
			at.NSSelectorMatchExp,
			at.Group,
			at.Service))
	}
	newRule := crdv1beta1.Rule{
		To:         make([]crdv1beta1.NetworkPolicyPeer, 0),
		ToServices: svcRefs,
		Action:     &action,
		Name:       name,
		AppliedTo:  appliedTos,
	}
	b.Spec.Egress = append(b.Spec.Egress, newRule)
	return b
}

func (b *ClusterNetworkPolicySpecBuilder) AddStretchedIngressRule(pSel, nsSel map[string]string,
	name string, ruleAppliedToSpecs []ACNPAppliedToSpec, action crdv1beta1.RuleAction) *ClusterNetworkPolicySpecBuilder {

	var appliedTos []crdv1beta1.AppliedTo
	for _, at := range ruleAppliedToSpecs {
		appliedTos = append(appliedTos, b.GetAppliedToPeer(at.PodSelector,
			at.NodeSelector,
			at.NSSelector,
			at.PodSelectorMatchExp,
			at.NodeSelectorMatchExp,
			at.NSSelectorMatchExp,
			at.Group,
			at.Service))
	}
	newRule := crdv1beta1.Rule{
		From:      []crdv1beta1.NetworkPolicyPeer{{Scope: "ClusterSet"}},
		Action:    &action,
		Name:      name,
		AppliedTo: appliedTos,
	}
	if len(pSel) > 0 {
		newRule.From[0].PodSelector = &metav1.LabelSelector{MatchLabels: pSel}
	}
	if len(nsSel) > 0 {
		newRule.From[0].NamespaceSelector = &metav1.LabelSelector{MatchLabels: nsSel}
	}
	b.Spec.Ingress = append(b.Spec.Ingress, newRule)
	return b
}

// AddEgressDNS mutates the nth policy rule to allow DNS, convenience method
func (b *ClusterNetworkPolicySpecBuilder) WithEgressDNS() *ClusterNetworkPolicySpecBuilder {
	protocolUDP, _ := AntreaPolicyProtocolToK8sProtocol(ProtocolUDP)
	route53 := crdv1beta1.NetworkPolicyPort{
		Protocol: &protocolUDP,
		Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 53},
	}

	for i, e := range b.Spec.Egress {
		e.Ports = append(e.Ports, route53)
		b.Spec.Egress[i] = e
	}
	return b
}

func (b *ClusterNetworkPolicySpecBuilder) AddEgressLogging(logLabel string) *ClusterNetworkPolicySpecBuilder {
	for i, e := range b.Spec.Egress {
		e.EnableLogging = true
		e.LogLabel = logLabel
		b.Spec.Egress[i] = e
	}
	return b
}
