package utils

import (
	"fmt"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

type NetworkPolicySpecBuilder struct {
	Spec      networkingv1.NetworkPolicySpec
	Name      string
	Namespace string
}

func (n *NetworkPolicySpecBuilder) Get() *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      n.Name,
			Namespace: n.Namespace,
		},
		Spec: n.Spec,
	}
}

func (n *NetworkPolicySpecBuilder) SetPodSelector(labels map[string]string) *NetworkPolicySpecBuilder {
	ps := metav1.LabelSelector{
		MatchLabels: labels,
	}
	n.Spec.PodSelector = ps
	return n
}

func (n *NetworkPolicySpecBuilder) SetName(namespace string, name string) *NetworkPolicySpecBuilder {
	n.Namespace = namespace
	n.Name = name
	return n
}

// TODO: Add tests to match expressions
func (n *NetworkPolicySpecBuilder) AddIngress(protoc v1.Protocol, port *int, portName *string, cidr *string, exceptCIDRs []string, podSelector map[string]string, nsSelector map[string]string, podSelectorMatchExp *[]metav1.LabelSelectorRequirement, nsSelectorMatchExp *[]metav1.LabelSelectorRequirement) *NetworkPolicySpecBuilder {

	var ps *metav1.LabelSelector
	var ns *metav1.LabelSelector
	if n.Spec.Ingress == nil {
		n.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{}
	}

	if podSelector != nil {
		ps = &metav1.LabelSelector{
			MatchLabels: podSelector,
		}
		if podSelectorMatchExp != nil {
			ps.MatchExpressions = *podSelectorMatchExp
		}
	}

	if podSelectorMatchExp != nil {
		ps = &metav1.LabelSelector{
			MatchExpressions: *podSelectorMatchExp,
		}
	}

	if nsSelector != nil {
		ns = &metav1.LabelSelector{
			MatchLabels: nsSelector,
		}
		if nsSelectorMatchExp != nil {
			ns.MatchExpressions = *nsSelectorMatchExp
		}
	}

	if nsSelectorMatchExp != nil {
		ns = &metav1.LabelSelector{
			MatchExpressions: *nsSelectorMatchExp,
		}
	}

	var ipBlock *networkingv1.IPBlock
	if cidr != nil {
		ipBlock = &networkingv1.IPBlock{
			CIDR:   *cidr,
			Except: exceptCIDRs,
		}
	}

	var policyPeer []networkingv1.NetworkPolicyPeer
	if ps != nil || ns != nil || ipBlock != nil {
		policyPeer = []networkingv1.NetworkPolicyPeer{{
			PodSelector:       ps,
			NamespaceSelector: ns,
			IPBlock:           ipBlock,
		}}
	}

	var ports []networkingv1.NetworkPolicyPort
	if port != nil && portName != nil {
		panic("specify portname or port, not both")
	}
	if port != nil {
		fmt.Println("port not nil")
		ports = []networkingv1.NetworkPolicyPort{
			{
				Port:     &intstr.IntOrString{IntVal: int32(*port)},
				Protocol: &protoc,
			},
		}
	}
	if portName != nil {
		fmt.Println("portName not nil")
		ports = []networkingv1.NetworkPolicyPort{
			{
				Port:     &intstr.IntOrString{Type: intstr.String, StrVal: *portName},
				Protocol: &protoc,
			},
		}
	}
	newRule := networkingv1.NetworkPolicyIngressRule{
		From:  policyPeer,
		Ports: ports,
	}
	n.Spec.Ingress = append(n.Spec.Ingress, newRule)
	return n
}

// AddEgressDNS mutates the nth policy rule to allow DNS, convenience method
func (n *NetworkPolicySpecBuilder) WithEgressDNS() *NetworkPolicySpecBuilder {
	protocolUDP := v1.ProtocolUDP
	route53 := networkingv1.NetworkPolicyPort{
		Protocol: &protocolUDP,
		Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 53},
	}

	for _, e := range n.Spec.Egress {
		e.Ports = append(e.Ports, route53)
	}
	return n
}

func (n *NetworkPolicySpecBuilder) AddEgress(protoc v1.Protocol, port *int, portName *string, cidr *string, exceptCIDRs []string, podSelector map[string]string, nsSelector map[string]string, podSelectorMatchExp *[]metav1.LabelSelectorRequirement, nsSelectorMatchExp *[]metav1.LabelSelectorRequirement) *NetworkPolicySpecBuilder {
	// For simplicity, we just reuse the Ingress code here.  The underlying data model for ingress/egress is identical
	// With the exception of calling the rule `To` vs. `From`.
	i := &NetworkPolicySpecBuilder{}
	i.AddIngress(protoc, port, portName, cidr, exceptCIDRs, podSelector, nsSelector, podSelectorMatchExp, nsSelectorMatchExp)
	theRule := i.Get().Spec.Ingress[0]

	n.Spec.Egress = append(n.Spec.Egress, networkingv1.NetworkPolicyEgressRule{
		To:    theRule.From,
		Ports: theRule.Ports,
	})

	return n
}

func (n *NetworkPolicySpecBuilder) SetTypeIngress() *NetworkPolicySpecBuilder {
	n.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}
	return n
}
func (n *NetworkPolicySpecBuilder) SetTypeEgress() *NetworkPolicySpecBuilder {
	n.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}
	return n
}
func (n *NetworkPolicySpecBuilder) SetTypeBoth() *NetworkPolicySpecBuilder {
	n.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeEgress, networkingv1.PolicyTypeIngress}
	return n
}
