// Copyright 2023 Antrea Authors
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

package networkpolicy

import (
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	"sigs.k8s.io/network-policy-api/apis/v1alpha1"

	"antrea.io/antrea/pkg/apis/controlplane"
	antreacrd "antrea.io/antrea/pkg/apis/crd/v1beta1"
	antreatypes "antrea.io/antrea/pkg/controller/types"
)

var (
	adminNetworkPolicyTierPriority = int32(251)
	banpTierPriority               = int32(254)
	banpPriority                   = float64(1)

	anpActionToAntreaActionMap = map[v1alpha1.AdminNetworkPolicyRuleAction]antreacrd.RuleAction{
		v1alpha1.AdminNetworkPolicyRuleActionAllow: antreacrd.RuleActionAllow,
		v1alpha1.AdminNetworkPolicyRuleActionDeny:  antreacrd.RuleActionDrop,
		v1alpha1.AdminNetworkPolicyRuleActionPass:  antreacrd.RuleActionPass,
	}

	banpActionToAntreaActionMap = map[v1alpha1.BaselineAdminNetworkPolicyRuleAction]antreacrd.RuleAction{
		v1alpha1.BaselineAdminNetworkPolicyRuleActionAllow: antreacrd.RuleActionAllow,
		v1alpha1.BaselineAdminNetworkPolicyRuleActionDeny:  antreacrd.RuleActionDrop,
	}
)

func getAdminNPReference(anp *v1alpha1.AdminNetworkPolicy) *controlplane.NetworkPolicyReference {
	return &controlplane.NetworkPolicyReference{
		Type: controlplane.AdminNetworkPolicy,
		Name: anp.Name,
		UID:  anp.UID,
	}
}

func getBANPReference(banp *v1alpha1.BaselineAdminNetworkPolicy) *controlplane.NetworkPolicyReference {
	return &controlplane.NetworkPolicyReference{
		Type: controlplane.BaselineAdminNetworkPolicy,
		Name: banp.Name,
		UID:  banp.UID,
	}
}

// addAdminNP receives AdminNetworkPolicy ADD events and enqueues a reference of
// the AdminNetworkPolicy to trigger its process.
func (n *NetworkPolicyController) addAdminNP(obj interface{}) {
	defer n.heartbeat("addAdminNP")
	anp := obj.(*v1alpha1.AdminNetworkPolicy)
	klog.InfoS("Processing AdminNetworkPolicy ADD event", "anp", anp.Name)
	n.enqueueInternalNetworkPolicy(getAdminNPReference(anp))
}

// updateAdminNP receives AdminNetworkPolicy UPDATE events and enqueues a
// reference of the AdminNetworkPolicy to trigger its process.
func (n *NetworkPolicyController) updateAdminNP(_, cur interface{}) {
	defer n.heartbeat("updateAdminNP")
	curANP := cur.(*v1alpha1.AdminNetworkPolicy)
	klog.InfoS("Processing AdminNetworkPolicy UPDATE event", "anp", curANP.Name)
	n.enqueueInternalNetworkPolicy(getAdminNPReference(curANP))
}

// deleteAdminNP receives AdminNetworkPolicy DELETE events and enqueues a
// reference of the AdminNetworkPolicy to trigger its process.
func (n *NetworkPolicyController) deleteAdminNP(old interface{}) {
	anp, ok := old.(*v1alpha1.AdminNetworkPolicy)
	if !ok {
		tombstone, ok := old.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Error decoding object when deleting AdminNetworkPolicy, invalid type: %v", old)
			return
		}
		anp, ok = tombstone.Obj.(*v1alpha1.AdminNetworkPolicy)
		if !ok {
			klog.Errorf("Error decoding object tombstone when deleting AdminNetworkPolicy, invalid type: %v", tombstone.Obj)
			return
		}
	}
	defer n.heartbeat("deleteAdminNP")
	klog.InfoS("Processing AdminNetworkPolicy DELETE event", "anp", anp.Name)
	n.enqueueInternalNetworkPolicy(getAdminNPReference(anp))
}

// addBANP receives BaselineAdminNetworkPolicy ADD events and enqueues a reference of
// the BaselineAdminNetworkPolicy to trigger its process.
func (n *NetworkPolicyController) addBANP(obj interface{}) {
	defer n.heartbeat("addBANP")
	banp := obj.(*v1alpha1.BaselineAdminNetworkPolicy)
	klog.InfoS("Processing BaselineAdminNetworkPolicy ADD event", "banp", banp.Name)
	n.enqueueInternalNetworkPolicy(getBANPReference(banp))
}

// updateBANP receives BaselineAdminNetworkPolicy UPDATE events and enqueues a
// reference of the BaselineAdminNetworkPolicy to trigger its process.
func (n *NetworkPolicyController) updateBANP(_, cur interface{}) {
	defer n.heartbeat("updateBANP")
	curBANP := cur.(*v1alpha1.BaselineAdminNetworkPolicy)
	klog.InfoS("Processing BaselineAdminNetworkPolicy UPDATE event", "banp", curBANP.Name)
	n.enqueueInternalNetworkPolicy(getBANPReference(curBANP))
}

// deleteBANP receives BaselineAdminNetworkPolicy DELETE events and enqueues a
// reference of the BaselineAdminNetworkPolicy to trigger its process.
func (n *NetworkPolicyController) deleteBANP(old interface{}) {
	banp, ok := old.(*v1alpha1.BaselineAdminNetworkPolicy)
	if !ok {
		tombstone, ok := old.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Error decoding object when deleting BaselineAdminNetworkPolicy, invalid type: %v", old)
			return
		}
		banp, ok = tombstone.Obj.(*v1alpha1.BaselineAdminNetworkPolicy)
		if !ok {
			klog.Errorf("Error decoding object tombstone when deleting BaselineAdminNetworkPolicy, invalid type: %v", tombstone.Obj)
			return
		}
	}
	defer n.heartbeat("deleteBANP")
	klog.InfoS("Processing BaselineAdminNetworkPolicy DELETE event", "banp", banp.Name)
	n.enqueueInternalNetworkPolicy(getBANPReference(banp))
}

// anpHasNamespaceLabelRule returns whether an AdminNetworkPolicy has rules defined by
// advanced Namespace selection (sameLabels and notSameLabels)
func anpHasNamespaceLabelRule(anp *v1alpha1.AdminNetworkPolicy) bool {
	for _, ingress := range anp.Spec.Ingress {
		for _, peer := range ingress.From {
			if peer.Namespaces != nil && (len(peer.Namespaces.SameLabels) > 0 || len(peer.Namespaces.NotSameLabels) > 0) {
				return true
			}
		}
	}
	for _, egress := range anp.Spec.Egress {
		for _, peer := range egress.To {
			if peer.Namespaces != nil && (len(peer.Namespaces.SameLabels) > 0 || len(peer.Namespaces.NotSameLabels) > 0) {
				return true
			}
		}
	}
	return false
}

// banpHasNamespaceLabelRule returns whether a BaselineAdminNetworkPolicy has rules defined by
// advanced Namespace selection (sameLabels and notSameLabels)
func banpHasNamespaceLabelRule(banp *v1alpha1.BaselineAdminNetworkPolicy) bool {
	for _, ingress := range banp.Spec.Ingress {
		for _, peer := range ingress.From {
			if peer.Namespaces != nil && (len(peer.Namespaces.SameLabels) > 0 || len(peer.Namespaces.NotSameLabels) > 0) {
				return true
			}
		}
	}
	for _, egress := range banp.Spec.Egress {
		for _, peer := range egress.To {
			if peer.Namespaces != nil && (len(peer.Namespaces.SameLabels) > 0 || len(peer.Namespaces.NotSameLabels) > 0) {
				return true
			}
		}
	}
	return false
}

// toAntreaServicesForPolicyCRD processes ports field for ANPs/BANPs and returns the translated
// Antrea Services.
func toAntreaServicesForPolicyCRD(npPorts []v1alpha1.AdminNetworkPolicyPort) []controlplane.Service {
	var antreaServices []controlplane.Service
	for _, npPort := range npPorts {
		if npPort.PortNumber != nil {
			port := intstr.FromInt(int(npPort.PortNumber.Port))
			antreaServices = append(antreaServices, controlplane.Service{
				Protocol: toAntreaProtocol(&npPort.PortNumber.Protocol),
				Port:     &port,
			})
		} else if npPort.PortRange != nil {
			portStart := intstr.FromInt(int(npPort.PortRange.Start))
			antreaServices = append(antreaServices, controlplane.Service{
				Protocol: toAntreaProtocol(&npPort.PortRange.Protocol),
				Port:     &portStart,
				EndPort:  &npPort.PortRange.End,
			})
		} else if npPort.NamedPort != nil {
			port := intstr.FromString(*npPort.NamedPort)
			antreaServices = append(antreaServices, controlplane.Service{
				Port: &port,
			})
		}
	}
	return antreaServices
}

// splitPolicyPeersByScope splits the ANP/BANP peers in the rule by whether the peer is cluster scoped
// or per-namespace scoped. Per-namespace peers are those whose defined by sameLabels and
// notSameLabels.
func splitPolicyPeerByScope(peers []v1alpha1.AdminNetworkPolicyPeer) ([]v1alpha1.AdminNetworkPolicyPeer, []v1alpha1.AdminNetworkPolicyPeer) {
	var clusterPeers, perNSLabelPeers []v1alpha1.AdminNetworkPolicyPeer
	for _, peer := range peers {
		if peer.Pods != nil && peer.Pods.Namespaces.NamespaceSelector != nil {
			clusterPeers = append(clusterPeers, peer)
		} else if peer.Namespaces != nil && peer.Namespaces.NamespaceSelector != nil {
			clusterPeers = append(clusterPeers, peer)
		} else {
			perNSLabelPeers = append(perNSLabelPeers, peer)
		}
	}
	return clusterPeers, perNSLabelPeers
}

// toAntreaPeerForPolicyCRD processes AdminNetworkPolicyPeers and yield Antrea NetworkPolicyPeers.
func (n *NetworkPolicyController) toAntreaPeerForPolicyCRD(peers []v1alpha1.AdminNetworkPolicyPeer) (*controlplane.NetworkPolicyPeer, []*antreatypes.AddressGroup) {
	var addressGroups []*antreatypes.AddressGroup
	for _, peer := range peers {
		if peer.Pods != nil {
			addressGroup := n.createAddressGroup("", &peer.Pods.PodSelector, peer.Pods.Namespaces.NamespaceSelector, nil, nil)
			addressGroups = append(addressGroups, addressGroup)
		} else if peer.Namespaces != nil {
			addressGroup := n.createAddressGroup("", nil, peer.Namespaces.NamespaceSelector, nil, nil)
			addressGroups = append(addressGroups, addressGroup)
		}
	}
	return &controlplane.NetworkPolicyPeer{
		AddressGroups: getAddressGroupNames(addressGroups),
	}, addressGroups
}

// processClusterSubject processes AdminNetworkPolicySubject and yield Antrea AppliedToGroups.
func (n *NetworkPolicyController) processClusterSubject(subject v1alpha1.AdminNetworkPolicySubject) []*antreatypes.AppliedToGroup {
	var appliedToGroups []*antreatypes.AppliedToGroup
	var atg *antreatypes.AppliedToGroup
	if subject.Pods != nil {
		atg = n.createAppliedToGroup("", &subject.Pods.PodSelector, &subject.Pods.NamespaceSelector, nil, nil)
	} else if subject.Namespaces != nil {
		atg = n.createAppliedToGroup("", nil, subject.Namespaces, nil, nil)
	}
	if atg != nil {
		appliedToGroups = append(appliedToGroups, atg)
	}
	return appliedToGroups
}

func anpActionToCRDAction(action v1alpha1.AdminNetworkPolicyRuleAction) *antreacrd.RuleAction {
	antreaAction, _ := anpActionToAntreaActionMap[action]
	return &antreaAction
}

func banpActionToCRDAction(action v1alpha1.BaselineAdminNetworkPolicyRuleAction) *antreacrd.RuleAction {
	antreaAction, _ := banpActionToAntreaActionMap[action]
	return &antreaAction
}

func (n *NetworkPolicyController) processAdminNetworkPolicy(anp *v1alpha1.AdminNetworkPolicy) (*antreatypes.NetworkPolicy, map[string]*antreatypes.AppliedToGroup, map[string]*antreatypes.AddressGroup) {
	appliedToPerRule := anpHasNamespaceLabelRule(anp)
	appliedToGroups := map[string]*antreatypes.AppliedToGroup{}
	addressGroups := map[string]*antreatypes.AddressGroup{}
	var rules []controlplane.NetworkPolicyRule

	for idx, anpIngressRule := range anp.Spec.Ingress {
		var services []controlplane.Service
		if anpIngressRule.Ports != nil {
			services = toAntreaServicesForPolicyCRD(*anpIngressRule.Ports)
		}
		clusterPeers, _ := splitPolicyPeerByScope(anpIngressRule.From)
		if len(clusterPeers) > 0 {
			peer, ags := n.toAntreaPeerForPolicyCRD(clusterPeers)
			rule := controlplane.NetworkPolicyRule{
				Direction: controlplane.DirectionIn,
				From:      *peer,
				Services:  services,
				Name:      anpIngressRule.Name,
				Action:    anpActionToCRDAction(anpIngressRule.Action),
				Priority:  int32(idx),
			}
			rules = append(rules, rule)
			addressGroups = mergeAddressGroups(addressGroups, ags...)
		}
		//TODO: implement SameLabels and NotSameLabels for per NS label ingress peers
	}
	for idx, anpEgressRule := range anp.Spec.Egress {
		var services []controlplane.Service
		if anpEgressRule.Ports != nil {
			services = toAntreaServicesForPolicyCRD(*anpEgressRule.Ports)
		}
		clusterPeers, _ := splitPolicyPeerByScope(anpEgressRule.To)
		if len(clusterPeers) > 0 {
			peer, ags := n.toAntreaPeerForPolicyCRD(clusterPeers)
			rule := controlplane.NetworkPolicyRule{
				Direction: controlplane.DirectionOut,
				To:        *peer,
				Services:  services,
				Name:      anpEgressRule.Name,
				Action:    anpActionToCRDAction(anpEgressRule.Action),
				Priority:  int32(idx),
			}
			rules = append(rules, rule)
			addressGroups = mergeAddressGroups(addressGroups, ags...)
		}
		//TODO: implement SameLabels and NotSameLabels for per NS label egress peers
	}
	priority := float64(anp.Spec.Priority)
	if !appliedToPerRule {
		appliedToGroups = mergeAppliedToGroups(appliedToGroups, n.processClusterSubject(anp.Spec.Subject)...)
	}
	internalNetworkPolicy := &antreatypes.NetworkPolicy{
		Name:       internalNetworkPolicyKeyFunc(anp),
		Generation: anp.Generation,
		SourceRef: &controlplane.NetworkPolicyReference{
			Type: controlplane.AdminNetworkPolicy,
			Name: anp.Name,
			UID:  anp.UID,
		},
		UID:              anp.UID,
		AppliedToGroups:  sets.List(sets.KeySet(appliedToGroups)),
		Rules:            rules,
		Priority:         &priority,
		TierPriority:     &adminNetworkPolicyTierPriority,
		AppliedToPerRule: appliedToPerRule,
	}
	return internalNetworkPolicy, appliedToGroups, addressGroups
}

func (n *NetworkPolicyController) processBaselineAdminNetworkPolicy(banp *v1alpha1.BaselineAdminNetworkPolicy) (*antreatypes.NetworkPolicy, map[string]*antreatypes.AppliedToGroup, map[string]*antreatypes.AddressGroup) {
	appliedToPerRule := banpHasNamespaceLabelRule(banp)
	appliedToGroups := map[string]*antreatypes.AppliedToGroup{}
	addressGroups := map[string]*antreatypes.AddressGroup{}
	var rules []controlplane.NetworkPolicyRule

	for idx, banpIngressRule := range banp.Spec.Ingress {
		var services []controlplane.Service
		if banpIngressRule.Ports != nil {
			services = toAntreaServicesForPolicyCRD(*banpIngressRule.Ports)
		}
		clusterPeers, _ := splitPolicyPeerByScope(banpIngressRule.From)
		if len(clusterPeers) > 0 {
			peer, ags := n.toAntreaPeerForPolicyCRD(clusterPeers)
			rule := controlplane.NetworkPolicyRule{
				Direction: controlplane.DirectionIn,
				From:      *peer,
				Services:  services,
				Name:      banpIngressRule.Name,
				Action:    banpActionToCRDAction(banpIngressRule.Action),
				Priority:  int32(idx),
			}
			rules = append(rules, rule)
			addressGroups = mergeAddressGroups(addressGroups, ags...)
		}
		//TODO: implement SameLabels and NotSameLabels for per NS label ingress peers
	}
	for idx, banpEgressRule := range banp.Spec.Egress {
		var services []controlplane.Service
		if banpEgressRule.Ports != nil {
			services = toAntreaServicesForPolicyCRD(*banpEgressRule.Ports)
		}
		clusterPeers, _ := splitPolicyPeerByScope(banpEgressRule.To)
		if len(clusterPeers) > 0 {
			peer, ags := n.toAntreaPeerForPolicyCRD(clusterPeers)
			rule := controlplane.NetworkPolicyRule{
				Direction: controlplane.DirectionOut,
				To:        *peer,
				Services:  services,
				Name:      banpEgressRule.Name,
				Action:    banpActionToCRDAction(banpEgressRule.Action),
				Priority:  int32(idx),
			}
			rules = append(rules, rule)
			addressGroups = mergeAddressGroups(addressGroups, ags...)
		}
		//TODO: implement SameLabels and NotSameLabels for per NS label egress peers
	}
	if !appliedToPerRule {
		appliedToGroups = mergeAppliedToGroups(appliedToGroups, n.processClusterSubject(banp.Spec.Subject)...)
	}
	internalNetworkPolicy := &antreatypes.NetworkPolicy{
		Name:       internalNetworkPolicyKeyFunc(banp),
		Generation: banp.Generation,
		SourceRef: &controlplane.NetworkPolicyReference{
			Type: controlplane.BaselineAdminNetworkPolicy,
			Name: banp.Name,
			UID:  banp.UID,
		},
		UID:              banp.UID,
		AppliedToGroups:  sets.List(sets.KeySet(appliedToGroups)),
		Rules:            rules,
		Priority:         &banpPriority,
		TierPriority:     &banpTierPriority,
		AppliedToPerRule: appliedToPerRule,
	}
	return internalNetworkPolicy, appliedToGroups, addressGroups
}
