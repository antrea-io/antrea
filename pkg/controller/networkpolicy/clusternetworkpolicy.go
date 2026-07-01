// Copyright 2026 Antrea Authors
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
	"errors"
	"strconv"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/network-policy-api/apis/v1alpha2"

	"antrea.io/antrea/v2/pkg/apis/controlplane"
	antreacrd "antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
	antreatypes "antrea.io/antrea/v2/pkg/controller/types"
)

const (
	// cnpAdminTierPriority is the fixed Tier priority reserved for upstream
	// (v1alpha2) ClusterNetworkPolicy admin-tier rules. It sits between the
	// default Antrea-native Application Tier (250) and the Platform Tier (200),
	// ensuring that administrator-created CNPs are evaluated after
	// administrative Tiers but before application Tier.
	cnpAdminTierPriority = int32(220)
	// cnpBaselineTierPriority is the fixed Tier priority for the Baseline tier
	// of upstream ClusterNetworkPolicies, evaluated after all other policies.
	cnpBaselineTierPriority = int32(254)
)

var (
	cnpActionToAntreaActionMap = map[v1alpha2.ClusterNetworkPolicyRuleAction]antreacrd.RuleAction{
		v1alpha2.ClusterNetworkPolicyRuleActionAccept: antreacrd.RuleActionAllow,
		v1alpha2.ClusterNetworkPolicyRuleActionDeny:   antreacrd.RuleActionDrop,
		v1alpha2.ClusterNetworkPolicyRuleActionPass:   antreacrd.RuleActionPass,
	}
)

func getCNPReference(cnp *v1alpha2.ClusterNetworkPolicy) *controlplane.NetworkPolicyReference {
	return &controlplane.NetworkPolicyReference{
		Type: controlplane.ClusterNetworkPolicy,
		Name: cnp.Name,
		UID:  cnp.UID,
	}
}

// addCNP receives v1alpha2 ClusterNetworkPolicy ADD events and enqueues a reference of
// the ClusterNetworkPolicy to trigger its process.
func (n *NetworkPolicyController) addCNP(obj interface{}) {
	defer n.heartbeat("addCNP")
	cnp := obj.(*v1alpha2.ClusterNetworkPolicy)
	klog.InfoS("Processing ClusterNetworkPolicy ADD event", "cnp", cnp.Name)
	n.enqueueInternalNetworkPolicy(getCNPReference(cnp))
}

// updateCNP receives v1alpha2 ClusterNetworkPolicy UPDATE events and enqueues a
// reference of the ClusterNetworkPolicy to trigger its process.
func (n *NetworkPolicyController) updateCNP(_, cur interface{}) {
	defer n.heartbeat("updateCNP")
	curCNP := cur.(*v1alpha2.ClusterNetworkPolicy)
	klog.InfoS("Processing ClusterNetworkPolicy UPDATE event", "cnp", curCNP.Name)
	n.enqueueInternalNetworkPolicy(getCNPReference(curCNP))
}

// deleteCNP receives v1alpha2 ClusterNetworkPolicy DELETE events and enqueues a
// reference of the ClusterNetworkPolicy to trigger its process.
func (n *NetworkPolicyController) deleteCNP(old interface{}) {
	cnp, ok := old.(*v1alpha2.ClusterNetworkPolicy)
	if !ok {
		tombstone, ok := old.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.ErrorS(errors.New("unexpected object type"), "Error decoding object when deleting ClusterNetworkPolicy", "object", old)
			return
		}
		cnp, ok = tombstone.Obj.(*v1alpha2.ClusterNetworkPolicy)
		if !ok {
			klog.ErrorS(errors.New("unexpected tombstone object type"), "Error decoding object tombstone when deleting ClusterNetworkPolicy", "object", tombstone.Obj)
			return
		}
	}
	defer n.heartbeat("deleteCNP")
	klog.InfoS("Processing ClusterNetworkPolicy DELETE event", "cnp", cnp.Name)
	n.enqueueInternalNetworkPolicy(getCNPReference(cnp))
}

// syncCNPCreationAllowed is a long-running goroutine that owns the cnpCreationAllowed flag. It
// recomputes the flag whenever signaled through syncCNPCreationAllowedCh (by the Tier add/delete
// event handlers or by the initial trigger in Run). Because it is the only writer of
// cnpCreationAllowed and always re-queries the current Tier state, updates are serialized and
// race-free: there is no window where a stale query result can overwrite a newer one.
func (n *NetworkPolicyController) syncCNPCreationAllowed(stopCh <-chan struct{}) {
	for {
		select {
		case <-n.syncCNPCreationAllowedCh:
			n.updateCNPCreationAllowed()
		case <-stopCh:
			return
		}
	}
}

// updateCNPCreationAllowed checks whether any user-created Tier at cnpAdminTierPriority exists and
// sets cnpCreationAllowed accordingly. It must only be called from the syncCNPCreationAllowed
// goroutine, and after the Tier informer cache has been synced.
func (n *NetworkPolicyController) updateCNPCreationAllowed() {
	priorityKey := strconv.FormatInt(int64(cnpAdminTierPriority), 10)
	tiers, err := n.tierInformer.Informer().GetIndexer().ByIndex(PriorityIndex, priorityKey)
	if err != nil {
		klog.ErrorS(err, "Failed to query Tier index for CNP creation check")
		n.cnpCreationAllowed.Store(false)
		return
	}
	if len(tiers) > 0 {
		klog.InfoS("A Tier already exists at cnpAdminTierPriority; upstream ClusterNetworkPolicy creation is blocked until the conflicting Tier is removed",
			"priority", cnpAdminTierPriority, "tier", tiers[0])
		n.cnpCreationAllowed.Store(false)
	} else {
		n.cnpCreationAllowed.Store(true)
	}
}

// triggerCNPCreationAllowedSync signals the syncCNPCreationAllowed goroutine to recompute the
// cnpCreationAllowed flag. The signal is non-blocking and coalescing: if a recomputation is already
// pending, the signal is dropped because the goroutine will read the latest Tier state anyway.
func (n *NetworkPolicyController) triggerCNPCreationAllowedSync() {
	select {
	case n.syncCNPCreationAllowedCh <- struct{}{}:
	default:
	}
}

// onTierAddForCNP is called when a Tier is created. If the new Tier's priority
// matches cnpAdminTierPriority, CNP creation is blocked.
// This should only be possible during upgrade case when there are existing user
// created Tier at cnpAdminTierPriority, or when the feature gate is not enabled.
func (n *NetworkPolicyController) onTierAddForCNP(obj interface{}) {
	tier, ok := obj.(*antreacrd.Tier)
	if !ok {
		return
	}
	if tier.Spec.Priority == cnpAdminTierPriority {
		n.triggerCNPCreationAllowedSync()
	}
}

// onTierDeleteForCNP is called when a Tier is deleted. If the deleted Tier's
// priority was cnpAdminTierPriority, CNP creation may be enabled.
func (n *NetworkPolicyController) onTierDeleteForCNP(obj interface{}) {
	tier, ok := obj.(*antreacrd.Tier)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return
		}
		tier, ok = tombstone.Obj.(*antreacrd.Tier)
		if !ok {
			return
		}
	}
	if tier.Spec.Priority == cnpAdminTierPriority {
		n.triggerCNPCreationAllowedSync()
	}
}

// cnpPortToService converts a v1alpha2 Port and IP protocol to an Antrea Service.
// port may be nil, which means "any port for this protocol".
func cnpPortToService(p *v1alpha2.Port, proto v1.Protocol) controlplane.Service {
	if p == nil {
		return controlplane.Service{
			Protocol: toAntreaProtocol(&proto),
		}
	}
	if p.Range != nil {
		return controlplane.Service{
			Protocol: toAntreaProtocol(&proto),
			Port:     ptr.To(intstr.FromInt32(p.Range.Start)),
			EndPort:  &p.Range.End,
		}
	}
	return controlplane.Service{
		Protocol: toAntreaProtocol(&proto),
		Port:     ptr.To(intstr.FromInt32(p.Number)),
	}
}

// toAntreaServicesForCNPProtocols translates v1alpha2 ClusterNetworkPolicy rule protocols to Antrea Services.
// DestinationPort is optional within each TCP/UDP/SCTP entry; a nil DestinationPort means "any port for
// that protocol".
func toAntreaServicesForCNPProtocols(protocols []v1alpha2.ClusterNetworkPolicyProtocol) []controlplane.Service {
	var antreaServices []controlplane.Service
	for _, cnpProto := range protocols {
		var service controlplane.Service
		switch {
		case cnpProto.DestinationNamedPort != "":
			// Leave Protocol unset so the agent matches on port name only.
			service = controlplane.Service{
				Port: ptr.To(intstr.FromString(cnpProto.DestinationNamedPort)),
			}
		case cnpProto.TCP != nil:
			service = cnpPortToService(cnpProto.TCP.DestinationPort, v1.ProtocolTCP)
		case cnpProto.UDP != nil:
			service = cnpPortToService(cnpProto.UDP.DestinationPort, v1.ProtocolUDP)
		case cnpProto.SCTP != nil:
			service = cnpPortToService(cnpProto.SCTP.DestinationPort, v1.ProtocolSCTP)
		}
		antreaServices = append(antreaServices, service)
	}
	return antreaServices
}

// toAntreaIngressPeerForCNP processes v1alpha2 ClusterNetworkPolicyIngressPeers and yields Antrea NetworkPolicyPeers.
// The processing is required to implement fail-closed semantics: if a peer has no recognized fields set (e.g.
// because the deployed CRD uses a field added in a newer API version), the rule action determines the behavior.
// For "Accept" and "Pass" rules the peer is treated as matching no traffic (empty peer). For "Deny" rules the
// entire peer list is replaced with matchAllPeer so all traffic is denied.
//
// Note: for "Pass", matching nothing (rather than everything) is the correct fail-closed behavior. A Pass rule
// that fires on nothing lets traffic fall through to underlying rules (e.g. a deny-all), achieving a safe
// deny-all net effect without inadvertently bypassing those rules. Same logic applies to Egress rules.
func (n *NetworkPolicyController) toAntreaIngressPeerForCNP(rule v1alpha2.ClusterNetworkPolicyIngressRule) (*controlplane.NetworkPolicyPeer, []*antreatypes.AddressGroup) {
	var addressGroups []*antreatypes.AddressGroup
	for _, peer := range rule.From {
		switch {
		case peer.Pods != nil:
			addressGroups = append(addressGroups, n.createAddressGroup("", &peer.Pods.PodSelector, &peer.Pods.NamespaceSelector, nil, nil))
		case peer.Namespaces != nil:
			addressGroups = append(addressGroups, n.createAddressGroup("", nil, peer.Namespaces, nil, nil))
		default:
			// No recognized field is set: the CRD may have been updated with a new peer type
			// that this implementation does not understand yet. Apply fail-closed semantics.
			if rule.Action == v1alpha2.ClusterNetworkPolicyRuleActionDeny {
				klog.InfoS("ClusterNetworkPolicy ingress peer has no recognized fields; failing closed with matchAllPeer for Deny rule", "ruleName", rule.Name, "action", rule.Action)
				return &matchAllPeer, nil
			}
			klog.InfoS("ClusterNetworkPolicy ingress peer has no recognized fields; failing closed with empty peer", "ruleName", rule.Name, "action", rule.Action)
		}
	}
	return &controlplane.NetworkPolicyPeer{
		AddressGroups: getAddressGroupNames(addressGroups),
	}, addressGroups
}

// toAntreaEgressPeerForCNP processes v1alpha2 ClusterNetworkPolicyEgressPeers and yields Antrea NetworkPolicyPeers.
// The processing is required to implement fail-closed semantics: if a peer has no recognized fields set (e.g.
// because the deployed CRD uses a field added in a newer API version), the rule action determines the behavior.
// For "Accept" and "Pass" rules the peer is treated as matching no traffic (empty peer). For "Deny" rules the
// entire peer list is replaced with matchAllPeer so all traffic is denied.
func (n *NetworkPolicyController) toAntreaEgressPeerForCNP(rule v1alpha2.ClusterNetworkPolicyEgressRule) (*controlplane.NetworkPolicyPeer, []*antreatypes.AddressGroup) {
	var addressGroups []*antreatypes.AddressGroup
	var fqdns []string
	var ipBlocks []controlplane.IPBlock
	for _, peer := range rule.To {
		switch {
		case peer.Pods != nil:
			addressGroups = append(addressGroups, n.createAddressGroup("", &peer.Pods.PodSelector, &peer.Pods.NamespaceSelector, nil, nil))
		case peer.Namespaces != nil:
			addressGroups = append(addressGroups, n.createAddressGroup("", nil, peer.Namespaces, nil, nil))
		case peer.Nodes != nil:
			addressGroups = append(addressGroups, n.createAddressGroup("", nil, nil, nil, peer.Nodes))
		case len(peer.DomainNames) > 0:
			for _, domainName := range peer.DomainNames {
				fqdns = append(fqdns, string(domainName))
			}
		case len(peer.Networks) > 0:
			ipBlocks = append(ipBlocks, toAntreaIPBlocksForCNPNetworks(peer.Networks)...)
		default:
			// No recognized field is set: the CRD may have been updated with a new peer type
			// that this implementation does not understand yet. Apply fail-closed semantics.
			if rule.Action == v1alpha2.ClusterNetworkPolicyRuleActionDeny {
				klog.InfoS("ClusterNetworkPolicy egress peer has no recognized fields; failing closed with matchAllPeer for Deny rule", "ruleName", rule.Name, "action", rule.Action)
				return &matchAllPeer, nil
			}
			klog.InfoS("ClusterNetworkPolicy egress peer has no recognized fields; failing closed with empty peer", "ruleName", rule.Name, "action", rule.Action)
		}
	}
	return &controlplane.NetworkPolicyPeer{
		AddressGroups: getAddressGroupNames(addressGroups),
		FQDNs:         fqdns,
		IPBlocks:      ipBlocks,
	}, addressGroups
}

// toAntreaIPBlocksForCNPNetworks converts a list of validated CIDRs to Antrea IPBlocks.
func toAntreaIPBlocksForCNPNetworks(networks []v1alpha2.CIDR) []controlplane.IPBlock {
	var ipBlocks []controlplane.IPBlock
	for _, net := range networks {
		ipNet, err := cidrStrToIPNet(string(net))
		if err != nil {
			// CIDR formats are validated at ClusterNetworkPolicy creation time by CEL validation,
			// so theoretically this should not happen.
			klog.ErrorS(err, "Failure processing ClusterNetworkPolicy network", "network", net)
			continue
		}
		ipBlocks = append(ipBlocks, controlplane.IPBlock{
			CIDR: *ipNet,
		})
	}
	return ipBlocks
}

// processCNPSubject processes v1alpha2 ClusterNetworkPolicySubject and yields Antrea AppliedToGroups.
func (n *NetworkPolicyController) processCNPSubject(subject v1alpha2.ClusterNetworkPolicySubject) []*antreatypes.AppliedToGroup {
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

func cnpActionToCRDAction(action v1alpha2.ClusterNetworkPolicyRuleAction) *antreacrd.RuleAction {
	antreaAction, ok := cnpActionToAntreaActionMap[action]
	if !ok {
		klog.InfoS("Unknown ClusterNetworkPolicy action; defaulting to Drop", "action", action)
		antreaAction = antreacrd.RuleActionDrop
	}
	return &antreaAction
}

func (n *NetworkPolicyController) processClusterNetworkPolicy(cnp *v1alpha2.ClusterNetworkPolicy) (*antreatypes.NetworkPolicy, map[string]*antreatypes.AppliedToGroup, map[string]*antreatypes.AddressGroup) {
	appliedToGroups := map[string]*antreatypes.AppliedToGroup{}
	addressGroups := map[string]*antreatypes.AddressGroup{}
	var rules []controlplane.NetworkPolicyRule

	for idx, cnpIngressRule := range cnp.Spec.Ingress {
		var services []controlplane.Service
		if len(cnpIngressRule.Protocols) > 0 {
			services = toAntreaServicesForCNPProtocols(cnpIngressRule.Protocols)
		}
		// From is required by the CRD to contain at least one peer.
		peer, ags := n.toAntreaIngressPeerForCNP(cnpIngressRule)
		rule := controlplane.NetworkPolicyRule{
			Direction: controlplane.DirectionIn,
			From:      *peer,
			Services:  services,
			Name:      cnpIngressRule.Name,
			Action:    cnpActionToCRDAction(cnpIngressRule.Action),
			Priority:  int32(idx),
		}
		rules = append(rules, rule)
		addressGroups = mergeAddressGroups(addressGroups, ags...)
	}
	for idx, cnpEgressRule := range cnp.Spec.Egress {
		var services []controlplane.Service
		if len(cnpEgressRule.Protocols) > 0 {
			services = toAntreaServicesForCNPProtocols(cnpEgressRule.Protocols)
		}
		// To is required by the CRD to contain at least one peer.
		peer, ags := n.toAntreaEgressPeerForCNP(cnpEgressRule)
		rule := controlplane.NetworkPolicyRule{
			Direction: controlplane.DirectionOut,
			To:        *peer,
			Services:  services,
			Name:      cnpEgressRule.Name,
			Action:    cnpActionToCRDAction(cnpEgressRule.Action),
			Priority:  int32(idx),
		}
		rules = append(rules, rule)
		addressGroups = mergeAddressGroups(addressGroups, ags...)
	}
	// Convert int32 priority to float64 for internal representation
	priority := float64(cnp.Spec.Priority)
	// Determine tier priority based on the tier
	var tierPriority int32
	switch cnp.Spec.Tier {
	case v1alpha2.AdminTier:
		tierPriority = cnpAdminTierPriority
	case v1alpha2.BaselineTier:
		tierPriority = cnpBaselineTierPriority
	default:
		// The API restricts tier to Admin or Baseline; treat anything else as Admin and surface a log line.
		klog.InfoS("Unexpected ClusterNetworkPolicy tier value, defaulting to Admin tier priority", "tier", cnp.Spec.Tier, "cnp", cnp.Name)
		tierPriority = cnpAdminTierPriority
	}

	appliedToGroups = mergeAppliedToGroups(appliedToGroups, n.processCNPSubject(cnp.Spec.Subject)...)
	internalNetworkPolicy := &antreatypes.NetworkPolicy{
		Name:       internalNetworkPolicyKeyFunc(cnp),
		Generation: cnp.Generation,
		SourceRef: &controlplane.NetworkPolicyReference{
			Type: controlplane.ClusterNetworkPolicy,
			Name: cnp.Name,
			UID:  cnp.UID,
		},
		UID:              cnp.UID,
		AppliedToGroups:  sets.List(sets.KeySet(appliedToGroups)),
		Rules:            rules,
		Priority:         &priority,
		TierPriority:     &tierPriority,
		AppliedToPerRule: false,
	}
	return internalNetworkPolicy, appliedToGroups, addressGroups
}
