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

package networkpolicy

import (
	"errors"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	"sigs.k8s.io/network-policy-api/apis/v1alpha2"

	"antrea.io/antrea/v2/pkg/apis/controlplane"
	antreacrd "antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
	antreatypes "antrea.io/antrea/v2/pkg/controller/types"
)

var (
	adminTierPriority    = int32(251)
	baselineTierPriority = int32(254)

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

// appendCNPPortToServices appends Antrea Services for a v1alpha2 Port and the given IP protocol.
func appendCNPPortToServices(services *[]controlplane.Service, p *v1alpha2.Port, proto v1.Protocol) {
	if p == nil {
		return
	}
	if p.Range != nil {
		portStart := intstr.FromInt32(p.Range.Start)
		end := p.Range.End
		*services = append(*services, controlplane.Service{
			Protocol: toAntreaProtocol(&proto),
			Port:     &portStart,
			EndPort:  &end,
		})
		return
	}
	port := intstr.FromInt32(p.Number)
	*services = append(*services, controlplane.Service{
		Protocol: toAntreaProtocol(&proto),
		Port:     &port,
	})
}

// toAntreaServicesForCNPProtocols translates v1alpha2 ClusterNetworkPolicy rule protocols to Antrea Services.
func toAntreaServicesForCNPProtocols(protocols []v1alpha2.ClusterNetworkPolicyProtocol) []controlplane.Service {
	var antreaServices []controlplane.Service
	for _, cnpProto := range protocols {
		switch {
		case cnpProto.DestinationNamedPort != "":
			port := intstr.FromString(cnpProto.DestinationNamedPort)
			// Leave Protocol unset so the agent matches on port name only.
			antreaServices = append(antreaServices, controlplane.Service{
				Port: &port,
			})
		case cnpProto.TCP != nil && cnpProto.TCP.DestinationPort != nil:
			appendCNPPortToServices(&antreaServices, cnpProto.TCP.DestinationPort, v1.ProtocolTCP)
		case cnpProto.UDP != nil && cnpProto.UDP.DestinationPort != nil:
			appendCNPPortToServices(&antreaServices, cnpProto.UDP.DestinationPort, v1.ProtocolUDP)
		case cnpProto.SCTP != nil && cnpProto.SCTP.DestinationPort != nil:
			appendCNPPortToServices(&antreaServices, cnpProto.SCTP.DestinationPort, v1.ProtocolSCTP)
		}
	}
	return antreaServices
}

// toAntreaIngressPeerForCNP processes v1alpha2 ClusterNetworkPolicyIngressPeers and yields Antrea NetworkPolicyPeers.
func (n *NetworkPolicyController) toAntreaIngressPeerForCNP(peers []v1alpha2.ClusterNetworkPolicyIngressPeer) (*controlplane.NetworkPolicyPeer, []*antreatypes.AddressGroup) {
	var addressGroups []*antreatypes.AddressGroup
	for _, peer := range peers {
		if peer.Pods != nil {
			addressGroup := n.createAddressGroup("", &peer.Pods.PodSelector, &peer.Pods.NamespaceSelector, nil, nil)
			addressGroups = append(addressGroups, addressGroup)
		} else if peer.Namespaces != nil {
			addressGroup := n.createAddressGroup("", nil, peer.Namespaces, nil, nil)
			addressGroups = append(addressGroups, addressGroup)
		}
	}
	return &controlplane.NetworkPolicyPeer{
		AddressGroups: getAddressGroupNames(addressGroups),
	}, addressGroups
}

// toAntreaEgressPeerForCNP processes v1alpha2 ClusterNetworkPolicyEgressPeers and yields Antrea NetworkPolicyPeers.
func (n *NetworkPolicyController) toAntreaEgressPeerForCNP(peers []v1alpha2.ClusterNetworkPolicyEgressPeer) (*controlplane.NetworkPolicyPeer, []*antreatypes.AddressGroup) {
	var addressGroups []*antreatypes.AddressGroup
	var fqdns []string
	var ipBlocks []controlplane.IPBlock
	for _, peer := range peers {
		if peer.Pods != nil {
			addressGroup := n.createAddressGroup("", &peer.Pods.PodSelector, &peer.Pods.NamespaceSelector, nil, nil)
			addressGroups = append(addressGroups, addressGroup)
		} else if peer.Namespaces != nil {
			addressGroup := n.createAddressGroup("", nil, peer.Namespaces, nil, nil)
			addressGroups = append(addressGroups, addressGroup)
		} else if peer.Nodes != nil {
			addressGroup := n.createAddressGroup("", nil, nil, nil, peer.Nodes)
			addressGroups = append(addressGroups, addressGroup)
		} else if peer.DomainNames != nil {
			for _, domainName := range peer.DomainNames {
				fqdns = append(fqdns, string(domainName))
			}
		} else if peer.Networks != nil {
			ipBlocks = append(ipBlocks, toAntreaIPBlocksForCNPNetworks(peer.Networks)...)
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
	antreaAction := cnpActionToAntreaActionMap[action]
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
		if len(cnpIngressRule.From) > 0 {
			peer, ags := n.toAntreaIngressPeerForCNP(cnpIngressRule.From)
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
	}
	for idx, cnpEgressRule := range cnp.Spec.Egress {
		var services []controlplane.Service
		if len(cnpEgressRule.Protocols) > 0 {
			services = toAntreaServicesForCNPProtocols(cnpEgressRule.Protocols)
		}
		if len(cnpEgressRule.To) > 0 {
			peer, ags := n.toAntreaEgressPeerForCNP(cnpEgressRule.To)
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
	}
	// Convert int32 priority to float64 for internal representation
	priority := float64(cnp.Spec.Priority)
	// Determine tier priority based on the tier
	var tierPriority int32
	switch cnp.Spec.Tier {
	case v1alpha2.AdminTier:
		tierPriority = adminTierPriority
	case v1alpha2.BaselineTier:
		tierPriority = baselineTierPriority
	default:
		// The API restricts tier to Admin or Baseline; treat anything else as Admin and surface a log line.
		klog.InfoS("Unexpected ClusterNetworkPolicy tier value, defaulting to Admin tier priority", "tier", cnp.Spec.Tier, "cnp", cnp.Name)
		tierPriority = adminTierPriority
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
