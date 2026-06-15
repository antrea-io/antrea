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
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	policyv1alpha2 "sigs.k8s.io/network-policy-api/apis/v1alpha2"

	"antrea.io/antrea/v2/pkg/apis/controlplane"
	antreacrd "antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
	antreatypes "antrea.io/antrea/v2/pkg/controller/types"
)

var (
	// adminTierPriority and baselineTierPriority are the Antrea internal Tier
	// priorities assigned to the Admin and Baseline tiers of a
	// ClusterNetworkPolicy respectively. The Admin tier takes precedence over
	// Antrea-native and K8s NetworkPolicies, while the Baseline tier is
	// evaluated last.
	adminTierPriority    = int32(251)
	baselineTierPriority = int32(254)

	// cnpActionToAntreaActionMap maps the network-policy-api ClusterNetworkPolicy
	// rule actions to the equivalent Antrea internal rule actions. Note that the
	// upstream "Accept" action maps to Antrea's "Allow": the API was renamed from
	// "Allow" (v1alpha1 AdminNetworkPolicy) to "Accept" (v1alpha2 ClusterNetworkPolicy).
	cnpActionToAntreaActionMap = map[policyv1alpha2.ClusterNetworkPolicyRuleAction]antreacrd.RuleAction{
		policyv1alpha2.ClusterNetworkPolicyRuleActionAccept: antreacrd.RuleActionAllow,
		policyv1alpha2.ClusterNetworkPolicyRuleActionDeny:   antreacrd.RuleActionDrop,
		policyv1alpha2.ClusterNetworkPolicyRuleActionPass:   antreacrd.RuleActionPass,
	}
)

// getK8sCNPReference returns a NetworkPolicyReference for the given ClusterNetworkPolicy.
func getK8sCNPReference(cnp *policyv1alpha2.ClusterNetworkPolicy) *controlplane.NetworkPolicyReference {
	return &controlplane.NetworkPolicyReference{
		Type: controlplane.K8sClusterNetworkPolicy,
		Name: cnp.Name,
		UID:  cnp.UID,
	}
}

// addK8sCNP receives ClusterNetworkPolicy ADD events and enqueues a reference of
// the ClusterNetworkPolicy to trigger its process.
func (n *NetworkPolicyController) addK8sCNP(obj interface{}) {
	defer n.heartbeat("addK8sCNP")
	cnp := obj.(*policyv1alpha2.ClusterNetworkPolicy)
	klog.InfoS("Processing ClusterNetworkPolicy ADD event", "clusterNetworkPolicy", cnp.Name)
	n.enqueueInternalNetworkPolicy(getK8sCNPReference(cnp))
}

// updateK8sCNP receives ClusterNetworkPolicy UPDATE events and enqueues a
// reference of the ClusterNetworkPolicy to trigger its process.
func (n *NetworkPolicyController) updateK8sCNP(_, cur interface{}) {
	defer n.heartbeat("updateK8sCNP")
	curCNP := cur.(*policyv1alpha2.ClusterNetworkPolicy)
	klog.InfoS("Processing ClusterNetworkPolicy UPDATE event", "clusterNetworkPolicy", curCNP.Name)
	n.enqueueInternalNetworkPolicy(getK8sCNPReference(curCNP))
}

// deleteK8sCNP receives ClusterNetworkPolicy DELETE events and enqueues a
// reference of the ClusterNetworkPolicy to trigger its process.
func (n *NetworkPolicyController) deleteK8sCNP(old interface{}) {
	cnp, ok := old.(*policyv1alpha2.ClusterNetworkPolicy)
	if !ok {
		tombstone, ok := old.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Error decoding object when deleting ClusterNetworkPolicy, invalid type: %v", old)
			return
		}
		cnp, ok = tombstone.Obj.(*policyv1alpha2.ClusterNetworkPolicy)
		if !ok {
			klog.Errorf("Error decoding object tombstone when deleting ClusterNetworkPolicy, invalid type: %v", tombstone.Obj)
			return
		}
	}
	defer n.heartbeat("deleteK8sCNP")
	klog.InfoS("Processing ClusterNetworkPolicy DELETE event", "clusterNetworkPolicy", cnp.Name)
	n.enqueueInternalNetworkPolicy(getK8sCNPReference(cnp))
}

// k8sCNPTierPriority returns the Antrea internal Tier priority for the given
// ClusterNetworkPolicy tier. The Baseline tier is evaluated after all other
// policies; any other value (i.e. Admin) takes the higher-precedence Admin tier.
func k8sCNPTierPriority(tier policyv1alpha2.Tier) int32 {
	if tier == policyv1alpha2.BaselineTier {
		return baselineTierPriority
	}
	return adminTierPriority
}

// k8sCNPActionToCRDAction translates a ClusterNetworkPolicy rule action to the
// equivalent Antrea internal rule action.
func k8sCNPActionToCRDAction(action policyv1alpha2.ClusterNetworkPolicyRuleAction) *antreacrd.RuleAction {
	antreaAction := cnpActionToAntreaActionMap[action]
	return &antreaAction
}

// toAntreaServicesForK8sCNP translates the Protocols field of a ClusterNetworkPolicy
// rule into Antrea Services.
func toAntreaServicesForK8sCNP(protocols []policyv1alpha2.ClusterNetworkPolicyProtocol) []controlplane.Service {
	var antreaServices []controlplane.Service
	for i := range protocols {
		protocol := &protocols[i]
		switch {
		case protocol.TCP != nil:
			antreaServices = append(antreaServices, toAntreaServiceForK8sCNPPort(v1.ProtocolTCP, protocol.TCP.DestinationPort))
		case protocol.UDP != nil:
			antreaServices = append(antreaServices, toAntreaServiceForK8sCNPPort(v1.ProtocolUDP, protocol.UDP.DestinationPort))
		case protocol.SCTP != nil:
			antreaServices = append(antreaServices, toAntreaServiceForK8sCNPPort(v1.ProtocolSCTP, protocol.SCTP.DestinationPort))
		case protocol.DestinationNamedPort != "":
			// Named ports are matched by name regardless of the transport protocol,
			// so the Service is created without a Protocol. The agent derives the
			// protocol from the target Pod's container spec when it resolves the
			// named port (see resolveService in the agent pod_reconciler).
			port := intstr.FromString(protocol.DestinationNamedPort)
			antreaServices = append(antreaServices, controlplane.Service{Port: &port})
		}
	}
	return antreaServices
}

// toAntreaServiceForK8sCNPPort builds an Antrea Service for a single transport
// protocol match. A nil port matches all ports of the protocol.
func toAntreaServiceForK8sCNPPort(protocol v1.Protocol, port *policyv1alpha2.Port) controlplane.Service {
	service := controlplane.Service{Protocol: toAntreaProtocol(&protocol)}
	if port == nil {
		return service
	}
	if port.Range != nil {
		start := intstr.FromInt(int(port.Range.Start))
		service.Port = &start
		service.EndPort = &port.Range.End
	} else {
		number := intstr.FromInt(int(port.Number))
		service.Port = &number
	}
	return service
}

// k8sCNPNetworkToAntreaIPBlock converts a ClusterNetworkPolicy "networks" CIDR
// peer into an Antrea IPBlock.
func k8sCNPNetworkToAntreaIPBlock(cidr string) (*controlplane.IPBlock, error) {
	ipNet, err := cidrStrToIPNet(cidr)
	if err != nil {
		return nil, err
	}
	return &controlplane.IPBlock{CIDR: *ipNet}, nil
}

// toAntreaPeerForK8sCNPIngress translates ClusterNetworkPolicy ingress peers
// into an Antrea NetworkPolicyPeer. Ingress peers only support Pods and
// Namespaces selectors.
func (n *NetworkPolicyController) toAntreaPeerForK8sCNPIngress(peers []policyv1alpha2.ClusterNetworkPolicyIngressPeer) (*controlplane.NetworkPolicyPeer, []*antreatypes.AddressGroup) {
	var addressGroups []*antreatypes.AddressGroup
	for i := range peers {
		peer := &peers[i]
		if peer.Pods != nil {
			ag := n.createAddressGroup("", &peer.Pods.PodSelector, &peer.Pods.NamespaceSelector, nil, nil)
			addressGroups = append(addressGroups, ag)
		} else if peer.Namespaces != nil {
			ag := n.createAddressGroup("", nil, peer.Namespaces, nil, nil)
			addressGroups = append(addressGroups, ag)
		}
	}
	return &controlplane.NetworkPolicyPeer{AddressGroups: getAddressGroupNames(addressGroups)}, addressGroups
}

// toAntreaPeerForK8sCNPEgress translates ClusterNetworkPolicy egress peers into
// an Antrea NetworkPolicyPeer. Egress peers support Pods and Namespaces
// selectors, plus the Networks (CIDR) peer type. The experimental Nodes and
// DomainNames peer types are not supported (and are rejected by the validating
// webhook).
func (n *NetworkPolicyController) toAntreaPeerForK8sCNPEgress(peers []policyv1alpha2.ClusterNetworkPolicyEgressPeer, cnpName string) (*controlplane.NetworkPolicyPeer, []*antreatypes.AddressGroup) {
	var addressGroups []*antreatypes.AddressGroup
	var ipBlocks []controlplane.IPBlock
	for i := range peers {
		peer := &peers[i]
		switch {
		case peer.Pods != nil:
			ag := n.createAddressGroup("", &peer.Pods.PodSelector, &peer.Pods.NamespaceSelector, nil, nil)
			addressGroups = append(addressGroups, ag)
		case peer.Namespaces != nil:
			ag := n.createAddressGroup("", nil, peer.Namespaces, nil, nil)
			addressGroups = append(addressGroups, ag)
		case len(peer.Networks) > 0:
			for _, cidr := range peer.Networks {
				ipBlock, err := k8sCNPNetworkToAntreaIPBlock(string(cidr))
				if err != nil {
					klog.ErrorS(err, "Failed to process ClusterNetworkPolicy Networks peer", "clusterNetworkPolicy", cnpName, "cidr", cidr)
					continue
				}
				ipBlocks = append(ipBlocks, *ipBlock)
			}
		}
	}
	return &controlplane.NetworkPolicyPeer{
		AddressGroups: getAddressGroupNames(addressGroups),
		IPBlocks:      ipBlocks,
	}, addressGroups
}

// processK8sCNPSubject translates a ClusterNetworkPolicySubject into Antrea
// AppliedToGroups.
func (n *NetworkPolicyController) processK8sCNPSubject(subject policyv1alpha2.ClusterNetworkPolicySubject) []*antreatypes.AppliedToGroup {
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

// processK8sClusterNetworkPolicy processes a network-policy-api ClusterNetworkPolicy
// and returns the equivalent Antrea internal NetworkPolicy together with its
// AppliedToGroups and AddressGroups. The internal Tier priority is derived from
// the policy's spec.tier (Admin or Baseline), while the in-tier precedence comes
// from spec.priority.
func (n *NetworkPolicyController) processK8sClusterNetworkPolicy(cnp *policyv1alpha2.ClusterNetworkPolicy) (*antreatypes.NetworkPolicy, map[string]*antreatypes.AppliedToGroup, map[string]*antreatypes.AddressGroup) {
	appliedToGroups := map[string]*antreatypes.AppliedToGroup{}
	addressGroups := map[string]*antreatypes.AddressGroup{}
	var rules []controlplane.NetworkPolicyRule

	for idx := range cnp.Spec.Ingress {
		ingressRule := &cnp.Spec.Ingress[idx]
		var services []controlplane.Service
		if len(ingressRule.Protocols) > 0 {
			services = toAntreaServicesForK8sCNP(ingressRule.Protocols)
		}
		peer, ags := n.toAntreaPeerForK8sCNPIngress(ingressRule.From)
		rules = append(rules, controlplane.NetworkPolicyRule{
			Direction: controlplane.DirectionIn,
			From:      *peer,
			Services:  services,
			Name:      ingressRule.Name,
			Action:    k8sCNPActionToCRDAction(ingressRule.Action),
			Priority:  int32(idx),
		})
		addressGroups = mergeAddressGroups(addressGroups, ags...)
	}
	for idx := range cnp.Spec.Egress {
		egressRule := &cnp.Spec.Egress[idx]
		var services []controlplane.Service
		if len(egressRule.Protocols) > 0 {
			services = toAntreaServicesForK8sCNP(egressRule.Protocols)
		}
		peer, ags := n.toAntreaPeerForK8sCNPEgress(egressRule.To, cnp.Name)
		rules = append(rules, controlplane.NetworkPolicyRule{
			Direction: controlplane.DirectionOut,
			To:        *peer,
			Services:  services,
			Name:      egressRule.Name,
			Action:    k8sCNPActionToCRDAction(egressRule.Action),
			Priority:  int32(idx),
		})
		addressGroups = mergeAddressGroups(addressGroups, ags...)
	}
	appliedToGroups = mergeAppliedToGroups(appliedToGroups, n.processK8sCNPSubject(cnp.Spec.Subject)...)
	priority := float64(cnp.Spec.Priority)
	tierPriority := k8sCNPTierPriority(cnp.Spec.Tier)
	internalNetworkPolicy := &antreatypes.NetworkPolicy{
		Name:            internalNetworkPolicyKeyFunc(cnp),
		Generation:      cnp.Generation,
		SourceRef:       getK8sCNPReference(cnp),
		UID:             cnp.UID,
		AppliedToGroups: sets.List(sets.KeySet(appliedToGroups)),
		Rules:           rules,
		Priority:        &priority,
		TierPriority:    &tierPriority,
	}
	return internalNetworkPolicy, appliedToGroups, addressGroups
}
