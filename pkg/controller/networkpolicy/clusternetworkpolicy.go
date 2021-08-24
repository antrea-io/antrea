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

package networkpolicy

import (
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/apis/controlplane"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/pkg/controller/networkpolicy/store"
	antreatypes "antrea.io/antrea/pkg/controller/types"
	utilsets "antrea.io/antrea/pkg/util/sets"
)

// addCNP receives ClusterNetworkPolicy ADD events and creates resources
// which can be consumed by agents to configure corresponding rules on the Nodes.
func (n *NetworkPolicyController) addCNP(obj interface{}) {
	defer n.heartbeat("addCNP")
	cnp := obj.(*crdv1alpha1.ClusterNetworkPolicy)
	klog.Infof("Processing ClusterNetworkPolicy %s ADD event", cnp.Name)
	// Create an internal NetworkPolicy object corresponding to this
	// ClusterNetworkPolicy and enqueue task to internal NetworkPolicy Workqueue.
	internalNP := n.processClusterNetworkPolicy(cnp)
	klog.V(2).Infof("Creating new internal NetworkPolicy %s for %s", internalNP.Name, internalNP.SourceRef.ToString())
	n.internalNetworkPolicyStore.Create(internalNP)
	key := internalNetworkPolicyKeyFunc(cnp)
	n.enqueueInternalNetworkPolicy(key)
}

// updateCNP receives ClusterNetworkPolicy UPDATE events and updates resources
// which can be consumed by agents to configure corresponding rules on the Nodes.
func (n *NetworkPolicyController) updateCNP(old, cur interface{}) {
	defer n.heartbeat("updateCNP")
	curCNP := cur.(*crdv1alpha1.ClusterNetworkPolicy)
	klog.Infof("Processing ClusterNetworkPolicy %s UPDATE event", curCNP.Name)
	// Update an internal NetworkPolicy, corresponding to this NetworkPolicy and
	// enqueue task to internal NetworkPolicy Workqueue.
	curInternalNP := n.processClusterNetworkPolicy(curCNP)
	klog.V(2).Infof("Updating existing internal NetworkPolicy %s for %s", curInternalNP.Name, curInternalNP.SourceRef.ToString())
	// Retrieve old crdv1alpha1.NetworkPolicy object.
	oldCNP := old.(*crdv1alpha1.ClusterNetworkPolicy)
	// Old and current NetworkPolicy share the same key.
	key := internalNetworkPolicyKeyFunc(oldCNP)
	// Lock access to internal NetworkPolicy store such that concurrent access
	// to an internal NetworkPolicy is not allowed. This will avoid the
	// case in which an Update to an internal NetworkPolicy object may
	// cause the SpanMeta member to be overridden with stale SpanMeta members
	// from an older internal NetworkPolicy.
	n.internalNetworkPolicyMutex.Lock()
	oldInternalNPObj, _, _ := n.internalNetworkPolicyStore.Get(key)
	oldInternalNP := oldInternalNPObj.(*antreatypes.NetworkPolicy)
	// Must preserve old internal NetworkPolicy Span.
	curInternalNP.SpanMeta = oldInternalNP.SpanMeta
	n.internalNetworkPolicyStore.Update(curInternalNP)
	// Unlock the internal NetworkPolicy store.
	n.internalNetworkPolicyMutex.Unlock()
	// Enqueue addressGroup keys to update their Node span.
	for _, rule := range curInternalNP.Rules {
		for _, addrGroupName := range rule.From.AddressGroups {
			n.enqueueAddressGroup(addrGroupName)
		}
		for _, addrGroupName := range rule.To.AddressGroups {
			n.enqueueAddressGroup(addrGroupName)
		}
	}
	n.enqueueInternalNetworkPolicy(key)
	for _, atg := range oldInternalNP.AppliedToGroups {
		// Delete the old AppliedToGroup object if it is not referenced
		// by any internal NetworkPolicy.
		n.deleteDereferencedAppliedToGroup(atg)
	}
	n.deleteDereferencedAddressGroups(oldInternalNP)
}

// deleteCNP receives ClusterNetworkPolicy DELETED events and deletes resources
// which can be consumed by agents to delete corresponding rules on the Nodes.
func (n *NetworkPolicyController) deleteCNP(old interface{}) {
	cnp, ok := old.(*crdv1alpha1.ClusterNetworkPolicy)
	if !ok {
		tombstone, ok := old.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Error decoding object when deleting ClusterNetworkPolicy, invalid type: %v", old)
			return
		}
		cnp, ok = tombstone.Obj.(*crdv1alpha1.ClusterNetworkPolicy)
		if !ok {
			klog.Errorf("Error decoding object tombstone when deleting ClusterNetworkPolicy, invalid type: %v", tombstone.Obj)
			return
		}
	}
	defer n.heartbeat("deleteCNP")
	klog.Infof("Processing ClusterNetworkPolicy %s DELETE event", cnp.Name)
	key := internalNetworkPolicyKeyFunc(cnp)
	// Lock access to internal NetworkPolicy store so that concurrent reprocessACNP
	// calls will not re-process and add a CNP that has already been deleted.
	n.internalNetworkPolicyMutex.Lock()
	oldInternalNPObj, _, _ := n.internalNetworkPolicyStore.Get(key)
	oldInternalNP := oldInternalNPObj.(*antreatypes.NetworkPolicy)
	klog.V(2).Infof("Deleting internal NetworkPolicy %s for %s", oldInternalNP.Name, oldInternalNP.SourceRef.ToString())
	err := n.internalNetworkPolicyStore.Delete(key)
	n.internalNetworkPolicyMutex.Unlock()
	if err != nil {
		klog.Errorf("Error deleting internal NetworkPolicy during NetworkPolicy %s delete: %v", cnp.Name, err)
		return
	}
	for _, atg := range oldInternalNP.AppliedToGroups {
		n.deleteDereferencedAppliedToGroup(atg)
	}
	n.deleteDereferencedAddressGroups(oldInternalNP)
}

// reprocessACNP is triggered by
// 1. Namespace ADD/UPDATE/DELETE events when they impact the per-Namespace rules of a ACNP
// 2. Service ADD/UPDATE/DELETE events when they impact the toService rules of a ACNP
// 3. Endpoints ADD/UPDATE/DELETE events when they impact the toService rules of a ACNP
func (n *NetworkPolicyController) reprocessACNP(acnp *crdv1alpha1.ClusterNetworkPolicy) {
	key := internalNetworkPolicyKeyFunc(acnp)
	n.internalNetworkPolicyMutex.Lock()
	oldInternalNPObj, exist, _ := n.internalNetworkPolicyStore.Get(key)
	if !exist {
		klog.V(2).InfoS("Cannot find the original internal NetworkPolicy, skip reprocessACNP")
		n.internalNetworkPolicyMutex.Unlock()
		return
	}
	defer n.heartbeat("reprocessACNP")
	klog.InfoS("Processing ClusterNetworkPolicy %s REPROCESS event", "clusterNetworkPolicy", acnp.Name)
	oldInternalNP := oldInternalNPObj.(*antreatypes.NetworkPolicy)
	curInternalNP := n.processClusterNetworkPolicy(acnp)
	// Must preserve old internal NetworkPolicy Span.
	curInternalNP.SpanMeta = oldInternalNP.SpanMeta
	n.internalNetworkPolicyStore.Update(curInternalNP)
	n.internalNetworkPolicyMutex.Unlock()
	// Enqueue addressGroup keys to update their Node span.
	for _, rule := range curInternalNP.Rules {
		for _, addrGroupName := range rule.From.AddressGroups {
			n.enqueueAddressGroup(addrGroupName)
		}
		for _, addrGroupName := range rule.To.AddressGroups {
			n.enqueueAddressGroup(addrGroupName)
		}
	}
	n.enqueueInternalNetworkPolicy(key)
	for _, atg := range oldInternalNP.AppliedToGroups {
		// Delete the old AppliedToGroup object if it is not referenced
		// by any internal NetworkPolicy.
		n.deleteDereferencedAppliedToGroup(atg)
	}
	n.deleteDereferencedAddressGroups(oldInternalNP)
}

// filterPerNamespaceRuleACNPsByNSLabels gets all ClusterNetworkPolicy names that will need to be
// re-processed based on the entire label set of an added/updated/deleted Namespace.
func (n *NetworkPolicyController) filterPerNamespaceRuleACNPsByNSLabels(nsLabels labels.Set) sets.String {
	n.internalNetworkPolicyMutex.Lock()
	defer n.internalNetworkPolicyMutex.Unlock()

	affectedPolicies := sets.String{}
	nps, err := n.internalNetworkPolicyStore.GetByIndex(store.PerNamespaceRuleIndex, store.HasPerNamespaceRule)
	if err != nil {
		klog.Errorf("Error fetching internal NetworkPolicies that have per-Namespace rules: %v", err)
		return affectedPolicies
	}
	for _, np := range nps {
		internalNP := np.(*antreatypes.NetworkPolicy)
		for _, sel := range internalNP.PerNamespaceSelectors {
			if sel.Matches(nsLabels) {
				affectedPolicies.Insert(internalNP.SourceRef.Name)
				break
			}
		}
	}
	return affectedPolicies
}

// addNamespace receives Namespace ADD events and triggers all ClusterNetworkPolicies that have a
// per-namespace rule applied to this Namespace to be re-processed.
func (n *NetworkPolicyController) addNamespace(obj interface{}) {
	defer n.heartbeat("addNamespace")
	namespace := obj.(*v1.Namespace)
	klog.V(2).Infof("Processing Namespace %s ADD event, labels: %v", namespace.Name, namespace.Labels)
	affectedACNPs := n.filterPerNamespaceRuleACNPsByNSLabels(namespace.Labels)
	for cnpName := range affectedACNPs {
		if cnp, err := n.acnpLister.Get(cnpName); err == nil {
			n.reprocessACNP(cnp)
		}
	}
}

// updateNamespace receives Namespace UPDATE events and triggers all ClusterNetworkPolicies that have a
// per-namespace rule applied to either the original or the new Namespace to be re-processed.
func (n *NetworkPolicyController) updateNamespace(oldObj, curObj interface{}) {
	defer n.heartbeat("updateNamespace")
	oldNamespace, curNamespace := oldObj.(*v1.Namespace), curObj.(*v1.Namespace)
	klog.V(2).Infof("Processing Namespace %s UPDATE event, labels: %v", curNamespace.Name, curNamespace.Labels)
	oldLabelSet, curLabelSet := labels.Set(oldNamespace.Labels), labels.Set(curNamespace.Labels)
	affectedACNPsByOldLabels := n.filterPerNamespaceRuleACNPsByNSLabels(oldLabelSet)
	affectedACNPsByCurLabels := n.filterPerNamespaceRuleACNPsByNSLabels(curLabelSet)
	affectedACNPs := utilsets.SymmetricDifferenceString(affectedACNPsByOldLabels, affectedACNPsByCurLabels)
	for cnpName := range affectedACNPs {
		if cnp, err := n.acnpLister.Get(cnpName); err == nil {
			n.reprocessACNP(cnp)
		}
	}
}

// deleteNamespace receives Namespace DELETE events and triggers all ClusterNetworkPolicies that have a
// per-namespace rule applied to this Namespace to be re-processed.
func (n *NetworkPolicyController) deleteNamespace(old interface{}) {
	namespace, ok := old.(*v1.Namespace)
	if !ok {
		tombstone, ok := old.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Error decoding object when deleting Namespace, invalid type: %v", old)
			return
		}
		namespace, ok = tombstone.Obj.(*v1.Namespace)
		if !ok {
			klog.Errorf("Error decoding object tombstone when deleting Namespace, invalid type: %v", tombstone.Obj)
			return
		}
	}
	defer n.heartbeat("deleteNamespace")
	klog.V(2).Infof("Processing Namespace %s DELETE event, labels: %v", namespace.Name, namespace.Labels)
	affectedACNPs := n.filterPerNamespaceRuleACNPsByNSLabels(labels.Set(namespace.Labels))
	for _, cnpName := range affectedACNPs.List() {
		cnp, err := n.acnpLister.Get(cnpName)
		if err != nil {
			klog.Errorf("Error getting Antrea ClusterNetworkPolicy %s", cnpName)
			continue
		}
		n.reprocessACNP(cnp)
	}
}

// processClusterNetworkPolicy creates an internal NetworkPolicy instance
// corresponding to the crdv1alpha1.ClusterNetworkPolicy object. This method
// does not commit the internal NetworkPolicy in store, instead returns an
// instance to the caller wherein, it will be either stored as a new Object
// in case of ADD event or modified and store the updated instance, in case
// of an UPDATE event.
func (n *NetworkPolicyController) processClusterNetworkPolicy(acnp *crdv1alpha1.ClusterNetworkPolicy) *antreatypes.NetworkPolicy {
	hasPerNamespaceRule := hasPerNamespaceRule(acnp)
	// If one of the ACNP rule is a per-namespace rule (a peer in that rule has namespaces.Match set
	// to Self), the policy will need to be converted to appliedTo per rule policy, as the appliedTo
	// will be different for rules created for each namespace.
	appliedToPerRule := len(acnp.Spec.AppliedTo) == 0 || hasPerNamespaceRule
	// atgNamesSet tracks all distinct appliedToGroups referred to by the ClusterNetworkPolicy,
	// either in the spec section or in ingress/egress rules.
	// The span calculation and stale appliedToGroup cleanup logic would work seamlessly for both cases.
	atgNamesSet := sets.String{}
	// affectedNamespaceSelectors tracks all the appliedTo's namespaceSelectors of per-namespace rules.
	// It is used by the PerNamespaceRuleIndex for internalNetworkPolicyStore to filter out internal NPs
	// that has per-namespace rules, and in Namespace ADD/UPDATE/DELETE events, trigger ACNPs that selects
	// this Namespace's label to be re-processed, and corresponding rules to re-calculate affected Namespaces.
	var affectedNamespaceSelectors []labels.Selector
	// If appliedTo is set at spec level and the ACNP has per-namespace rules, then each appliedTo needs
	// to be split into appliedToGroups for each of its affected Namespace.
	var clusterAppliedToAffectedNS []string
	// atgForNamespace is the appliedToGroups splitted by Namespaces.
	var atgForNamespace []string
	if hasPerNamespaceRule && len(acnp.Spec.AppliedTo) > 0 {
		for _, at := range acnp.Spec.AppliedTo {
			affectedNS, selectors := n.getAffectedNamespacesForAppliedTo(at)
			affectedNamespaceSelectors = append(affectedNamespaceSelectors, selectors...)
			for _, ns := range affectedNS {
				atg := n.createAppliedToGroup(ns, at.PodSelector, nil, at.ExternalEntitySelector)
				atgNamesSet.Insert(atg)
				clusterAppliedToAffectedNS = append(clusterAppliedToAffectedNS, ns)
				atgForNamespace = append(atgForNamespace, atg)
			}
		}
	}
	var rules []controlplane.NetworkPolicyRule
	// Compute NetworkPolicyRules for Ingress Rules.
	ingressRules, ingressAffectedNamespaceSelectors := n.processRules(acnp, controlplane.DirectionIn, atgNamesSet, appliedToPerRule, clusterAppliedToAffectedNS, atgForNamespace)
	rules = append(rules, ingressRules...)
	affectedNamespaceSelectors = append(affectedNamespaceSelectors, ingressAffectedNamespaceSelectors...)
	// Compute NetworkPolicyRules for Egress Rules.
	egressRules, egressAffectedNamespaceSelectors := n.processRules(acnp, controlplane.DirectionOut, atgNamesSet, appliedToPerRule, clusterAppliedToAffectedNS, atgForNamespace)
	rules = append(rules, egressRules...)
	affectedNamespaceSelectors = append(affectedNamespaceSelectors, egressAffectedNamespaceSelectors...)
	// Create AppliedToGroup for each AppliedTo present in ClusterNetworkPolicy spec.
	if !hasPerNamespaceRule {
		n.processClusterAppliedTo(acnp.Spec.AppliedTo, atgNamesSet)
	}
	tierPriority := n.getTierPriority(acnp.Spec.Tier)
	internalNetworkPolicy := &antreatypes.NetworkPolicy{
		Name:       internalNetworkPolicyKeyFunc(acnp),
		Generation: acnp.Generation,
		SourceRef: &controlplane.NetworkPolicyReference{
			Type: controlplane.AntreaClusterNetworkPolicy,
			Name: acnp.Name,
			UID:  acnp.UID,
		},
		UID:                   acnp.UID,
		AppliedToGroups:       atgNamesSet.List(),
		Rules:                 rules,
		Priority:              &acnp.Spec.Priority,
		TierPriority:          &tierPriority,
		AppliedToPerRule:      appliedToPerRule,
		PerNamespaceSelectors: getUniqueNSSelectors(affectedNamespaceSelectors),
	}
	return internalNetworkPolicy
}

func (n *NetworkPolicyController) processRules(
	acnp *crdv1alpha1.ClusterNetworkPolicy,
	direction controlplane.Direction,
	atgNamesSet sets.String,
	appliedToPerRule bool,
	clusterAppliedToAffectedNS []string,
	atgForNamespace []string) (rules []controlplane.NetworkPolicyRule, affectedNamespaceSelectors []labels.Selector) {
	var acnpRules []crdv1alpha1.Rule
	if direction == controlplane.DirectionIn {
		acnpRules = acnp.Spec.Ingress
	} else {
		acnpRules = acnp.Spec.Egress
	}
	for idx, acnpRule := range acnpRules {
		addRule := func(peer *controlplane.NetworkPolicyPeer, services []controlplane.Service, dir controlplane.Direction, ruleAppliedTos []string) {
			rule := controlplane.NetworkPolicyRule{
				Direction:       dir,
				Services:        services,
				Name:            acnpRule.Name,
				Action:          acnpRule.Action,
				Priority:        int32(idx),
				EnableLogging:   acnpRule.EnableLogging,
				AppliedToGroups: ruleAppliedTos,
			}
			if dir == controlplane.DirectionIn {
				rule.From = *peer
			} else if dir == controlplane.DirectionOut {
				rule.To = *peer
			}
			rules = append(rules, rule)
		}
		if acnpRule.ToServices == nil {
			services, namedPortExists := toAntreaServicesForCRD(acnpRule.Ports)
			clusterPeers, perNSPeers := splitPeersByScope(acnpRule, direction)

			// When a rule's NetworkPolicyPeer is empty, a cluster level rule should be created
			// with an Antrea peer matching all addresses.
			if len(clusterPeers) > 0 || len(perNSPeers) == 0 {
				ruleAppliedTos := acnpRule.AppliedTo
				// For ACNPs that have per-namespace rules, cluster-level rules will be created with appliedTo
				// set as the spec appliedTo for each rule.
				if appliedToPerRule && len(acnp.Spec.AppliedTo) > 0 {
					ruleAppliedTos = acnp.Spec.AppliedTo
				}
				ruleATGNames := n.processClusterAppliedTo(ruleAppliedTos, atgNamesSet)
				klog.V(4).InfoS("Adding a new cluster-level rule with appliedTos a ClusterNetworkPolicy", "appliedToGroupNames", ruleATGNames, "clusterNetworkPolicy", acnp.Name)
				addRule(n.toAntreaPeerForCRD(clusterPeers, acnp, direction, namedPortExists), services, direction, ruleATGNames)
			}
			if len(perNSPeers) > 0 {
				if len(acnp.Spec.AppliedTo) > 0 {
					// Create a rule for each affected Namespace of appliedTo at spec level
					for i := range clusterAppliedToAffectedNS {
						klog.V(4).InfoS("Adding a new per-namespace rule with appliedTo a ClusterNetworkPolicy rule", "appliedToAffectedNS", clusterAppliedToAffectedNS[i], "ruleIndex", idx, "clusterNetworkPolicy", acnp.Name)
						addRule(n.toNamespacedPeerForCRD(perNSPeers, clusterAppliedToAffectedNS[i]), services, direction, []string{atgForNamespace[i]})
					}
				} else {
					// Create a rule for each affected Namespace of appliedTo at rule level
					for _, at := range acnpRule.AppliedTo {
						affectedNS, selectors := n.getAffectedNamespacesForAppliedTo(at)
						affectedNamespaceSelectors = append(affectedNamespaceSelectors, selectors...)
						for _, ns := range affectedNS {
							atg := n.createAppliedToGroup(ns, at.PodSelector, nil, at.ExternalEntitySelector)
							atgNamesSet.Insert(atg)
							klog.V(4).InfoS("Adding a new per-namespace rule with appliedTo for a ClusterNetworkPolicy rule", "appliedToGroup", atg, "ruleIndex", idx, "clusterNetworkPolicy", acnp.Name)
							addRule(n.toNamespacedPeerForCRD(perNSPeers, ns), services, direction, []string{atg})
						}
					}
				}
			}
			klog.InfoS("Checking cluster or perNSPeers", "numberOfClusterPeers", len(clusterPeers), "numberOfPerNamespacePeers", len(perNSPeers))
		} else {
			// Handle toService rules.
			ruleAppliedTos := acnpRule.AppliedTo
			if appliedToPerRule && len(acnp.Spec.AppliedTo) > 0 {
				ruleAppliedTos = acnp.Spec.AppliedTo
			}
			ruleATGNames := n.processClusterAppliedTo(ruleAppliedTos, atgNamesSet)
			// Because each ServiceReference refers to its own combination of ports and
			// Pods/IPBlocks，we need to add an individual rule for each ServiceReference.
			for _, eachService := range acnpRule.ToServices {
				svc, err := n.serviceLister.Services(eachService.Namespace).Get(eachService.Name)
				if err != nil {
					klog.V(2).InfoS("Service referred in `toServices` doesn't exist", "serviceNamespace", eachService.Namespace, "serviceName", eachService.Name)
					continue
				}
				if svc.Spec.Type != v1.ServiceTypeNodePort {
					klog.V(2).InfoS("Processing NodePort Service: still install rules matching the Endpoints IP+Ports, but no rule matching NodePort will be installed", "serviceNamespace", eachService.Namespace, "serviceName", eachService.Name)
				}
				antreaServices, antreaPeers, err := n.toAntreaServicesAndPeersFromServiceReference(eachService)
				if err != nil {
					klog.V(2).InfoS("Can't get the Endpoints of this Service", "serviceNamespace", eachService.Namespace, "serviceName", eachService.Name)
					continue
				}
				klog.V(4).InfoS("Adding a new cluster-level rule with appliedTos a ClusterNetworkPolicy", "appliedToGroupNames", ruleATGNames, "clusterNetworkPolicy", acnp.Name)
				addRule(antreaPeers, antreaServices, direction, ruleATGNames)
			}
		}
	}
	return rules, affectedNamespaceSelectors
}

// hasPerNamespaceRule returns true if there is at least one per-namespace rule
func hasPerNamespaceRule(cnp *crdv1alpha1.ClusterNetworkPolicy) bool {
	for _, ingress := range cnp.Spec.Ingress {
		for _, peer := range ingress.From {
			if peer.Namespaces != nil && peer.Namespaces.Match == crdv1alpha1.NamespaceMatchSelf {
				return true
			}
		}
	}
	for _, egress := range cnp.Spec.Egress {
		for _, peer := range egress.To {
			if peer.Namespaces != nil && peer.Namespaces.Match == crdv1alpha1.NamespaceMatchSelf {
				return true
			}
		}
	}
	return false
}

// processClusterAppliedTo processes appliedTo groups in Antrea ClusterNetworkPolicy set
// at cluster level (appliedTo groups which will not need to be split by Namespaces).
func (n *NetworkPolicyController) processClusterAppliedTo(appliedTo []crdv1alpha1.NetworkPolicyPeer, appliedToGroupNamesSet sets.String) []string {
	var appliedToGroupNames []string
	for _, at := range appliedTo {
		var atg string
		if at.Group != "" {
			atg = n.processAppliedToGroupForCG(at.Group)
		} else {
			atg = n.createAppliedToGroup("", at.PodSelector, at.NamespaceSelector, at.ExternalEntitySelector)
		}
		if atg != "" {
			appliedToGroupNames = append(appliedToGroupNames, atg)
			appliedToGroupNamesSet.Insert(atg)
		}
	}
	return appliedToGroupNames
}

// splitPeersByScope splits the ClusterNetworkPolicy peers in the rule by whether the peer
// is cluster-scoped or per-namespace.
func splitPeersByScope(rule crdv1alpha1.Rule, dir controlplane.Direction) ([]crdv1alpha1.NetworkPolicyPeer, []crdv1alpha1.NetworkPolicyPeer) {
	var clusterPeers, perNSPeers []crdv1alpha1.NetworkPolicyPeer
	peers := rule.From
	if dir == controlplane.DirectionOut {
		peers = rule.To
	}
	for _, peer := range peers {
		if peer.Namespaces != nil && peer.Namespaces.Match == crdv1alpha1.NamespaceMatchSelf {
			perNSPeers = append(perNSPeers, peer)
		} else {
			clusterPeers = append(clusterPeers, peer)
		}
	}
	return clusterPeers, perNSPeers
}

// getAffectedNamespacesForAppliedTo computes the Namespaces currently affected by the appliedTo
// Namespace selectors. It also returns the list of Namespace selectors used to compute affected
// Namespaces.
func (n *NetworkPolicyController) getAffectedNamespacesForAppliedTo(appliedTo crdv1alpha1.NetworkPolicyPeer) ([]string, []labels.Selector) {
	var affectedNS []string
	var affectedNamespaceSelectors []labels.Selector

	nsLabelSelector := appliedTo.NamespaceSelector
	if appliedTo.Group != "" {
		cg, err := n.cgLister.Get(appliedTo.Group)
		if err != nil {
			// This error should not occur as we validate that a CG must exist before
			// referencing it in an ACNP.
			klog.Errorf("ClusterGroup %s not found: %v", appliedTo.Group, err)
			return affectedNS, affectedNamespaceSelectors
		}
		if cg.Spec.NamespaceSelector != nil || cg.Spec.PodSelector != nil {
			nsLabelSelector = cg.Spec.NamespaceSelector
		}
	}
	nsSel, _ := metav1.LabelSelectorAsSelector(nsLabelSelector)
	// An empty nsLabelSelector means select from all Namespaces
	if nsLabelSelector == nil {
		nsSel = labels.Everything()
	}
	affectedNamespaceSelectors = append(affectedNamespaceSelectors, nsSel)
	namespaces, _ := n.namespaceLister.List(nsSel)
	for _, ns := range namespaces {
		affectedNS = append(affectedNS, ns.Name)
	}
	return affectedNS, affectedNamespaceSelectors
}

// getUniqueNSSelectors dedups the Namespace selectors, which are used as index to re-process
// affected ClusterNetworkPolicy when there is Namespace CRUD events. Note that when there is
// an empty selector in the list, this function will simply return a list with only one empty
// selector, because all Namespace events will affect this ClusterNetworkPolicy no matter
// what the other Namespace selectors are.
func getUniqueNSSelectors(selectors []labels.Selector) []labels.Selector {
	selectorStrings := sets.String{}
	i := 0
	for _, sel := range selectors {
		if sel.Empty() {
			return []labels.Selector{labels.Everything()}
		}
		if selectorStrings.Has(sel.String()) {
			continue
		}
		selectorStrings.Insert(sel.String())
		selectors[i] = sel
		i++
	}
	return selectors[:i]
}

// processRefCG processes the ClusterGroup reference present in the rule and returns the
// NetworkPolicyPeer with the corresponding AddressGroup or IPBlock.
func (n *NetworkPolicyController) processRefCG(g string) (string, []controlplane.IPBlock) {
	// Retrieve ClusterGroup for corresponding entry in the rule.
	cg, err := n.cgLister.Get(g)
	if err != nil {
		// This error should not occur as we validate that a CG must exist before
		// referencing it in an ACNP.
		klog.Errorf("ClusterGroup %s not found: %v", g, err)
		return "", nil
	}
	key := internalGroupKeyFunc(cg)
	// Find the internal Group corresponding to this ClusterGroup
	ig, found, _ := n.internalGroupStore.Get(key)
	if !found {
		// Internal Group was not found. Once the internal Group is created, the sync
		// worker for internal group will re-enqueue the ClusterNetworkPolicy processing
		// which will trigger the creation of AddressGroup.
		return "", nil
	}
	intGrp := ig.(*antreatypes.Group)
	if len(intGrp.IPBlocks) > 0 {
		return "", intGrp.IPBlocks
	}
	agKey := n.createAddressGroupForClusterGroupCRD(intGrp)
	// Return if addressGroup was created or found.
	return agKey, nil
}

func (n *NetworkPolicyController) processAppliedToGroupForCG(g string) string {
	// Retrieve ClusterGroup for corresponding entry in the AppliedToGroup.
	cg, err := n.cgLister.Get(g)
	if err != nil {
		// This error should not occur as we validate that a CG must exist before
		// referencing it in an ACNP.
		klog.Errorf("ClusterGroup %s not found: %v", g, err)
		return ""
	}
	key := internalGroupKeyFunc(cg)
	// Find the internal Group corresponding to this ClusterGroup
	ig, found, _ := n.internalGroupStore.Get(key)
	if !found {
		// Internal Group was not found. Once the internal Group is created, the sync
		// worker for internal group will re-enqueue the ClusterNetworkPolicy processing
		// which will trigger the creation of AddressGroup.
		return ""
	}
	intGrp := ig.(*antreatypes.Group)
	if len(intGrp.IPBlocks) > 0 {
		klog.V(2).Infof("ClusterGroup %s with IPBlocks will not be processed as AppliedTo", g)
		return ""
	}
	return n.createAppliedToGroupForClusterGroupCRD(intGrp)
}
