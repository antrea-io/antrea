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
	"reflect"
	"sort"
	"strings"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/apis/controlplane"
	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/pkg/controller/grouping"
	"antrea.io/antrea/pkg/controller/networkpolicy/store"
	antreatypes "antrea.io/antrea/pkg/controller/types"
	"antrea.io/antrea/pkg/util/k8s"
	utilsets "antrea.io/antrea/pkg/util/sets"
)

const (
	labelValueSeparator = ","
)

func getACNPReference(cnp *crdv1beta1.ClusterNetworkPolicy) *controlplane.NetworkPolicyReference {
	return &controlplane.NetworkPolicyReference{
		Type: controlplane.AntreaClusterNetworkPolicy,
		Name: cnp.Name,
		UID:  cnp.UID,
	}
}

// addCNP receives ClusterNetworkPolicy ADD events and enqueues a reference of
// the ClusterNetworkPolicy to trigger its process.
func (n *NetworkPolicyController) addCNP(obj interface{}) {
	defer n.heartbeat("addCNP")
	cnp := obj.(*crdv1beta1.ClusterNetworkPolicy)
	klog.Infof("Processing ClusterNetworkPolicy %s ADD event", cnp.Name)
	n.enqueueInternalNetworkPolicy(getACNPReference(cnp))
}

// updateCNP receives ClusterNetworkPolicy UPDATE events and enqueues a
// reference of the ClusterNetworkPolicy to trigger its process.
func (n *NetworkPolicyController) updateCNP(_, cur interface{}) {
	defer n.heartbeat("updateACNP")
	curCNP := cur.(*crdv1beta1.ClusterNetworkPolicy)
	klog.Infof("Processing ClusterNetworkPolicy %s UPDATE event", curCNP.Name)
	n.enqueueInternalNetworkPolicy(getACNPReference(curCNP))
}

// deleteCNP receives ClusterNetworkPolicy DELETE events and enqueues a
// reference of the ClusterNetworkPolicy to trigger its process.
func (n *NetworkPolicyController) deleteCNP(old interface{}) {
	cnp, ok := old.(*crdv1beta1.ClusterNetworkPolicy)
	if !ok {
		tombstone, ok := old.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Error decoding object when deleting ClusterNetworkPolicy, invalid type: %v", old)
			return
		}
		cnp, ok = tombstone.Obj.(*crdv1beta1.ClusterNetworkPolicy)
		if !ok {
			klog.Errorf("Error decoding object tombstone when deleting ClusterNetworkPolicy, invalid type: %v", tombstone.Obj)
			return
		}
	}
	defer n.heartbeat("deleteCNP")
	klog.Infof("Processing ClusterNetworkPolicy %s DELETE event", cnp.Name)
	n.enqueueInternalNetworkPolicy(getACNPReference(cnp))
}

// filterPerNamespaceRuleACNPsByNSLabels gets all ClusterNetworkPolicy names that will need to be
// re-processed based on the entire label set of an added/updated/deleted Namespace.
func (n *NetworkPolicyController) filterPerNamespaceRuleACNPsByNSLabels(nsLabels labels.Set) sets.Set[string] {
	namespaceLabelMatches := func(peers []crdv1beta1.AppliedTo) bool {
		for _, peer := range peers {
			nsLabelSelector := peer.NamespaceSelector
			if peer.Group != "" {
				cg, err := n.cgLister.Get(peer.Group)
				// It's fine to ignore this peer if the ClusterGroup is not found. After the ClusterGroup is created,
				// the ClusterNetworkPolicy will be reprocessed anyway.
				if err != nil {
					continue
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
			if nsSel.Matches(nsLabels) {
				return true
			}
		}
		return false
	}

	peerNamespacesSelectorExists := func(peers []crdv1beta1.NetworkPolicyPeer) bool {
		for _, peer := range peers {
			if peer.Namespaces != nil {
				return true
			}
		}
		return false
	}

	affectedPolicies := sets.New[string]()
	objs, _ := n.acnpInformer.Informer().GetIndexer().ByIndex(perNamespaceRuleIndex, indexValueTrue)
	for _, obj := range objs {
		cnp := obj.(*crdv1beta1.ClusterNetworkPolicy)
		if affected := func() bool {
			if len(cnp.Spec.AppliedTo) > 0 {
				// The policy has only spec level AppliedTo.
				return namespaceLabelMatches(cnp.Spec.AppliedTo)
			}
			// The policy has rule level AppliedTo.
			// It needs to check each rule's peers. If any peer of the rule has PeerNamespaces selector and its
			// AppliedTo selects this Namespace, the ClusterNetworkPolicy will be affected by the Namespace.
			for _, rule := range cnp.Spec.Ingress {
				if peerNamespacesSelectorExists(rule.From) && namespaceLabelMatches(rule.AppliedTo) {
					return true
				}
			}
			for _, rule := range cnp.Spec.Egress {
				if peerNamespacesSelectorExists(rule.To) && namespaceLabelMatches(rule.AppliedTo) {
					return true
				}
			}
			return false
		}(); affected {
			affectedPolicies.Insert(cnp.Name)
		}
	}
	return affectedPolicies
}

// getACNPsWithRulesMatchingAnyLabelKey gets all ACNPs that have relevant rules based on Namespace label keys.
func (n *NetworkPolicyController) getACNPsWithRulesMatchingAnyLabelKey(labelKeys sets.Set[string]) sets.Set[string] {
	matchedPolicyNames := sets.New[string]()
	for k := range labelKeys {
		objs, _ := n.acnpInformer.Informer().GetIndexer().ByIndex(namespaceRuleLabelKeyIndex, k)
		for _, obj := range objs {
			cnp := obj.(*crdv1beta1.ClusterNetworkPolicy)
			matchedPolicyNames.Insert(cnp.Name)
		}
	}
	return matchedPolicyNames
}

// getACNPsWithRulesMatchingAnyUpdatedLabels gets all ACNPs that have rules based on Namespace
// label keys, which have changes in value across Namespace update.
func (n *NetworkPolicyController) getACNPsWithRulesMatchingAnyUpdatedLabels(oldNSLabels, newNSLabels map[string]string) sets.Set[string] {
	updatedLabelKeys := sets.New[string]()
	for k, v := range oldNSLabels {
		if v2, ok := newNSLabels[k]; !ok || v2 != v {
			updatedLabelKeys.Insert(k)
		}
	}
	for k, v2 := range newNSLabels {
		if v, ok := oldNSLabels[k]; !ok || v != v2 {
			updatedLabelKeys.Insert(k)
		}
	}
	return n.getACNPsWithRulesMatchingAnyLabelKey(updatedLabelKeys)
}

// addNamespace receives Namespace ADD events and triggers all ClusterNetworkPolicies that have a
// per-namespace rule applied to this Namespace to be re-processed.
func (n *NetworkPolicyController) addNamespace(obj interface{}) {
	defer n.heartbeat("addNamespace")
	namespace := obj.(*v1.Namespace)
	klog.V(2).Infof("Processing Namespace %s ADD event, labels: %v", namespace.Name, namespace.Labels)
	affectedACNPs := n.filterPerNamespaceRuleACNPsByNSLabels(namespace.Labels)
	for cnpName := range affectedACNPs {
		// Ignore the ClusterNetworkPolicy if it has been removed during the process.
		if cnp, err := n.acnpLister.Get(cnpName); err == nil {
			n.enqueueInternalNetworkPolicy(getACNPReference(cnp))
		}
	}
}

// updateNamespace receives Namespace UPDATE events and triggers all ClusterNetworkPolicies that have a
// per-namespace rule applied to either the original or the new Namespace to be re-processed.
// It also triggers all K8s NetworkPolicies in the new Namespace to be re-processed
// if the logging Annotation changes.
func (n *NetworkPolicyController) updateNamespace(oldObj, curObj interface{}) {
	defer n.heartbeat("updateNamespace")
	oldNamespace, curNamespace := oldObj.(*v1.Namespace), curObj.(*v1.Namespace)
	klog.V(2).Infof("Processing Namespace %s UPDATE event, labels: %v, annotations: %v", curNamespace.Name, curNamespace.Labels, curNamespace.Annotations)
	// No ClusterNetworkPolicies are affected if the Namespace's labels do not change.
	if !labels.Equals(oldNamespace.Labels, curNamespace.Labels) {
		affectedACNPsByOldLabels := n.filterPerNamespaceRuleACNPsByNSLabels(oldNamespace.Labels)
		affectedACNPsByCurLabels := n.filterPerNamespaceRuleACNPsByNSLabels(curNamespace.Labels)
		affectedACNPs := utilsets.SymmetricDifferenceString(affectedACNPsByOldLabels, affectedACNPsByCurLabels)
		// Any ACNPs that has Namespace label rules that refers to the label key set that has
		// changed during the Namespace update will need to be re-processed.
		acnpsWithRulesMatchingNSLabelKeys := n.getACNPsWithRulesMatchingAnyUpdatedLabels(oldNamespace.Labels, curNamespace.Labels)
		affectedACNPs = affectedACNPs.Union(acnpsWithRulesMatchingNSLabelKeys)
		for cnpName := range affectedACNPs {
			// Ignore the ClusterNetworkPolicy if it has been removed during the process.
			if cnp, err := n.acnpLister.Get(cnpName); err == nil {
				n.enqueueInternalNetworkPolicy(getACNPReference(cnp))
			}
		}
	}

	if oldNamespace.Annotations[EnableNPLoggingAnnotationKey] != curNamespace.Annotations[EnableNPLoggingAnnotationKey] {
		affectedNPs, _ := n.networkPolicyLister.NetworkPolicies(curNamespace.Name).List(labels.Everything())
		for _, np := range affectedNPs {
			n.enqueueInternalNetworkPolicy(getKNPReference(np))
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
	affectedACNPs := n.filterPerNamespaceRuleACNPsByNSLabels(namespace.Labels)
	for _, cnpName := range sets.List(affectedACNPs) {
		// Ignore the ClusterNetworkPolicy if it has been removed during the process.
		if cnp, err := n.acnpLister.Get(cnpName); err == nil {
			n.enqueueInternalNetworkPolicy(getACNPReference(cnp))
		}
	}
}

func (c *NetworkPolicyController) filterAGsFromNodeLabels(node *v1.Node) sets.Set[string] {
	ags := sets.New[string]()
	addressGroupObjs, _ := c.addressGroupStore.GetByIndex(store.IsNodeAddressGroupIndex, "true")
	for _, addressGroupObj := range addressGroupObjs {
		addressGroup := addressGroupObj.(*antreatypes.AddressGroup)
		nodeSelector := addressGroup.Selector.NodeSelector
		if nodeSelector.Matches(labels.Set(node.GetLabels())) {
			ags.Insert(addressGroup.Name)
		}
	}
	return ags
}

func (c *NetworkPolicyController) getATGsAppliedToService() sets.Set[string] {
	atgs := sets.New[string]()
	appliedToGroupObjs, _ := c.appliedToGroupStore.GetByIndex(store.IsAppliedToServiceIndex, "true")
	for _, appliedToGroupObj := range appliedToGroupObjs {
		appliedToGroup := appliedToGroupObj.(*antreatypes.AppliedToGroup)
		atgs.Insert(appliedToGroup.Name)
	}
	return atgs
}

func (c *NetworkPolicyController) addNode(obj interface{}) {
	node := obj.(*v1.Node)
	affectedAGs := c.filterAGsFromNodeLabels(node)
	for key := range affectedAGs {
		c.enqueueAddressGroup(key)
	}
	// All AppliedToGroups that are applied to Services need re-sync.
	affectedATGs := c.getATGsAppliedToService()
	for key := range affectedATGs {
		c.enqueueAppliedToGroup(key)
	}
	klog.V(2).InfoS("Processed Node CREATE event", "nodeName", node.Name, "affectedAGs", affectedAGs.Len())
}

func (c *NetworkPolicyController) deleteNode(obj interface{}) {
	node, ok := obj.(*v1.Node)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.ErrorS(nil, "Processed Node DELETE event error", "obj", obj)
			return
		}
		node, ok = tombstone.Obj.(*v1.Node)
		if !ok {
			klog.ErrorS(nil, "Processed Node DELETE event error", "obj", tombstone.Obj)
			return
		}
	}
	// enqueue affected address group
	affectedAGs := c.filterAGsFromNodeLabels(node)
	for key := range affectedAGs {
		c.enqueueAddressGroup(key)
	}
	// All AppliedToGroups that are applied to Services need re-sync.
	affectedATGs := c.getATGsAppliedToService()
	for key := range affectedATGs {
		c.enqueueAppliedToGroup(key)
	}
	klog.V(2).InfoS("Processed Node DELETE event", "nodeName", node.Name, "affectedAGs", affectedAGs.Len())
}

func nodeIPChanged(oldNode, newNode *v1.Node) (changed bool) {
	oldIPs, _ := k8s.GetNodeAllAddrs(oldNode)
	newIPs, _ := k8s.GetNodeAllAddrs(newNode)
	return !oldIPs.Equal(newIPs)
}

func (c *NetworkPolicyController) updateNode(oldObj, newObj interface{}) {
	node := newObj.(*v1.Node)
	oldNode := oldObj.(*v1.Node)
	ipChanged := nodeIPChanged(oldNode, node)
	labelsChanged := !reflect.DeepEqual(node.GetLabels(), oldNode.GetLabels())
	if !labelsChanged && !ipChanged {
		klog.V(2).InfoS("Processed Node UPDATE event, labels and IPs not changed", "nodeName", node.Name)
		return
	}

	affectedAGs := c.filterAGsFromNodeLabels(node)
	if labelsChanged {
		oldAGs := c.filterAGsFromNodeLabels(oldNode)
		if ipChanged {
			affectedAGs = utilsets.MergeString(affectedAGs, oldAGs)
		} else {
			affectedAGs = utilsets.SymmetricDifferenceString(affectedAGs, oldAGs)
		}
	}
	for ag := range affectedAGs {
		c.enqueueAddressGroup(ag)
	}
	klog.V(2).InfoS("Processed Node UPDATE event", "nodeName", node.Name, "affectedAGs", affectedAGs.Len())
}

// processClusterNetworkPolicy creates an internal NetworkPolicy instance
// corresponding to the crdv1beta1.ClusterNetworkPolicy object. This method
// does not commit the internal NetworkPolicy in store, instead returns an
// instance to the caller wherein, it will be either stored as a new Object
// in case of ADD event or modified and store the updated instance, in case
// of an UPDATE event.
func (n *NetworkPolicyController) processClusterNetworkPolicy(cnp *crdv1beta1.ClusterNetworkPolicy) (*antreatypes.NetworkPolicy, map[string]*antreatypes.AppliedToGroup, map[string]*antreatypes.AddressGroup) {
	hasPerNamespaceRule := hasPerNamespaceRule(cnp)
	// If one of the ACNP rule is a per-namespace rule (a peer in that rule has namespaces.Match set
	// to Self), the policy will need to be converted to appliedTo per rule policy, as the appliedTo
	// will be different for rules created for each namespace.
	appliedToPerRule := len(cnp.Spec.AppliedTo) == 0 || hasPerNamespaceRule
	// appliedToGroups tracks all distinct appliedToGroups referred to by the ClusterNetworkPolicy,
	// either in the spec section or in ingress/egress rules.
	// The span calculation and stale appliedToGroup cleanup logic would work seamlessly for both cases.
	appliedToGroups := map[string]*antreatypes.AppliedToGroup{}
	addressGroups := map[string]*antreatypes.AddressGroup{}
	// If appliedTo is set at spec level and the ACNP has per-namespace rules, then each appliedTo needs
	// to be split into appliedToGroups for each of its affected Namespace.
	atgPerAffectedNS := map[string]*antreatypes.AppliedToGroup{}
	// When appliedTo is set at spec level and the ACNP has rules that select peer Namespaces by sameLabels,
	// this field tracks the labels of all Namespaces selected by the appliedTo.
	labelsPerAffectedNS := map[string]labels.Set{}
	// clusterSetScopeSelectorKeys keeps track of all the ClusterSet-scoped selector keys of the policy.
	// During policy peer processing, any ClusterSet-scoped selector will be registered with the
	// labelIdentityInterface and added to this set. By the end of the function, this set will
	// be used to remove any stale selector from the policy in the labelIdentityInterface.
	var clusterSetScopeSelectorKeys sets.Set[string]
	if hasPerNamespaceRule && len(cnp.Spec.AppliedTo) > 0 {
		for _, at := range cnp.Spec.AppliedTo {
			if at.ServiceAccount != nil {
				atg := n.createAppliedToGroup(at.ServiceAccount.Namespace, serviceAccountNameToPodSelector(at.ServiceAccount.Name), nil, nil, nil)
				appliedToGroups = mergeAppliedToGroups(appliedToGroups, atg)
				atgPerAffectedNS[at.ServiceAccount.Namespace] = atg
				labelsPerAffectedNS[at.ServiceAccount.Namespace] = n.getNamespaceLabels(at.ServiceAccount.Namespace)
			} else {
				labelsPerAffectedNS = n.getAffectedNamespacesForAppliedTo(at)
				for ns := range labelsPerAffectedNS {
					atg := n.createAppliedToGroup(ns, at.PodSelector, nil, at.ExternalEntitySelector, nil)
					appliedToGroups = mergeAppliedToGroups(appliedToGroups, atg)
					atgPerAffectedNS[ns] = atg
				}
			}
		}
	}
	var rules []controlplane.NetworkPolicyRule
	processRules := func(cnpRules []crdv1beta1.Rule, direction controlplane.Direction) {
		for idx, cnpRule := range cnpRules {
			services, namedPortExists := toAntreaServicesForCRD(cnpRule.Ports, cnpRule.Protocols)
			clusterPeers, perNSPeers, nsLabelPeers := splitPeersByScope(cnpRule, direction)
			addRule := func(peer *controlplane.NetworkPolicyPeer, ruleAddressGroups []*antreatypes.AddressGroup, dir controlplane.Direction, ruleAppliedTos []*antreatypes.AppliedToGroup) {
				rule := controlplane.NetworkPolicyRule{
					Direction:       dir,
					Services:        services,
					Name:            cnpRule.Name,
					Action:          cnpRule.Action,
					Priority:        int32(idx),
					EnableLogging:   cnpRule.EnableLogging,
					AppliedToGroups: getAppliedToGroupNames(ruleAppliedTos),
					L7Protocols:     toAntreaL7ProtocolsForCRD(cnpRule.L7Protocols),
					LogLabel:        cnpRule.LogLabel,
				}
				if dir == controlplane.DirectionIn {
					rule.From = *peer
				} else if dir == controlplane.DirectionOut {
					rule.To = *peer
				}
				rules = append(rules, rule)
				addressGroups = mergeAddressGroups(addressGroups, ruleAddressGroups...)
				appliedToGroups = mergeAppliedToGroups(appliedToGroups, ruleAppliedTos...)
			}
			// When a rule's NetworkPolicyPeer is empty, a cluster level rule should be created
			// with an Antrea peer matching all addresses.
			if len(clusterPeers) > 0 || len(perNSPeers)+len(nsLabelPeers) == 0 {
				ruleAppliedTos := cnpRule.AppliedTo
				// For ACNPs that have per-namespace rules, cluster-level rules will be created with appliedTo
				// set as the spec appliedTo for each rule.
				if appliedToPerRule && len(cnp.Spec.AppliedTo) > 0 {
					ruleAppliedTos = cnp.Spec.AppliedTo
				}
				ruleATGs := n.processClusterAppliedTo(ruleAppliedTos)
				klog.V(4).InfoS("Adding a new cluster-level rule", "appliedTos", ruleATGs, "ClusterNetworkPolicy", klog.KObj(cnp))
				if cnpRule.ToServices != nil {
					addRule(n.svcRefToPeerForCRD(cnpRule.ToServices, ""), nil, direction, ruleATGs)
				} else {
					peer, ags, selKeys := n.toAntreaPeerForCRD(clusterPeers, cnp, direction, namedPortExists)
					if selKeys != nil {
						clusterSetScopeSelectorKeys = clusterSetScopeSelectorKeys.Union(selKeys)
					}
					addRule(peer, ags, direction, ruleATGs)
				}
			}
			if len(perNSPeers) > 0 {
				if len(cnp.Spec.AppliedTo) > 0 {
					// Create a rule for each affected Namespace of appliedTo at spec level
					for ns, atg := range atgPerAffectedNS {
						klog.V(4).Infof("Adding a new per-namespace rule with appliedTo %v for rule %d of %s", atg, idx, cnp.Name)
						peer, ags, selKeys := n.toNamespacedPeerForCRD(perNSPeers, cnp, ns)
						clusterSetScopeSelectorKeys = clusterSetScopeSelectorKeys.Union(selKeys)
						addRule(peer, ags, direction, []*antreatypes.AppliedToGroup{atg})
					}
				} else {
					// Create a rule for each affected Namespace of appliedTo at rule level
					for _, at := range cnpRule.AppliedTo {
						if at.ServiceAccount != nil {
							atg := n.createAppliedToGroup(at.ServiceAccount.Namespace, serviceAccountNameToPodSelector(at.ServiceAccount.Name), nil, nil, nil)
							klog.V(4).Infof("Adding a new per-namespace rule with appliedTo %v for rule %d of %s", atg, idx, cnp.Name)
							peer, ags, selKeys := n.toNamespacedPeerForCRD(perNSPeers, cnp, at.ServiceAccount.Namespace)
							clusterSetScopeSelectorKeys = clusterSetScopeSelectorKeys.Union(selKeys)
							addRule(peer, ags, direction, []*antreatypes.AppliedToGroup{atg})
						} else {
							affectedNS := n.getAffectedNamespacesForAppliedTo(at)
							for ns := range affectedNS {
								atg := n.createAppliedToGroup(ns, at.PodSelector, nil, at.ExternalEntitySelector, nil)
								klog.V(4).Infof("Adding a new per-namespace rule with appliedTo %v for rule %d of %s", atg, idx, cnp.Name)
								peer, ags, selKeys := n.toNamespacedPeerForCRD(perNSPeers, cnp, ns)
								clusterSetScopeSelectorKeys = clusterSetScopeSelectorKeys.Union(selKeys)
								addRule(peer, ags, direction, []*antreatypes.AppliedToGroup{atg})
							}
						}
					}
				}
			}
			if len(nsLabelPeers) > 0 {
				if len(cnp.Spec.AppliedTo) > 0 {
					// All affected Namespaces and their labels are already stored in labelsPerAffectedNS
					for _, peer := range nsLabelPeers {
						nsGroupByLabelVal := groupNamespacesByLabelValue(labelsPerAffectedNS, peer.Namespaces.SameLabels)
						for labelValues, groupedNamespaces := range nsGroupByLabelVal {
							peer, atgs, ags, selKeys := n.toAntreaPeerForSameLabelNamespaces(peer, cnp, atgPerAffectedNS, labelValues, groupedNamespaces)
							clusterSetScopeSelectorKeys = clusterSetScopeSelectorKeys.Union(selKeys)
							addRule(peer, ags, direction, atgs)
						}
					}
				} else {
					atgPerRuleAffectedNS := map[string]*antreatypes.AppliedToGroup{}
					labelsPerRuleAffectedNS := map[string]labels.Set{}
					for _, at := range cnpRule.AppliedTo {
						if at.ServiceAccount != nil {
							atg := n.createAppliedToGroup(at.ServiceAccount.Namespace, serviceAccountNameToPodSelector(at.ServiceAccount.Name), nil, nil, nil)
							atgPerRuleAffectedNS[at.ServiceAccount.Namespace] = atg
							labelsPerRuleAffectedNS[at.ServiceAccount.Namespace] = n.getNamespaceLabels(at.ServiceAccount.Namespace)
						} else {
							labelsPerRuleAffectedNS = n.getAffectedNamespacesForAppliedTo(at)
							for ns := range labelsPerRuleAffectedNS {
								atg := n.createAppliedToGroup(ns, at.PodSelector, nil, at.ExternalEntitySelector, nil)
								atgPerRuleAffectedNS[ns] = atg
							}
						}
					}
					for _, peer := range nsLabelPeers {
						nsGroupByLabelVal := groupNamespacesByLabelValue(labelsPerRuleAffectedNS, peer.Namespaces.SameLabels)
						for labelValues, groupedNamespaces := range nsGroupByLabelVal {
							peer, atgs, ags, selKeys := n.toAntreaPeerForSameLabelNamespaces(peer, cnp, atgPerRuleAffectedNS, labelValues, groupedNamespaces)
							clusterSetScopeSelectorKeys = clusterSetScopeSelectorKeys.Union(selKeys)
							addRule(peer, ags, direction, atgs)
						}
					}
				}
			}
		}
	}
	// Compute NetworkPolicyRules for Ingress Rules.
	processRules(cnp.Spec.Ingress, controlplane.DirectionIn)
	// Compute NetworkPolicyRules for Egress Rules.
	processRules(cnp.Spec.Egress, controlplane.DirectionOut)
	// Create AppliedToGroup for each AppliedTo present in ClusterNetworkPolicy spec.
	if !hasPerNamespaceRule {
		appliedToGroups = mergeAppliedToGroups(appliedToGroups, n.processClusterAppliedTo(cnp.Spec.AppliedTo)...)
	}
	tierPriority := n.getTierPriority(cnp.Spec.Tier)
	internalNetworkPolicy := &antreatypes.NetworkPolicy{
		Name:       internalNetworkPolicyKeyFunc(cnp),
		Generation: cnp.Generation,
		SourceRef: &controlplane.NetworkPolicyReference{
			Type: controlplane.AntreaClusterNetworkPolicy,
			Name: cnp.Name,
			UID:  cnp.UID,
		},
		UID:              cnp.UID,
		AppliedToGroups:  sets.List(sets.KeySet(appliedToGroups)),
		Rules:            rules,
		Priority:         &cnp.Spec.Priority,
		TierPriority:     &tierPriority,
		AppliedToPerRule: appliedToPerRule,
	}
	if n.stretchNPEnabled {
		n.labelIdentityInterface.RemoveStalePolicySelectors(clusterSetScopeSelectorKeys, internalNetworkPolicyKeyFunc(cnp))
	}
	return internalNetworkPolicy, appliedToGroups, addressGroups
}

// serviceAccountNameToPodSelector returns a PodSelector which could be used to
// select Pods based on their ServiceAccountName.
func serviceAccountNameToPodSelector(saName string) *metav1.LabelSelector {
	return &metav1.LabelSelector{
		MatchLabels: map[string]string{grouping.CustomLabelKeyPrefix + grouping.CustomLabelKeyServiceAccount: saName},
	}
}

// hasPerNamespaceRule returns true if there is at least one per-namespace rule
func hasPerNamespaceRule(cnp *crdv1beta1.ClusterNetworkPolicy) bool {
	for _, ingress := range cnp.Spec.Ingress {
		for _, peer := range ingress.From {
			if peer.Namespaces != nil {
				return true
			}
		}
	}
	for _, egress := range cnp.Spec.Egress {
		for _, peer := range egress.To {
			if peer.Namespaces != nil {
				return true
			}
		}
	}
	return false
}

func namespaceRuleLabelKeys(cnp *crdv1beta1.ClusterNetworkPolicy) sets.Set[string] {
	keys := sets.New[string]()
	for _, ingress := range cnp.Spec.Ingress {
		for _, peer := range ingress.From {
			if peer.Namespaces != nil {
				for _, k := range peer.Namespaces.SameLabels {
					keys.Insert(k)
				}
			}
		}
	}
	for _, egress := range cnp.Spec.Egress {
		for _, peer := range egress.To {
			if peer.Namespaces != nil {
				for _, k := range peer.Namespaces.SameLabels {
					keys.Insert(k)
				}
			}
		}
	}
	return keys
}

func (n *NetworkPolicyController) getNamespaceLabels(ns string) labels.Set {
	namespace, err := n.namespaceLister.Get(ns)
	if err != nil {
		// The Namespace referred to (by ServiceAccount etc.) does not exist yet.
		// ACNP will be re-queued once that Namespace event is received.
		return labels.Set{}
	}
	return namespace.Labels
}

// groupNamespaceByLabelValue groups Namespaces if they have the same label value for all the
// label keys listed. If a Namespace is missing at least one of the label keys, it will not
// be grouped. Example:
//
//	  ns1: app=web, tier=test, tenant=t1
//	  ns2: app=web, tier=test, tenant=t2
//	  ns3: app=web, tier=production, tenant=t1
//	  ns4: app=web, tier=production, tenant=t2
//	  ns5: app=db, tenant=t1
//	labelKeys = [app, tier]
//	Result after grouping:
//	  "web,test,":       [ns1, ns2]
//	  "web,production,": [ns3, ns4]
func groupNamespacesByLabelValue(affectedNSAndLabels map[string]labels.Set, labelKeys []string) map[string][]string {
	nsGroupedByLabelVal := map[string][]string{}
	for ns, nsLabels := range affectedNSAndLabels {
		if groupKey := getLabelValues(nsLabels, labelKeys); groupKey != "" {
			nsGroupedByLabelVal[groupKey] = append(nsGroupedByLabelVal[groupKey], ns)
		}
	}
	return nsGroupedByLabelVal
}

func getLabelValues(labels map[string]string, labelKeys []string) string {
	key := ""
	for _, k := range labelKeys {
		if v, ok := labels[k]; !ok {
			return ""
		} else {
			key += v + labelValueSeparator
		}
	}
	return key
}

// convertSameLabelsToSelector creates a LabelSelector based on a list of label keys
// and their expected values.
func convertSameLabelsToSelector(labelKeys []string, labelValues string) *metav1.LabelSelector {
	labelValuesSep := strings.Split(labelValues, labelValueSeparator)
	labelMatchCriteria := map[string]string{}
	for i := range labelKeys {
		labelMatchCriteria[labelKeys[i]] = labelValuesSep[i]
	}
	return &metav1.LabelSelector{
		MatchLabels: labelMatchCriteria,
	}
}

// toAntreaPeerForSameLabelNamespaces computes the appliedToGroups and addressGroups for each
// group of Namespaces who have the same values for the sameLabels keys.
func (n *NetworkPolicyController) toAntreaPeerForSameLabelNamespaces(peer crdv1beta1.NetworkPolicyPeer,
	np metav1.Object, atgPerAffectedNS map[string]*antreatypes.AppliedToGroup,
	labelValues string,
	namespacesByLabelValues []string) (*controlplane.NetworkPolicyPeer, []*antreatypes.AppliedToGroup, []*antreatypes.AddressGroup, sets.Set[string]) {
	labelKeys := peer.Namespaces.SameLabels
	var labelIdentities []uint32
	uniqueLabelIDs := sets.New[uint32]()
	clusterSetScopeSelectorKeys := sets.New[string]()
	// select Namespaces who, for specific label keys, have the same values as the appliedTo Namespaces.
	nsSelForSameLabels := convertSameLabelsToSelector(labelKeys, labelValues)
	addressGroups := []*antreatypes.AddressGroup{n.createAddressGroup("", peer.PodSelector, nsSelForSameLabels, peer.ExternalEntitySelector, nil)}
	if n.stretchNPEnabled && peer.Scope == crdv1beta1.ScopeClusterSet {
		newClusterSetScopeSelector := antreatypes.NewGroupSelector("", peer.PodSelector, nsSelForSameLabels, peer.ExternalEntitySelector, nil)
		clusterSetScopeSelectorKeys.Insert(newClusterSetScopeSelector.NormalizedName)
		// In addition to getting the matched Label Identity IDs, AddSelector also registers the selector
		// with the labelIdentityInterface.
		matchedLabelIDs := n.labelIdentityInterface.AddSelector(newClusterSetScopeSelector, internalNetworkPolicyKeyFunc(np))
		for _, id := range matchedLabelIDs {
			uniqueLabelIDs.Insert(id)
		}
	}
	for id := range uniqueLabelIDs {
		labelIdentities = append(labelIdentities, id)
	}
	antreaPeer := &controlplane.NetworkPolicyPeer{
		AddressGroups:   getAddressGroupNames(addressGroups),
		LabelIdentities: labelIdentities,
	}
	var atgs []*antreatypes.AppliedToGroup
	sort.Strings(namespacesByLabelValues)
	for _, ns := range namespacesByLabelValues {
		atgForNamespace, _ := atgPerAffectedNS[ns]
		atgs = append(atgs, atgForNamespace)
	}
	return antreaPeer, atgs, addressGroups, clusterSetScopeSelectorKeys
}

// processClusterAppliedTo processes appliedTo groups in Antrea ClusterNetworkPolicy set
// at cluster level (appliedTo groups which will not need to be split by Namespaces).
func (n *NetworkPolicyController) processClusterAppliedTo(appliedTo []crdv1beta1.AppliedTo) []*antreatypes.AppliedToGroup {
	var appliedToGroups []*antreatypes.AppliedToGroup
	for _, at := range appliedTo {
		var atg *antreatypes.AppliedToGroup
		if at.NodeSelector != nil {
			atg = n.createAppliedToGroup("", nil, nil, nil, at.NodeSelector)
		} else if at.Group != "" {
			atg = n.createAppliedToGroupForGroup("", at.Group)
		} else if at.Service != nil {
			atg = n.createAppliedToGroupForService(at.Service)
		} else if at.ServiceAccount != nil {
			atg = n.createAppliedToGroup(at.ServiceAccount.Namespace, serviceAccountNameToPodSelector(at.ServiceAccount.Name), nil, nil, nil)
		} else {
			atg = n.createAppliedToGroup("", at.PodSelector, at.NamespaceSelector, at.ExternalEntitySelector, nil)
		}
		if atg != nil {
			appliedToGroups = append(appliedToGroups, atg)
		}
	}
	return appliedToGroups
}

// splitPeersByScope splits the ClusterNetworkPolicy peers in the rule by whether the peer
// is cluster-scoped or per-namespace.
func splitPeersByScope(rule crdv1beta1.Rule, dir controlplane.Direction) ([]crdv1beta1.NetworkPolicyPeer, []crdv1beta1.NetworkPolicyPeer, []crdv1beta1.NetworkPolicyPeer) {
	var clusterPeers, perNSPeers, nsLabelPeers []crdv1beta1.NetworkPolicyPeer
	peers := rule.From
	if dir == controlplane.DirectionOut {
		peers = rule.To
	}
	for _, peer := range peers {
		if peer.Namespaces != nil {
			if peer.Namespaces.Match == crdv1beta1.NamespaceMatchSelf {
				perNSPeers = append(perNSPeers, peer)
			} else if len(peer.Namespaces.SameLabels) > 0 {
				nsLabelPeers = append(nsLabelPeers, peer)
			}
		} else {
			clusterPeers = append(clusterPeers, peer)
		}
	}
	return clusterPeers, perNSPeers, nsLabelPeers
}

// getAffectedNamespacesForAppliedTo computes the Namespaces currently affected by the appliedTo
// Namespace selectors, and returns these Namespaces along with their labels.
func (n *NetworkPolicyController) getAffectedNamespacesForAppliedTo(appliedTo crdv1beta1.AppliedTo) map[string]labels.Set {
	affectedNSAndLabels := map[string]labels.Set{}

	nsLabelSelector := appliedTo.NamespaceSelector
	if appliedTo.Group != "" {
		cg, err := n.cgLister.Get(appliedTo.Group)
		if err != nil {
			return affectedNSAndLabels
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
	namespaces, _ := n.namespaceLister.List(nsSel)
	for _, ns := range namespaces {
		affectedNSAndLabels[ns.Name] = ns.Labels
	}
	return affectedNSAndLabels
}

// processInternalGroupForRule examines the internal group (and its childGroups if applicable)
// to determine whether an addressGroup needs to be created, and returns any ipBlocks contained
// by the internal Group as well.
func (n *NetworkPolicyController) processInternalGroupForRule(group *antreatypes.Group) (bool, []controlplane.IPBlock) {
	if len(group.IPBlocks) > 0 {
		return false, group.IPBlocks
	} else if len(group.ChildGroups) == 0 {
		return true, nil
	}
	var ipBlocks []controlplane.IPBlock
	createAddrGroup := false
	for _, childName := range group.ChildGroups {
		childName = k8s.NamespacedName(group.SourceReference.Namespace, childName)
		childGroup, found, _ := n.internalGroupStore.Get(childName)
		if found {
			child := childGroup.(*antreatypes.Group)
			createChildAG, ipb := n.processInternalGroupForRule(child)
			if createChildAG {
				createAddrGroup = true
			}
			ipBlocks = append(ipBlocks, ipb...)
		}
	}
	return createAddrGroup, ipBlocks
}

// processRefGroupOrClusterGroup processes the Group/ClusterGroup reference present in the rule and returns the
// NetworkPolicyPeer with the corresponding AddressGroup or IPBlock.
func (n *NetworkPolicyController) processRefGroupOrClusterGroup(g, namespace string) (*antreatypes.AddressGroup, []controlplane.IPBlock) {
	// Namespaced Group uses NAMESPACE/NAME as the key of the corresponding internal group while ClusterGroup uses Name.
	key := k8s.NamespacedName(namespace, g)
	// Find the internal Group corresponding to this ClusterGroup
	ig, found, _ := n.internalGroupStore.Get(key)
	if !found {
		// Internal Group was not found. Once the internal Group is created, the sync
		// worker for internal group will re-enqueue the ClusterNetworkPolicy processing
		// which will trigger the creation of AddressGroup.
		return nil, nil
	}
	intGrp := ig.(*antreatypes.Group)
	// The Group/ClusterGroup referred in the rule might have childGroups defined using selectors
	// or ipBlocks (or both). An addressGroup needs to be created as long as there is at least
	// one childGroup defined by selectors, or the Group/ClusterGroup itself is defined by selectors.
	// In case of updates, the original addressGroup created will be de-referenced and cleaned
	// up if the Group/ClusterGroup becomes ipBlocks-only.
	createAddrGroup, ipb := n.processInternalGroupForRule(intGrp)
	if createAddrGroup {
		ag := &antreatypes.AddressGroup{UID: intGrp.UID, Name: key, SourceGroup: key}
		return ag, ipb
	}
	return nil, ipb
}
