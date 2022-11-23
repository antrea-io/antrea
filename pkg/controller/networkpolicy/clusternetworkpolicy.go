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

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/apis/controlplane"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/pkg/controller/grouping"
	"antrea.io/antrea/pkg/controller/networkpolicy/store"
	antreatypes "antrea.io/antrea/pkg/controller/types"
	"antrea.io/antrea/pkg/util/k8s"
	utilsets "antrea.io/antrea/pkg/util/sets"
)

func getACNPReference(cnp *crdv1alpha1.ClusterNetworkPolicy) *controlplane.NetworkPolicyReference {
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
	cnp := obj.(*crdv1alpha1.ClusterNetworkPolicy)
	klog.Infof("Processing ClusterNetworkPolicy %s ADD event", cnp.Name)
	n.enqueueInternalNetworkPolicy(getACNPReference(cnp))
}

// updateCNP receives ClusterNetworkPolicy UPDATE events and enqueues a
// reference of the ClusterNetworkPolicy to trigger its process.
func (n *NetworkPolicyController) updateCNP(_, cur interface{}) {
	defer n.heartbeat("updateCNP")
	curCNP := cur.(*crdv1alpha1.ClusterNetworkPolicy)
	klog.Infof("Processing ClusterNetworkPolicy %s UPDATE event", curCNP.Name)
	n.enqueueInternalNetworkPolicy(getACNPReference(curCNP))
}

// deleteCNP receives ClusterNetworkPolicy DELETE events and enqueues a
// reference of the ClusterNetworkPolicy to trigger its process.
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
	n.enqueueInternalNetworkPolicy(getACNPReference(cnp))
}

// filterPerNamespaceRuleACNPsByNSLabels gets all ClusterNetworkPolicy names that will need to be
// re-processed based on the entire label set of an added/updated/deleted Namespace.
func (n *NetworkPolicyController) filterPerNamespaceRuleACNPsByNSLabels(nsLabels labels.Set) sets.String {
	namespaceLabelMatches := func(peers []crdv1alpha1.AppliedTo) bool {
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

	peerNamespacesSelectorExists := func(peers []crdv1alpha1.NetworkPolicyPeer) bool {
		for _, peer := range peers {
			if peer.Namespaces != nil && peer.Namespaces.Match == crdv1alpha1.NamespaceMatchSelf {
				return true
			}
		}
		return false
	}

	affectedPolicies := sets.NewString()
	objs, _ := n.cnpInformer.Informer().GetIndexer().ByIndex(perNamespaceRuleIndex, HasPerNamespaceRule)
	for _, obj := range objs {
		cnp := obj.(*crdv1alpha1.ClusterNetworkPolicy)
		if affected := func() bool {
			if len(cnp.Spec.AppliedTo) > 0 {
				// The policy has only spec level AppliedTo.
				if namespaceLabelMatches(cnp.Spec.AppliedTo) {
					return true
				}
				return false
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

// addNamespace receives Namespace ADD events and triggers all ClusterNetworkPolicies that have a
// per-namespace rule applied to this Namespace to be re-processed.
func (n *NetworkPolicyController) addNamespace(obj interface{}) {
	defer n.heartbeat("addNamespace")
	namespace := obj.(*v1.Namespace)
	klog.V(2).Infof("Processing Namespace %s ADD event, labels: %v", namespace.Name, namespace.Labels)
	affectedACNPs := n.filterPerNamespaceRuleACNPsByNSLabels(namespace.Labels)
	for cnpName := range affectedACNPs {
		// Ignore the ClusterNetworkPolicy if it has been removed during the process.
		if cnp, err := n.cnpLister.Get(cnpName); err == nil {
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
		for cnpName := range affectedACNPs {
			// Ignore the ClusterNetworkPolicy if it has been removed during the process.
			if cnp, err := n.cnpLister.Get(cnpName); err == nil {
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
	for _, cnpName := range affectedACNPs.List() {
		// Ignore the ClusterNetworkPolicy if it has been removed during the process.
		if cnp, err := n.cnpLister.Get(cnpName); err == nil {
			n.enqueueInternalNetworkPolicy(getACNPReference(cnp))
		}
	}
}

func (c *NetworkPolicyController) filterAGsFromNodeLabels(node *v1.Node) sets.String {
	ags := sets.NewString()
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

func (c *NetworkPolicyController) getATGsAppliedToService() sets.String {
	atgs := sets.NewString()
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
// corresponding to the crdv1alpha1.ClusterNetworkPolicy object. This method
// does not commit the internal NetworkPolicy in store, instead returns an
// instance to the caller wherein, it will be either stored as a new Object
// in case of ADD event or modified and store the updated instance, in case
// of an UPDATE event.
func (n *NetworkPolicyController) processClusterNetworkPolicy(cnp *crdv1alpha1.ClusterNetworkPolicy) (*antreatypes.NetworkPolicy, map[string]*antreatypes.AppliedToGroup, map[string]*antreatypes.AddressGroup) {
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
	var clusterAppliedToAffectedNS []string
	// atgForNamespace is the appliedToGroups split by Namespaces.
	var atgForNamespace []*antreatypes.AppliedToGroup
	if hasPerNamespaceRule && len(cnp.Spec.AppliedTo) > 0 {
		for _, at := range cnp.Spec.AppliedTo {
			if at.ServiceAccount != nil {
				atg := n.createAppliedToGroup(at.ServiceAccount.Namespace, serviceAccountNameToPodSelector(at.ServiceAccount.Name), nil, nil)
				appliedToGroups = mergeAppliedToGroups(appliedToGroups, atg)
				clusterAppliedToAffectedNS = append(clusterAppliedToAffectedNS, at.ServiceAccount.Namespace)
				atgForNamespace = append(atgForNamespace, atg)
			} else {
				affectedNS := n.getAffectedNamespacesForAppliedTo(at)
				for _, ns := range affectedNS {
					atg := n.createAppliedToGroup(ns, at.PodSelector, nil, at.ExternalEntitySelector)
					appliedToGroups = mergeAppliedToGroups(appliedToGroups, atg)
					clusterAppliedToAffectedNS = append(clusterAppliedToAffectedNS, ns)
					atgForNamespace = append(atgForNamespace, atg)
				}
			}
		}
	}
	var rules []controlplane.NetworkPolicyRule
	processRules := func(cnpRules []crdv1alpha1.Rule, direction controlplane.Direction) {
		for idx, cnpRule := range cnpRules {
			services, namedPortExists := toAntreaServicesForCRD(cnpRule.Ports, cnpRule.Protocols)
			clusterPeers, perNSPeers := splitPeersByScope(cnpRule, direction)
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
			if len(clusterPeers) > 0 || len(perNSPeers) == 0 {
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
					peer, ags := n.toAntreaPeerForCRD(clusterPeers, cnp, direction, namedPortExists)
					addRule(peer, ags, direction, ruleATGs)
				}
			}
			if len(perNSPeers) > 0 {
				if len(cnp.Spec.AppliedTo) > 0 {
					// Create a rule for each affected Namespace of appliedTo at spec level
					for i := range clusterAppliedToAffectedNS {
						klog.V(4).Infof("Adding a new per-namespace rule with appliedTo %v for rule %d of %s", clusterAppliedToAffectedNS[i], idx, cnp.Name)
						peer, ags := n.toNamespacedPeerForCRD(perNSPeers, clusterAppliedToAffectedNS[i])
						addRule(peer, ags, direction, []*antreatypes.AppliedToGroup{atgForNamespace[i]})
					}
				} else {
					// Create a rule for each affected Namespace of appliedTo at rule level
					for _, at := range cnpRule.AppliedTo {
						if at.ServiceAccount != nil {
							atg := n.createAppliedToGroup(at.ServiceAccount.Namespace, serviceAccountNameToPodSelector(at.ServiceAccount.Name), nil, nil)
							klog.V(4).Infof("Adding a new per-namespace rule with appliedTo %v for rule %d of %s", atg, idx, cnp.Name)
							peer, ags := n.toNamespacedPeerForCRD(perNSPeers, at.ServiceAccount.Namespace)
							addRule(peer, ags, direction, []*antreatypes.AppliedToGroup{atg})
						} else {
							affectedNS := n.getAffectedNamespacesForAppliedTo(at)
							for _, ns := range affectedNS {
								atg := n.createAppliedToGroup(ns, at.PodSelector, nil, at.ExternalEntitySelector)
								klog.V(4).Infof("Adding a new per-namespace rule with appliedTo %v for rule %d of %s", atg, idx, cnp.Name)
								peer, ags := n.toNamespacedPeerForCRD(perNSPeers, ns)
								addRule(peer, ags, direction, []*antreatypes.AppliedToGroup{atg})
							}
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
		AppliedToGroups:  sets.StringKeySet(appliedToGroups).List(),
		Rules:            rules,
		Priority:         &cnp.Spec.Priority,
		TierPriority:     &tierPriority,
		AppliedToPerRule: appliedToPerRule,
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
func (n *NetworkPolicyController) processClusterAppliedTo(appliedTo []crdv1alpha1.AppliedTo) []*antreatypes.AppliedToGroup {
	var appliedToGroups []*antreatypes.AppliedToGroup
	for _, at := range appliedTo {
		var atg *antreatypes.AppliedToGroup
		if at.Group != "" {
			atg = n.createAppliedToGroupForGroup("", at.Group)
		} else if at.Service != nil {
			atg = n.createAppliedToGroupForService(at.Service)
		} else if at.ServiceAccount != nil {
			atg = n.createAppliedToGroup(at.ServiceAccount.Namespace, serviceAccountNameToPodSelector(at.ServiceAccount.Name), nil, nil)
		} else {
			atg = n.createAppliedToGroup("", at.PodSelector, at.NamespaceSelector, at.ExternalEntitySelector)
		}
		if atg != nil {
			appliedToGroups = append(appliedToGroups, atg)
		}
	}
	return appliedToGroups
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
// Namespace selectors.
func (n *NetworkPolicyController) getAffectedNamespacesForAppliedTo(appliedTo crdv1alpha1.AppliedTo) []string {
	var affectedNS []string

	nsLabelSelector := appliedTo.NamespaceSelector
	if appliedTo.Group != "" {
		cg, err := n.cgLister.Get(appliedTo.Group)
		if err != nil {
			return affectedNS
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
		affectedNS = append(affectedNS, ns.Name)
	}
	return affectedNS
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
		ag := &antreatypes.AddressGroup{UID: intGrp.UID, Name: key}
		return ag, ipb
	}
	return nil, ipb
}
