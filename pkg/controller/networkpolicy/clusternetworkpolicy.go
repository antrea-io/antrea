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
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/apis/controlplane"
	secv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/security/v1alpha1"
	antreatypes "github.com/vmware-tanzu/antrea/pkg/controller/types"
)

// addCNP receives ClusterNetworkPolicy ADD events and creates resources
// which can be consumed by agents to configure corresponding rules on the Nodes.
func (n *NetworkPolicyController) addCNP(obj interface{}) {
	defer n.heartbeat("addCNP")
	cnp := obj.(*secv1alpha1.ClusterNetworkPolicy)
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
	curCNP := cur.(*secv1alpha1.ClusterNetworkPolicy)
	klog.Infof("Processing ClusterNetworkPolicy %s UPDATE event", curCNP.Name)
	// Update an internal NetworkPolicy, corresponding to this NetworkPolicy and
	// enqueue task to internal NetworkPolicy Workqueue.
	curInternalNP := n.processClusterNetworkPolicy(curCNP)
	klog.V(2).Infof("Updating existing internal NetworkPolicy %s for %s", curInternalNP.Name, curInternalNP.SourceRef.ToString())
	// Retrieve old secv1alpha1.NetworkPolicy object.
	oldCNP := old.(*secv1alpha1.ClusterNetworkPolicy)
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
	cnp, ok := old.(*secv1alpha1.ClusterNetworkPolicy)
	if !ok {
		tombstone, ok := old.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Error decoding object when deleting ClusterNetworkPolicy, invalid type: %v", old)
			return
		}
		cnp, ok = tombstone.Obj.(*secv1alpha1.ClusterNetworkPolicy)
		if !ok {
			klog.Errorf("Error decoding object tombstone when deleting ClusterNetworkPolicy, invalid type: %v", tombstone.Obj)
			return
		}
	}
	defer n.heartbeat("deleteCNP")
	klog.Infof("Processing ClusterNetworkPolicy %s DELETE event", cnp.Name)
	key := internalNetworkPolicyKeyFunc(cnp)
	oldInternalNPObj, _, _ := n.internalNetworkPolicyStore.Get(key)
	oldInternalNP := oldInternalNPObj.(*antreatypes.NetworkPolicy)
	klog.V(2).Infof("Deleting internal NetworkPolicy %s for %s", oldInternalNP.Name, oldInternalNP.SourceRef.ToString())
	err := n.internalNetworkPolicyStore.Delete(key)
	if err != nil {
		klog.Errorf("Error deleting internal NetworkPolicy during NetworkPolicy %s delete: %v", cnp.Name, err)
		return
	}
	for _, atg := range oldInternalNP.AppliedToGroups {
		n.deleteDereferencedAppliedToGroup(atg)
	}
	n.deleteDereferencedAddressGroups(oldInternalNP)
}

// processClusterNetworkPolicy creates an internal NetworkPolicy instance
// corresponding to the secv1alpha1.ClusterNetworkPolicy object. This method
// does not commit the internal NetworkPolicy in store, instead returns an
// instance to the caller wherein, it will be either stored as a new Object
// in case of ADD event or modified and store the updated instance, in case
// of an UPDATE event.
func (n *NetworkPolicyController) processClusterNetworkPolicy(cnp *secv1alpha1.ClusterNetworkPolicy) *antreatypes.NetworkPolicy {
	appliedToPerRule := len(cnp.Spec.AppliedTo) == 0
	// appliedToGroupNames tracks all distinct appliedToGroups referred to by the ClusterNetworkPolicy,
	// either in the spec section or in ingress/egress rules.
	// The span calculation and stale appliedToGroup cleanup logic would work seamlessly for both cases.
	appliedToGroupNamesSet := sets.String{}
	// Create AppliedToGroup for each AppliedTo present in ClusterNetworkPolicy spec.
	for _, at := range cnp.Spec.AppliedTo {
		appliedToGroupNamesSet.Insert(n.createAppliedToGroup(
			"", at.PodSelector, at.NamespaceSelector, at.ExternalEntitySelector))
	}
	rules := make([]controlplane.NetworkPolicyRule, 0, len(cnp.Spec.Ingress)+len(cnp.Spec.Egress))
	// Compute NetworkPolicyRule for Ingress Rule.
	for idx, ingressRule := range cnp.Spec.Ingress {
		// Set default action to ALLOW to allow traffic.
		services, namedPortExists := toAntreaServicesForCRD(ingressRule.Ports)
		var appliedToGroupNamesForRule []string
		// Create AppliedToGroup for each AppliedTo present in the ingress rule.
		for _, at := range ingressRule.AppliedTo {
			atGroup := n.createAppliedToGroup("", at.PodSelector, at.NamespaceSelector, at.ExternalEntitySelector)
			appliedToGroupNamesForRule = append(appliedToGroupNamesForRule, atGroup)
			appliedToGroupNamesSet.Insert(atGroup)
		}
		rules = append(rules, controlplane.NetworkPolicyRule{
			Direction:       controlplane.DirectionIn,
			From:            *n.toAntreaPeerForCRD(ingressRule.From, cnp, controlplane.DirectionIn, namedPortExists),
			Services:        services,
			Action:          ingressRule.Action,
			Priority:        int32(idx),
			EnableLogging:   ingressRule.EnableLogging,
			AppliedToGroups: appliedToGroupNamesForRule,
		})
	}
	// Compute NetworkPolicyRule for Egress Rule.
	for idx, egressRule := range cnp.Spec.Egress {
		// Set default action to ALLOW to allow traffic.
		services, namedPortExists := toAntreaServicesForCRD(egressRule.Ports)
		var appliedToGroupNamesForRule []string
		// Create AppliedToGroup for each AppliedTo present in the ingress rule.
		for _, at := range egressRule.AppliedTo {
			atGroup := n.createAppliedToGroup("", at.PodSelector, at.NamespaceSelector, at.ExternalEntitySelector)
			appliedToGroupNamesForRule = append(appliedToGroupNamesForRule, atGroup)
			appliedToGroupNamesSet.Insert(atGroup)
		}
		rules = append(rules, controlplane.NetworkPolicyRule{
			Direction:       controlplane.DirectionOut,
			To:              *n.toAntreaPeerForCRD(egressRule.To, cnp, controlplane.DirectionOut, namedPortExists),
			Services:        services,
			Action:          egressRule.Action,
			Priority:        int32(idx),
			EnableLogging:   egressRule.EnableLogging,
			AppliedToGroups: appliedToGroupNamesForRule,
		})
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
		AppliedToGroups:  appliedToGroupNamesSet.List(),
		Rules:            rules,
		Priority:         &cnp.Spec.Priority,
		TierPriority:     &tierPriority,
		AppliedToPerRule: appliedToPerRule,
	}
	return internalNetworkPolicy
}

// processRefCG processes the ClusterGroup reference present in the rule and returns the
// NetworkPolicyPeer with the corresponding AddressGroup or IPBlock.
func (n *NetworkPolicyController) processRefCG(g string) (string, *controlplane.IPBlock) {
	// Retrieve ClusterGroup for corresponding entry in the rule.
	cg, err := n.cgLister.Get(g)
	if err != nil {
		klog.V(2).Infof("ClusterGroup %s not found. %v", g, err)
		return "", nil
	}
	if cg.Spec.IPBlock != nil {
		ipBlock, err := toAntreaIPBlockForCRD(cg.Spec.IPBlock)
		if err != nil {
			klog.Errorf("Failure processing ClusterGroup %s IPBlock %v: %v", cg.Name, cg.Spec.IPBlock, err)
			return "", nil
		}
		return "", ipBlock
	}
	agKey := n.createAddressGroupForClusterGroupCRD(cg)
	// Return if addressGroup was created or found.
	return agKey, nil
}
