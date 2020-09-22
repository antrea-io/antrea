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
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/apis/controlplane"
	secv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/security/v1alpha1"
	antreatypes "github.com/vmware-tanzu/antrea/pkg/controller/types"
)

// addANP receives AntreaNetworkPolicy ADD events and creates resources
// which can be consumed by agents to configure corresponding rules on the Nodes.
func (n *NetworkPolicyController) addANP(obj interface{}) {
	defer n.heartbeat("addANP")
	np := obj.(*secv1alpha1.NetworkPolicy)
	klog.Infof("Processing Antrea NetworkPolicy %s/%s ADD event", np.Namespace, np.Name)
	// Create an internal NetworkPolicy object corresponding to this
	// NetworkPolicy and enqueue task to internal NetworkPolicy Workqueue.
	internalNP := n.processAntreaNetworkPolicy(np)
	klog.Infof("Creating new internal NetworkPolicy %#v", internalNP)
	n.internalNetworkPolicyStore.Create(internalNP)
	key, _ := keyFunc(np)
	n.enqueueInternalNetworkPolicy(key)
}

// updateANP receives AntreaNetworkPolicy UPDATE events and updates resources
// which can be consumed by agents to configure corresponding rules on the Nodes.
func (n *NetworkPolicyController) updateANP(old, cur interface{}) {
	defer n.heartbeat("updateANP")
	curNP := cur.(*secv1alpha1.NetworkPolicy)
	klog.Infof("Processing Antrea NetworkPolicy %s/%s UPDATE event", curNP.Namespace, curNP.Name)
	// Update an internal NetworkPolicy, corresponding to this NetworkPolicy and
	// enqueue task to internal NetworkPolicy Workqueue.
	curInternalNP := n.processAntreaNetworkPolicy(curNP)
	klog.V(2).Infof("Updating existing internal NetworkPolicy %s", curInternalNP.Name)
	// Retrieve old secv1alpha1.NetworkPolicy object.
	oldNP := old.(*secv1alpha1.NetworkPolicy)
	// Old and current NetworkPolicy share the same key.
	key, _ := keyFunc(oldNP)
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

// deleteANP receives AntreaNetworkPolicy DELETED events and deletes resources
// which can be consumed by agents to delete corresponding rules on the Nodes.
func (n *NetworkPolicyController) deleteANP(old interface{}) {
	np, ok := old.(*secv1alpha1.NetworkPolicy)
	if !ok {
		tombstone, ok := old.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Error decoding object when deleting Antrea NetworkPolicy, invalid type: %v", old)
			return
		}
		np, ok = tombstone.Obj.(*secv1alpha1.NetworkPolicy)
		if !ok {
			klog.Errorf("Error decoding object tombstone when deleting Antrea NetworkPolicy, invalid type: %v", tombstone.Obj)
			return
		}
	}
	defer n.heartbeat("deleteANP")
	klog.Infof("Processing Antrea NetworkPolicy %s/%s DELETE event", np.Namespace, np.Name)
	key, _ := keyFunc(np)
	oldInternalNPObj, _, _ := n.internalNetworkPolicyStore.Get(key)
	oldInternalNP := oldInternalNPObj.(*antreatypes.NetworkPolicy)
	klog.V(4).Infof("Old internal NetworkPolicy %#v", oldInternalNP)
	err := n.internalNetworkPolicyStore.Delete(key)
	if err != nil {
		klog.Errorf("Error deleting internal NetworkPolicy during Antrea NetworkPolicy %s delete: %v", np.Name, err)
		return
	}
	for _, atg := range oldInternalNP.AppliedToGroups {
		n.deleteDereferencedAppliedToGroup(atg)
	}
	n.deleteDereferencedAddressGroups(oldInternalNP)
}

// processAntreaNetworkPolicy creates an internal NetworkPolicy instance
// corresponding to the secv1alpha1.NetworkPolicy object. This method
// does not commit the internal NetworkPolicy in store, instead returns an
// instance to the caller wherein, it will be either stored as a new Object
// in case of ADD event or modified and store the updated instance, in case
// of an UPDATE event.
func (n *NetworkPolicyController) processAntreaNetworkPolicy(np *secv1alpha1.NetworkPolicy) *antreatypes.NetworkPolicy {
	appliedToGroupNames := make([]string, 0, len(np.Spec.AppliedTo))
	// Create AppliedToGroup for each AppliedTo present in
	// AntreaNetworkPolicy spec.
	for _, at := range np.Spec.AppliedTo {
		appliedToGroupNames = append(appliedToGroupNames, n.createAppliedToGroup(
			np.Namespace, at.PodSelector, at.NamespaceSelector, at.ExternalEntitySelector))
	}
	rules := make([]controlplane.NetworkPolicyRule, 0, len(np.Spec.Ingress)+len(np.Spec.Egress))
	// Compute NetworkPolicyRule for Egress Rule.
	for idx, ingressRule := range np.Spec.Ingress {
		// Set default action to ALLOW to allow traffic.
		services, namedPortExists := toAntreaServicesForCRD(ingressRule.Ports)
		rules = append(rules, controlplane.NetworkPolicyRule{
			Direction: controlplane.DirectionIn,
			From:      *n.toAntreaPeerForCRD(ingressRule.From, np, controlplane.DirectionIn, namedPortExists),
			Services:  services,
			Action:    ingressRule.Action,
			Priority:  int32(idx),
		})
	}
	// Compute NetworkPolicyRule for Egress Rule.
	for idx, egressRule := range np.Spec.Egress {
		// Set default action to ALLOW to allow traffic.
		services, namedPortExists := toAntreaServicesForCRD(egressRule.Ports)
		rules = append(rules, controlplane.NetworkPolicyRule{
			Direction: controlplane.DirectionOut,
			To:        *n.toAntreaPeerForCRD(egressRule.To, np, controlplane.DirectionOut, namedPortExists),
			Services:  services,
			Action:    egressRule.Action,
			Priority:  int32(idx),
		})
	}
	tierPriority := getTierPriority(np.Spec.Tier)
	internalNetworkPolicy := &antreatypes.NetworkPolicy{
		SourceRef: &controlplane.NetworkPolicyReference{
			Type:      controlplane.AntreaNetworkPolicy,
			Namespace: np.Namespace,
			Name:      np.Name,
			UID:       np.UID,
		},
		Name:            np.Name,
		Namespace:       np.Namespace,
		UID:             np.UID,
		AppliedToGroups: appliedToGroupNames,
		Rules:           rules,
		Priority:        &np.Spec.Priority,
		TierPriority:    &tierPriority,
	}
	return internalNetworkPolicy
}
