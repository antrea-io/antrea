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
	"fmt"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/apis/controlplane"
	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	antreatypes "antrea.io/antrea/pkg/controller/types"
)

func getANNPReference(annp *crdv1beta1.NetworkPolicy) *controlplane.NetworkPolicyReference {
	return &controlplane.NetworkPolicyReference{
		Type:      controlplane.AntreaNetworkPolicy,
		Namespace: annp.Namespace,
		Name:      annp.Name,
		UID:       annp.UID,
	}
}

// addANNP receives AntreaNetworkPolicy ADD events and enqueues a reference of
// the AntreaNetworkPolicy to trigger its process.
func (n *NetworkPolicyController) addANNP(obj interface{}) {
	defer n.heartbeat("addANNP")
	np := obj.(*crdv1beta1.NetworkPolicy)
	klog.Infof("Processing Antrea NetworkPolicy %s/%s ADD event", np.Namespace, np.Name)
	n.enqueueInternalNetworkPolicy(getANNPReference(np))
}

// updateANNP receives AntreaNetworkPolicy UPDATE events and enqueues a reference
// of the AntreaNetworkPolicy to trigger its process.
func (n *NetworkPolicyController) updateANNP(old, cur interface{}) {
	defer n.heartbeat("updateANNP")
	curNP := cur.(*crdv1beta1.NetworkPolicy)
	klog.Infof("Processing Antrea NetworkPolicy %s/%s UPDATE event", curNP.Namespace, curNP.Name)
	n.enqueueInternalNetworkPolicy(getANNPReference(curNP))
}

// deleteANNP receives AntreaNetworkPolicy DELETE events and enqueues a reference
// of the AntreaNetworkPolicy to trigger its process.
func (n *NetworkPolicyController) deleteANNP(old interface{}) {
	np, ok := old.(*crdv1beta1.NetworkPolicy)
	if !ok {
		tombstone, ok := old.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Error decoding object when deleting Antrea NetworkPolicy, invalid type: %v", old)
			return
		}
		np, ok = tombstone.Obj.(*crdv1beta1.NetworkPolicy)
		if !ok {
			klog.Errorf("Error decoding object tombstone when deleting Antrea NetworkPolicy, invalid type: %v", tombstone.Obj)
			return
		}
	}
	defer n.heartbeat("deleteANNP")
	klog.Infof("Processing Antrea NetworkPolicy %s/%s DELETE event", np.Namespace, np.Name)
	n.enqueueInternalNetworkPolicy(getANNPReference(np))
}

// processAntreaNetworkPolicy creates an internal NetworkPolicy instance
// corresponding to the crdv1beta1.NetworkPolicy object. This method
// does not commit the internal NetworkPolicy in store, instead returns an
// instance to the caller.
func (n *NetworkPolicyController) processAntreaNetworkPolicy(np *crdv1beta1.NetworkPolicy) (*antreatypes.NetworkPolicy, map[string]*antreatypes.AppliedToGroup, map[string]*antreatypes.AddressGroup) {
	appliedToPerRule := len(np.Spec.AppliedTo) == 0
	// appliedToGroups tracks all distinct appliedToGroups referred to by the Antrea NetworkPolicy,
	// either in the spec section or in ingress/egress rules.
	// The span calculation and stale appliedToGroup cleanup logic would work seamlessly for both cases.
	appliedToGroups := map[string]*antreatypes.AppliedToGroup{}
	addressGroups := map[string]*antreatypes.AddressGroup{}
	rules := make([]controlplane.NetworkPolicyRule, 0, len(np.Spec.Ingress)+len(np.Spec.Egress))
	// clusterSetScopeSelectorKeys keeps track of all the ClusterSet-scoped selector keys of the policy.
	// During policy peer processing, any ClusterSet-scoped selector will be registered with the
	// labelIdentityInterface and added to this set. By the end of the function, this set will
	// be used to remove any stale selector from the policy in the labelIdentityInterface.
	var clusterSetScopeSelectorKeys sets.Set[string]
	// Create AppliedToGroup for each AppliedTo present in AntreaNetworkPolicy spec.
	atgs := n.processAppliedTo(np.Namespace, np.Spec.AppliedTo)
	appliedToGroups = mergeAppliedToGroups(appliedToGroups, atgs...)
	// Compute NetworkPolicyRule for Ingress Rule.
	for idx, ingressRule := range np.Spec.Ingress {
		// Set default action to ALLOW to allow traffic.
		services, namedPortExists := toAntreaServicesForCRD(ingressRule.Ports, ingressRule.Protocols)
		// Create AppliedToGroup for each AppliedTo present in the ingress rule.
		atgs := n.processAppliedTo(np.Namespace, ingressRule.AppliedTo)
		appliedToGroups = mergeAppliedToGroups(appliedToGroups, atgs...)
		peer, ags, selKeys := n.toAntreaPeerForCRD(ingressRule.From, np, controlplane.DirectionIn, namedPortExists)
		if selKeys != nil {
			clusterSetScopeSelectorKeys = clusterSetScopeSelectorKeys.Union(selKeys)
		}
		addressGroups = mergeAddressGroups(addressGroups, ags...)
		rules = append(rules, controlplane.NetworkPolicyRule{
			Direction:       controlplane.DirectionIn,
			From:            *peer,
			Services:        services,
			Name:            ingressRule.Name,
			Action:          ingressRule.Action,
			Priority:        int32(idx),
			EnableLogging:   ingressRule.EnableLogging,
			AppliedToGroups: getAppliedToGroupNames(atgs),
			L7Protocols:     toAntreaL7ProtocolsForCRD(ingressRule.L7Protocols),
			LogLabel:        ingressRule.LogLabel,
		})
	}
	// Compute NetworkPolicyRule for Egress Rule.
	for idx, egressRule := range np.Spec.Egress {
		// Set default action to ALLOW to allow traffic.
		services, namedPortExists := toAntreaServicesForCRD(egressRule.Ports, egressRule.Protocols)
		// Create AppliedToGroup for each AppliedTo present in the egress rule.
		atgs := n.processAppliedTo(np.Namespace, egressRule.AppliedTo)
		appliedToGroups = mergeAppliedToGroups(appliedToGroups, atgs...)
		var peer *controlplane.NetworkPolicyPeer
		if egressRule.ToServices != nil {
			peer = n.svcRefToPeerForCRD(egressRule.ToServices, np.Namespace)
		} else {
			var ags []*antreatypes.AddressGroup
			var selKeys sets.Set[string]
			peer, ags, selKeys = n.toAntreaPeerForCRD(egressRule.To, np, controlplane.DirectionOut, namedPortExists)
			addressGroups = mergeAddressGroups(addressGroups, ags...)
			if selKeys != nil {
				clusterSetScopeSelectorKeys = clusterSetScopeSelectorKeys.Union(selKeys)
			}
		}
		rules = append(rules, controlplane.NetworkPolicyRule{
			Direction:       controlplane.DirectionOut,
			To:              *peer,
			Services:        services,
			Name:            egressRule.Name,
			Action:          egressRule.Action,
			Priority:        int32(idx),
			EnableLogging:   egressRule.EnableLogging,
			AppliedToGroups: getAppliedToGroupNames(atgs),
			L7Protocols:     toAntreaL7ProtocolsForCRD(egressRule.L7Protocols),
			LogLabel:        egressRule.LogLabel,
		})
	}
	tierPriority := n.getTierPriority(np.Spec.Tier)
	internalNetworkPolicy := &antreatypes.NetworkPolicy{
		SourceRef: &controlplane.NetworkPolicyReference{
			Type:      controlplane.AntreaNetworkPolicy,
			Namespace: np.Namespace,
			Name:      np.Name,
			UID:       np.UID,
		},
		Name:             internalNetworkPolicyKeyFunc(np),
		UID:              np.UID,
		Generation:       np.Generation,
		AppliedToGroups:  sets.List(sets.KeySet(appliedToGroups)),
		Rules:            rules,
		Priority:         &np.Spec.Priority,
		TierPriority:     &tierPriority,
		AppliedToPerRule: appliedToPerRule,
	}
	if n.stretchNPEnabled {
		n.labelIdentityInterface.RemoveStalePolicySelectors(clusterSetScopeSelectorKeys, internalNetworkPolicyKeyFunc(np))
	}
	return internalNetworkPolicy, appliedToGroups, addressGroups
}

func (n *NetworkPolicyController) processAppliedTo(namespace string, appliedTo []crdv1beta1.AppliedTo) []*antreatypes.AppliedToGroup {
	var appliedToGroups []*antreatypes.AppliedToGroup
	for _, at := range appliedTo {
		var atg *antreatypes.AppliedToGroup
		if at.Group != "" {
			atg = n.createAppliedToGroupForGroup(namespace, at.Group)
		} else {
			atg = n.createAppliedToGroup(namespace, at.PodSelector, at.NamespaceSelector, at.ExternalEntitySelector, nil)
		}
		if atg != nil {
			appliedToGroups = append(appliedToGroups, atg)
		}
	}
	return appliedToGroups
}

// ErrNetworkPolicyAppliedToUnsupportedGroup is an error response when
// a Group with Pods in other Namespaces is used as AppliedTo.
type ErrNetworkPolicyAppliedToUnsupportedGroup struct {
	namespace string
	groupName string
}

func (e *ErrNetworkPolicyAppliedToUnsupportedGroup) Error() string {
	return fmt.Sprintf("Group %s/%s with Pods in other Namespaces can not be used as AppliedTo", e.namespace, e.groupName)
}
