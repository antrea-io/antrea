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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	"github.com/vmware-tanzu/antrea/pkg/apis/networking"
	secv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/security/v1alpha1"
	antreatypes "github.com/vmware-tanzu/antrea/pkg/controller/types"
)

var (
	// matchAllPodsPeerCrd is a secv1alpha1.NetworkPolicyPeer matching all
	// Pods from all Namespaces.
	matchAllPodsPeerCrd = secv1alpha1.NetworkPolicyPeer{
		NamespaceSelector: &metav1.LabelSelector{},
	}
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
	klog.Infof("Creating new internal NetworkPolicy %#v", internalNP)
	n.internalNetworkPolicyStore.Create(internalNP)
	key, _ := keyFunc(cnp)
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
	klog.V(2).Infof("Updating existing internal NetworkPolicy %s", curInternalNP.Name)
	// Retrieve old secv1alpha1.NetworkPolicy object.
	oldCNP := old.(*secv1alpha1.ClusterNetworkPolicy)
	// Old and current NetworkPolicy share the same key.
	key, _ := keyFunc(oldCNP)
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
	key, _ := keyFunc(cnp)
	oldInternalNPObj, _, _ := n.internalNetworkPolicyStore.Get(key)
	oldInternalNP := oldInternalNPObj.(*antreatypes.NetworkPolicy)
	klog.Infof("Old internal NetworkPolicy %#v", oldInternalNP)
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

// toAntreaServicesForCRD converts a secv1alpha1.NetworkPolicyPort object to an
// Antrea Service object.
func toAntreaServicesForCRD(npPorts []secv1alpha1.NetworkPolicyPort) []networking.Service {
	var antreaServices []networking.Service
	for _, npPort := range npPorts {
		antreaService := networking.Service{
			Protocol: toAntreaProtocol(npPort.Protocol),
			Port:     npPort.Port,
		}
		antreaServices = append(antreaServices, antreaService)
	}
	return antreaServices
}

// toAntreaIPBlockForCRD converts a secv1alpha1.IPBlock to an Antrea IPBlock.
func toAntreaIPBlockForCRD(ipBlock *secv1alpha1.IPBlock) (*networking.IPBlock, error) {
	// Convert the allowed IPBlock to networkpolicy.IPNet.
	ipNet, err := cidrStrToIPNet(ipBlock.CIDR)
	if err != nil {
		return nil, err
	}
	antreaIPBlock := &networking.IPBlock{
		CIDR: *ipNet,
		// secv1alpha.IPBlock does not have the Except slices.
		Except: []networking.IPNet{},
	}
	return antreaIPBlock, nil
}

func (n *NetworkPolicyController) toAntreaPeerForCRD(peers []secv1alpha1.NetworkPolicyPeer, cnp *secv1alpha1.ClusterNetworkPolicy, dir networking.Direction) *networking.NetworkPolicyPeer {
	var addressGroups []string
	// Empty NetworkPolicyPeer is supposed to match all addresses.
	// It's treated as an IPBlock "0.0.0.0/0".
	if len(peers) == 0 {
		// For an ingress Peer, skip adding the AddressGroup matching all Pods
		// because in case of ingress Rule, the named Port resolution happens on
		// Pods in AppliedToGroup.
		if dir == networking.DirectionIn {
			return &matchAllPeer
		}
		// For an egress Peer, create an AddressGroup matching all Pods in all
		// Namespaces such that it can be used to resolve named Ports. This
		// AddressGroup is set in the NetworkPolicyPeer of matchAllPeer.
		allPodsGroupUID := n.createAddressGroupForCRD(matchAllPodsPeerCrd, cnp)
		podsPeer := matchAllPeer
		addressGroups = append(addressGroups, allPodsGroupUID)
		podsPeer.AddressGroups = addressGroups
		return &podsPeer
	}
	var ipBlocks []networking.IPBlock
	for _, peer := range peers {
		// A secv1alpha1.NetworkPolicyPeer will either have an IPBlock or a
		// podSelector and/or namespaceSelector set.
		if peer.IPBlock != nil {
			ipBlock, err := toAntreaIPBlockForCRD(peer.IPBlock)
			if err != nil {
				klog.Errorf("Failure processing ClusterNetworkPolicy %s IPBlock %v: %v", cnp.Name, peer.IPBlock, err)
				continue
			}
			ipBlocks = append(ipBlocks, *ipBlock)
		} else {
			normalizedUID := n.createAddressGroupForCRD(peer, cnp)
			addressGroups = append(addressGroups, normalizedUID)
		}
	}
	return &networking.NetworkPolicyPeer{AddressGroups: addressGroups, IPBlocks: ipBlocks}
}

// createAddressGroupForCRD creates an AddressGroup object corresponding to a
// secv1alpha1.NetworkPolicyPeer object in Cluster NetworkPolicyRule. This
// function simply creates the object without actually populating the
// PodAddresses as the affected Pods are calculated during sync process.
func (n *NetworkPolicyController) createAddressGroupForCRD(peer secv1alpha1.NetworkPolicyPeer, np *secv1alpha1.ClusterNetworkPolicy) string {
	groupSelector := toGroupSelector("", peer.PodSelector, peer.NamespaceSelector)
	normalizedUID := getNormalizedUID(groupSelector.NormalizedName)
	// Get or create an AddressGroup for the generated UID.
	_, found, _ := n.addressGroupStore.Get(normalizedUID)
	if found {
		return normalizedUID
	}
	// Create an AddressGroup object per Peer object.
	addressGroup := &antreatypes.AddressGroup{
		UID:      types.UID(normalizedUID),
		Name:     normalizedUID,
		Selector: *groupSelector,
	}
	klog.V(2).Infof("Creating new AddressGroup %s with selector (%s)", addressGroup.Name, addressGroup.Selector.NormalizedName)
	n.addressGroupStore.Create(addressGroup)
	return normalizedUID
}

// processClusterNetworkPolicy creates an internal NetworkPolicy instance
// corresponding to the secv1alpha1.ClusterNetworkPolicy object. This method
// does not commit the internal NetworkPolicy in store, instead returns an
// instance to the caller wherein, it will be either stored as a new Object
// in case of ADD event or modified and store the updated instance, in case
// of an UPDATE event.
func (n *NetworkPolicyController) processClusterNetworkPolicy(cnp *secv1alpha1.ClusterNetworkPolicy) *antreatypes.NetworkPolicy {
	appliedToGroupNames := make([]string, 0, len(cnp.Spec.AppliedTo))
	// Create AppliedToGroup for each AppliedTo present in
	// ClusterNetworkPolicy spec.
	for _, at := range cnp.Spec.AppliedTo {
		appliedToGroupNames = append(appliedToGroupNames, n.createAppliedToGroup("", at.PodSelector, at.NamespaceSelector))
	}
	rules := make([]networking.NetworkPolicyRule, 0, len(cnp.Spec.Ingress)+len(cnp.Spec.Egress))
	// Compute NetworkPolicyRule for Egress Rule.
	for idx, ingressRule := range cnp.Spec.Ingress {
		// Set default action to ALLOW to allow traffic.
		rules = append(rules, networking.NetworkPolicyRule{
			Direction: networking.DirectionIn,
			From:      *n.toAntreaPeerForCRD(ingressRule.From, cnp, networking.DirectionIn),
			Services:  toAntreaServicesForCRD(ingressRule.Ports),
			Action:    ingressRule.Action,
			Priority:  int32(idx),
		})
	}
	// Compute NetworkPolicyRule for Egress Rule.
	for idx, egressRule := range cnp.Spec.Egress {
		// Set default action to ALLOW to allow traffic.
		rules = append(rules, networking.NetworkPolicyRule{
			Direction: networking.DirectionOut,
			To:        *n.toAntreaPeerForCRD(egressRule.To, cnp, networking.DirectionOut),
			Services:  toAntreaServicesForCRD(egressRule.Ports),
			Action:    egressRule.Action,
			Priority:  int32(idx),
		})
	}
	internalNetworkPolicy := &antreatypes.NetworkPolicy{
		Name:            cnp.Name,
		Namespace:       "",
		UID:             cnp.UID,
		AppliedToGroups: appliedToGroupNames,
		Rules:           rules,
		Priority:        &cnp.Spec.Priority,
	}
	return internalNetworkPolicy
}
