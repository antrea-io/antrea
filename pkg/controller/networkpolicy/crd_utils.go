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
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/conversion"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"

	"antrea.io/antrea/multicluster/controllers/multicluster/common"
	"antrea.io/antrea/pkg/apis/controlplane"
	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	antreatypes "antrea.io/antrea/pkg/controller/types"
	"antrea.io/antrea/pkg/util/k8s"
)

var (
	// matchAllPodsPeerCrd is a crdv1beta1.NetworkPolicyPeer matching all
	// Pods from all Namespaces.
	matchAllPodsPeerCrd = crdv1beta1.NetworkPolicyPeer{
		NamespaceSelector: &metav1.LabelSelector{},
	}
)

// semanticIgnoreLastTransitionTime does semantic deep equality checks for
// NetworkPolicyCondition but excludes LastTransitionTime. They are used when
// comparing NetworkPolicyCondition in NetworkPolicyStatus objects to avoid
// unnecessary updates caused different status generation time.
var semanticIgnoreLastTransitionTime = conversion.EqualitiesOrDie(
	func(a, b crdv1beta1.NetworkPolicyCondition) bool {
		a.LastTransitionTime = metav1.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC)
		b.LastTransitionTime = metav1.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC)
		return a == b
	},
)

// NetworkPolicyStatusEqual compares two NetworkPolicyStatus objects. It disregards
// the LastTransitionTime field in the status Conditions.
func NetworkPolicyStatusEqual(oldStatus, newStatus crdv1beta1.NetworkPolicyStatus) bool {
	return semanticIgnoreLastTransitionTime.DeepEqual(oldStatus, newStatus)
}

// groupMembersComputedConditionEqual checks whether the condition status for GroupMembersComputed condition
// is same. Returns true if equal, otherwise returns false. It disregards the lastTransitionTime field.
func groupMembersComputedConditionEqual(conds []crdv1beta1.GroupCondition, condition crdv1beta1.GroupCondition) bool {
	for _, c := range conds {
		if c.Type == crdv1beta1.GroupMembersComputed {
			if c.Status == condition.Status {
				return true
			}
		}
	}
	return false
}

// toAntreaServicesForCRD converts a slice of crdv1beta1.NetworkPolicyPort objects
// and a slice of v1beta1.NetworkPolicyProtocol objects to a slice of Antrea
// Service objects. A bool is returned along with the Service objects to indicate
// whether any named port exists.
func toAntreaServicesForCRD(npPorts []crdv1beta1.NetworkPolicyPort, npProtocols []crdv1beta1.NetworkPolicyProtocol) ([]controlplane.Service, bool) {
	var antreaServices []controlplane.Service
	var namedPortExists bool
	for _, npPort := range npPorts {
		if npPort.Port != nil && npPort.Port.Type == intstr.String {
			namedPortExists = true
		}
		antreaServices = append(antreaServices, controlplane.Service{
			Protocol:   toAntreaProtocol(npPort.Protocol),
			Port:       npPort.Port,
			EndPort:    npPort.EndPort,
			SrcPort:    npPort.SourcePort,
			SrcEndPort: npPort.SourceEndPort,
		})
	}
	for _, npProtocol := range npProtocols {
		if npProtocol.ICMP != nil {
			curProtocol := controlplane.ProtocolICMP
			antreaServices = append(antreaServices, controlplane.Service{
				Protocol: &curProtocol,
				ICMPType: npProtocol.ICMP.ICMPType,
				ICMPCode: npProtocol.ICMP.ICMPCode,
			})
		}
		if npProtocol.IGMP != nil {
			curProtocol := controlplane.ProtocolIGMP
			antreaServices = append(antreaServices, controlplane.Service{
				Protocol:     &curProtocol,
				IGMPType:     npProtocol.IGMP.IGMPType,
				GroupAddress: npProtocol.IGMP.GroupAddress,
			})
		}
	}
	return antreaServices, namedPortExists
}

// toAntreaL7ProtocolsForCRD converts a slice of v1beta1.L7Protocol objects to
// a slice of Antrea L7Protocol objects.
func toAntreaL7ProtocolsForCRD(l7Protocols []crdv1beta1.L7Protocol) []controlplane.L7Protocol {
	var antreaL7Protocols []controlplane.L7Protocol
	for _, l7p := range l7Protocols {
		antreaL7Protocols = append(antreaL7Protocols, controlplane.L7Protocol{
			HTTP: (*controlplane.HTTPProtocol)(l7p.HTTP),
			TLS:  (*controlplane.TLSProtocol)(l7p.TLS),
		})
	}
	return antreaL7Protocols
}

// toAntreaIPBlockForCRD converts a crdv1beta1.IPBlock to an Antrea IPBlock.
func toAntreaIPBlockForCRD(ipBlock *crdv1beta1.IPBlock) (*controlplane.IPBlock, error) {
	// Convert the allowed IPBlock to networkpolicy.IPNet.
	ipNet, err := cidrStrToIPNet(ipBlock.CIDR)
	if err != nil {
		return nil, err
	}
	antreaIPBlock := &controlplane.IPBlock{
		CIDR: *ipNet,
		// secv1alpha.IPBlock does not have the Except slices.
		Except: []controlplane.IPNet{},
	}
	return antreaIPBlock, nil
}

// toAntreaPeerForCRD creates an Antrea controlplane NetworkPolicyPeer for crdv1beta1 NetworkPolicyPeer.
// It is used when peer's Namespaces are not matched by NamespaceMatchTypes, for which the controlplane
// NetworkPolicyPeers will need to be created on a per-Namespace basis.
// Any ClusterSet scoped selector in this peer will also be registered with the labelIdentityInterface
// for the policy.
func (n *NetworkPolicyController) toAntreaPeerForCRD(peers []crdv1beta1.NetworkPolicyPeer,
	np metav1.Object, dir controlplane.Direction, namedPortExists bool) (*controlplane.NetworkPolicyPeer, []*antreatypes.AddressGroup, sets.Set[string]) {
	var addressGroups []*antreatypes.AddressGroup
	// NetworkPolicyPeer is supposed to match all addresses when it is empty and no clusterGroup is present.
	// It's treated as an IPBlock "0.0.0.0/0".
	if len(peers) == 0 {
		// For an egress Peer that specifies any named ports, it creates or
		// reuses the AddressGroup matching all Pods in all Namespaces and
		// appends the AddressGroup UID to the returned Peer such that it can be
		// used to resolve the named ports.
		// For other cases it uses the IPBlock "0.0.0.0/0" to avoid the overhead
		// of handling member updates of the AddressGroup.
		if dir == controlplane.DirectionIn || !namedPortExists {
			return &matchAllPeer, nil, nil
		}
		allPodsGroup := n.createAddressGroup("", matchAllPodsPeerCrd.PodSelector, matchAllPodsPeerCrd.NamespaceSelector, nil, nil)
		addressGroups = append(addressGroups, allPodsGroup)
		podsPeer := matchAllPeer
		podsPeer.AddressGroups = append(podsPeer.AddressGroups, allPodsGroup.Name)
		return &podsPeer, addressGroups, nil
	}
	var ipBlocks []controlplane.IPBlock
	var fqdns []string
	var labelIdentities []uint32
	uniqueLabelIDs := map[uint32]struct{}{}
	clusterSetScopeSelectorKeys := sets.New[string]()
	for _, peer := range peers {
		// A crdv1beta1.NetworkPolicyPeer will have exactly one of the following fields set:
		// - podSelector and/or namespaceSelector (in-cluster scope or ClusterSet scope)
		// - reference to a Group/ClusterGroup
		// - IPBlocks
		// - FQDNs
		if peer.IPBlock != nil {
			ipBlock, err := toAntreaIPBlockForCRD(peer.IPBlock)
			if err != nil {
				klog.Errorf("Failure processing Antrea NetworkPolicy %s/%s IPBlock %v: %v", np.GetNamespace(), np.GetName(), peer.IPBlock, err)
				continue
			}
			ipBlocks = append(ipBlocks, *ipBlock)
		} else if peer.Group != "" {
			addressGroup, groupIPBlocks := n.processRefGroupOrClusterGroup(peer.Group, np.GetNamespace())
			if addressGroup != nil {
				addressGroups = append(addressGroups, addressGroup)
			}
			ipBlocks = append(ipBlocks, groupIPBlocks...)
		} else if peer.FQDN != "" {
			fqdns = append(fqdns, peer.FQDN)
		} else if peer.ServiceAccount != nil {
			addressGroup := n.createAddressGroup(peer.ServiceAccount.Namespace, serviceAccountNameToPodSelector(peer.ServiceAccount.Name), nil, nil, nil)
			addressGroups = append(addressGroups, addressGroup)
		} else if peer.NodeSelector != nil {
			addressGroup := n.createAddressGroup("", nil, nil, nil, peer.NodeSelector)
			addressGroups = append(addressGroups, addressGroup)
		} else {
			addressGroup := n.createAddressGroup(np.GetNamespace(), peer.PodSelector, peer.NamespaceSelector, peer.ExternalEntitySelector, nil)
			addressGroups = append(addressGroups, addressGroup)
		}
		if n.stretchNPEnabled && peer.Scope == crdv1beta1.ScopeClusterSet {
			newClusterSetScopeSelector := antreatypes.NewGroupSelector(np.GetNamespace(), peer.PodSelector, peer.NamespaceSelector, nil, nil)
			clusterSetScopeSelectorKeys.Insert(newClusterSetScopeSelector.NormalizedName)
			// In addition to getting the matched Label Identity IDs, AddSelector also registers the selector
			// with the labelIdentityInterface.
			matchedLabelIDs := n.labelIdentityInterface.AddSelector(newClusterSetScopeSelector, internalNetworkPolicyKeyFunc(np))
			for _, id := range matchedLabelIDs {
				uniqueLabelIDs[id] = struct{}{}
			}
		}
	}
	for id := range uniqueLabelIDs {
		labelIdentities = append(labelIdentities, id)
	}
	return &controlplane.NetworkPolicyPeer{
		AddressGroups:   getAddressGroupNames(addressGroups),
		IPBlocks:        ipBlocks,
		FQDNs:           fqdns,
		LabelIdentities: labelIdentities,
	}, addressGroups, clusterSetScopeSelectorKeys
}

// toNamespacedPeerForCRD creates an Antrea controlplane NetworkPolicyPeer for crdv1beta1 NetworkPolicyPeer
// for a particular Namespace. It is used when a single crdv1beta1 NetworkPolicyPeer maps to multiple
// controlplane NetworkPolicyPeers because the appliedTo workloads reside in different Namespaces.
func (n *NetworkPolicyController) toNamespacedPeerForCRD(peers []crdv1beta1.NetworkPolicyPeer,
	np metav1.Object, namespace string) (*controlplane.NetworkPolicyPeer, []*antreatypes.AddressGroup, sets.Set[string]) {
	var addressGroups []*antreatypes.AddressGroup
	var labelIdentities []uint32
	uniqueLabelIDs := map[uint32]struct{}{}
	clusterSetScopeSelectorKeys := sets.New[string]()
	for _, peer := range peers {
		addressGroup := n.createAddressGroup(namespace, peer.PodSelector, nil, peer.ExternalEntitySelector, nil)
		addressGroups = append(addressGroups, addressGroup)
		if n.stretchNPEnabled && peer.Scope == crdv1beta1.ScopeClusterSet {
			newClusterSetScopeSelector := antreatypes.NewGroupSelector(namespace, peer.PodSelector, nil, peer.ExternalEntitySelector, nil)
			clusterSetScopeSelectorKeys.Insert(newClusterSetScopeSelector.NormalizedName)
			// In addition to getting the matched Label Identity IDs, AddSelector also registers the selector
			// with the labelIdentityInterface.
			matchedLabelIDs := n.labelIdentityInterface.AddSelector(newClusterSetScopeSelector, internalNetworkPolicyKeyFunc(np))
			for _, id := range matchedLabelIDs {
				uniqueLabelIDs[id] = struct{}{}
			}
		}
	}
	for id := range uniqueLabelIDs {
		labelIdentities = append(labelIdentities, id)
	}
	return &controlplane.NetworkPolicyPeer{
		AddressGroups: getAddressGroupNames(addressGroups), LabelIdentities: labelIdentities,
	}, addressGroups, clusterSetScopeSelectorKeys
}

// svcRefToPeerForCRD creates an Antrea controlplane NetworkPolicyPeer from ServiceReferences in ToServices
// or ToMulticlusterServices field of a crdv1beta1 NetworkPolicyPeer. For ANNP NetworkPolicyPeers, if
// Namespace is not provided in the ServiceReference, the policy's Namespace will be assumed.
func (n *NetworkPolicyController) svcRefToPeerForCRD(svcRefs []crdv1beta1.PeerService, defaultNamespace string) *controlplane.NetworkPolicyPeer {
	var controlplaneSvcRefs []controlplane.ServiceReference
	for _, svcRef := range svcRefs {
		svcNS, svcName := defaultNamespace, svcRef.Name
		if svcRef.Namespace != "" {
			svcNS = svcRef.Namespace
		}
		if svcRef.Scope == crdv1beta1.ScopeClusterSet {
			if n.stretchNPEnabled {
				svcName = common.ToMCResourceName(svcName)
			} else {
				klog.Error("Unable to process ClusterSet scoped service reference when stretched networkpolicy is not enabled")
				continue
			}
		}
		controlplaneSvcRefs = append(controlplaneSvcRefs, controlplane.ServiceReference{
			Namespace: svcNS,
			Name:      svcName,
		})
	}
	return &controlplane.NetworkPolicyPeer{ToServices: controlplaneSvcRefs}
}

// createAppliedToGroupForService creates an AppliedToGroup object corresponding to a Service.
func (n *NetworkPolicyController) createAppliedToGroupForService(service *crdv1beta1.NamespacedName) *antreatypes.AppliedToGroup {
	key := getNormalizedUID(k8s.NamespacedName(service.Namespace, service.Name))

	// Create an AppliedToGroup object for this Service.
	appliedToGroup := &antreatypes.AppliedToGroup{
		UID:  types.UID(key),
		Name: key,
		Service: &controlplane.ServiceReference{
			Namespace: service.Namespace,
			Name:      service.Name,
		},
	}
	return appliedToGroup
}

// createAppliedToGroupForGroup creates an AppliedToGroup object corresponding to a ClusterGroup or a Group.
// The namespace parameter is only provided when the group is namespace scoped.
func (n *NetworkPolicyController) createAppliedToGroupForGroup(namespace, group string) *antreatypes.AppliedToGroup {
	// Cluster group uses NAME and Namespaced group uses NAMESPACE/NAME as the key of the corresponding internal group.
	key := k8s.NamespacedName(namespace, group)
	// Find the internal Group corresponding to this ClusterGroup/Group.
	// There is no need to check if the ClusterGroup/Group exists in clusterGroupLister/groupLister because its
	// existence will eventually be reflected in internalGroupStore.
	ig, found, _ := n.internalGroupStore.Get(key)
	if !found {
		// Internal Group was not found. Once the internal Group is created, the sync worker for internal group will
		// re-enqueue the ClusterNetworkPolicy/AntreaNetworkPolicy processing which will call this method again. So it's
		// fine to ignore NotFound case.
		return nil
	}
	intGrp := ig.(*antreatypes.Group)
	// A Group may have child Groups, some of which contain regular Pod selectors and some of which contain IPBlocks.
	// When the Group is used as AppliedTo, it seems obvious that we should just apply NetworkPolicy to the selected
	// Pods and ignore the IPBlocks, instead of reporting errors and asking users to remove IPBlocks from child Groups,
	// as the Group could also be used as AddressGroup.
	// To keep the behavior consistent regarding IPBlocks, we ignore Groups containing only IPBlocks when it's used as
	// AppliedTo.
	if len(intGrp.IPBlocks) > 0 {
		klog.V(2).InfoS("Group with IPBlocks can not be used as AppliedTo", "Group", key)
		return nil
	}
	return &antreatypes.AppliedToGroup{UID: intGrp.UID, Name: key, SourceGroup: key}
}

// getTierPriority retrieves the priority associated with the input Tier name.
// If the Tier name is empty, by default, the lowest priority Application Tier
// is returned.
func (n *NetworkPolicyController) getTierPriority(tier string) int32 {
	if tier == "" {
		return crdv1beta1.DefaultTierPriority
	}
	// If the tier name is part of the static tier name set, we need to convert
	// tier name to lowercase to match the corresponding Tier CRD name. This is
	// possible in case of upgrade where in a previously created Antrea Policy
	// CRD was referring to an old static tier. Static tiers were introduced in
	// release 0.9.0 and deprecated in 0.10.0. So any upgrade from 0.9.0 to a
	// later release will undergo this conversion.
	if staticTierSet.Has(tier) {
		tier = strings.ToLower(tier)
	}
	t, err := n.tierLister.Get(tier)
	if err != nil {
		// This error should ideally not occur as we perform validation.
		klog.Errorf("Failed to retrieve Tier %s. Setting default tier priority: %v", tier, err)
		return crdv1beta1.DefaultTierPriority
	}
	return t.Spec.Priority
}

// getNormalizedNameForSelector retrieves the normalized name for GroupSelector.
// If the GroupSelector is nil, an empty string is returned.
func getNormalizedNameForSelector(sel *antreatypes.GroupSelector) string {
	if sel != nil {
		return sel.NormalizedName
	}
	return ""
}

func (n *NetworkPolicyController) syncInternalGroup(key string) error {
	defer n.triggerANNPUpdates(key)
	defer n.triggerCNPUpdates(key)
	defer n.triggerParentGroupUpdates(key)
	defer n.triggerDerivedGroupUpdates(key)
	// Retrieve the internal Group corresponding to this key.
	grpObj, found, _ := n.internalGroupStore.Get(key)
	if !found {
		klog.V(2).InfoS("Internal group not found", "internalGroup", key)
		n.groupingInterface.DeleteGroup(internalGroupType, key)
		return nil
	}
	grp := grpObj.(*antreatypes.Group)
	if grp.SourceReference.Namespace != "" {
		// Sync the Group as a Namespaced Group.
		return n.syncInternalNamespacedGroup(grp)
	}
	return n.syncInternalClusterGroup(grp)
}
