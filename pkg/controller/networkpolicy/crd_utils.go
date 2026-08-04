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
	"net"
	"strings"
	"time"

	v1 "k8s.io/api/core/v1"
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
	"antrea.io/antrea/pkg/util/ip"
	"antrea.io/antrea/pkg/util/k8s"
)

// maxGroupNestingLevel is the maximum number of Group levels that Antrea supports: a Group
// listing childGroups is at level 1, and its children, at level 2, must not have childGroups of
// their own. Reaching level 3 means the definition is invalid, and admission validation rejects
// it (see validateChildGroup/validateChildClusterGroup).
//
// Raising it would also invalidate the assumption triggerParentGroupUpdates documents, that a
// Group having children cannot have parents.
const maxGroupNestingLevel = 2

var (
	// matchAllPodsPeerCrd is a crdv1beta1.NetworkPolicyPeer matching all
	// Pods from all Namespaces.
	matchAllPodsPeerCrd = crdv1beta1.NetworkPolicyPeer{
		NamespaceSelector: &metav1.LabelSelector{},
	}
)

// AddressGroupExcludedPodFilter returns true for Pods that are excluded from network policy
// enforcement as address-group or internal-group members, and from group-association queries.
// It excludes:
//   - Host-network Pods, which share the Node's network namespace; their address can only be
//     selected via nodeSelector, not podSelector.
//   - Terminated Pods, whose IPs may be recycled and reassigned to new Pods.
//   - Pods that have not yet received an IP address.
//
// Note: AppliedToGroup membership uses a different filter (see syncAppliedToGroup) that also
// excludes unscheduled Pods (NodeName == "") but does not check PodIPs.
func AddressGroupExcludedPodFilter(pod *v1.Pod) bool {
	return pod.Spec.HostNetwork || k8s.IsPodTerminated(pod) || len(pod.Status.PodIPs) == 0
}

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
//
// Reason and Message are compared as well, so that a change of reason at an unchanged status is
// still reported. If the antrea-controller is upgraded ahead of the CRDs, the API server prunes
// those two fields and this never matches for a condition that sets them, which means one
// redundant UpdateStatus call per sync of the affected Group. That is bounded: the informers are
// created with no resync period, and update{Cluster,}Group ignores an event that changes nothing
// but the status, so the write cannot feed itself.
func groupMembersComputedConditionEqual(conds []crdv1beta1.GroupCondition, condition crdv1beta1.GroupCondition) bool {
	for _, c := range conds {
		if c.Type == crdv1beta1.GroupMembersComputed {
			if c.Status == condition.Status && c.Reason == condition.Reason && c.Message == condition.Message {
				return true
			}
		}
	}
	return false
}

// groupMembersComputedReportsNestingExceeded returns true if the GroupMembersComputed condition
// currently reported by the source object blames the nesting level. A Group that stops being
// over-nested without becoming fully realized - because one of its childGroups does not exist, or
// is not realized yet - takes neither of the two branches that write a status, so the reason has
// to be cleared explicitly or it would keep pointing at a definition that has already been fixed.
//
// The callers check the internal Group's ChildGroupsNestingExceeded first, which is the same
// transition observed in memory: it is accurate as soon as the sync that clears the flag runs,
// while the conditions read here come from the informer cache and lag a watch round-trip behind
// the UpdateStatus call that set them. This is the fallback for the cases in which the in-memory
// signal is gone, i.e. after an antrea-controller restart, or after an ADD/UPDATE event on the
// Group itself reset the flag.
func groupMembersComputedReportsNestingExceeded(conds []crdv1beta1.GroupCondition) bool {
	for _, c := range conds {
		if c.Type == crdv1beta1.GroupMembersComputed {
			return c.Reason == crdv1beta1.ChildGroupsNestingExceeded
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
	var exceptNets []controlplane.IPNet
	for _, exc := range ipBlock.Except {
		// Convert the except IPBlock to networkpolicy.IPNet.
		exceptNet, err := cidrStrToIPNet(exc)
		if err != nil {
			return nil, err
		}
		exceptNets = append(exceptNets, *exceptNet)
	}
	antreaIPBlock := &controlplane.IPBlock{
		CIDR:   *ipNet,
		Except: exceptNets,
	}
	return antreaIPBlock, nil
}

// computeEffectiveIPNetForIPBlocks calculates the list of net.IPNet CIDRs after the
// "except" CIDRs are subtracted from each corresponding ipBlock.
func computeEffectiveIPNetForIPBlocks(ipBlocks []crdv1beta1.IPBlock) []*net.IPNet {
	var ipNets []*net.IPNet
	for i := range ipBlocks {
		// CIDR format is already validated by the webhook
		_, ipNet, _ := net.ParseCIDR(ipBlocks[i].CIDR)
		var exceptIPNets []*net.IPNet
		for j := range ipBlocks[i].Except {
			_, exceptNet, _ := net.ParseCIDR(ipBlocks[i].Except[j])
			exceptIPNets = append(exceptIPNets, exceptNet)
		}
		diffCIDRs, err := ip.DiffFromCIDRs(ipNet, exceptIPNets)
		if err != nil {
			// This should not happen theoretically since the except CIDRs are all validated
			// to be a subnet of the ipBlock.CIDR
			klog.ErrorS(err, "Error when computing effective CIDRs by removing except IPNets from IPBlock")
			continue
		}
		ipNets = append(ipNets, diffCIDRs...)
	}
	return ip.MergeCIDRs(ipNets)
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
	// triggerParentGroupUpdates reads ChildGroupsNestingExceeded from internalGroupStore, which
	// the syncInternal{Cluster,Namespaced}Group call below computes and persists synchronously,
	// before any deferred call unwinds. Preserve that ordering: a Group that references itself
	// is its own parent, so reading the flag before the sync refreshes it reintroduces the CPU
	// spin that a ChildGroups cycle causes.
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

// groupMembersComputedCondition returns a GroupMembersComputed condition with the given status
// and no reason: a status of True needs no explanation, and members that are merely not computed
// yet are reported as before, by the absence of a True condition.
func groupMembersComputedCondition(status v1.ConditionStatus) crdv1beta1.GroupCondition {
	return crdv1beta1.GroupCondition{
		Type:   crdv1beta1.GroupMembersComputed,
		Status: status,
	}
}

// childGroupsNestingExceededCondition returns the GroupMembersComputed condition reported for a
// Group or ClusterGroup that is not realized because of its nesting level. kind is the Kind of
// the source object, so that the message names what the user is looking at.
func childGroupsNestingExceededCondition(kind string) crdv1beta1.GroupCondition {
	return crdv1beta1.GroupCondition{
		Type:   crdv1beta1.GroupMembersComputed,
		Status: v1.ConditionFalse,
		Reason: crdv1beta1.ChildGroupsNestingExceeded,
		Message: fmt.Sprintf("The childGroups of this %s must not have childGroups of their own. "+
			"Its members cannot be computed and it is not realized: fix its definition, or the "+
			"definition of one of its childGroups.", kind),
	}
}

// childGroupsNestingExceeded returns true if resolving the given internal Group's childGroups
// reaches a level deeper than maxGroupNestingLevel, i.e. if one of its children has childGroups
// of its own. Such a Group is not realized, and it is excluded from parent Group updates.
//
// Admission validation is meant to make this impossible: it rejects a Group that references
// itself, and it rejects a Group whose child has children, or whose parent has a parent. Those
// two checks read the informer cache and the internal Group store though, so concurrent requests
// can race past them, and a hierarchy created before this validation existed is reloaded from
// etcd on restart without being validated.
//
// A ChildGroups cycle is one way to exceed the limit, and it is the dangerous one: every member
// of a cycle is its own ancestor, so it is nested infinitely deep. The check does not need to
// identify cycles as such, and it does not need a visited set: it never walks deeper than
// maxGroupNestingLevel, so it terminates on any graph.
func (n *NetworkPolicyController) childGroupsNestingExceeded(group *antreatypes.Group) bool {
	// A Group with no childGroups is at level 1 with nothing below it, and this is the common case.
	if len(group.ChildGroups) == 0 {
		return false
	}
	groups := []*antreatypes.Group{group}
	for level := 1; level < maxGroupNestingLevel; level++ {
		var nextLevel []*antreatypes.Group
		// Expand each Group of the next level once, however many times it is referenced: a
		// childGroup listed twice, or reachable through two parents, has the same childGroups
		// either way, so it expands to the same Groups and answers the leaf question below
		// identically. This bounds each level by the size of the store instead of letting
		// duplicates and diamonds multiply the frontier from one level to the next. The set is
		// deliberately per level and not shared across levels: the same Group appearing at two
		// levels must still be tested at the deepest one.
		expanded := sets.New[string]()
		for _, grp := range groups {
			for _, childName := range grp.ChildGroups {
				// childName is the name of a child ClusterGroup, or the name of a child Group
				// in the same Namespace as its parent.
				childKey := k8s.NamespacedName(grp.SourceReference.Namespace, childName)
				if expanded.Has(childKey) {
					continue
				}
				expanded.Insert(childKey)
				childObj, found, _ := n.internalGroupStore.Get(childKey)
				if !found {
					// The child does not exist yet: it contributes no members, and the Group
					// will be synced again when it is created.
					continue
				}
				nextLevel = append(nextLevel, childObj.(*antreatypes.Group))
			}
		}
		groups = nextLevel
	}
	// Any Group at the deepest supported level must be a leaf. Note that this is evaluated on the
	// Group's own childGroups list, not on the children it resolves to, so the answer does not
	// change when a child that is referenced but does not exist yet is created.
	for _, grp := range groups {
		if len(grp.ChildGroups) > 0 {
			return true
		}
	}
	return false
}
