// Copyright 2021 Antrea Authors
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
	"context"
	"net"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/apis/controlplane"
	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	antreatypes "antrea.io/antrea/pkg/controller/types"
	"antrea.io/antrea/pkg/util/k8s"
)

// addGroup is responsible for processing the ADD event of a Group resource.
func (n *NetworkPolicyController) addGroup(curObj interface{}) {
	g := curObj.(*crdv1beta1.Group)
	key := internalGroupKeyFunc(g)
	klog.V(2).InfoS("Processing ADD event for Group", "Group", key)
	newGroup := n.processGroup(g)
	klog.V(2).InfoS("Creating new internal Group", "internalGroup", newGroup.UID)
	n.internalGroupStore.Create(newGroup)
	n.enqueueInternalGroup(key)
}

// updateGroup is responsible for processing the UPDATE event of a Group resource.
func (n *NetworkPolicyController) updateGroup(oldObj, curObj interface{}) {
	cg := curObj.(*crdv1beta1.Group)
	og := oldObj.(*crdv1beta1.Group)
	key := internalGroupKeyFunc(cg)
	klog.V(2).InfoS("Processing UPDATE event for Group", "Group", key)
	newGroup := n.processGroup(cg)
	oldGroup := n.processGroup(og)

	selectorUpdated := func() bool {
		return getNormalizedNameForSelector(newGroup.Selector) != getNormalizedNameForSelector(oldGroup.Selector)
	}
	svcRefUpdated := func() bool {
		oldSvc, newSvc := oldGroup.ServiceReference, newGroup.ServiceReference
		if oldSvc != nil && newSvc != nil && oldSvc.Name == newSvc.Name && oldSvc.Namespace == newSvc.Namespace {
			return false
		} else if oldSvc == nil && newSvc == nil {
			return false
		}
		return true
	}
	ipBlocksUpdated := func() bool {
		oldIPBs, newIPBs := sets.Set[string]{}, sets.Set[string]{}
		for _, ipb := range oldGroup.IPBlocks {
			oldIPBs.Insert(ipb.CIDR.String())
		}
		for _, ipb := range newGroup.IPBlocks {
			newIPBs.Insert(ipb.CIDR.String())
		}
		return oldIPBs.Equal(newIPBs)
	}
	childGroupsUpdated := func() bool {
		oldChildGroups, newChildGroups := sets.Set[string]{}, sets.Set[string]{}
		for _, c := range oldGroup.ChildGroups {
			oldChildGroups.Insert(c)
		}
		for _, c := range newGroup.ChildGroups {
			newChildGroups.Insert(c)
		}
		return !oldChildGroups.Equal(newChildGroups)
	}
	if !ipBlocksUpdated() && !svcRefUpdated() && !selectorUpdated() && !childGroupsUpdated() {
		// No change in the contents of the Group. No need to enqueue for further sync.
		return
	}
	n.internalGroupStore.Update(newGroup)
	n.enqueueInternalGroup(key)
}

// deleteGroup is responsible for processing the DELETE event of a Group resource.
func (n *NetworkPolicyController) deleteGroup(oldObj interface{}) {
	og, ok := oldObj.(*crdv1beta1.Group)
	klog.V(2).InfoS("Processing DELETE event for Group", "Group", internalGroupKeyFunc(og))
	if !ok {
		tombstone, ok := oldObj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Error decoding object when deleting Group, invalid type: %v", oldObj)
			return
		}
		og, ok = tombstone.Obj.(*crdv1beta1.Group)
		if !ok {
			klog.Errorf("Error decoding object tombstone when deleting Group, invalid type: %v", tombstone.Obj)
			return
		}
	}
	key := internalGroupKeyFunc(og)
	klog.V(2).InfoS("Deleting internal Group", "Group", key)
	err := n.internalGroupStore.Delete(key)
	if err != nil {
		klog.Errorf("Unable to delete internal Group %s from store: %v", key, err)
	}
	n.enqueueInternalGroup(key)
}

func (n *NetworkPolicyController) processGroup(g *crdv1beta1.Group) *antreatypes.Group {
	internalGroup := antreatypes.Group{
		SourceReference: getGroupSourceRef(g),
		UID:             g.UID,
	}
	if len(g.Spec.ChildGroups) > 0 {
		for _, childGName := range g.Spec.ChildGroups {
			internalGroup.ChildGroups = append(internalGroup.ChildGroups, string(childGName))
		}
		return &internalGroup
	}
	if len(g.Spec.IPBlocks) > 0 {
		for i := range g.Spec.IPBlocks {
			ipb, _ := toAntreaIPBlockForCRD(&g.Spec.IPBlocks[i])
			internalGroup.IPBlocks = append(internalGroup.IPBlocks, *ipb)
			// CIDR format is already validated by the webhook
			_, ipNet, _ := net.ParseCIDR(g.Spec.IPBlocks[i].CIDR)
			internalGroup.IPNets = append(internalGroup.IPNets, *ipNet)
		}
		return &internalGroup
	}
	svcSelector := g.Spec.ServiceReference
	if svcSelector != nil {
		// ServiceReference will be converted to groupSelector once the internalGroup is synced.
		internalGroup.ServiceReference = &controlplane.ServiceReference{
			Namespace: svcSelector.Namespace,
			Name:      svcSelector.Name,
		}
	} else {
		groupSelector := antreatypes.NewGroupSelector(g.Namespace, g.Spec.PodSelector, g.Spec.NamespaceSelector, g.Spec.ExternalEntitySelector, nil)
		internalGroup.Selector = groupSelector
	}
	return &internalGroup
}

func getGroupSourceRef(g *crdv1beta1.Group) *controlplane.GroupReference {
	return &controlplane.GroupReference{
		Name:      g.GetName(),
		Namespace: g.GetNamespace(),
		UID:       g.GetUID(),
	}
}

func (n *NetworkPolicyController) syncInternalNamespacedGroup(grp *antreatypes.Group) error {
	originalMembersComputedStatus := grp.MembersComputed
	// Retrieve the Group corresponding to this key.
	g, err := n.grpLister.Groups(grp.SourceReference.Namespace).Get(grp.SourceReference.Name)
	if err != nil {
		klog.InfoS("Didn't find Group, skip processing of internal group", "Group", grp.SourceReference.ToTypedString())
		return nil
	}
	key := internalGroupKeyFunc(g)
	selectorUpdated := n.processServiceReference(grp)
	if grp.Selector != nil {
		n.groupingInterface.AddGroup(internalGroupType, key, grp.Selector)
	} else {
		n.groupingInterface.DeleteGroup(internalGroupType, key)
	}

	membersComputed, membersComputedStatus := true, v1.ConditionFalse
	// Update the Group status to Realized as Antrea has recognized the Group and
	// processed its group members. The Group is considered realized if:
	//   1. It does not have child groups. The group members are immediately considered
	//      computed during syncInternalGroup, as the group selector is finalized.
	//   2. All its child groups are created and realized.
	if len(grp.ChildGroups) > 0 {
		for _, cgName := range grp.ChildGroups {
			internalGroup, found, _ := n.internalGroupStore.Get(k8s.NamespacedName(grp.SourceReference.Namespace, cgName))
			if !found || internalGroup.(*antreatypes.Group).MembersComputed != v1.ConditionTrue {
				membersComputed = false
				break
			}
		}
	}
	if membersComputed {
		klog.V(4).InfoS("Updating GroupMembersComputed Status for Group", "Group", key)
		err = n.updateGroupStatus(g, v1.ConditionTrue)
		if err != nil {
			klog.Errorf("Failed to update Group %s/%s GroupMembersComputed condition to %s: %v", g.Namespace, g.Name, v1.ConditionTrue, err)
		} else {
			membersComputedStatus = v1.ConditionTrue
		}
	}
	if selectorUpdated || membersComputedStatus != originalMembersComputedStatus {
		// Update the internal Group object in the store with the new selector and status.
		updatedGrp := &antreatypes.Group{
			UID:              grp.UID,
			SourceReference:  grp.SourceReference,
			MembersComputed:  membersComputedStatus,
			Selector:         grp.Selector,
			IPBlocks:         grp.IPBlocks,
			IPNets:           grp.IPNets,
			ServiceReference: grp.ServiceReference,
			ChildGroups:      grp.ChildGroups,
		}
		klog.V(2).InfoS("Updating existing internal Group", "internalGroup", grp.SourceReference.ToGroupName())
		n.internalGroupStore.Update(updatedGrp)
	}
	return err
}

// triggerANNPUpdates triggers processing of Antrea NetworkPolicies associated with the input Group.
func (n *NetworkPolicyController) triggerANNPUpdates(g string) {
	// If a Group is added/updated, it might have a reference in Antrea NetworkPolicy.
	annps, _ := n.annpInformer.Informer().GetIndexer().ByIndex(GroupIndex, g)
	for _, obj := range annps {
		n.enqueueInternalNetworkPolicy(getANNPReference(obj.(*crdv1beta1.NetworkPolicy)))
	}
}

// updateGroupStatus updates the Status subresource for a Group.
func (n *NetworkPolicyController) updateGroupStatus(g *crdv1beta1.Group, cStatus v1.ConditionStatus) error {
	condStatus := crdv1beta1.GroupCondition{
		Status: cStatus,
		Type:   crdv1beta1.GroupMembersComputed,
	}
	if groupMembersComputedConditionEqual(g.Status.Conditions, condStatus) {
		// There is no change in conditions.
		return nil
	}
	condStatus.LastTransitionTime = metav1.Now()
	status := crdv1beta1.GroupStatus{
		Conditions: []crdv1beta1.GroupCondition{condStatus},
	}
	klog.V(4).InfoS("Updating Group status", "Group", internalGroupKeyFunc(g), "status", condStatus)
	toUpdate := g.DeepCopy()
	toUpdate.Status = status
	_, err := n.crdClient.CrdV1beta1().Groups(g.GetNamespace()).UpdateStatus(context.TODO(), toUpdate, metav1.UpdateOptions{})
	return err
}
