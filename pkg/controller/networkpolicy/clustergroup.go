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
	"fmt"
	"net"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/apis/controlplane"
	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/pkg/controller/networkpolicy/store"
	antreatypes "antrea.io/antrea/pkg/controller/types"
)

// addClusterGroup is responsible for processing the ADD event of a ClusterGroup resource.
func (c *NetworkPolicyController) addClusterGroup(curObj interface{}) {
	cg := curObj.(*crdv1beta1.ClusterGroup)
	key := internalGroupKeyFunc(cg)
	klog.V(2).Infof("Processing ADD event for ClusterGroup %s", cg.Name)
	newGroup := c.processClusterGroup(cg)
	klog.V(2).Infof("Creating new internal Group %s", newGroup.UID)
	c.internalGroupStore.Create(newGroup)
	c.enqueueInternalGroup(key)
}

// updateClusterGroup is responsible for processing the UPDATE event of a ClusterGroup resource.
func (c *NetworkPolicyController) updateClusterGroup(oldObj, curObj interface{}) {
	cg := curObj.(*crdv1beta1.ClusterGroup)
	og := oldObj.(*crdv1beta1.ClusterGroup)
	key := internalGroupKeyFunc(cg)
	klog.V(2).Infof("Processing UPDATE event for ClusterGroup %s", cg.Name)
	newGroup := c.processClusterGroup(cg)
	oldGroup := c.processClusterGroup(og)

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
		return !oldIPBs.Equal(newIPBs)
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
		// No change in the contents of the ClusterGroup. No need to enqueue for further sync.
		return
	}
	c.internalGroupStore.Update(newGroup)
	c.enqueueInternalGroup(key)
}

// deleteClusterGroup is responsible for processing the DELETE event of a ClusterGroup resource.
func (c *NetworkPolicyController) deleteClusterGroup(oldObj interface{}) {
	og, ok := oldObj.(*crdv1beta1.ClusterGroup)
	klog.V(2).Infof("Processing DELETE event for ClusterGroup %s", og.Name)
	if !ok {
		tombstone, ok := oldObj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Error decoding object when deleting ClusterGroup, invalid type: %v", oldObj)
			return
		}
		og, ok = tombstone.Obj.(*crdv1beta1.ClusterGroup)
		if !ok {
			klog.Errorf("Error decoding object tombstone when deleting ClusterGroup, invalid type: %v", tombstone.Obj)
			return
		}
	}
	key := internalGroupKeyFunc(og)
	klog.V(2).Infof("Deleting internal Group %s", key)
	err := c.internalGroupStore.Delete(key)
	if err != nil {
		klog.Errorf("Unable to delete internal Group %s from store: %v", key, err)
	}
	c.enqueueInternalGroup(key)
}

func (c *NetworkPolicyController) processClusterGroup(cg *crdv1beta1.ClusterGroup) *antreatypes.Group {
	internalGroup := antreatypes.Group{
		SourceReference: getClusterGroupSourceRef(cg),
		UID:             cg.UID,
	}
	if len(cg.Spec.ChildGroups) > 0 {
		for _, childCGName := range cg.Spec.ChildGroups {
			internalGroup.ChildGroups = append(internalGroup.ChildGroups, string(childCGName))
		}
		return &internalGroup
	}
	if len(cg.Spec.IPBlocks) > 0 {
		for i := range cg.Spec.IPBlocks {
			ipb, _ := toAntreaIPBlockForCRD(&cg.Spec.IPBlocks[i])
			internalGroup.IPBlocks = append(internalGroup.IPBlocks, *ipb)
			// CIDR format is already validated by the webhook
			_, ipNet, _ := net.ParseCIDR(cg.Spec.IPBlocks[i].CIDR)
			internalGroup.IPNets = append(internalGroup.IPNets, *ipNet)
		}
		return &internalGroup
	}
	svcSelector := cg.Spec.ServiceReference
	if svcSelector != nil {
		// ServiceReference will be converted to groupSelector once the internalGroup is synced.
		internalGroup.ServiceReference = &controlplane.ServiceReference{
			Namespace: svcSelector.Namespace,
			Name:      svcSelector.Name,
		}
	} else {
		groupSelector := antreatypes.NewGroupSelector("", cg.Spec.PodSelector, cg.Spec.NamespaceSelector, cg.Spec.ExternalEntitySelector, nil)
		internalGroup.Selector = groupSelector
	}
	return &internalGroup
}

// filterInternalGroupsForService computes a list of internal Group keys which references the Service.
func (c *NetworkPolicyController) filterInternalGroupsForService(obj metav1.Object) sets.Set[string] {
	matchingKeySet := sets.Set[string]{}
	indexKey, _ := cache.MetaNamespaceKeyFunc(obj)
	matchedSvcGroups, _ := c.internalGroupStore.GetByIndex(store.ServiceIndex, indexKey)
	for i := range matchedSvcGroups {
		key, _ := store.GroupKeyFunc(matchedSvcGroups[i])
		matchingKeySet.Insert(key)
	}
	return matchingKeySet
}

func (c *NetworkPolicyController) enqueueInternalGroup(key string) {
	klog.V(4).Infof("Adding new key %s to internal Group queue", key)
	c.internalGroupQueue.Add(key)
}

func (c *NetworkPolicyController) internalGroupWorker() {
	for c.processNextInternalGroupWorkItem() {
	}
}

// Processes an item in the "internalGroup" work queue, by calling
// syncInternalGroup after casting the item to a string (Group key).
// If syncInternalGroup returns an error, this function handles it by re-queueing
// the item so that it can be processed again later. If syncInternalGroup is
// successful, the ClusterGroup is removed from the queue until we get notify
// of a new change. This function return false if and only if the work queue
// was shutdown (no more items will be processed).
func (c *NetworkPolicyController) processNextInternalGroupWorkItem() bool {
	key, quit := c.internalGroupQueue.Get()
	if quit {
		return false
	}
	defer c.internalGroupQueue.Done(key)

	err := c.syncInternalGroup(key.(string))
	if err != nil {
		// Put the item back in the workqueue to handle any transient errors.
		c.internalGroupQueue.AddRateLimited(key)
		klog.Errorf("Failed to sync internal Group %s: %v", key, err)
		return true
	}
	// If no error occurs we Forget this item so it does not get queued again until
	// another change happens.
	c.internalGroupQueue.Forget(key)
	return true
}

func (c *NetworkPolicyController) syncInternalClusterGroup(grp *antreatypes.Group) error {
	originalMembersComputedStatus := grp.MembersComputed
	// Retrieve the ClusterGroup corresponding to this key.
	cg, err := c.cgLister.Get(grp.SourceReference.ToGroupName())
	if err != nil {
		klog.InfoS("Didn't find ClusterGroup, skip processing of internal group", "ClusterGroup", grp.SourceReference.ToTypedString())
		return nil
	}
	selectorUpdated := c.processServiceReference(grp)
	if grp.Selector != nil {
		c.groupingInterface.AddGroup(internalGroupType, grp.SourceReference.ToGroupName(), grp.Selector)
	} else {
		c.groupingInterface.DeleteGroup(internalGroupType, grp.SourceReference.ToGroupName())
	}

	membersComputed, membersComputedStatus := true, v1.ConditionFalse
	// Update the ClusterGroup status to Realized as Antrea has recognized the Group and
	// processed its group members. The ClusterGroup is considered realized if:
	//   1. It does not have child groups. The group members are immediately considered
	//      computed during syncInternalGroup, as the group selector is finalized.
	//   2. All its child groups are created and realized.
	if len(grp.ChildGroups) > 0 {
		for _, cgName := range grp.ChildGroups {
			internalGroup, found, _ := c.internalGroupStore.Get(cgName)
			if !found || internalGroup.(*antreatypes.Group).MembersComputed != v1.ConditionTrue {
				membersComputed = false
				break
			}
		}
	}
	if membersComputed {
		klog.V(4).InfoS("Updating GroupMembersComputed Status for ClusterGroup", "ClusterGroup", cg.Name)
		err = c.updateClusterGroupStatus(cg, v1.ConditionTrue)
		if err != nil {
			klog.Errorf("Failed to update ClusterGroup %s GroupMembersComputed condition to %s: %v", cg.Name, v1.ConditionTrue, err)
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
		c.internalGroupStore.Update(updatedGrp)
	}
	return err
}

func getClusterGroupSourceRef(cg *crdv1beta1.ClusterGroup) *controlplane.GroupReference {
	return &controlplane.GroupReference{
		Name:      cg.GetName(),
		Namespace: cg.GetNamespace(),
		UID:       cg.GetUID(),
	}
}

func (c *NetworkPolicyController) triggerParentGroupUpdates(grp string) {
	// TODO: if the max supported group nesting level increases, a Group having children
	//  will no longer be a valid indication that it cannot have parents.
	parentGroupObjs, err := c.internalGroupStore.GetByIndex(store.ChildGroupIndex, grp)
	if err != nil {
		klog.Errorf("Error retrieving parents of ClusterGroup %s: %v", grp, err)
		return
	}
	for _, p := range parentGroupObjs {
		parentGrp := p.(*antreatypes.Group)
		c.enqueueInternalGroup(parentGrp.SourceReference.ToGroupName())
	}
}

// triggerDerivedGroupUpdates triggers processing of AppliedToGroup and AddressGroup derived from the provided group.
func (c *NetworkPolicyController) triggerDerivedGroupUpdates(grp string) {
	groups, _ := c.appliedToGroupStore.GetByIndex(store.SourceGroupIndex, grp)
	for _, group := range groups {
		// It's fine if the group is deleted after checking its existence as syncAppliedToGroup will do nothing when it
		// doesn't find the group.
		c.enqueueAppliedToGroup(group.(*antreatypes.AppliedToGroup).Name)
	}
	groups, _ = c.addressGroupStore.GetByIndex(store.SourceGroupIndex, grp)
	for _, group := range groups {
		// It's fine if the group is deleted after checking its existence as syncAddressGroup will do nothing when it
		// doesn't find the group.
		c.enqueueAddressGroup(group.(*antreatypes.AddressGroup).Name)
	}
}

// triggerCNPUpdates triggers processing of ClusterNetworkPolicies associated with the input ClusterGroup.
func (c *NetworkPolicyController) triggerCNPUpdates(cg string) {
	// If a ClusterGroup is added/updated, it might have a reference in ClusterNetworkPolicy.
	cnps, err := c.acnpInformer.Informer().GetIndexer().ByIndex(ClusterGroupIndex, cg)
	if err != nil {
		klog.Errorf("Error retrieving ClusterNetworkPolicies corresponding to ClusterGroup %s", cg)
		return
	}
	for _, obj := range cnps {
		c.enqueueInternalNetworkPolicy(getACNPReference(obj.(*crdv1beta1.ClusterNetworkPolicy)))
	}
}

// updateClusterGroupStatus updates the Status subresource for a ClusterGroup.
func (c *NetworkPolicyController) updateClusterGroupStatus(cg *crdv1beta1.ClusterGroup, cStatus v1.ConditionStatus) error {
	condStatus := crdv1beta1.GroupCondition{
		Status: cStatus,
		Type:   crdv1beta1.GroupMembersComputed,
	}
	if groupMembersComputedConditionEqual(cg.Status.Conditions, condStatus) {
		// There is no change in conditions.
		return nil
	}
	condStatus.LastTransitionTime = metav1.Now()
	status := crdv1beta1.GroupStatus{
		Conditions: []crdv1beta1.GroupCondition{condStatus},
	}
	klog.V(4).Infof("Updating ClusterGroup %s status to %#v", cg.Name, condStatus)
	toUpdate := cg.DeepCopy()
	toUpdate.Status = status
	_, err := c.crdClient.CrdV1beta1().ClusterGroups().UpdateStatus(context.TODO(), toUpdate, metav1.UpdateOptions{})
	return err
}

// processServiceReference knows how to process the serviceReference in the group, and set the group
// selector based on the Service referenced. It returns true if the group's selector needs to be
// updated after serviceReference processing, and false otherwise.
func (c *NetworkPolicyController) processServiceReference(group *antreatypes.Group) bool {
	svcRef := group.ServiceReference
	if svcRef == nil {
		return false
	}
	originalSelectorName := getNormalizedNameForSelector(group.Selector)
	svc, err := c.serviceLister.Services(svcRef.Namespace).Get(svcRef.Name)
	if err != nil {
		klog.V(2).InfoS("Error getting Service object, setting empty selector for internal Group", "Service", svcRef.Namespace+"/"+svcRef.Name, "error", err, "internalGroup", group.SourceReference.ToTypedString())
		group.Selector = nil
		return originalSelectorName == getNormalizedNameForSelector(nil)
	}
	newSelector := c.serviceToGroupSelector(svc)
	group.Selector = newSelector
	return originalSelectorName == getNormalizedNameForSelector(newSelector)
}

// serviceToGroupSelector knows how to generate GroupSelector for a Service.
func (c *NetworkPolicyController) serviceToGroupSelector(service *v1.Service) *antreatypes.GroupSelector {
	if len(service.Spec.Selector) == 0 {
		klog.Infof("Service %s/%s is without selectors and not supported by serviceReference in ClusterGroup", service.Namespace, service.Name)
		return nil
	}
	svcPodSelector := metav1.LabelSelector{
		MatchLabels: service.Spec.Selector,
	}
	// Convert Service.spec.selector to GroupSelector by setting the Namespace to the Service's Namespace
	// and podSelector to Service's selector.
	groupSelector := antreatypes.NewGroupSelector(service.Namespace, &svcPodSelector, nil, nil, nil)
	return groupSelector
}

// GetAssociatedGroups retrieves the internal Groups associated with the entity being
// queried (Pod or ExternalEntity identified by name and namespace).
func (c *NetworkPolicyController) GetAssociatedGroups(name, namespace string) []antreatypes.Group {
	// Try Pod first, then ExternalEntity.
	groups, exists := c.groupingInterface.GetGroupsForPod(namespace, name)
	if !exists {
		groups, exists = c.groupingInterface.GetGroupsForExternalEntity(namespace, name)
		if !exists {
			return nil
		}
	}
	clusterGroups, exists := groups[internalGroupType]
	if !exists {
		return nil
	}
	var groupObjs []antreatypes.Group
	for _, g := range clusterGroups {
		associatedGroups := c.getAssociatedGroupsByName(g)
		groupObjs = append(groupObjs, associatedGroups...)
	}
	// Remove duplicates in the groupObj slice.
	groupKeys, j := make(map[string]bool), 0
	for _, g := range groupObjs {
		if _, exists := groupKeys[g.SourceReference.ToGroupName()]; !exists {
			groupKeys[g.SourceReference.ToGroupName()] = true
			groupObjs[j] = g
			j++
		}
	}
	return groupObjs[:j]
}

// getAssociatedGroupsByName retrieves the internal Group and all it's parent Group objects
// (if any) by Group name.
func (c *NetworkPolicyController) getAssociatedGroupsByName(grpName string) []antreatypes.Group {
	var groups []antreatypes.Group
	groupObj, found, _ := c.internalGroupStore.Get(grpName)
	if !found {
		return groups
	}
	grp := groupObj.(*antreatypes.Group)
	groups = append(groups, *grp)
	parentGroups := c.getParentGroups(grp.SourceReference.ToGroupName())
	groups = append(groups, parentGroups...)
	return groups
}

func (c *NetworkPolicyController) getParentGroups(grpName string) []antreatypes.Group {
	var groups []antreatypes.Group
	parentGroupObjs, _ := c.internalGroupStore.GetByIndex(store.ChildGroupIndex, grpName)
	for _, p := range parentGroupObjs {
		parentGrp := p.(*antreatypes.Group)
		groups = append(groups, *parentGrp)
	}
	return groups
}

// GetGroupMembers returns the current members of a ClusterGroup/Group.
// If the ClusterGroup/Group is defined with IPBlocks, the returned members will be []controlplane.IPBlock.
// Otherwise, the returned members will be of type controlplane.GroupMemberSet.
func (c *NetworkPolicyController) GetGroupMembers(name string) (controlplane.GroupMemberSet, []controlplane.IPBlock, error) {
	groupObj, found, _ := c.internalGroupStore.Get(name)
	if found {
		group := groupObj.(*antreatypes.Group)
		member, ipb := c.getInternalGroupMembers(group)
		return member, ipb, nil
	}
	return nil, nil, fmt.Errorf("no internal Group with name %s is found", name)
}

func (c *NetworkPolicyController) GetAssociatedIPBlockGroups(ip net.IP) []antreatypes.Group {
	ipBlockGroupObjs, _ := c.internalGroupStore.GetByIndex(store.IPBlockGroupIndex, store.HasIPBlocks)
	var matchedGroups []antreatypes.Group
	for _, obj := range ipBlockGroupObjs {
		group := obj.(*antreatypes.Group)
		for _, ipNet := range group.IPNets {
			if ipNet.Contains(ip) {
				matchedGroups = append(matchedGroups, *group)
				// Append all parent groups to matchedGroups
				parentGroups := c.getParentGroups(group.SourceReference.ToGroupName())
				matchedGroups = append(matchedGroups, parentGroups...)
			}
		}
	}
	return matchedGroups
}
