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

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/apis/controlplane"
	corev1a2 "github.com/vmware-tanzu/antrea/pkg/apis/core/v1alpha2"
	secv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/security/v1alpha1"
	"github.com/vmware-tanzu/antrea/pkg/controller/networkpolicy/store"
	antreatypes "github.com/vmware-tanzu/antrea/pkg/controller/types"
)

// addClusterGroup is responsible for processing the ADD event of a ClusterGroup resource.
func (n *NetworkPolicyController) addClusterGroup(curObj interface{}) {
	cg := curObj.(*corev1a2.ClusterGroup)
	key := internalGroupKeyFunc(cg)
	klog.V(2).Infof("Processing ADD event for ClusterGroup %s", cg.Name)
	newGroup := n.processClusterGroup(cg)
	klog.V(2).Infof("Creating new internal Group %s with selector (%s)", newGroup.UID, newGroup.Selector.NormalizedName)
	n.internalGroupStore.Create(newGroup)
	n.enqueueInternalGroup(key)
}

// updateClusterGroup is responsible for processing the UPDATE event of a ClusterGroup resource.
func (n *NetworkPolicyController) updateClusterGroup(oldObj, curObj interface{}) {
	cg := curObj.(*corev1a2.ClusterGroup)
	og := oldObj.(*corev1a2.ClusterGroup)
	key := internalGroupKeyFunc(cg)
	klog.V(2).Infof("Processing UPDATE event for ClusterGroup %s", cg.Name)
	newGroup := n.processClusterGroup(cg)
	oldGroup := n.processClusterGroup(og)
	selUpdated := newGroup.Selector.NormalizedName != oldGroup.Selector.NormalizedName
	ipBlockUpdated := newGroup.IPBlock != oldGroup.IPBlock
	if !selUpdated && !ipBlockUpdated {
		// No change in the selectors of the ClusterGroup. No need to enqueue for further sync.
		return
	}
	n.internalGroupStore.Update(newGroup)
	n.enqueueInternalGroup(key)
}

// deleteClusterGroup is responsible for processing the DELETE event of a ClusterGroup resource.
func (n *NetworkPolicyController) deleteClusterGroup(oldObj interface{}) {
	og, ok := oldObj.(*corev1a2.ClusterGroup)
	klog.V(2).Infof("Processing DELETE event for ClusterGroup %s", og.Name)
	if !ok {
		tombstone, ok := oldObj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Error decoding object when deleting ClusterGroup, invalid type: %v", oldObj)
			return
		}
		og, ok = tombstone.Obj.(*corev1a2.ClusterGroup)
		if !ok {
			klog.Errorf("Error decoding object tombstone when deleting ClusterGroup, invalid type: %v", tombstone.Obj)
			return
		}
	}
	key := internalGroupKeyFunc(og)
	klog.V(2).Infof("Deleting internal Group %s", key)
	err := n.internalGroupStore.Delete(key)
	if err != nil {
		klog.Errorf("Unable to delete internal Group %s from store: %v", key, err)
	}
}

func (n *NetworkPolicyController) processClusterGroup(cg *corev1a2.ClusterGroup) *antreatypes.Group {
	internalGroup := antreatypes.Group{
		Name: cg.Name,
		UID:  cg.UID,
	}
	if cg.Spec.IPBlock != nil {
		ipb, _ := toAntreaIPBlockForCRD(cg.Spec.IPBlock)
		internalGroup.IPBlock = ipb
		return &internalGroup
	}
	groupSelector := toGroupSelector("", cg.Spec.PodSelector, cg.Spec.NamespaceSelector, nil)
	internalGroup.Selector = *groupSelector
	return &internalGroup
}

// filterInternalGroupsForPod computes a list of internal Group keys which match the Pod's labels.
func (n *NetworkPolicyController) filterInternalGroupsForPod(obj metav1.Object) sets.String {
	matchingKeySet := sets.String{}
	clusterScopedGroups, _ := n.internalGroupStore.GetByIndex(cache.NamespaceIndex, "")
	ns, _ := n.namespaceLister.Get(obj.GetNamespace())
	for _, group := range clusterScopedGroups {
		key, _ := store.GroupKeyFunc(group)
		g := group.(*antreatypes.Group)
		if n.labelsMatchGroupSelector(obj, ns, &g.Selector) {
			matchingKeySet.Insert(key)
			klog.V(2).Infof("%s/%s matched internal Group %s", obj.GetNamespace(), obj.GetName(), key)
		}
	}
	return matchingKeySet
}

// filterInternalGroupsForNamespace computes a list of internal Group keys which
// match the Namespace's labels.
func (n *NetworkPolicyController) filterInternalGroupsForNamespace(namespace *v1.Namespace) sets.String {
	matchingKeys := sets.String{}
	groups, _ := n.internalGroupStore.GetByIndex(cache.NamespaceIndex, "")
	for _, group := range groups {
		key, _ := store.GroupKeyFunc(group)
		g := group.(*antreatypes.Group)
		if g.Selector.NamespaceSelector != nil && g.Selector.NamespaceSelector.Matches(labels.Set(namespace.Labels)) {
			matchingKeys.Insert(key)
			klog.V(2).Infof("Namespace %s matched internal Group %s", namespace.Name, key)
		}
	}
	return matchingKeys
}

func (n *NetworkPolicyController) enqueueInternalGroup(key string) {
	klog.V(4).Infof("Adding new key %s to internal Group queue", key)
	n.internalGroupQueue.Add(key)
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

func (n *NetworkPolicyController) syncInternalGroup(key string) error {
	// Retrieve the internal Group corresponding to this key.
	grpObj, found, _ := n.internalGroupStore.Get(key)
	if !found {
		klog.V(2).Infof("Internal group %s not found.", key)
		return nil
	}
	grp := grpObj.(*antreatypes.Group)
	if grp.IPBlock == nil {
		// Find all Pods matching its selectors and update store.
		groupSelector := grp.Selector
		pods, _ := n.processSelector(groupSelector)
		memberSet := controlplane.GroupMemberSet{}
		for _, pod := range pods {
			if pod.Status.PodIP == "" {
				// No need to insert Pod IPAddress when it is unset.
				continue
			}
			memberSet.Insert(podToGroupMember(pod, true))
		}
		// Update the internal Group object in the store with the Pods as GroupMembers.
		updatedGrp := &antreatypes.Group{
			UID:          grp.UID,
			Name:         grp.Name,
			Selector:     grp.Selector,
			GroupMembers: memberSet,
		}
		klog.V(2).Infof("Updating existing internal Group %s with %d GroupMembers", key, len(memberSet))
		n.internalGroupStore.Update(updatedGrp)
	}
	// Retrieve the ClusterGroup corresponding to this key.
	cg, err := n.cgLister.Get(grp.Name)
	if err != nil {
		klog.Infof("Didn't find the ClusterGroup %s, skip processing of internal group", grp.Name)
		return nil
	}
	// Update the ClusterGroup status to Realized as Antrea has recognized the Group and
	// processed its group members.
	err = n.updateGroupStatus(cg, v1.ConditionTrue)
	if err != nil {
		klog.Errorf("Failed to update ClusterGroup %s GroupMembersComputed condition to %s: %v", cg.Name, v1.ConditionTrue, err)
		return err
	}
	return n.triggerCNPUpdates(cg)
}

// triggerCNPUpdates triggers processing of ClusterNetworkPolicies associated with the input ClusterGroup.
func (n *NetworkPolicyController) triggerCNPUpdates(cg *corev1a2.ClusterGroup) error {
	// If a ClusterGroup is added/updated, it might have a reference in ClusterNetworkPolicy.
	cnps, err := n.cnpInformer.Informer().GetIndexer().ByIndex(ClusterGroupIndex, cg.Name)
	if err != nil {
		klog.Errorf("Error retrieving ClusterNetworkPolicies corresponding to ClusterGroup %s", cg.Name)
		return err
	}
	for _, obj := range cnps {
		cnp := obj.(*secv1alpha1.ClusterNetworkPolicy)
		// Re-process ClusterNetworkPolicies which may be affected due to updates to CG.
		curInternalNP := n.processClusterNetworkPolicy(cnp)
		klog.V(2).Infof("Updating existing internal NetworkPolicy %s for %s", curInternalNP.Name, curInternalNP.SourceRef.ToString())
		key := internalNetworkPolicyKeyFunc(cnp)
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
		// Enqueue addressGroup keys to update their group members.
		for _, rule := range curInternalNP.Rules {
			for _, addrGroupName := range rule.From.AddressGroups {
				n.enqueueAddressGroup(addrGroupName)
			}
			for _, addrGroupName := range rule.To.AddressGroups {
				n.enqueueAddressGroup(addrGroupName)
			}
		}
		n.enqueueInternalNetworkPolicy(key)
		n.deleteDereferencedAddressGroups(oldInternalNP)
	}
	return nil
}

// updateGroupStatus updates the Status subresource for a ClusterGroup.
func (n *NetworkPolicyController) updateGroupStatus(cg *corev1a2.ClusterGroup, cStatus v1.ConditionStatus) error {
	condStatus := corev1a2.GroupCondition{
		Status: cStatus,
		Type:   corev1a2.GroupMembersComputed,
	}
	if groupMembersComputedConditionEqual(cg.Status.Conditions, condStatus) {
		// There is no change in conditions.
		return nil
	}
	condStatus.LastTransitionTime = metav1.Now()
	status := corev1a2.GroupStatus{
		Conditions: []corev1a2.GroupCondition{condStatus},
	}
	klog.V(4).Infof("Updating ClusterGroup %s status to %#v", cg.Name, condStatus)
	toUpdate := cg.DeepCopy()
	toUpdate.Status = status
	_, err := n.crdClient.CoreV1alpha2().ClusterGroups().UpdateStatus(context.TODO(), toUpdate, metav1.UpdateOptions{})
	return err
}

// groupMembersComputedConditionEqual checks whether the condition status for GroupMembersComputed condition
// is same. Returns true if equal, otherwise returns false. It disregards the lastTransitionTime field.
func groupMembersComputedConditionEqual(conds []corev1a2.GroupCondition, condition corev1a2.GroupCondition) bool {
	for _, c := range conds {
		if c.Type == corev1a2.GroupMembersComputed {
			if c.Status == condition.Status {
				return true
			}
		}
	}
	return false
}
