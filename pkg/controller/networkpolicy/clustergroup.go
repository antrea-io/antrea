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

// Package group provides ClusterGroupController implementation to manage
// and synchronize the GroupMembers and Namespaces affected by selectors in a
// ClusterGroup.

package networkpolicy

import (
	"github.com/vmware-tanzu/antrea/pkg/apis/controlplane"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"

	corev1a2 "github.com/vmware-tanzu/antrea/pkg/apis/core/v1alpha2"
	antreatypes "github.com/vmware-tanzu/antrea/pkg/controller/types"
)

// addCG is responsible to process the ADD event of a ClusterGroup resource.
func (n *NetworkPolicyController) addCG(curObj interface{}) {
	cg := curObj.(*corev1a2.ClusterGroup)
	klog.V(2).Infof("Processing ADD event for ClusterGroup %s", cg.Name)
	newGroup := n.processClusterGroup(cg)
	// Get or create a Group for the generated UID.
	// Ignoring returned error (here and elsewhere in this file) as with the
	// current store implementation, no error is ever returned.
	_, found, _ := n.groupStore.Get(newGroup.Name)
	if found {
		klog.V(4).Infof("Found existing internal group %s with same selectors while processing ADD event of ClusterGroup %s", newGroup.Name, cg.Name)
		return
	}
	klog.V(2).Infof("Creating new internal Group %s with selector (%s)", newGroup.Name, newGroup.Selector.NormalizedName)
	n.groupStore.Create(newGroup)
	if newGroup.IPBlock != nil {
		return
	}
	n.enqueueGroup(newGroup.Name)
}

// updateCG is responsible to process the UPDATE event of a ClusterGroup resource.
func (n *NetworkPolicyController) updateCG(oldObj, curObj interface{}) {
	cg := curObj.(*corev1a2.ClusterGroup)
	og := oldObj.(*corev1a2.ClusterGroup)
	klog.V(2).Infof("Processing UPDATE event for ClusterGroup %s", cg.Name)
	newGroup := n.processClusterGroup(cg)
	oldGroup := n.processClusterGroup(og)
	if newGroup.Name == oldGroup.Name {
		// No change in the selectors of the ClusterGroup. No need to enqueue for further sync.
		return
	}
	// Get or create a Group for the generated UID of current ClusterGroup.
	_, found, _ := n.groupStore.Get(newGroup.Name)
	if !found {
		// If internal Group is not found corresponding to changes in selectors, create a new Group and enqueue it to
		// sync its members.
		klog.V(2).Infof("Creating new internal Group %s with selector (%s)", newGroup.Name, newGroup.Selector.NormalizedName)
		n.groupStore.Create(newGroup)
		if newGroup.IPBlock == nil {
			n.enqueueGroup(newGroup.Name)
		}
	}
	// Delete old internal Group if it is no longer referenced by any other ClusterGroups.
	n.deleteDereferencedInternalGroup(oldGroup.Name)
}

// deleteCG is responsible to process the DELETE event of a ClusterGroup resource.
func (n *NetworkPolicyController) deleteCG(oldObj interface{}) {
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
	gUID := getNormalizedUID(toGroupSelector("", og.Spec.PodSelector, og.Spec.NamespaceSelector, nil).NormalizedName)
	oldInternalGroupObj, _, _ := n.groupStore.Get(gUID)
	oldInternalGroup := oldInternalGroupObj.(*antreatypes.Group)
	klog.Infof("Deleting internal Group %s for %s", oldInternalGroup.Name, oldInternalGroup.SourceRef.ToString())
	n.deleteDereferencedInternalGroup(gUID)
}

func (n *NetworkPolicyController) processClusterGroup(cg *corev1a2.ClusterGroup) *antreatypes.Group {
	var gUID string
	internalGroup := antreatypes.Group{
		SourceRef: &antreatypes.GroupReference{
			Type:      antreatypes.ClusterGroup,
			Namespace: "",
			Name:      cg.Name,
			UID:       cg.UID,
		},
	}
	if cg.Spec.IPBlock != nil {
		ipb, _ := toAntreaIPBlockForCRD(cg.Spec.IPBlock)
		internalGroup.Name = string(cg.UID)
		internalGroup.UID = cg.UID
		internalGroup.IPBlock = ipb
		return &internalGroup
	}
	groupSelector := toGroupSelector("", cg.Spec.PodSelector, cg.Spec.NamespaceSelector, nil)
	// Generate the UID based on the normalized name of the Group
	gUID = getNormalizedUID(groupSelector.NormalizedName)
	// Construct a new Group and populate fields.
	internalGroup.UID = types.UID(gUID)
	internalGroup.Name = gUID
	internalGroup.Selector = *groupSelector
	return &internalGroup
}

// deleteDereferencedInternalGroup checks whether an internal Group has a reference to an existing ClusterGroup before
// deleting the internal Group from store.
func (n *NetworkPolicyController) deleteDereferencedInternalGroup(key string) {
	// Get all ClusterGroup objects that refers the internal Group.
	cgs, err := n.cgInformer.Informer().GetIndexer().ByIndex("internalGroup", key)
	if err != nil {
		klog.Errorf("Unable to filter ClusterGroups for internal Group %s: %v", key, err)
		return
	}
	if len(cgs) == 0 {
		// No ClusterGroup refers to this internal Group. Safe to delete.
		klog.V(2).Infof("Deleting unreferenced internal Group %s", key)
		err := n.groupStore.Delete(key)
		if err != nil {
			klog.Errorf("Unable to delete internal Group %s from store: %v", key, err)
		}
	}
}

// filterGroupsForPod computes a list of Group keys which match the Pod's labels.
func (n *NetworkPolicyController) filterGroupsForPod(obj metav1.Object) sets.String {
	matchingKeySet := sets.String{}
	clusterScopedGroups, _ := n.groupStore.GetByIndex(cache.NamespaceIndex, "")
	ns, _ := n.namespaceLister.Get(obj.GetNamespace())
	for _, group := range clusterScopedGroups {
		g := group.(*antreatypes.Group)
		if n.labelsMatchGroupSelector(obj, ns, &g.Selector) {
			matchingKeySet.Insert(g.Name)
			klog.V(2).Infof("%s/%s matched Group %s", obj.GetNamespace(), obj.GetName(), g.Name)
		}
	}
	return matchingKeySet
}

// filterGroupsForNamespace computes a list of Group keys which
// match the Namespace's labels.
func (n *NetworkPolicyController) filterGroupsForNamespace(namespace *v1.Namespace) sets.String {
	matchingKeys := sets.String{}
	// Only cluster scoped groups or AddressGroups created by CNP can possibly select this Namespace.
	groups, _ := n.groupStore.GetByIndex(cache.NamespaceIndex, "")
	for _, group := range groups {
		g := group.(*antreatypes.Group)
		// Group created by CNP might not have NamespaceSelector.
		if g.Selector.NamespaceSelector != nil && g.Selector.NamespaceSelector.Matches(labels.Set(namespace.Labels)) {
			matchingKeys.Insert(g.Name)
			klog.V(2).Infof("Namespace %s matched Group %s", namespace.Name, g.Name)
		}
	}
	return matchingKeys
}

func (n *NetworkPolicyController) enqueueGroup(key string) {
	klog.V(4).Infof("Adding new key %s to Group queue", key)
	n.groupQueue.Add(key)
}

func (c *NetworkPolicyController) groupWorker() {
	for c.processNextGroupWorkItem() {
	}
}

// Processes an item in the "group" work queue, by calling
// syncGroup after casting the item to a string (Group key).
// If syncGroup returns an error, this function handles it by re-queueing
// the item so that it can be processed again later. If syncGroup is
// successful, the ClusterGroup is removed from the queue until we get notify
// of a new change. This function return false if and only if the work queue
// was shutdown (no more items will be processed).
func (c *NetworkPolicyController) processNextGroupWorkItem() bool {
	key, quit := c.groupQueue.Get()
	if quit {
		return false
	}
	defer c.groupQueue.Done(key)

	err := c.syncGroup(key.(string))
	if err != nil {
		// Put the item back on the workqueue to handle any transient errors.
		c.groupQueue.AddRateLimited(key)
		klog.Errorf("Failed to sync ClusterGroup %s: %v", key, err)
		return true
	}
	// If no error occurs we Forget this item so it does not get queued again until
	// another change happens.
	c.groupQueue.Forget(key)
	return true
}

func (n *NetworkPolicyController) syncGroup(key string) error {
	// Retrieve the internal Group corresponding to this key.
	grpObj, found, _ := n.groupStore.Get(key)
	if !found {
		klog.V(2).Info("Group %s not found.", key)
		return nil
	}

	grp := grpObj.(*antreatypes.Group)
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
	// Update the Group object in the store with the Pods as GroupMembers.
	updatedGrp := &antreatypes.Group{
		Name:         grp.Name,
		UID:          grp.UID,
		SourceRef:    grp.SourceRef,
		Selector:     grp.Selector,
		GroupMembers: memberSet,
	}
	klog.V(2).Infof("Updating existing Group %s with %d GroupMembers", key, len(memberSet))
	n.groupStore.Update(updatedGrp)
	return nil
}
