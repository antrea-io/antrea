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
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/apis/controlplane"
	corev1a2 "github.com/vmware-tanzu/antrea/pkg/apis/core/v1alpha2"
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
	if newGroup.IPBlock == nil {
		n.enqueueInternalGroup(key)
	}
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
	if newGroup.IPBlock == nil {
		n.enqueueInternalGroup(key)
	}
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
		SourceRef: &antreatypes.GroupReference{
			Namespace: "",
			Name:      cg.Name,
		},
		UID: cg.UID,
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
		SourceRef:    grp.SourceRef,
		Selector:     grp.Selector,
		GroupMembers: memberSet,
	}
	klog.V(2).Infof("Updating existing internal Group %s with %d GroupMembers", key, len(memberSet))
	n.internalGroupStore.Update(updatedGrp)
	return nil
}
