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

package egress

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"sync"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/apis/controlplane"
	egressv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/pkg/apiserver/storage"
	clientset "antrea.io/antrea/pkg/client/clientset/versioned"
	egressinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1beta1"
	egresslisters "antrea.io/antrea/pkg/client/listers/crd/v1beta1"
	"antrea.io/antrea/pkg/controller/externalippool"
	"antrea.io/antrea/pkg/controller/grouping"
	antreatypes "antrea.io/antrea/pkg/controller/types"
)

const (
	controllerName = "EgressController"
	// Set resyncPeriod to 0 to disable resyncing.
	resyncPeriod time.Duration = 0
	// How long to wait before retrying the processing of an Egress change.
	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second
	// Default number of workers processing an Egress change.
	defaultWorkers = 4
	// egressGroupType is the type used when registering EgressGroups to the grouping interface.
	egressGroupType grouping.GroupType = "egressGroup"

	externalIPPoolIndex = "externalIPPool"
)

// ipAllocation contains the IP and the IP Pool which allocates it.
type ipAllocation struct {
	ip     net.IP
	ipPool string
}

// EgressController is responsible for synchronizing the EgressGroups selected by Egresses.
type EgressController struct {
	crdClient clientset.Interface

	externalIPAllocator externalippool.ExternalIPAllocator

	// ipAllocationMap is a map from Egress name to ipAllocation, which is used to check whether the Egress's IP has
	// changed and to release the IP after the Egress is removed.
	ipAllocationMap   map[string]*ipAllocation
	ipAllocationMutex sync.RWMutex

	egressInformer egressinformers.EgressInformer
	egressLister   egresslisters.EgressLister
	egressIndexer  cache.Indexer
	// egressListerSynced is a function which returns true if the Egresses shared informer has been synced at least once.
	egressListerSynced cache.InformerSynced
	// egressGroupStore is the storage where the EgressGroups are stored.
	egressGroupStore storage.Interface
	// queue maintains the EgressGroup objects that need to be synced.
	queue workqueue.RateLimitingInterface
	// groupingInterface knows Pods that a given group selects.
	groupingInterface grouping.Interface
	// Added as a member to the struct to allow injection for testing.
	groupingInterfaceSynced func() bool
}

// NewEgressController returns a new *EgressController.
func NewEgressController(crdClient clientset.Interface,
	groupingInterface grouping.Interface,
	egressInformer egressinformers.EgressInformer,
	externalIPAllocator externalippool.ExternalIPAllocator,
	egressGroupStore storage.Interface) *EgressController {
	c := &EgressController{
		crdClient:               crdClient,
		egressInformer:          egressInformer,
		egressLister:            egressInformer.Lister(),
		egressListerSynced:      egressInformer.Informer().HasSynced,
		egressIndexer:           egressInformer.Informer().GetIndexer(),
		egressGroupStore:        egressGroupStore,
		queue:                   workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "egress"),
		groupingInterface:       groupingInterface,
		groupingInterfaceSynced: groupingInterface.HasSynced,
		ipAllocationMap:         map[string]*ipAllocation{},
		externalIPAllocator:     externalIPAllocator,
	}
	// Add handlers for Group events and Egress events.
	c.groupingInterface.AddEventHandler(egressGroupType, c.enqueueEgressGroup)
	egressInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.addEgress,
			UpdateFunc: c.updateEgress,
			DeleteFunc: c.deleteEgress,
		},
		resyncPeriod,
	)
	// externalIPPoolIndex will be used to get all Egresses associated with a given ExternalIPPool.
	egressInformer.Informer().AddIndexers(cache.Indexers{externalIPPoolIndex: func(obj interface{}) (strings []string, e error) {
		egress, ok := obj.(*egressv1beta1.Egress)
		if !ok {
			return nil, fmt.Errorf("obj is not Egress: %+v", obj)
		}
		var externalIPPools []string
		if egress.Spec.ExternalIPPool != "" {
			externalIPPools = append(externalIPPools, egress.Spec.ExternalIPPool)
		}
		for _, externalIPPool := range egress.Spec.ExternalIPPools {
			if externalIPPool != "" {
				externalIPPools = append(externalIPPools, externalIPPool)
			}
		}
		return externalIPPools, nil
	}})
	c.externalIPAllocator.AddEventHandler(func(ipPool string) {
		c.enqueueEgresses(ipPool)
	})
	return c
}

// Run begins watching and syncing of the EgressController.
func (c *EgressController) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	klog.InfoS("Starting", "controller", controllerName)
	defer klog.InfoS("Shutting down", "controller", controllerName)

	cacheSyncs := []cache.InformerSynced{c.egressListerSynced, c.groupingInterfaceSynced, c.externalIPAllocator.HasSynced}
	if !cache.WaitForNamedCacheSync(controllerName, stopCh, cacheSyncs...) {
		return
	}
	egresses, _ := c.egressLister.List(labels.Everything())
	c.restoreIPAllocations(egresses)
	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.egressGroupWorker, time.Second, stopCh)
	}
	<-stopCh
}

// restoreIPAllocations restores the existing EgressIPs of Egresses and records the successful ones in ipAllocationMap.
func (c *EgressController) restoreIPAllocations(egresses []*egressv1beta1.Egress) {
	var previousIPAllocations []externalippool.IPAllocation
	for _, egress := range egresses {
		// Ignore Egress that is not associated to ExternalIPPool or doesn't have EgressIP assigned.
		if egress.Spec.ExternalIPPool == "" || egress.Spec.EgressIP == "" {
			continue
		}
		ip := net.ParseIP(egress.Spec.EgressIP)
		allocation := externalippool.IPAllocation{
			ObjectReference: v1.ObjectReference{
				Name: egress.Name,
				Kind: egress.Kind,
			},
			IPPoolName: egress.Spec.ExternalIPPool,
			IP:         ip,
		}
		previousIPAllocations = append(previousIPAllocations, allocation)
	}
	succeededAllocations := c.externalIPAllocator.RestoreIPAllocations(previousIPAllocations)
	for _, alloc := range succeededAllocations {
		c.setIPAllocation(alloc.ObjectReference.Name, alloc.IP, alloc.IPPoolName)
		klog.InfoS("Restored EgressIP", "egress", alloc.ObjectReference.Name, "ip", alloc.IP, "pool", alloc.IPPoolName)
	}
}

func (c *EgressController) egressGroupWorker() {
	for c.processNextEgressGroupWorkItem() {
	}
}

func (c *EgressController) processNextEgressGroupWorkItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	err := c.syncEgress(key.(string))
	if err != nil {
		// Put the item back on the workqueue to handle any transient errors.
		c.queue.AddRateLimited(key)
		klog.ErrorS(err, "Failed to sync EgressGroup", "key", key)
		return true
	}
	// If no error occurs we Forget this item so it does not get queued again until
	// another change happens.
	c.queue.Forget(key)
	return true
}

func (c *EgressController) getIPAllocation(egressName string) (net.IP, string, bool) {
	c.ipAllocationMutex.RLock()
	defer c.ipAllocationMutex.RUnlock()
	allocation, exists := c.ipAllocationMap[egressName]
	if !exists {
		return nil, "", false
	}
	return allocation.ip, allocation.ipPool, true
}

func (c *EgressController) deleteIPAllocation(egressName string) {
	c.ipAllocationMutex.Lock()
	defer c.ipAllocationMutex.Unlock()
	delete(c.ipAllocationMap, egressName)
}

func (c *EgressController) setIPAllocation(egressName string, ip net.IP, poolName string) {
	c.ipAllocationMutex.Lock()
	defer c.ipAllocationMutex.Unlock()
	c.ipAllocationMap[egressName] = &ipAllocation{
		ip:     ip,
		ipPool: poolName,
	}
}

// syncEgressIP is responsible for releasing stale EgressIP and allocating new EgressIP for an Egress if applicable.
func (c *EgressController) syncEgressIP(egress *egressv1beta1.Egress) (net.IP, *egressv1beta1.Egress, error) {
	prevIP, prevIPPool, exists := c.getIPAllocation(egress.Name)
	if exists {
		// The EgressIP and the ExternalIPPool don't change, do nothing.
		if prevIP.String() == egress.Spec.EgressIP && prevIPPool == egress.Spec.ExternalIPPool && c.externalIPAllocator.IPPoolExists(egress.Spec.ExternalIPPool) {
			return prevIP, egress, nil
		}
		// Either EgressIP or ExternalIPPool changes, release the previous one first.
		if err := c.releaseEgressIP(egress.Name, prevIP, prevIPPool); err != nil {
			return nil, egress, err
		}
	}

	// Skip allocating EgressIP if ExternalIPPool is not specified and return whatever user specifies.
	if egress.Spec.ExternalIPPool == "" {
		return net.ParseIP(egress.Spec.EgressIP), egress, nil
	}

	if !c.externalIPAllocator.IPPoolExists(egress.Spec.ExternalIPPool) {
		// The IP pool has been deleted, reclaim the IP from the Egress API.
		if egress.Spec.EgressIP != "" {
			if updatedEgress, err := c.updateEgressIP(egress, ""); err != nil {
				return nil, egress, err
			} else {
				egress = updatedEgress
			}
		}
		return nil, egress, fmt.Errorf("ExternalIPPool %s does not exist", egress.Spec.ExternalIPPool)
	}

	var ip net.IP
	// User specifies the Egress IP, try to allocate it. If it fails, the datapath may still work, we just don't track
	// the IP allocation so deleting this Egress won't release the IP to the Pool.
	// TODO: Use validation webhook to ensure the requested IP matches the pool.
	if egress.Spec.EgressIP != "" {
		ip = net.ParseIP(egress.Spec.EgressIP)
		if err := c.externalIPAllocator.UpdateIPAllocation(egress.Spec.ExternalIPPool, ip); err != nil {
			return nil, egress, fmt.Errorf("error when allocating IP %v for Egress %s from ExternalIPPool %s: %v", ip, egress.Name, egress.Spec.ExternalIPPool, err)
		}
	} else {
		var err error
		// User doesn't specify the Egress IP, allocate one.
		if ip, err = c.externalIPAllocator.AllocateIPFromPool(egress.Spec.ExternalIPPool); err != nil {
			return nil, egress, err
		}
		if updatedEgress, err := c.updateEgressIP(egress, ip.String()); err != nil {
			if rerr := c.externalIPAllocator.ReleaseIP(egress.Spec.ExternalIPPool, ip); rerr != nil &&
				rerr != externalippool.ErrExternalIPPoolNotFound {
				klog.ErrorS(rerr, "Failed to release IP", "ip", ip, "pool", egress.Spec.ExternalIPPool)
			}
			return nil, egress, err
		} else {
			egress = updatedEgress
		}
	}
	c.setIPAllocation(egress.Name, ip, egress.Spec.ExternalIPPool)
	klog.InfoS("Allocated EgressIP", "egress", egress.Name, "ip", ip, "pool", egress.Spec.ExternalIPPool)
	return ip, egress, nil
}

// updateEgressIP updates the Egress's EgressIP in Kubernetes API.
func (c *EgressController) updateEgressIP(egress *egressv1beta1.Egress, ip string) (*egressv1beta1.Egress, error) {
	var egressIPPtr *string
	if len(ip) > 0 {
		egressIPPtr = &ip
	}
	patch := map[string]interface{}{
		"spec": map[string]*string{
			"egressIP": egressIPPtr,
		},
	}
	patchBytes, _ := json.Marshal(patch)
	if updatedEgress, err := c.crdClient.CrdV1beta1().Egresses().Patch(context.TODO(), egress.Name, types.MergePatchType, patchBytes, metav1.PatchOptions{}); err != nil {
		return nil, fmt.Errorf("error when updating EgressIP for Egress %s: %v", egress.Name, err)
	} else {
		return updatedEgress, nil
	}
}

// releaseEgressIP removes the Egress's ipAllocation in the cache and releases the IP to the pool.
func (c *EgressController) releaseEgressIP(egressName string, egressIP net.IP, poolName string) error {
	if err := c.externalIPAllocator.ReleaseIP(poolName, egressIP); err != nil {
		if err == externalippool.ErrExternalIPPoolNotFound {
			// Ignore the error since the external IP Pool could be deleted.
			klog.InfoS("Failed to release EgressIP because IP Pool does not exist", "egress", egressName, "ip", egressIP, "pool", poolName)
		} else {
			klog.ErrorS(err, "Failed to release IP", "ip", egressIP, "pool", poolName)
			return err
		}
	} else {
		klog.InfoS("Released EgressIP", "egress", egressName, "ip", egressIP, "pool", poolName)
	}
	c.deleteIPAllocation(egressName)
	return nil
}

func (c *EgressController) syncEgress(key string) error {
	startTime := time.Now()
	defer func() {
		d := time.Since(startTime)
		klog.V(2).InfoS("Finished syncing Egress", "egress", key, "duration", d)
	}()

	egress, err := c.egressLister.Get(key)
	if err != nil {
		// The Egress has been deleted, release its EgressIP if there was one.
		if prevIP, prevIPPool, exists := c.getIPAllocation(key); exists {
			c.releaseEgressIP(key, prevIP, prevIPPool)
		}
		return nil
	}

	_, egress, err = c.syncEgressIP(egress)
	c.updateEgressAllocatedCondition(egress, err)
	if err != nil {
		return err
	}

	egressGroupObj, found, _ := c.egressGroupStore.Get(key)
	if !found {
		klog.V(2).InfoS("EgressGroup %s not found", "name", key)
		return nil
	}

	nodeNames := sets.Set[string]{}
	podNum := 0
	memberSetByNode := make(map[string]controlplane.GroupMemberSet)
	egressGroup := egressGroupObj.(*antreatypes.EgressGroup)
	pods, _ := c.groupingInterface.GetEntities(egressGroupType, key)
	for _, pod := range pods {
		// Ignore Pod if it's not scheduled or not running. And Egress does not support HostNetwork Pods, so also ignore
		// Pod if it's HostNetwork Pod.
		if pod.Spec.NodeName == "" || pod.Spec.HostNetwork {
			continue
		}
		podNum++
		podSet := memberSetByNode[pod.Spec.NodeName]
		if podSet == nil {
			podSet = controlplane.GroupMemberSet{}
			memberSetByNode[pod.Spec.NodeName] = podSet
		}
		groupMember := &controlplane.GroupMember{
			Pod: &controlplane.PodReference{
				Name:      pod.Name,
				Namespace: pod.Namespace,
			},
		}
		podSet.Insert(groupMember)
		// Update the NodeNames in order to set the SpanMeta for EgressGroup.
		nodeNames.Insert(pod.Spec.NodeName)
	}
	updatedEgressGroup := &antreatypes.EgressGroup{
		UID:               egressGroup.UID,
		Name:              egressGroup.Name,
		GroupMemberByNode: memberSetByNode,
		SpanMeta:          antreatypes.SpanMeta{NodeNames: nodeNames},
	}
	klog.V(2).InfoS("Updating existing EgressGroup", "name", key, "podNum", podNum, "nodeNum", nodeNames.Len())
	c.egressGroupStore.Update(updatedEgressGroup)
	return nil
}

func (c *EgressController) enqueueEgressGroup(key string) {
	klog.V(4).InfoS("Adding new key to EgressGroup queue", "key", key)
	c.queue.Add(key)
}

// addEgress processes Egress ADD events and creates corresponding EgressGroup.
func (c *EgressController) addEgress(obj interface{}) {
	egress := obj.(*egressv1beta1.Egress)
	klog.InfoS("Processing Egress ADD event", "egress", egress.Name, "selector", egress.Spec.AppliedTo)
	// Create an EgressGroup object corresponding to this Egress and enqueue task to the workqueue.
	egressGroup := &antreatypes.EgressGroup{
		Name: egress.Name,
		UID:  egress.UID,
	}
	c.egressGroupStore.Create(egressGroup)
	// Register the group to the grouping interface.
	groupSelector := antreatypes.NewGroupSelector("", egress.Spec.AppliedTo.PodSelector, egress.Spec.AppliedTo.NamespaceSelector, nil, nil)
	c.groupingInterface.AddGroup(egressGroupType, egress.Name, groupSelector)
	c.queue.Add(egress.Name)
}

// updateEgress processes Egress UPDATE events and updates corresponding EgressGroup.
func (c *EgressController) updateEgress(old, cur interface{}) {
	oldEgress := old.(*egressv1beta1.Egress)
	curEgress := cur.(*egressv1beta1.Egress)
	klog.InfoS("Processing Egress UPDATE event", "egress", curEgress.Name, "selector", curEgress.Spec.AppliedTo)
	// TODO: Define custom Equal function to be more efficient.
	if !reflect.DeepEqual(oldEgress.Spec.AppliedTo, curEgress.Spec.AppliedTo) {
		// Update the group's selector in the grouping interface.
		groupSelector := antreatypes.NewGroupSelector("", curEgress.Spec.AppliedTo.PodSelector, curEgress.Spec.AppliedTo.NamespaceSelector, nil, nil)
		c.groupingInterface.AddGroup(egressGroupType, curEgress.Name, groupSelector)
	}
	if oldEgress.GetGeneration() != curEgress.GetGeneration() {
		c.queue.Add(curEgress.Name)
	}
}

// deleteEgress processes Egress DELETE events and deletes corresponding EgressGroup.
func (c *EgressController) deleteEgress(obj interface{}) {
	egress := obj.(*egressv1beta1.Egress)
	klog.InfoS("Processing Egress DELETE event", "egress", egress.Name)
	c.egressGroupStore.Delete(egress.Name)
	// Unregister the group from the grouping interface.
	c.groupingInterface.DeleteGroup(egressGroupType, egress.Name)
	c.queue.Add(egress.Name)
}

// enqueueEgresses enqueues all Egresses that refer to the provided ExternalIPPool.
func (c *EgressController) enqueueEgresses(poolName string) {
	objects, _ := c.egressIndexer.ByIndex(externalIPPoolIndex, poolName)
	for _, object := range objects {
		egress := object.(*egressv1beta1.Egress)
		c.queue.Add(egress.Name)
	}
}

func (c *EgressController) updateEgressAllocatedCondition(egress *egressv1beta1.Egress, err error) {
	var desiredCondition *egressv1beta1.EgressCondition
	if egress.Spec.ExternalIPPool != "" {
		if err == nil {
			desiredCondition = &egressv1beta1.EgressCondition{
				Type:               egressv1beta1.IPAllocated,
				Status:             v1.ConditionTrue,
				Reason:             "Allocated",
				Message:            "EgressIP is successfully allocated",
				LastTransitionTime: metav1.Now(),
			}
		} else {
			desiredCondition = &egressv1beta1.EgressCondition{
				Type:               egressv1beta1.IPAllocated,
				Status:             v1.ConditionFalse,
				Reason:             "AllocationError",
				Message:            fmt.Sprintf("Cannot allocate EgressIP from ExternalIPPool: %v", err),
				LastTransitionTime: metav1.Now(),
			}
		}
	}

	toUpdate := egress.DeepCopy()
	var updateErr, getErr error
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		actualCondition := egressv1beta1.GetEgressCondition(toUpdate.Status.Conditions, egressv1beta1.IPAllocated)
		if compareConditionIgnoringTimestamp(actualCondition, desiredCondition) {
			return nil
		}
		var newConditions []egressv1beta1.EgressCondition
		for _, c := range toUpdate.Status.Conditions {
			if c.Type != egressv1beta1.IPAllocated {
				newConditions = append(newConditions, c)
			}
		}
		if desiredCondition != nil {
			newConditions = append(newConditions, *desiredCondition)
		}
		toUpdate.Status.Conditions = newConditions
		_, updateErr = c.crdClient.CrdV1beta1().Egresses().UpdateStatus(context.TODO(), toUpdate, metav1.UpdateOptions{})
		if updateErr != nil && errors.IsConflict(updateErr) {
			if toUpdate, getErr = c.crdClient.CrdV1beta1().Egresses().Get(context.TODO(), egress.Name, metav1.GetOptions{}); getErr != nil {
				return getErr
			}
		}
		return updateErr
	}); err != nil {
		klog.ErrorS(err, "Error updating Egress Status")
	}
}

// compareConditionIgnoringTimestamp compares two conditions ignoring the timestamp
func compareConditionIgnoringTimestamp(condition1, condition2 *egressv1beta1.EgressCondition) bool {
	if condition1 == nil && condition2 == nil {
		return true
	}
	if condition1 == nil || condition2 == nil {
		return false
	}
	return condition1.Message == condition2.Message && condition1.Reason == condition2.Reason && condition1.Status == condition2.Status
}
