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
	"slices"
	"sync"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"antrea.io/antrea/v2/pkg/apis/controlplane"
	egressv1beta2 "antrea.io/antrea/v2/pkg/apis/crd/v1beta2"
	"antrea.io/antrea/v2/pkg/apiserver/storage"
	clientset "antrea.io/antrea/v2/pkg/client/clientset/versioned"
	egressinformers "antrea.io/antrea/v2/pkg/client/informers/externalversions/crd/v1beta2"
	egresslisters "antrea.io/antrea/v2/pkg/client/listers/crd/v1beta2"
	"antrea.io/antrea/v2/pkg/controller/externalippool"
	"antrea.io/antrea/v2/pkg/controller/grouping"
	antreatypes "antrea.io/antrea/v2/pkg/controller/types"
	"antrea.io/antrea/v2/pkg/util/k8s"
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
	egressIPIndex       = "egressIP"
)

// ipAllocation records the reserved IPs and the Egress configuration for which they were reserved.
type ipAllocation struct {
	ips          []net.IP
	requestedIPs []net.IP
	ipPool       string
}

// EgressController is responsible for synchronizing the EgressGroups selected by Egresses.
type EgressController struct {
	crdClient clientset.Interface

	externalIPAllocator externalippool.ExternalIPAllocator

	// ipAllocationMap tracks Egress IP reservations and detects changes to the requested addresses.
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
	queue workqueue.TypedRateLimitingInterface[string]
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
		crdClient:          crdClient,
		egressInformer:     egressInformer,
		egressLister:       egressInformer.Lister(),
		egressListerSynced: egressInformer.Informer().HasSynced,
		egressIndexer:      egressInformer.Informer().GetIndexer(),
		egressGroupStore:   egressGroupStore,
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.NewTypedItemExponentialFailureRateLimiter[string](minRetryDelay, maxRetryDelay),
			workqueue.TypedRateLimitingQueueConfig[string]{
				Name: "egress",
			},
		),
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
	// Index by Pool for reconciliation and canonical IP for targeted overlap validation.
	egressInformer.Informer().AddIndexers(cache.Indexers{
		externalIPPoolIndex: func(obj interface{}) ([]string, error) {
			egress := obj.(*egressv1beta2.Egress)
			if egress.Spec.ExternalIPPool == "" {
				return nil, nil
			}
			return []string{egress.Spec.ExternalIPPool}, nil
		},
		egressIPIndex: func(obj interface{}) ([]string, error) {
			egress := obj.(*egressv1beta2.Egress)
			var ips []string
			for _, value := range egress.Spec.EgressIPs {
				if ip := net.ParseIP(value); ip != nil {
					ips = append(ips, ip.String())
				}
			}
			return ips, nil
		},
	})
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
func (c *EgressController) restoreIPAllocations(egresses []*egressv1beta2.Egress) {
	var previousIPAllocations []externalippool.IPAllocation
	requested := make(map[string][]net.IP)
	for _, egress := range egresses {
		if egress.Spec.ExternalIPPool == "" {
			continue
		}
		for _, egressIP := range egress.Spec.EgressIPs {
			ip := net.ParseIP(egressIP)
			requested[egress.Name] = append(requested[egress.Name], ip)
			previousIPAllocations = append(previousIPAllocations, externalippool.IPAllocation{
				ObjectReference: v1.ObjectReference{Name: egress.Name, Kind: egress.Kind},
				IPPoolName:      egress.Spec.ExternalIPPool,
				IP:              ip,
			})
		}
	}
	succeededAllocations := c.externalIPAllocator.RestoreIPAllocations(previousIPAllocations)
	restored := make(map[string][]net.IP)
	for _, alloc := range succeededAllocations {
		restored[alloc.ObjectReference.Name] = append(restored[alloc.ObjectReference.Name], alloc.IP)
	}
	for _, egress := range egresses {
		ips := restored[egress.Name]
		requestedIPs := requested[egress.Name]
		if len(requestedIPs) == 0 {
			continue
		}
		if len(ips) != len(requestedIPs) {
			c.releaseEgressIPs(egress.Name, ips, egress.Spec.ExternalIPPool)
			ips = nil
			klog.V(2).InfoS("Egress IP allocation restoration is incomplete", "egress", egress.Name, "pool", egress.Spec.ExternalIPPool)
		} else {
			klog.InfoS("Restored EgressIPs", "egress", egress.Name, "ips", ips, "pool", egress.Spec.ExternalIPPool)
		}
		// Retain the observed spec even if restoration failed, so reconciliation can distinguish stale
		// addresses after a restart from a new explicit request. Only ips contains owned reservations.
		c.setIPAllocation(egress.Name, &ipAllocation{ips: ips, requestedIPs: requestedIPs, ipPool: egress.Spec.ExternalIPPool})
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

	if err := c.syncEgress(key); err != nil {
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

func (c *EgressController) getIPAllocation(egressName string) (*ipAllocation, bool) {
	c.ipAllocationMutex.RLock()
	defer c.ipAllocationMutex.RUnlock()
	allocation, exists := c.ipAllocationMap[egressName]
	return allocation, exists
}

func (c *EgressController) deleteIPAllocation(egressName string) {
	c.ipAllocationMutex.Lock()
	defer c.ipAllocationMutex.Unlock()
	delete(c.ipAllocationMap, egressName)
}

func (c *EgressController) setIPAllocation(egressName string, allocation *ipAllocation) {
	c.ipAllocationMutex.Lock()
	defer c.ipAllocationMutex.Unlock()
	c.ipAllocationMap[egressName] = allocation
}

// syncEgressIP releases obsolete allocations and allocates all requested Egress IPs together.
func (c *EgressController) syncEgressIP(egress *egressv1beta2.Egress) ([]net.IP, *egressv1beta2.Egress, error) {
	var ips []net.IP
	for _, value := range egress.Spec.EgressIPs {
		ips = append(ips, net.ParseIP(value))
	}
	poolName := egress.Spec.ExternalIPPool
	if previous, exists := c.getIPAllocation(egress.Name); exists {
		if previous.ipPool == poolName && slices.EqualFunc(previous.requestedIPs, ips, net.IP.Equal) {
			valid := true
			for _, ip := range ips {
				if !c.externalIPAllocator.IPPoolHasIP(poolName, ip) {
					valid = false
					break
				}
			}
			if valid && len(previous.ips) == len(ips) {
				return previous.ips, egress, nil
			}
			if !valid {
				klog.InfoS("Allocated EgressIPs are no longer part of ExternalIPPool, releasing them", "egress", klog.KObj(egress), "ips", ips, "pool", poolName)
				updated, err := c.clearEgressIPs(egress, ips)
				if err != nil {
					return nil, egress, err
				}
				egress, ips = updated, nil
			}
		}
		c.releaseEgressIPs(egress.Name, previous.ips, previous.ipPool)
		c.deleteIPAllocation(egress.Name)
	}
	if poolName == "" {
		return ips, egress, nil
	}
	if !c.externalIPAllocator.IPPoolExists(poolName) {
		if len(ips) > 0 {
			updated, err := c.clearEgressIPs(egress, ips)
			if err != nil {
				return nil, egress, err
			}
			egress = updated
		}
		return nil, egress, fmt.Errorf("ExternalIPPool %s does not exist", poolName)
	}
	allocated, err := c.allocateEgressIPs(egress, ips)
	if err != nil {
		return nil, egress, err
	}
	if len(ips) == 0 {
		values := make([]string, 0, len(allocated))
		for _, ip := range allocated {
			values = append(values, ip.String())
		}
		updated, err := c.updateEgressIPs(egress, values)
		if err != nil {
			c.releaseEgressIPs(egress.Name, allocated, poolName)
			return nil, egress, err
		}
		egress = updated
	}
	c.setIPAllocation(egress.Name, &ipAllocation{ips: allocated, requestedIPs: allocated, ipPool: poolName})
	klog.InfoS("Allocated EgressIPs", "egress", egress.Name, "ips", allocated, "pool", poolName)
	return allocated, egress, nil
}

// allocateEgressIPs reserves the requested addresses, or allocates one for each requested family.
// If any reservation fails, all reservations made by this call are released.
func (c *EgressController) allocateEgressIPs(egress *egressv1beta2.Egress, ips []net.IP) ([]net.IP, error) {
	poolName := egress.Spec.ExternalIPPool
	var allocated []net.IP
	if len(ips) > 0 {
		for _, ip := range ips {
			if err := c.externalIPAllocator.UpdateIPAllocation(poolName, ip); err != nil {
				c.releaseEgressIPs(egress.Name, allocated, poolName)
				return nil, fmt.Errorf("error allocating IP %s for Egress %s from ExternalIPPool %s: %w", ip, egress.Name, poolName, err)
			}
			allocated = append(allocated, ip)
		}
		return allocated, nil
	}
	families := egress.Spec.IPFamilies
	if len(families) == 0 {
		// An omitted family preserves the default allocation behavior for existing Egresses.
		families = []v1.IPFamily{""}
	}
	for _, family := range families {
		var ip net.IP
		var err error
		if family == "" {
			ip, err = c.externalIPAllocator.AllocateIPFromPool(poolName)
		} else {
			ip, err = c.externalIPAllocator.AllocateIPFromPoolWithFamily(poolName, family)
		}
		if err != nil {
			c.releaseEgressIPs(egress.Name, allocated, poolName)
			return nil, fmt.Errorf("error allocating IP for Egress %s from ExternalIPPool %s: %w", egress.Name, poolName, err)
		}
		allocated = append(allocated, ip)
	}
	return allocated, nil
}

// clearEgressIPs preserves both families when removing obsolete dual-stack addresses, so retries and
// restarts do not fall back to single-stack allocation. Single-stack Egresses without IPFamilies
// retain their default allocation behavior when the pool's family changes.
func (c *EgressController) clearEgressIPs(egress *egressv1beta2.Egress, ips []net.IP) (*egressv1beta2.Egress, error) {
	if len(egress.Spec.IPFamilies) == 0 && len(ips) == 2 {
		egress = egress.DeepCopy()
		for _, ip := range ips {
			family := v1.IPv6Protocol
			if ip.To4() != nil {
				family = v1.IPv4Protocol
			}
			egress.Spec.IPFamilies = append(egress.Spec.IPFamilies, family)
		}
	}
	return c.updateEgressIPs(egress, nil)
}

// updateEgressIPs updates the Egress IP addresses without overwriting a concurrent Egress update.
func (c *EgressController) updateEgressIPs(egress *egressv1beta2.Egress, ips []string) (*egressv1beta2.Egress, error) {
	patch := map[string]interface{}{
		"metadata": map[string]interface{}{
			"resourceVersion": egress.ResourceVersion,
		},
		"spec": map[string]interface{}{
			"egressIPs":  ips,
			"ipFamilies": egress.Spec.IPFamilies,
		},
	}
	patchBytes, err := json.Marshal(patch)
	if err != nil {
		return nil, fmt.Errorf("error marshaling EgressIPs patch for Egress %s: %w", egress.Name, err)
	}
	updatedEgress, err := c.crdClient.CrdV1beta2().Egresses().Patch(context.TODO(), egress.Name, types.MergePatchType, patchBytes, metav1.PatchOptions{})
	if err != nil {
		return nil, fmt.Errorf("error updating EgressIPs for Egress %s: %w", egress.Name, err)
	}
	return updatedEgress, nil
}

// releaseEgressIPs releases allocations, including those made by an incomplete allocation or restoration.
func (c *EgressController) releaseEgressIPs(egressName string, ips []net.IP, poolName string) {
	for _, ip := range ips {
		if err := c.externalIPAllocator.ReleaseIP(poolName, ip); err != nil {
			if err == externalippool.ErrExternalIPPoolNotFound {
				klog.InfoS("Failed to release EgressIP because IP Pool does not exist", "egress", egressName, "ip", ip, "pool", poolName)
			} else {
				// ReleaseIP errors are non-transient: the Pool may have been recreated with different ranges.
				klog.ErrorS(err, "Failed to release EgressIP", "egress", egressName, "ip", ip, "pool", poolName)
			}
		} else {
			klog.InfoS("Released EgressIP", "egress", egressName, "ip", ip, "pool", poolName)
		}
	}
}

func requiresDualStackEgress(egress *egressv1beta2.Egress) bool {
	return len(egress.Spec.EgressIPs) == 2 || len(egress.Spec.IPFamilies) == 2
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
		if previous, exists := c.getIPAllocation(key); exists {
			c.releaseEgressIPs(key, previous.ips, previous.ipPool)
			c.deleteIPAllocation(key)
		}
		return nil
	}

	_, egress, err = c.syncEgressIP(egress)
	if !errors.IsConflict(err) {
		c.updateEgressAllocatedCondition(egress, err)
	}
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
		// Ignore Pod if it's not scheduled or is already terminated. And Egress does not support HostNetwork Pods, so also ignore
		// Pod if it's HostNetwork Pod.
		if pod.Spec.NodeName == "" || pod.Spec.HostNetwork || k8s.IsPodTerminated(pod) {
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
	egress := obj.(*egressv1beta2.Egress)
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
	oldEgress := old.(*egressv1beta2.Egress)
	curEgress := cur.(*egressv1beta2.Egress)
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
	egress, ok := obj.(*egressv1beta2.Egress)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.V(2).InfoS("Error decoding object when deleting Egress, invalid type", "object", obj)
			return
		}
		egress, ok = tombstone.Obj.(*egressv1beta2.Egress)
		if !ok {
			klog.V(2).InfoS("Error decoding object tombstone when deleting Egress, invalid type", "object", tombstone.Obj)
			return
		}
	}
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
		egress := object.(*egressv1beta2.Egress)
		c.queue.Add(egress.Name)
	}
}

func (c *EgressController) updateEgressAllocatedCondition(egress *egressv1beta2.Egress, err error) {
	var desiredCondition *metav1.Condition
	if egress.Spec.ExternalIPPool != "" {
		if err == nil {
			desiredCondition = &metav1.Condition{
				Type:               egressv1beta2.IPAllocated,
				Status:             metav1.ConditionTrue,
				Reason:             "Allocated",
				Message:            "EgressIPs are successfully allocated",
				LastTransitionTime: metav1.Now(),
			}
		} else {
			desiredCondition = &metav1.Condition{
				Type:               egressv1beta2.IPAllocated,
				Status:             metav1.ConditionFalse,
				Reason:             "AllocationError",
				Message:            fmt.Sprintf("Cannot allocate EgressIPs from ExternalIPPool: %v", err),
				LastTransitionTime: metav1.Now(),
			}
		}
	}
	c.setEgressAllocatedCondition(egress, desiredCondition)
}

func (c *EgressController) setEgressAllocatedCondition(
	egress *egressv1beta2.Egress,
	desiredCondition *metav1.Condition,
) {
	toUpdate := egress.DeepCopy()
	var updateErr, getErr error
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		actualCondition := meta.FindStatusCondition(toUpdate.Status.Conditions, egressv1beta2.IPAllocated)
		if compareConditionIgnoringTimestamp(actualCondition, desiredCondition) {
			return nil
		}
		var newConditions []metav1.Condition
		for _, c := range toUpdate.Status.Conditions {
			if c.Type != egressv1beta2.IPAllocated {
				newConditions = append(newConditions, c)
			}
		}
		if desiredCondition != nil {
			newConditions = append(newConditions, *desiredCondition)
		}
		toUpdate.Status.Conditions = newConditions
		_, updateErr = c.crdClient.CrdV1beta2().Egresses().UpdateStatus(context.TODO(), toUpdate, metav1.UpdateOptions{})
		if updateErr != nil && errors.IsConflict(updateErr) {
			if toUpdate, getErr = c.crdClient.CrdV1beta2().Egresses().Get(context.TODO(), egress.Name, metav1.GetOptions{}); getErr != nil {
				return getErr
			}
		}
		return updateErr
	}); err != nil {
		klog.ErrorS(err, "Error updating Egress Status")
	}
}

// compareConditionIgnoringTimestamp compares two conditions ignoring the timestamp
func compareConditionIgnoringTimestamp(condition1, condition2 *metav1.Condition) bool {
	if condition1 == nil && condition2 == nil {
		return true
	}
	if condition1 == nil || condition2 == nil {
		return false
	}
	return condition1.Message == condition2.Message && condition1.Reason == condition2.Reason && condition1.Status == condition2.Status
}
