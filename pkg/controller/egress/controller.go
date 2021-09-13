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
	"errors"
	"fmt"
	"net"
	"reflect"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
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
	egressv1alpha2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	"antrea.io/antrea/pkg/apiserver/storage"
	clientset "antrea.io/antrea/pkg/client/clientset/versioned"
	egressinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha2"
	egresslisters "antrea.io/antrea/pkg/client/listers/crd/v1alpha2"
	"antrea.io/antrea/pkg/controller/grouping"
	"antrea.io/antrea/pkg/controller/metrics"
	antreatypes "antrea.io/antrea/pkg/controller/types"
	"antrea.io/antrea/pkg/ipam/ipallocator"
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

var (
	externalIPPoolNotFound = errors.New("ExternalIPPool not found")
)

// ipAllocation contains the IP and the IP Pool which allocates it.
type ipAllocation struct {
	ip     net.IP
	ipPool string
}

// EgressController is responsible for synchronizing the EgressGroups selected by Egresses.
type EgressController struct {
	crdClient                  clientset.Interface
	externalIPPoolLister       egresslisters.ExternalIPPoolLister
	externalIPPoolListerSynced cache.InformerSynced
	// ipAllocatorMap is a map from ExternalIPPool name to MultiIPAllocator.
	ipAllocatorMap   map[string]ipallocator.MultiIPAllocator
	ipAllocatorMutex sync.RWMutex

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
	// poolQueue maintains the ExternalIPPool objects that need to be synced.
	poolQueue workqueue.RateLimitingInterface
	// groupingInterface knows Pods that a given group selects.
	groupingInterface grouping.Interface
	// Added as a member to the struct to allow injection for testing.
	groupingInterfaceSynced func() bool
}

// NewEgressController returns a new *EgressController.
func NewEgressController(crdClient clientset.Interface,
	groupingInterface grouping.Interface,
	egressInformer egressinformers.EgressInformer,
	externalIPPoolInformer egressinformers.ExternalIPPoolInformer,
	egressGroupStore storage.Interface) *EgressController {
	c := &EgressController{
		crdClient:                  crdClient,
		egressInformer:             egressInformer,
		egressLister:               egressInformer.Lister(),
		egressListerSynced:         egressInformer.Informer().HasSynced,
		egressIndexer:              egressInformer.Informer().GetIndexer(),
		externalIPPoolLister:       externalIPPoolInformer.Lister(),
		externalIPPoolListerSynced: externalIPPoolInformer.Informer().HasSynced,
		egressGroupStore:           egressGroupStore,
		queue:                      workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "egress"),
		poolQueue:                  workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "externalIPPool"),
		groupingInterface:          groupingInterface,
		groupingInterfaceSynced:    groupingInterface.HasSynced,
		ipAllocatorMap:             map[string]ipallocator.MultiIPAllocator{},
		ipAllocationMap:            map[string]*ipAllocation{},
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
		egress, ok := obj.(*egressv1alpha2.Egress)
		if !ok {
			return nil, fmt.Errorf("obj is not Egress: %+v", obj)
		}
		if egress.Spec.ExternalIPPool == "" {
			return nil, nil
		}
		return []string{egress.Spec.ExternalIPPool}, nil
	}})
	externalIPPoolInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.addExternalIPPool,
			UpdateFunc: c.updateExternalIPPool,
			DeleteFunc: c.deleteExternalIPPool,
		},
		resyncPeriod,
	)
	return c
}

// Run begins watching and syncing of the EgressController.
func (c *EgressController) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()
	defer c.poolQueue.ShutDown()

	klog.Infof("Starting %s", controllerName)
	defer klog.Infof("Shutting down %s", controllerName)

	cacheSyncs := []cache.InformerSynced{c.egressListerSynced, c.externalIPPoolListerSynced, c.groupingInterfaceSynced}
	if !cache.WaitForNamedCacheSync(controllerName, stopCh, cacheSyncs...) {
		return
	}

	// Initialize the ipAllocatorMap and ipAllocationMap with the existing ExternalIPPools and Egresses.
	ipPools, _ := c.externalIPPoolLister.List(labels.Everything())
	for _, ipPool := range ipPools {
		c.createOrUpdateIPAllocator(ipPool)
	}
	egresses, _ := c.egressLister.List(labels.Everything())
	for _, egress := range egresses {
		c.updateIPAllocation(egress)
	}

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.egressGroupWorker, time.Second, stopCh)
		go wait.Until(c.externalIPPoolWorker, time.Second, stopCh)
	}
	<-stopCh
}

// updateIPAllocation sets the EgressIP of an Egress as allocated in the specified ExternalIPPool and records the
// allocation in ipAllocationMap.
func (c *EgressController) updateIPAllocation(egress *egressv1alpha2.Egress) {
	// Ignore Egress that is not associated to ExternalIPPool or doesn't have EgressIP assigned.
	if egress.Spec.ExternalIPPool == "" || egress.Spec.EgressIP == "" {
		return
	}
	ipAllocator, exists := c.getIPAllocator(egress.Spec.ExternalIPPool)
	if !exists {
		klog.ErrorS(externalIPPoolNotFound, "Failed to allocate EgressIP", "egress", egress.Name, "ip", egress.Spec.EgressIP, "pool", egress.Spec.ExternalIPPool)
		return
	}
	ip := net.ParseIP(egress.Spec.EgressIP)
	err := ipAllocator.AllocateIP(ip)
	if err != nil {
		klog.ErrorS(err, "Failed to allocate EgressIP", "egress", egress.Name, "ip", egress.Spec.EgressIP, "pool", egress.Spec.ExternalIPPool)
		return
	}
	// Record the valid IP allocation.
	c.setIPAllocation(egress.Name, ip, egress.Spec.ExternalIPPool)
	klog.InfoS("Allocated EgressIP", "egress", egress.Name, "ip", egress.Spec.EgressIP, "pool", egress.Spec.ExternalIPPool)
}

// createOrUpdateIPAllocator creates or updates the IP allocator based on the provided ExternalIPPool.
// Currently it's assumed that only new ranges will be added and existing ranges should not be deleted.
// TODO: Use validation webhook to ensure it.
func (c *EgressController) createOrUpdateIPAllocator(ipPool *egressv1alpha2.ExternalIPPool) bool {
	changed := false
	c.ipAllocatorMutex.Lock()
	defer c.ipAllocatorMutex.Unlock()

	existingIPRanges := sets.NewString()
	multiIPAllocator, exists := c.ipAllocatorMap[ipPool.Name]
	if !exists {
		multiIPAllocator = ipallocator.MultiIPAllocator{}
		changed = true
	} else {
		existingIPRanges.Insert(multiIPAllocator.Names()...)
	}

	for _, ipRange := range ipPool.Spec.IPRanges {
		ipRangeStr := ipRange.CIDR
		if ipRangeStr == "" {
			ipRangeStr = fmt.Sprintf("%s-%s", ipRange.Start, ipRange.End)
		}
		// The ipRange is already in the allocator.
		if existingIPRanges.Has(ipRangeStr) {
			continue
		}
		var ipAllocator *ipallocator.SingleIPAllocator
		var err error
		if ipRange.CIDR != "" {
			ipAllocator, err = ipallocator.NewCIDRAllocator(ipRange.CIDR)
		} else {
			ipAllocator, err = ipallocator.NewIPRangeAllocator(ipRange.Start, ipRange.End)
		}
		if err != nil {
			klog.ErrorS(err, "Failed to create IPAllocator", "ipRange", ipRange)
			continue
		}
		multiIPAllocator = append(multiIPAllocator, ipAllocator)
		changed = true
	}
	c.ipAllocatorMap[ipPool.Name] = multiIPAllocator
	c.poolQueue.Add(ipPool.Name)
	return changed
}

// deleteIPAllocator deletes the IP allocator of the given IP pool.
func (c *EgressController) deleteIPAllocator(ipPoolName string) {
	c.ipAllocatorMutex.Lock()
	defer c.ipAllocatorMutex.Unlock()
	delete(c.ipAllocatorMap, ipPoolName)
}

// getIPAllocator gets the IP allocator of the given IP pool.
func (c *EgressController) getIPAllocator(ipPoolName string) (ipallocator.MultiIPAllocator, bool) {
	c.ipAllocatorMutex.RLock()
	defer c.ipAllocatorMutex.RUnlock()
	ipAllocator, exists := c.ipAllocatorMap[ipPoolName]
	return ipAllocator, exists
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
		klog.Errorf("Failed to sync EgressGroup %s: %v", key, err)
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

func (c *EgressController) updateExternalIPPoolStatus(poolName string) error {
	eip, err := c.externalIPPoolLister.Get(poolName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}

	ipAllocator, exists := c.getIPAllocator(eip.Name)
	if !exists {
		return externalIPPoolNotFound
	}
	total, used := ipAllocator.Total(), ipAllocator.Used()
	toUpdate := eip.DeepCopy()
	var getErr error
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		actualStatus := eip.Status
		usage := egressv1alpha2.ExternalIPPoolUsage{Total: total, Used: used}
		if actualStatus.Usage == usage {
			return nil
		}
		klog.V(2).InfoS("Updating ExternalIPPool status", "ExternalIPPool", poolName, "usage", usage)
		toUpdate.Status.Usage = usage
		if _, updateErr := c.crdClient.CrdV1alpha2().ExternalIPPools().UpdateStatus(context.TODO(), toUpdate, metav1.UpdateOptions{}); updateErr != nil && apierrors.IsConflict(updateErr) {
			toUpdate, getErr = c.crdClient.CrdV1alpha2().ExternalIPPools().Get(context.TODO(), poolName, metav1.GetOptions{})
			if getErr != nil {
				return getErr
			}
			return updateErr
		}
		return nil
	}); err != nil {
		return fmt.Errorf("updating ExternalIPPool %s status error: %v", poolName, err)
	}
	klog.V(2).InfoS("Updated ExternalIPPool status", "ExternalIPPool", poolName)
	metrics.AntreaExternalIPPoolStatusUpdates.Inc()
	return nil
}

// syncEgressIP is responsible for releasing stale EgressIP and allocating new EgressIP for an Egress if applicable.
func (c *EgressController) syncEgressIP(egress *egressv1alpha2.Egress) (net.IP, error) {
	prevIP, prevIPPool, exists := c.getIPAllocation(egress.Name)
	if exists {
		_, ipAllocatorExists := c.getIPAllocator(prevIPPool)
		// The EgressIP and the ExternalIPPool don't change, do nothing.
		if prevIP.String() == egress.Spec.EgressIP && prevIPPool == egress.Spec.ExternalIPPool && ipAllocatorExists {
			return prevIP, nil
		}
		// Either EgressIP or ExternalIPPool changes, release the previous one first.
		c.releaseEgressIP(egress.Name, prevIP, prevIPPool)
	}

	// Skip allocating EgressIP if ExternalIPPool is not specified and return whatever user specifies.
	if egress.Spec.ExternalIPPool == "" {
		return net.ParseIP(egress.Spec.EgressIP), nil
	}

	ipAllocator, exists := c.getIPAllocator(egress.Spec.ExternalIPPool)
	if !exists {
		// The IP pool has been deleted, reclaim the IP from the Egress API.
		if egress.Spec.EgressIP != "" {
			if err := c.updateEgressIP(egress, ""); err != nil {
				return nil, err
			}
		}
		return nil, externalIPPoolNotFound
	}

	var ip net.IP
	// User specifies the Egress IP, try to allocate it. If it fails, the datapath may still work, we just don't track
	// the IP allocation so deleting this Egress won't release the IP to the Pool.
	// TODO: Use validation webhook to ensure the requested IP matches the pool.
	if egress.Spec.EgressIP != "" {
		ip = net.ParseIP(egress.Spec.EgressIP)
		if err := ipAllocator.AllocateIP(ip); err != nil {
			return nil, fmt.Errorf("error when allocating IP %v for Egress %s from ExternalIPPool %s: %v", ip, egress.Name, egress.Spec.ExternalIPPool, err)
		}
	} else {
		var err error
		// User doesn't specify the Egress IP, allocate one.
		if ip, err = ipAllocator.AllocateNext(); err != nil {
			return nil, err
		}
		if err = c.updateEgressIP(egress, ip.String()); err != nil {
			ipAllocator.Release(ip)
			return nil, err
		}
	}
	c.setIPAllocation(egress.Name, ip, egress.Spec.ExternalIPPool)
	c.poolQueue.Add(egress.Spec.ExternalIPPool)
	klog.InfoS("Allocated EgressIP", "egress", egress.Name, "ip", ip, "pool", egress.Spec.ExternalIPPool)
	return ip, nil
}

// updateEgressIP updates the Egress's EgressIP in Kubernetes API.
func (c *EgressController) updateEgressIP(egress *egressv1alpha2.Egress, ip string) error {
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
	if _, err := c.crdClient.CrdV1alpha2().Egresses().Patch(context.TODO(), egress.Name, types.MergePatchType, patchBytes, metav1.PatchOptions{}); err != nil {
		return fmt.Errorf("error when updating EgressIP for Egress %s: %v", egress.Name, err)
	}
	return nil
}

// releaseEgressIP removes the Egress's ipAllocation in the cache and releases the IP to the pool.
func (c *EgressController) releaseEgressIP(egressName string, egressIP net.IP, poolName string) {
	c.deleteIPAllocation(egressName)
	allocator, exists := c.getIPAllocator(poolName)
	if !exists {
		klog.ErrorS(externalIPPoolNotFound, "Failed to release EgressIP", "egress", egressName, "ip", egressIP, "pool", poolName)
		return
	}
	if err := allocator.Release(egressIP); err != nil {
		klog.ErrorS(err, "Failed to release EgressIP", "egress", egressName, "ip", egressIP, "pool", poolName)
		return
	}
	c.poolQueue.Add(poolName)
	klog.InfoS("Released EgressIP", "egress", egressName, "ip", egressIP, "pool", poolName)
}

func (c *EgressController) syncEgress(key string) error {
	startTime := time.Now()
	defer func() {
		d := time.Since(startTime)
		klog.V(2).Infof("Finished syncing Egress %s. (%v)", key, d)
	}()

	egress, err := c.egressLister.Get(key)
	if err != nil {
		// The Egress has been deleted, release its EgressIP if there was one.
		if prevIP, prevIPPool, exists := c.getIPAllocation(key); exists {
			c.releaseEgressIP(key, prevIP, prevIPPool)
		}
		return nil
	}

	if _, err := c.syncEgressIP(egress); err != nil {
		return err
	}

	egressGroupObj, found, _ := c.egressGroupStore.Get(key)
	if !found {
		klog.V(2).Infof("EgressGroup %s not found", key)
		return nil
	}

	nodeNames := sets.String{}
	podNum := 0
	memberSetByNode := make(map[string]controlplane.GroupMemberSet)
	egressGroup := egressGroupObj.(*antreatypes.EgressGroup)
	pods, _ := c.groupingInterface.GetEntities(egressGroupType, key)
	for _, pod := range pods {
		// Ignore Pod if it's not scheduled or not running. And Egress does not support HostNetwork Pods, so also ignore
		// Pod if it's HostNetwork Pod.
		// TODO: If a Pod is scheduled but not running, it can be included in the EgressGroup so that the agent can
		// install its SNAT rule right after the Pod's CNI request is processed, which just requires a notification from
		// CNIServer to the agent's EgressController. However the current notification mechanism (the entityUpdate
		// channel) allows only single consumer. Once it allows multiple consumers, we can change the condition to
		// include scheduled Pods that have no IPs.
		if pod.Spec.NodeName == "" || len(pod.Status.PodIPs) == 0 || pod.Spec.HostNetwork {
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
	klog.V(2).Infof("Updating existing EgressGroup %s with %d Pods on %d Nodes", key, podNum, nodeNames.Len())
	c.egressGroupStore.Update(updatedEgressGroup)
	return nil
}

func (c *EgressController) externalIPPoolWorker() {
	for c.processNextExternalIPPoolWorkItem() {
	}
}

func (c *EgressController) processNextExternalIPPoolWorkItem() bool {
	key, quit := c.poolQueue.Get()
	if quit {
		return false
	}
	defer c.poolQueue.Done(key)

	err := c.updateExternalIPPoolStatus(key.(string))
	if err != nil {
		// Put the item back in the workqueue to handle any transient errors.
		c.poolQueue.AddRateLimited(key)
		klog.ErrorS(err, "Failed to sync ExternalIPPool status", "ExternalIPPool", key)
		return true
	}
	// If no error occurs we Forget this item so it does not get queued again until
	// another change happens.
	c.poolQueue.Forget(key)
	return true
}

func (c *EgressController) enqueueEgressGroup(key string) {
	klog.V(4).Infof("Adding new key %s to EgressGroup queue", key)
	c.queue.Add(key)
}

// addEgress processes Egress ADD events and creates corresponding EgressGroup.
func (c *EgressController) addEgress(obj interface{}) {
	egress := obj.(*egressv1alpha2.Egress)
	klog.Infof("Processing Egress %s ADD event with selector (%s)", egress.Name, egress.Spec.AppliedTo)
	// Create an EgressGroup object corresponding to this Egress and enqueue task to the workqueue.
	egressGroup := &antreatypes.EgressGroup{
		Name: egress.Name,
		UID:  egress.UID,
	}
	c.egressGroupStore.Create(egressGroup)
	// Register the group to the grouping interface.
	groupSelector := antreatypes.NewGroupSelector("", egress.Spec.AppliedTo.PodSelector, egress.Spec.AppliedTo.NamespaceSelector, nil)
	c.groupingInterface.AddGroup(egressGroupType, egress.Name, groupSelector)
	c.queue.Add(egress.Name)
}

// updateEgress processes Egress UPDATE events and updates corresponding EgressGroup.
func (c *EgressController) updateEgress(old, cur interface{}) {
	oldEgress := old.(*egressv1alpha2.Egress)
	curEgress := cur.(*egressv1alpha2.Egress)
	klog.Infof("Processing Egress %s UPDATE event with selector (%s)", curEgress.Name, curEgress.Spec.AppliedTo)
	// TODO: Define custom Equal function to be more efficient.
	if !reflect.DeepEqual(oldEgress.Spec.AppliedTo, curEgress.Spec.AppliedTo) {
		// Update the group's selector in the grouping interface.
		groupSelector := antreatypes.NewGroupSelector("", curEgress.Spec.AppliedTo.PodSelector, curEgress.Spec.AppliedTo.NamespaceSelector, nil)
		c.groupingInterface.AddGroup(egressGroupType, curEgress.Name, groupSelector)
	}
	if oldEgress.GetGeneration() != curEgress.GetGeneration() {
		c.queue.Add(curEgress.Name)
	}
}

// deleteEgress processes Egress DELETE events and deletes corresponding EgressGroup.
func (c *EgressController) deleteEgress(obj interface{}) {
	egress := obj.(*egressv1alpha2.Egress)
	klog.Infof("Processing Egress %s DELETE event", egress.Name)
	c.egressGroupStore.Delete(egress.Name)
	// Unregister the group from the grouping interface.
	c.groupingInterface.DeleteGroup(egressGroupType, egress.Name)
	c.queue.Add(egress.Name)
}

// addExternalIPPool processes ExternalIPPool ADD events. It creates an IPAllocator for the pool and triggers
// reconciliation of Egresses that refer to the pool.
func (c *EgressController) addExternalIPPool(obj interface{}) {
	pool := obj.(*egressv1alpha2.ExternalIPPool)
	klog.InfoS("Processing ExternalIPPool ADD event", "pool", pool.Name, "ipRanges", pool.Spec.IPRanges)
	c.createOrUpdateIPAllocator(pool)
	c.enqueueEgresses(pool.Name)
}

// enqueueEgresses enqueues all Egresses that refer to the provided ExternalIPPool.
func (c *EgressController) enqueueEgresses(poolName string) {
	objects, _ := c.egressIndexer.ByIndex(externalIPPoolIndex, poolName)
	for _, object := range objects {
		egress := object.(*egressv1alpha2.Egress)
		c.queue.Add(egress.Name)
	}
}

// updateExternalIPPool processes ExternalIPPool UPDATE events. It updates the IPAllocator for the pool and triggers
// reconciliation of Egresses that refer to the pool if the IPAllocator changes.
func (c *EgressController) updateExternalIPPool(_, cur interface{}) {
	pool := cur.(*egressv1alpha2.ExternalIPPool)
	klog.InfoS("Processing ExternalIPPool UPDATE event", "pool", pool.Name, "ipRanges", pool.Spec.IPRanges)
	if c.createOrUpdateIPAllocator(pool) {
		c.enqueueEgresses(pool.Name)
	}
}

// deleteExternalIPPool processes ExternalIPPool DELETE events. It deletes the IPAllocator for the pool and triggers
// reconciliation of Egresses that refer to the pool.
func (c *EgressController) deleteExternalIPPool(obj interface{}) {
	pool := obj.(*egressv1alpha2.ExternalIPPool)
	klog.InfoS("Processing ExternalIPPool DELETE event", "pool", pool.Name, "ipRanges", pool.Spec.IPRanges)
	c.deleteIPAllocator(pool.Name)
	// Enqueue the Egresses to reclaim the IPs allocated from the pool.
	c.enqueueEgresses(pool.Name)
}
