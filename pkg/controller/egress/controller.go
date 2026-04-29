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

	"antrea.io/antrea/v2/pkg/apis/controlplane"
	egressv1beta1 "antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/v2/pkg/apiserver/storage"
	clientset "antrea.io/antrea/v2/pkg/client/clientset/versioned"
	egressinformers "antrea.io/antrea/v2/pkg/client/informers/externalversions/crd/v1beta1"
	egresslisters "antrea.io/antrea/v2/pkg/client/listers/crd/v1beta1"
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

	// effectiveDualStackCount is the number of IPs (one IPv4 + one IPv6) that the current
	// implementation actually realizes on the datapath for a dual-stack Egress.
	effectiveDualStackCount = 2
)

// ipAllocation contains the IP and the IP Pool which allocates it.
type ipAllocation struct {
	ip     net.IP
	ipPool string
}

// multipleIPAllocation tracks all IP allocations for an Egress.
// Each entry corresponds positionally to EgressIPs[i] / ExternalIPPools[i].
type multipleIPAllocation struct {
	allocs []*ipAllocation
}

// EgressController is responsible for synchronizing the EgressGroups selected by Egresses.
type EgressController struct {
	crdClient clientset.Interface

	externalIPAllocator externalippool.ExternalIPAllocator

	// ipAllocationMap is a map from Egress name to ipAllocation, which is used to check whether the Egress's IP has
	// changed and to release the IP after the Egress is removed. It supports both single-IP and multiple-IP(dual-stack) Egresses.
	ipAllocationMap   map[string]*multipleIPAllocation
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
		ipAllocationMap:         map[string]*multipleIPAllocation{},
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

func (c *EgressController) getPoolToIPMapping(egress *egressv1beta1.Egress) map[string]string {
	mapping := make(map[string]string)

	if egress.Spec.ExternalIPPool != "" {
		mapping[egress.Spec.ExternalIPPool] = egress.Spec.EgressIP
		return mapping
	}

	pools := egress.Spec.ExternalIPPools
	if len(pools) > effectiveDualStackCount {
		pools = pools[:effectiveDualStackCount]
	}
	for i, pool := range pools {
		if i >= len(egress.Spec.EgressIPs) {
			break
		}
		mapping[pool] = egress.Spec.EgressIPs[i]
	}
	return mapping
}

// restoreIPAllocations restores the existing EgressIPs of Egresses and records the successful ones in ipAllocationMap.
func (c *EgressController) restoreIPAllocations(egresses []*egressv1beta1.Egress) {
	var previousIPAllocations []externalippool.IPAllocation
	egressByName := make(map[string]*egressv1beta1.Egress, len(egresses))
	for _, egress := range egresses {
		egressByName[egress.Name] = egress
		poolToIPs := c.getPoolToIPMapping(egress)

		for pool, ipStr := range poolToIPs {
			// Ignore Egress that is not associated to ExternalIPPool or doesn't have EgressIP assigned.
			if ipStr == "" {
				continue
			}
			ip := net.ParseIP(ipStr)
			allocation := externalippool.IPAllocation{
				ObjectReference: v1.ObjectReference{
					Name: egress.Name,
					Kind: egress.Kind,
				},
				IPPoolName: pool,
				IP:         ip,
			}
			previousIPAllocations = append(previousIPAllocations, allocation)
		}
	}
	succeededAllocations := c.externalIPAllocator.RestoreIPAllocations(previousIPAllocations)
	for _, alloc := range succeededAllocations {
		egressName := alloc.ObjectReference.Name
		egress, exists := egressByName[egressName]
		if !exists {
			klog.InfoS("Failed to find Egress in restore input, skipping", "egress", egressName)
			continue
		}

		effectivePools := egress.Spec.ExternalIPPools
		if egress.Spec.ExternalIPPool != "" {
			effectivePools = []string{egress.Spec.ExternalIPPool}
		}
		if len(effectivePools) > effectiveDualStackCount {
			effectivePools = effectivePools[:effectiveDualStackCount]
		}

		existing, _ := c.getIPAllocation(egressName)
		if existing == nil {
			existing = &multipleIPAllocation{
				allocs: make([]*ipAllocation, len(effectivePools)),
			}
		}
		a := c.newIPAllocation(alloc.IP, alloc.IPPoolName)
		for idx, pool := range effectivePools {
			if pool == alloc.IPPoolName {
				existing.allocs[idx] = a
				break
			}
		}
		c.setIPAllocation(egressName, existing)
		klog.InfoS("Restored EgressIP", "egress", egressName, "ip", alloc.IP, "pool", alloc.IPPoolName)
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

func (c *EgressController) getIPAllocation(egressName string) (*multipleIPAllocation, bool) {
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

func (c *EgressController) setIPAllocation(egressName string, alloc *multipleIPAllocation) {
	c.ipAllocationMutex.Lock()
	defer c.ipAllocationMutex.Unlock()
	c.ipAllocationMap[egressName] = alloc
}

func (c *EgressController) newIPAllocation(ip net.IP, poolName string) *ipAllocation {
	return &ipAllocation{
		ip:     ip,
		ipPool: poolName,
	}
}

func (c *EgressController) releaseEgressIPs(egressName string, alloc *multipleIPAllocation) {
	for _, a := range alloc.allocs {
		if a != nil {
			c.releaseEgressIP(egressName, a.ip, a.ipPool)
		}
	}
	c.deleteIPAllocation(egressName)
}

func (c *EgressController) updateEgressIPs(egress *egressv1beta1.Egress, ips []string) (*egressv1beta1.Egress, error) {
	patch := map[string]interface{}{
		"spec": map[string]interface{}{
			"egressIPs": ips,
		},
	}
	patchBytes, err := json.Marshal(patch)
	if err != nil {
		return nil, fmt.Errorf("error when marshaling EgressIPs patch for Egress %s: %w", egress.Name, err)
	}
	var updatedEgress *egressv1beta1.Egress
	if updatedEgress, err = c.crdClient.CrdV1beta1().Egresses().Patch(context.TODO(), egress.Name, types.MergePatchType, patchBytes, metav1.PatchOptions{}); err != nil {
		return nil, fmt.Errorf("error when updating EgressIPs for Egress %s: %w", egress.Name, err)
	}
	return updatedEgress, nil
}

func (c *EgressController) ipAllocationsValid(pools, specIPs []string, alloc *multipleIPAllocation) bool {
	if len(pools) != len(alloc.allocs) {
		return false
	}

	for i, poolName := range pools {
		if !c.externalIPAllocator.IPPoolExists(poolName) {
			return false
		}

		prevAlloc := alloc.allocs[i]
		if prevAlloc == nil || prevAlloc.ipPool != poolName {
			return false
		}

		if !c.externalIPAllocator.IPPoolHasIP(poolName, prevAlloc.ip) {
			return false
		}

		if i < len(specIPs) && specIPs[i] != "" {
			if prevAlloc.ip.String() != specIPs[i] {
				return false
			}
		}
	}
	return true
}

func (c *EgressController) syncEgressIPs(egress *egressv1beta1.Egress) ([]net.IP, *egressv1beta1.Egress, error) {
	var effectivePools []string
	var effectiveSpecIPs []string

	if egress.Spec.ExternalIPPool != "" {
		// Single-stack with ExternalIPPool
		effectivePools = []string{egress.Spec.ExternalIPPool}
		if egress.Spec.EgressIP != "" {
			effectiveSpecIPs = []string{egress.Spec.EgressIP}
		}
	} else if egress.Spec.EgressIP != "" {
		// Single-stack IP-Only mode: user specifies EgressIP directly without pool
		effectivePools = []string{}
		effectiveSpecIPs = []string{egress.Spec.EgressIP}
	} else {
		effectivePools = egress.Spec.ExternalIPPools
		effectiveSpecIPs = egress.Spec.EgressIPs

		// Validate: if EgressIPs is specified but ExternalIPPools is empty,
		// this is egress IP-Only mode.
		// However, if EgressIPs is specified but ExternalIPPools is NOT empty,
		// we need len(EgressIPs) == len(ExternalIPPools) to avoid index out of bounds.
		if len(effectivePools) > 0 && len(effectiveSpecIPs) > 0 && len(effectiveSpecIPs) != len(effectivePools) {
			klog.ErrorS(nil, "Mismatched EgressIPs and ExternalIPPools", "egress", klog.KObj(egress), "ipsCount", len(effectiveSpecIPs), "poolsCount", len(effectivePools))
			return nil, egress, fmt.Errorf("invalid Egress configuration: %d EgressIPs specified but only %d ExternalIPPools provided", len(effectiveSpecIPs), len(effectivePools))
		}
	}

	// Limit to effectiveDualStackCount for now (can support more in the future)
	if len(effectivePools) > effectiveDualStackCount {
		effectivePools = effectivePools[:effectiveDualStackCount]
	}
	if len(effectiveSpecIPs) > effectiveDualStackCount {
		effectiveSpecIPs = effectiveSpecIPs[:effectiveDualStackCount]
	}

	prevAlloc, exists := c.getIPAllocation(egress.Name)

	if exists {
		if c.ipAllocationsValid(effectivePools, effectiveSpecIPs, prevAlloc) {
			var ips []net.IP
			for _, a := range prevAlloc.allocs {
				if a != nil {
					ips = append(ips, a.ip)
				}
			}
			return ips, egress, nil
		}

		// If transitioning to IP-Only mode (no pools), just release previous allocations
		if len(effectivePools) == 0 {
			c.releaseEgressIPs(egress.Name, prevAlloc)
			// Return the user-provided IPs for IP-Only mode
			var ips []net.IP
			for _, ipStr := range effectiveSpecIPs {
				if ipStr != "" {
					ips = append(ips, net.ParseIP(ipStr))
				}
			}
			return ips, egress, nil
		}

		poolsMatch := len(effectivePools) == len(prevAlloc.allocs)
		if poolsMatch {
			for i, poolName := range effectivePools {
				if prevAlloc.allocs[i] == nil || prevAlloc.allocs[i].ipPool != poolName {
					poolsMatch = false
					break
				}
				if i < len(effectiveSpecIPs) && effectiveSpecIPs[i] != "" {
					if prevAlloc.allocs[i].ip.String() != effectiveSpecIPs[i] {
						poolsMatch = false
						break
					}
				}
			}
		}
		if poolsMatch {
			klog.InfoS("Allocated EgressIPs are no longer valid for ExternalIPPools, releasing them", "egress", klog.KObj(egress))
			c.releaseEgressIPs(egress.Name, prevAlloc)
			// Clear the effectiveSpecIPs to trigger re-allocation
			effectiveSpecIPs = nil
		} else {
			// If pools changed, release IPs immediately as they're no longer valid
			c.releaseEgressIPs(egress.Name, prevAlloc)
		}
	}

	// Support IP-Only mode: if no pools are specified, just return the user-provided IPs
	// without attempting to allocate or track them
	if len(effectivePools) == 0 {
		var ips []net.IP
		for _, ipStr := range effectiveSpecIPs {
			if ipStr != "" {
				ips = append(ips, net.ParseIP(ipStr))
			}
		}
		return ips, egress, nil
	}

	for _, poolName := range effectivePools {
		if !c.externalIPAllocator.IPPoolExists(poolName) {
			// The IP pool has been deleted, reclaim the IP from the Egress.
			if len(effectiveSpecIPs) > 0 {
				if egress.Spec.ExternalIPPool != "" {
					if updatedEgress, err := c.updateEgressIP(egress, ""); err != nil {
						return nil, egress, err
					} else {
						egress = updatedEgress
					}
				} else {
					if updatedEgress, err := c.updateEgressIPs(egress, nil); err != nil {
						return nil, egress, err
					} else {
						egress = updatedEgress
					}
				}
			}
			return nil, egress, fmt.Errorf("ExternalIPPool %s does not exist", poolName)
		}
	}

	var allocs []*ipAllocation
	newAlloc := &multipleIPAllocation{}
	var allocatedIPs []net.IP

	if len(effectiveSpecIPs) > 0 {
		for i, ipStr := range effectiveSpecIPs {
			// Boundary check: ensure the pool index exists
			if i >= len(effectivePools) {
				return nil, egress, fmt.Errorf("invalid Egress configuration: EgressIP index %d out of range for ExternalIPPools (length %d)", i, len(effectivePools))
			}
			ip := net.ParseIP(ipStr)
			if err := c.externalIPAllocator.UpdateIPAllocation(effectivePools[i], ip); err != nil {
				for j := 0; j < i; j++ {
					c.externalIPAllocator.ReleaseIP(effectivePools[j], allocatedIPs[j])
				}
				return nil, egress, err
			}
			allocs = append(allocs, c.newIPAllocation(ip, effectivePools[i]))
			allocatedIPs = append(allocatedIPs, ip)
		}
	} else {
		for i, poolName := range effectivePools {
			ip, err := c.externalIPAllocator.AllocateIPFromPool(poolName)
			if err != nil {
				// Rollback: release all previously allocated IPs in this batch
				for j := 0; j < i; j++ {
					c.externalIPAllocator.ReleaseIP(effectivePools[j], allocatedIPs[j])
				}
				return nil, egress, err
			}
			allocatedIPs = append(allocatedIPs, ip)
			allocs = append(allocs, c.newIPAllocation(ip, poolName))
		}

		// Update the Egress with allocated IPs
		ipStrs := make([]string, len(allocatedIPs))
		for i, ip := range allocatedIPs {
			ipStrs[i] = ip.String()
		}

		if egress.Spec.ExternalIPPool != "" {
			// Single ExternalIPPool case: update EgressIP field
			if updatedEgress, err := c.updateEgressIP(egress, ipStrs[0]); err != nil {
				// Rollback: release all allocated IPs
				for i, ip := range allocatedIPs {
					if rerr := c.externalIPAllocator.ReleaseIP(effectivePools[i], ip); rerr != nil {
						klog.ErrorS(rerr, "Failed to release IP during rollback", "ip", ip, "pool", effectivePools[i])
					}
				}
				return nil, egress, err
			} else {
				egress = updatedEgress
			}
		} else {
			// Multiple ExternalIPPools case: update EgressIPs field
			if updatedEgress, err := c.updateEgressIPs(egress, ipStrs); err != nil {
				// Rollback: release all allocated IPs
				for i, ip := range allocatedIPs {
					if rerr := c.externalIPAllocator.ReleaseIP(effectivePools[i], ip); rerr != nil {
						klog.ErrorS(rerr, "Failed to release IP during rollback", "ip", ip, "pool", effectivePools[i])
					}
				}
				return nil, egress, err
			} else {
				egress = updatedEgress
			}
		}
	}

	newAlloc.allocs = allocs

	c.setIPAllocation(egress.Name, newAlloc)
	klog.InfoS("Allocated EgressIPs", "egress", egress.Name, "ips", allocatedIPs)
	return allocatedIPs, egress, nil
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
	patchBytes, err := json.Marshal(patch)
	if err != nil {
		return nil, fmt.Errorf("error when marshaling EgressIPs patch for Egress %s: %v", egress.Name, err)
	}
	if updatedEgress, err := c.crdClient.CrdV1beta1().Egresses().Patch(context.TODO(), egress.Name, types.MergePatchType, patchBytes, metav1.PatchOptions{}); err != nil {
		return nil, fmt.Errorf("error when updating EgressIP for Egress %s: %v", egress.Name, err)
	} else {
		return updatedEgress, nil
	}
}

// releaseEgressIP removes the Egress's ipAllocation in the cache and releases the IP to the pool.
func (c *EgressController) releaseEgressIP(egressName string, egressIP net.IP, poolName string) {
	if err := c.externalIPAllocator.ReleaseIP(poolName, egressIP); err != nil {
		if err == externalippool.ErrExternalIPPoolNotFound {
			// Ignore the error since the external IP Pool could be deleted.
			klog.InfoS("Failed to release EgressIP because IP Pool does not exist", "egress", egressName, "ip", egressIP, "pool", poolName)
		} else {
			// It is possible for the external IP Pool to have been deleted and
			// recreated immediately with a different range, which would trigger this
			// case. Transient errors in ReleaseIP are not possible, so there is no
			// point in retrying. We should still delete our own state by calling
			// deleteIPAllocation.
			klog.ErrorS(err, "Failed to release IP", "ip", egressIP, "pool", poolName)
		}
	} else {
		klog.InfoS("Released EgressIP", "egress", egressName, "ip", egressIP, "pool", poolName)
	}
	c.deleteIPAllocation(egressName)
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
		if prevAlloc, exists := c.getIPAllocation(key); exists {
			c.releaseEgressIPs(key, prevAlloc)
		}
		return nil
	}

	_, egress, err = c.syncEgressIPs(egress)
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
	egress, ok := obj.(*egressv1beta1.Egress)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.V(2).InfoS("Error decoding object when deleting Egress, invalid type", "object", obj)
			return
		}
		egress, ok = tombstone.Obj.(*egressv1beta1.Egress)
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
		egress := object.(*egressv1beta1.Egress)
		c.queue.Add(egress.Name)
	}
}

func (c *EgressController) updateEgressAllocatedCondition(egress *egressv1beta1.Egress, err error) {
	var desiredCondition *egressv1beta1.EgressCondition
	if egress.Spec.ExternalIPPool != "" || len(egress.Spec.ExternalIPPools) > 0 {
		msg := "EgressIP is successfully allocated"
		if err == nil {
			desiredCondition = &egressv1beta1.EgressCondition{
				Type:               egressv1beta1.IPAllocated,
				Status:             v1.ConditionTrue,
				Reason:             "Allocated",
				Message:            msg,
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
