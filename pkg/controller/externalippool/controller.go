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

package externalippool

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"

	antreacrds "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	clientset "antrea.io/antrea/pkg/client/clientset/versioned"
	antreainformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha2"
	antrealisters "antrea.io/antrea/pkg/client/listers/crd/v1alpha2"
	"antrea.io/antrea/pkg/controller/metrics"
	"antrea.io/antrea/pkg/ipam/ipallocator"
	iputil "antrea.io/antrea/pkg/util/ip"
)

const (
	controllerName = "ExternalIPPoolController"
	// Set resyncPeriod to 0 to disable resyncing.
	resyncPeriod time.Duration = 0
	// How long to wait before retrying the processing of an ExternalIPPool change.
	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second
	// Default number of workers processing an ExternalIPPool change.
	defaultWorkers = 4
)

var (
	ErrExternalIPPoolNotFound = errors.New("ExternalIPPool not found")
)

// IPAllocation contains the IP and the IP Pool which allocates it.
type IPAllocation struct {
	// ObjectReference is useful to track the owner of this IP allocation.
	ObjectReference corev1.ObjectReference
	// IPPoolName is the name of the IP pool.
	IPPoolName string
	// IP is the allocated IP.
	IP net.IP
}

// ExternalIPPoolEventHandler defines a consumer to subscribe for external ExternalIPPool events.
type ExternalIPPoolEventHandler func(externalIPPool string)

type ExternalIPAllocator interface {
	// AddEventHandler adds a consumer for ExternalIPPool events. It will block other consumers from allocating new IPs by
	// AllocateIPFromPool() until it calls RestoreIPAllocations().
	AddEventHandler(handler ExternalIPPoolEventHandler)
	// RestoreIPAllocations is used to restore the previous allocated IPs after controller restarts. It will return the
	// succeeded IP Allocations.
	RestoreIPAllocations(allocations []IPAllocation) []IPAllocation
	// AllocateIPFromPool allocates an IP from the given IP pool.
	AllocateIPFromPool(externalIPPool string) (net.IP, error)
	// IPPoolExists checks whether the IP pool exists.
	IPPoolExists(externalIPPool string) bool
	// IPPoolHasIP checks whether the IP pool contains the given IP.
	IPPoolHasIP(externalIPPool string, ip net.IP) bool
	// UpdateIPAllocation marks the IP in the specified ExternalIPPool as occupied.
	UpdateIPAllocation(externalIPPool string, ip net.IP) error
	// ReleaseIP releases the IP to the IP pool.
	ReleaseIP(externalIPPool string, ip net.IP) error
	// HasSynced indicates ExternalIPAllocator has finished syncing all ExternalIPPool resources.
	HasSynced() bool
}

var _ ExternalIPAllocator = (*ExternalIPPoolController)(nil)

// ExternalIPPoolController is responsible for synchronizing the ExternalIPPool resources.
type ExternalIPPoolController struct {
	crdClient                  clientset.Interface
	externalIPPoolLister       antrealisters.ExternalIPPoolLister
	externalIPPoolListerSynced cache.InformerSynced

	// ipAllocatorMap is a map from ExternalIPPool name to MultiIPAllocator.
	ipAllocatorMap   map[string]ipallocator.MultiIPAllocator
	ipAllocatorMutex sync.RWMutex

	// ipAllocatorInitialized stores a boolean value, which tracks if the ipAllocatorMap has been initialized
	// with the full list of ExternalIPPool.
	ipAllocatorInitialized *atomic.Value

	// handlers is an array of handlers will be notified when ExternalIPPool updates.
	handlers          []ExternalIPPoolEventHandler
	handlersWaitGroup sync.WaitGroup

	// queue maintains the ExternalIPPool objects that need to be synced.
	queue workqueue.RateLimitingInterface
}

// NewExternalIPPoolController returns a new *ExternalIPPoolController.
func NewExternalIPPoolController(crdClient clientset.Interface, externalIPPoolInformer antreainformers.ExternalIPPoolInformer) *ExternalIPPoolController {
	c := &ExternalIPPoolController{
		crdClient:                  crdClient,
		externalIPPoolLister:       externalIPPoolInformer.Lister(),
		externalIPPoolListerSynced: externalIPPoolInformer.Informer().HasSynced,
		queue:                      workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "externalIPPool"),
		ipAllocatorInitialized:     &atomic.Value{},
		ipAllocatorMap:             make(map[string]ipallocator.MultiIPAllocator),
	}
	externalIPPoolInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.addExternalIPPool,
			UpdateFunc: c.updateExternalIPPool,
			DeleteFunc: c.deleteExternalIPPool,
		},
		resyncPeriod,
	)
	c.ipAllocatorInitialized.Store(false)
	return c
}

func (c *ExternalIPPoolController) HasSynced() bool {
	return c.ipAllocatorInitialized.Load().(bool)
}

func (c *ExternalIPPoolController) AddEventHandler(handler ExternalIPPoolEventHandler) {
	c.handlers = append(c.handlers, handler)
	c.handlersWaitGroup.Add(1)
}

func (c *ExternalIPPoolController) RestoreIPAllocations(allocations []IPAllocation) []IPAllocation {
	var succeeded []IPAllocation
	for _, allocation := range allocations {
		if err := c.UpdateIPAllocation(allocation.IPPoolName, allocation.IP); err != nil {
			klog.ErrorS(err, "Failed to restore IP allocation", "ip", allocation.IP, "ipPool", allocation.IPPoolName)
		} else {
			succeeded = append(succeeded, allocation)
		}
	}
	c.handlersWaitGroup.Done()
	return succeeded
}

// Run begins watching and syncing of the ExternalIPPoolController.
func (c *ExternalIPPoolController) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	klog.Infof("Starting %s", controllerName)
	defer klog.Infof("Shutting down %s", controllerName)

	cacheSyncs := []cache.InformerSynced{c.externalIPPoolListerSynced}
	if !cache.WaitForNamedCacheSync(controllerName, stopCh, cacheSyncs...) {
		return
	}

	// Initialize the ipAllocatorMap with the existing ExternalIPPools.
	ipPools, _ := c.externalIPPoolLister.List(labels.Everything())
	for _, ipPool := range ipPools {
		c.createOrUpdateIPAllocator(ipPool)
	}

	c.ipAllocatorInitialized.Store(true)

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}
	<-stopCh
}

// createOrUpdateIPAllocator creates or updates the IP allocator based on the provided ExternalIPPool.
// Currently it's assumed that only new ranges will be added and existing ranges should not be deleted.
// TODO: Use validation webhook to ensure it.
func (c *ExternalIPPoolController) createOrUpdateIPAllocator(ipPool *antreacrds.ExternalIPPool) bool {
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
		ipAllocator, err := func() (*ipallocator.SingleIPAllocator, error) {
			if ipRange.CIDR != "" {
				_, ipNet, err := net.ParseCIDR(ipRange.CIDR)
				if err != nil {
					return nil, err
				}
				// Must use normalized IPNet string to check if the IP range exists. Otherwise non-strict CIDR like
				// 192.168.0.1/24 will be considered new even if it doesn't change.
				// Validating or normalizing the input CIDR should be a better solution but the externalIPPools that
				// have been created will still have this issue, so we just normalize the CIDR when using it.
				if existingIPRanges.Has(ipNet.String()) {
					return nil, nil
				}
				// Don't use the IPv4 network's broadcast address.
				var reservedIPs []net.IP
				if utilnet.IsIPv4CIDR(ipNet) {
					reservedIPs = append(reservedIPs, iputil.GetLocalBroadcastIP(ipNet))
				}
				return ipallocator.NewCIDRAllocator(ipNet, reservedIPs)
			} else {
				if existingIPRanges.Has(fmt.Sprintf("%s-%s", ipRange.Start, ipRange.End)) {
					return nil, nil
				}
				return ipallocator.NewIPRangeAllocator(net.ParseIP(ipRange.Start), net.ParseIP(ipRange.End))
			}
		}()
		if err != nil {
			klog.ErrorS(err, "Failed to create IPAllocator", "ipRange", ipRange)
			continue
		}
		// The IP range already exists in multiIPAllocator.
		if ipAllocator == nil {
			continue
		}
		multiIPAllocator = append(multiIPAllocator, ipAllocator)
		changed = true
	}
	c.ipAllocatorMap[ipPool.Name] = multiIPAllocator
	c.queue.Add(ipPool.Name)
	return changed
}

// deleteIPAllocator deletes the IP allocator of the given IP pool.
func (c *ExternalIPPoolController) deleteIPAllocator(poolName string) {
	c.ipAllocatorMutex.Lock()
	defer c.ipAllocatorMutex.Unlock()
	delete(c.ipAllocatorMap, poolName)
}

// getIPAllocator gets the IP allocator of the given IP pool.
func (c *ExternalIPPoolController) getIPAllocator(poolName string) (ipallocator.MultiIPAllocator, bool) {
	c.ipAllocatorMutex.RLock()
	defer c.ipAllocatorMutex.RUnlock()
	ipAllocator, exists := c.ipAllocatorMap[poolName]
	return ipAllocator, exists
}

// AllocateIPFromPool allocates an IP from the the given IP pool.
func (c *ExternalIPPoolController) AllocateIPFromPool(ipPoolName string) (net.IP, error) {
	c.handlersWaitGroup.Wait()
	ipAllocator, exists := c.getIPAllocator(ipPoolName)
	if !exists {
		return nil, ErrExternalIPPoolNotFound
	}
	ip, err := ipAllocator.AllocateNext()
	if err != nil {
		return ip, err
	}
	c.queue.Add(ipPoolName)
	return ip, nil
}

// UpdateIPAllocation sets the IP in the specified ExternalIPPool.
func (c *ExternalIPPoolController) UpdateIPAllocation(poolName string, ip net.IP) error {
	ipAllocator, exists := c.getIPAllocator(poolName)
	if !exists {
		return ErrExternalIPPoolNotFound
	}
	err := ipAllocator.AllocateIP(ip)
	if err != nil {
		return err
	}
	c.queue.Add(poolName)
	return nil
}

func (c *ExternalIPPoolController) updateExternalIPPoolStatus(poolName string) error {
	eip, err := c.externalIPPoolLister.Get(poolName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}
	ipAllocator, exists := c.getIPAllocator(eip.Name)
	if !exists {
		return ErrExternalIPPoolNotFound
	}
	total, used := ipAllocator.Total(), ipAllocator.Used()
	toUpdate := eip.DeepCopy()
	var getErr error
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		actualStatus := eip.Status
		usage := antreacrds.ExternalIPPoolUsage{Total: total, Used: used}
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

// ReleaseIP releases the IP to the pool.
func (c *ExternalIPPoolController) ReleaseIP(poolName string, ip net.IP) error {
	allocator, exists := c.getIPAllocator(poolName)
	if !exists {
		return ErrExternalIPPoolNotFound
	}
	if err := allocator.Release(ip); err != nil {
		return err
	}
	c.queue.Add(poolName)
	return nil
}

func (c *ExternalIPPoolController) IPPoolHasIP(poolName string, ip net.IP) bool {
	allocator, exists := c.getIPAllocator(poolName)
	if !exists {
		return false
	}
	return allocator.Has(ip)
}

func (c *ExternalIPPoolController) IPPoolExists(pool string) bool {
	_, exists := c.getIPAllocator(pool)
	return exists
}

func (c *ExternalIPPoolController) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *ExternalIPPoolController) processNextWorkItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	err := c.updateExternalIPPoolStatus(key.(string))
	if err != nil {
		// Put the item back in the workqueue to handle any transient errors.
		c.queue.AddRateLimited(key)
		klog.ErrorS(err, "Failed to sync ExternalIPPool status", "ExternalIPPool", key)
		return true
	}
	// If no error occurs we Forget this item so it does not get queued again until
	// another change happens.
	c.queue.Forget(key)
	return true
}

// addExternalIPPool processes ExternalIPPool ADD events. It creates an IPAllocator for the pool and triggers
// reconciliation of consumers that refer to the pool.
func (c *ExternalIPPoolController) addExternalIPPool(obj interface{}) {
	pool := obj.(*antreacrds.ExternalIPPool)
	klog.InfoS("Processing ExternalIPPool ADD event", "pool", pool.Name, "ipRanges", pool.Spec.IPRanges)
	c.createOrUpdateIPAllocator(pool)
	for _, h := range c.handlers {
		h(pool.Name)
	}
}

// updateExternalIPPool processes ExternalIPPool UPDATE events. It updates the IPAllocator for the pool and triggers
// reconciliation of consumers that refer to the pool if the IPAllocator changes.
func (c *ExternalIPPoolController) updateExternalIPPool(_, cur interface{}) {
	pool := cur.(*antreacrds.ExternalIPPool)
	klog.InfoS("Processing ExternalIPPool UPDATE event", "pool", pool.Name, "ipRanges", pool.Spec.IPRanges)
	if c.createOrUpdateIPAllocator(pool) {
		for _, h := range c.handlers {
			h(pool.Name)
		}
	}
}

// deleteExternalIPPool processes ExternalIPPool DELETE events. It deletes the IPAllocator for the pool and triggers
// reconciliation of all consumers that refer to the pool.
func (c *ExternalIPPoolController) deleteExternalIPPool(obj interface{}) {
	pool := obj.(*antreacrds.ExternalIPPool)
	klog.InfoS("Processing ExternalIPPool DELETE event", "pool", pool.Name, "ipRanges", pool.Spec.IPRanges)
	c.deleteIPAllocator(pool.Name)
	// Call consumers to reclaim the IPs allocated from the pool.
	for _, h := range c.handlers {
		h(pool.Name)
	}
}
