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

package serviceexternalip

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apimachineryerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	apimachinerytypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	antreaagenttypes "antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/controller/externalippool"
)

const (
	controllerName = "ExternalIPController"
	// Set resyncPeriod to 0 to disable resyncing.
	resyncPeriod time.Duration = 0
	// How long to wait before retrying the processing of an Service change.
	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second
	// Default number of workers processing an Service change.
	defaultWorkers = 4

	// externalIPPoolIndex is an index of serviceInformer.
	externalIPPoolIndex = "externalIPPool"
	// ipIndex is an index of ipAllocations.
	ipIndex = "ip"
)

// ipAllocation contains the IP and the IP Pool which allocates it.
type ipAllocation struct {
	service  apimachinerytypes.NamespacedName
	ip       net.IP
	ipPool   string
	sharable bool
}

// ServiceExternalIPController is responsible for synchronizing the Services that need external IPs.
type ServiceExternalIPController struct {
	externalIPAllocator externalippool.ExternalIPAllocator
	client              clientset.Interface

	// ipAllocations caches the IP and the IP Pool which allocates it for each Service.
	ipAllocations     cache.Indexer
	ipAllocationMutex sync.RWMutex

	serviceInformer     cache.SharedIndexInformer
	serviceLister       corelisters.ServiceLister
	serviceListerSynced cache.InformerSynced
	// queue maintains the Service objects that need to be synced.
	queue workqueue.TypedRateLimitingInterface[apimachinerytypes.NamespacedName]
}

func NewServiceExternalIPController(
	client clientset.Interface,
	serviceInformer coreinformers.ServiceInformer,
	externalIPAllocator externalippool.ExternalIPAllocator,
) *ServiceExternalIPController {
	c := &ServiceExternalIPController{
		client: client,
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.NewTypedItemExponentialFailureRateLimiter[apimachinerytypes.NamespacedName](minRetryDelay, maxRetryDelay),
			workqueue.TypedRateLimitingQueueConfig[apimachinerytypes.NamespacedName]{
				Name: "serviceExternalIP",
			},
		),
		serviceInformer:     serviceInformer.Informer(),
		serviceLister:       serviceInformer.Lister(),
		serviceListerSynced: serviceInformer.Informer().HasSynced,
		externalIPAllocator: externalIPAllocator,
		ipAllocations: cache.NewIndexer(func(obj interface{}) (string, error) {
			return obj.(*ipAllocation).service.String(), nil
		}, cache.Indexers{
			ipIndex: func(obj interface{}) ([]string, error) {
				return []string{obj.(*ipAllocation).ip.String()}, nil
			},
		}),
	}

	c.serviceInformer.AddIndexers(cache.Indexers{
		externalIPPoolIndex: func(obj interface{}) ([]string, error) {
			service, ok := obj.(*corev1.Service)
			if !ok {
				return nil, fmt.Errorf("obj is not Service: %+v", obj)
			}
			eipName := getServiceExternalIPPool(service)
			if eipName == "" {
				return nil, nil
			}
			return []string{eipName}, nil
		},
	})

	c.serviceInformer.AddEventHandlerWithResyncPeriod(
		cache.FilteringResourceEventHandler{
			FilterFunc: func(obj interface{}) bool {
				svc, ok := obj.(*corev1.Service)
				if ok {
					return getServiceExternalIPPool(svc) != ""
				}
				if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
					if cast, ok := tombstone.Obj.(*corev1.Service); ok {
						return getServiceExternalIPPool(cast) != ""
					}
				}
				return false
			},
			Handler: cache.ResourceEventHandlerFuncs{
				AddFunc: c.enqueueService,
				UpdateFunc: func(_, obj interface{}) {
					c.enqueueService(obj)
				},
				DeleteFunc: c.enqueueService,
			},
		},
		resyncPeriod,
	)

	c.externalIPAllocator.AddEventHandler(c.enqueueServicesByExternalIPPool)
	return c
}

func (c *ServiceExternalIPController) enqueueService(obj interface{}) {
	service, ok := obj.(*corev1.Service)
	if !ok {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Received unexpected object: %v", obj)
			return
		}
		service, ok = deletedState.Obj.(*corev1.Service)
		if !ok {
			klog.Errorf("DeletedFinalStateUnknown contains non-Service object: %v", deletedState.Obj)
			return
		}
	}
	namespacedName := apimachinerytypes.NamespacedName{
		Namespace: service.Namespace,
		Name:      service.Name,
	}
	c.queue.Add(namespacedName)
}

// enqueueServicesByExternalIPPool enqueues all Services that refer to the provided ExternalIPPool.
// The ExternalIPPool is affected by a Node update/create/delete event or ExternalIPPool changes.
func (c *ServiceExternalIPController) enqueueServicesByExternalIPPool(eipName string) {
	objects, _ := c.serviceInformer.GetIndexer().ByIndex(externalIPPoolIndex, eipName)
	for _, object := range objects {
		c.enqueueService(object)
	}
	klog.InfoS("Detected ExternalIPPool event", "ExternalIPPool", eipName)
}

// enqueueServicesWithoutIPs enqueues all Services that refer to the provided ExternalIPPool and have empty
// LoadBalancerIP in LoadBalancerStatus.
func (c *ServiceExternalIPController) enqueueServicesWithoutIPs(eipName string) {
	objects, _ := c.serviceInformer.GetIndexer().ByIndex(externalIPPoolIndex, eipName)
	for _, object := range objects {
		if getServiceExternalIP(object.(*corev1.Service)) == "" {
			c.enqueueService(object)
		}
	}
}

// Run will create defaultWorkers workers (go routines) which will process the Service events from the
// workqueue.
func (c *ServiceExternalIPController) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	klog.Infof("Starting %s", controllerName)
	defer klog.Infof("Shutting down %s", controllerName)

	if !cache.WaitForNamedCacheSync(controllerName, stopCh, c.serviceListerSynced, c.externalIPAllocator.HasSynced) {
		return
	}

	svcs, _ := c.serviceLister.List(labels.Everything())
	c.restoreIPAllocations(svcs)

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}
	<-stopCh
}

// restoreIPAllocations restores the existing external IPs of Services and records the successful ones in ipAllocations.
func (c *ServiceExternalIPController) restoreIPAllocations(services []*corev1.Service) {
	// requestedIPAllocations contains IPAllocations we are going to request based on the Service statuses.
	var requestedIPAllocations []externalippool.IPAllocation
	// knownIPsByPool is used to deduplicate IPAllocations.
	knownIPsByPool := map[string]sets.Set[string]{}
	// eligibleServices contains Services which had a LoadBalancerIP assigned previously.
	var eligibleServices []*corev1.Service
	for _, svc := range services {
		ipPool := getServiceExternalIPPool(svc)
		ip := getServiceExternalIP(svc)
		if svc.Spec.Type != corev1.ServiceTypeLoadBalancer || ipPool == "" || ip == "" {
			continue
		}
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			continue
		}

		eligibleServices = append(eligibleServices, svc)
		if _, exists := knownIPsByPool[ipPool]; !exists {
			knownIPsByPool[ipPool] = sets.New[string]()
		}
		// Another Service already tried to restore the IP allocation, and restoring an IP more than once will fail for
		// sure. Therefore, we use a set to ensure we restore each IP once. If the IP is restored successfully, all
		// Services that had it assigned can continue using it.
		if knownIPsByPool[ipPool].Has(ip) {
			continue
		}
		knownIPsByPool[ipPool].Insert(ip)
		// We don't set ObjectReference here as it might be shared between multiple Services.
		allocation := externalippool.IPAllocation{
			IPPoolName: ipPool,
			IP:         parsedIP,
		}
		requestedIPAllocations = append(requestedIPAllocations, allocation)
	}

	succeededAllocations := c.externalIPAllocator.RestoreIPAllocations(requestedIPAllocations)
	// Convert the succeeded IPAllocations for ease of querying.
	succeededIPsByPool := map[string]sets.Set[string]{}
	for _, allocation := range succeededAllocations {
		if _, exists := succeededIPsByPool[allocation.IPPoolName]; !exists {
			succeededIPsByPool[allocation.IPPoolName] = sets.New[string]()
		}
		succeededIPsByPool[allocation.IPPoolName].Insert(allocation.IP.String())
	}

	c.ipAllocationMutex.Lock()
	defer c.ipAllocationMutex.Unlock()
	for _, svc := range eligibleServices {
		ipPool := getServiceExternalIPPool(svc)
		ip := getServiceExternalIP(svc)
		if succeededIPsByPool[ipPool].Has(ip) {
			name := apimachinerytypes.NamespacedName{
				Namespace: svc.Namespace,
				Name:      svc.Name,
			}
			c.addIPAllocationLocked(name, ipPool, net.ParseIP(ip), isServiceExternalIPSharable(svc))
		}
		klog.InfoS("Restored external IP", "service", klog.KObj(svc), "ip", ip, "pool", ipPool)
	}
}

func (c *ServiceExternalIPController) updateIPAllocation(name apimachinerytypes.NamespacedName, ipPool string, ip net.IP, sharable bool) {
	c.ipAllocationMutex.Lock()
	defer c.ipAllocationMutex.Unlock()
	newAllocation := &ipAllocation{
		service:  name,
		ip:       ip,
		ipPool:   ipPool,
		sharable: sharable,
	}
	oldObj, exists, _ := c.ipAllocations.Get(newAllocation)
	c.ipAllocations.Update(newAllocation)
	// Update other Services if the Service changes from unsharable to sharable.
	if sharable && exists && !oldObj.(*ipAllocation).sharable {
		c.enqueueServicesWithoutIPs(ipPool)
	}
}

func (c *ServiceExternalIPController) addIPAllocationLocked(name apimachinerytypes.NamespacedName, ipPool string, ip net.IP, sharable bool) {
	c.ipAllocations.Add(&ipAllocation{
		service:  name,
		ip:       ip,
		ipPool:   ipPool,
		sharable: sharable,
	})
}

// worker is a long-running function that will continually call the processNextWorkItem function in
// order to read and process a message on the workqueue.
func (c *ServiceExternalIPController) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *ServiceExternalIPController) processNextWorkItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)
	if err := c.syncService(key); err == nil {
		// If no error occurs we Forget this item so it does not get queued again until
		// another change happens.
		c.queue.Forget(key)
	} else {
		// Put the item back on the workqueue to handle any transient errors.
		c.queue.AddRateLimited(key)
		klog.Errorf("Error syncing Service %s, requeuing. Error: %v", key, err)
	}
	return true
}

func (c *ServiceExternalIPController) releaseExternalIP(service apimachinerytypes.NamespacedName) (bool, error) {
	c.ipAllocationMutex.Lock()
	defer c.ipAllocationMutex.Unlock()
	obj, exists, _ := c.ipAllocations.GetByKey(service.String())
	if exists {
		allocation := obj.(*ipAllocation)
		objs, _ := c.ipAllocations.ByIndex(ipIndex, allocation.ip.String())
		// The IP is exclusively used by the Service.
		if len(objs) == 1 {
			if err := c.externalIPAllocator.ReleaseIP(allocation.ipPool, allocation.ip); err != nil {
				if err == externalippool.ErrExternalIPPoolNotFound {
					// Ignore the error since the external IP Pool could be deleted.
					klog.Warningf("Failed to release IP %s for service %s: IP Pool %s does not exist", service, allocation.ip, allocation.ipPool)
				} else {
					klog.ErrorS(err, "Failed to release external IP", "service", service, "ip", allocation.ip, "pool", allocation.ipPool)
					return false, err
				}
			} else {
				klog.InfoS("Released external IP", "service", service, "ip", allocation.ip, "pool", allocation.ipPool)
			}
		}
		c.ipAllocations.Delete(obj)
		// Update other Services as they may be affected by the deletion of this allocation.
		// It's necessary even when the IP was not exclusively used by the deleted Service, considering this case:
		// 1. Service A requests to share an IP with Service B, and both get the IP assigned.
		// 2. Service A changes to not allow shared IP, currently the IP is still shared between A and B, but Service C
		//    cannot get the IP assigned even if it allows shared IP.
		// 3. Service A is deleted, the only remaining owner of the IP, Service B, allows shared IP, so Service C is
		//    eligible for the IP.
		c.enqueueServicesWithoutIPs(allocation.ipPool)
		return true, nil
	}
	return false, nil
}

func (c *ServiceExternalIPController) allocateExternalIP(service apimachinerytypes.NamespacedName, pool string, requestedIP string, allowSharedIP bool) (net.IP, error) {
	c.ipAllocationMutex.Lock()
	defer c.ipAllocationMutex.Unlock()

	// Allocate IP from ExternalIPPool.
	if requestedIP == "" {
		ip, err := c.externalIPAllocator.AllocateIPFromPool(pool)
		if err != nil {
			return nil, fmt.Errorf("error when allocating IP from ExternalIPPool %s for Service %s: %v", pool, service, err)
		}
		klog.InfoS("Allocated external IP for Service", "service", service, "externalIPPool", pool, "ip", ip)
		c.addIPAllocationLocked(service, pool, ip, allowSharedIP)
		return ip, nil
	}

	// Check whether the requested IP is in the IP pool or not.
	ip := net.ParseIP(requestedIP)
	if !c.externalIPAllocator.IPPoolHasIP(pool, ip) {
		klog.ErrorS(nil, "ExternalIPPool did not contain the requested IP", "externalIPPool", pool, "ip", requestedIP)
		return nil, nil
	}

	// Check whether the requested IP is already used.
	objs, _ := c.ipAllocations.ByIndex(ipIndex, ip.String())
	if len(objs) > 0 {
		// Fail if the Service itself doesn't allow shared IP.
		if !allowSharedIP {
			klog.ErrorS(nil, "The Service didn't allow shared IP but the requested IP had been allocated to other Service", "service", service, "externalIPPool", pool, "ip", requestedIP)
			return nil, nil
		}
		// Fail if any Service already using the IP doesn't allow shared IP.
		for _, obj := range objs {
			allocation := obj.(*ipAllocation)
			if !allocation.sharable {
				klog.ErrorS(nil, "The requested IP had been allocated to other Service not allowing shared IP", "service", service, "externalIPPool", pool, "ip", requestedIP)
				return nil, nil
			}
		}
		klog.InfoS("Shared external IP for Service", "service", service, "externalIPPool", pool, "ip", ip)
		c.addIPAllocationLocked(service, pool, ip, allowSharedIP)
		return ip, nil
	}

	// The requested IP is not used yet, allocate it.
	if err := c.externalIPAllocator.UpdateIPAllocation(pool, ip); err != nil {
		return nil, fmt.Errorf("error when allocating IP %s from ExternalIPPool %s for Service %s: %v", requestedIP, pool, service, err)
	}
	klog.InfoS("Requested external IP for Service", "service", service, "externalIPPool", pool, "ip", ip)
	c.addIPAllocationLocked(service, pool, ip, allowSharedIP)
	return ip, nil
}

func (c *ServiceExternalIPController) getExternalIPAllocation(service apimachinerytypes.NamespacedName) (*ipAllocation, bool) {
	c.ipAllocationMutex.RLock()
	defer c.ipAllocationMutex.RUnlock()
	obj, exist, _ := c.ipAllocations.GetByKey(service.String())
	if !exist {
		return nil, false
	}
	return obj.(*ipAllocation), true
}

func getServiceExternalIP(service *corev1.Service) string {
	if len(service.Status.LoadBalancer.Ingress) == 0 {
		return ""
	}
	return service.Status.LoadBalancer.Ingress[0].IP
}

func getServiceExternalIPPool(service *corev1.Service) string {
	return service.Annotations[antreaagenttypes.ServiceExternalIPPoolAnnotationKey]
}

func isServiceExternalIPSharable(service *corev1.Service) bool {
	value, exists := service.Annotations[antreaagenttypes.ServiceAllowSharedIPAnnotationKey]
	if !exists {
		return false
	}
	sharable, _ := strconv.ParseBool(value)
	return sharable
}

func (c *ServiceExternalIPController) syncService(key apimachinerytypes.NamespacedName) error {
	startTime := time.Now()
	defer func() {
		klog.V(4).Infof("Finished syncing Service for %s. (%v)", key, time.Since(startTime))
	}()

	service, err := c.serviceLister.Services(key.Namespace).Get(key.Name)
	if err != nil {
		// Service already deleted
		if apimachineryerrors.IsNotFound(err) {
			if _, err := c.releaseExternalIP(key); err != nil {
				return err
			}
			return nil
		}
		return err
	}

	// Service does not need external IP or type has changed.
	if service.Spec.Type != corev1.ServiceTypeLoadBalancer {
		released, err := c.releaseExternalIP(key)
		if err != nil {
			return err
		}
		// Ensure the LoadBalancerStatus in Kubernetes API is unset if the IP was allocated by it.
		if released {
			return c.updateServiceLoadBalancerIP(service, nil)
		}
		return nil
	}

	currentIPPool := getServiceExternalIPPool(service)
	allowSharedIP := isServiceExternalIPSharable(service)
	prevIPAllocation, allocationExists := c.getExternalIPAllocation(key)
	currentExternalIP := getServiceExternalIP(service)

	// If user specifies external IP in spec, we should check whether it matches the current external IP.
	specIPMatched := service.Spec.LoadBalancerIP == "" || service.Spec.LoadBalancerIP == currentExternalIP

	if allocationExists && specIPMatched &&
		c.externalIPAllocator.IPPoolExists(currentIPPool) &&
		c.externalIPAllocator.IPPoolHasIP(currentIPPool, prevIPAllocation.ip) &&
		currentIPPool == prevIPAllocation.ipPool &&
		currentExternalIP == prevIPAllocation.ip.String() {
		// Only the sharable annotation changes, update it.
		if allowSharedIP != prevIPAllocation.sharable {
			c.updateIPAllocation(key, prevIPAllocation.ipPool, prevIPAllocation.ip, allowSharedIP)
		}
		// Ensure the LoadBalancerStatus in Kubernetes API matches the cache.
		return c.updateServiceLoadBalancerIP(service, prevIPAllocation.ip)
	}

	// The ExternalIPPool does not exist or has been deleted. Reclaim the external IP.
	if currentIPPool != "" && !c.externalIPAllocator.IPPoolExists(currentIPPool) {
		if _, err := c.releaseExternalIP(key); err != nil {
			return err
		}
		return c.updateServiceLoadBalancerIP(service, nil)
	}

	// The external IP or ExternalIPPool changes. Delete the previous allocation.
	released, err := c.releaseExternalIP(key)
	if err != nil {
		return err
	}

	if currentIPPool == "" {
		klog.V(2).InfoS("Ignored Service as the required annotation no longer exists", "service", key)
		if released {
			return c.updateServiceLoadBalancerIP(service, nil)
		}
		return nil
	}

	newExternalIP, err := c.allocateExternalIP(key, currentIPPool, service.Spec.LoadBalancerIP, allowSharedIP)
	if err != nil {
		return err
	}
	if err := c.updateServiceLoadBalancerIP(service, newExternalIP); err != nil {
		return err
	}
	return nil
}

// updateService updates the Service status in Kubernetes API.
func (c *ServiceExternalIPController) updateServiceLoadBalancerIP(svc *corev1.Service, ip net.IP) error {
	expectedLoadBalancerStatus := corev1.LoadBalancerStatus{}
	if ip != nil {
		expectedLoadBalancerStatus.Ingress = append(expectedLoadBalancerStatus.Ingress, corev1.LoadBalancerIngress{IP: ip.String()})
	}
	toUpdate := svc.DeepCopy()
	var updateErr, getErr error
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if reflect.DeepEqual(expectedLoadBalancerStatus, toUpdate.Status.LoadBalancer) {
			return nil
		}
		toUpdate.Status.LoadBalancer = expectedLoadBalancerStatus
		_, updateErr = c.client.CoreV1().Services(toUpdate.Namespace).UpdateStatus(context.TODO(), toUpdate, metav1.UpdateOptions{})
		if updateErr != nil && apimachineryerrors.IsConflict(updateErr) {
			if toUpdate, getErr = c.client.CoreV1().Services(toUpdate.Namespace).Get(context.TODO(), svc.Name, metav1.GetOptions{}); getErr != nil {
				return getErr
			}
		}
		return updateErr
	}); err != nil {
		return err
	}
	return nil
}
