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
	"errors"
	"fmt"
	"net"
	"reflect"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	apimachineryerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	apimachinerytypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
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

	externalIPPoolIndex = "externalIPPool"
)

// ipAllocation contains the IP and the IP Pool which allocates it.
type ipAllocation struct {
	ip     net.IP
	ipPool string
}

// ServiceExternalIPController is responsible for synchronizing the Services that need external IPs.
type ServiceExternalIPController struct {
	externalIPAllocator externalippool.ExternalIPAllocator
	client              clientset.Interface

	// ipAllocationMap is a map from Service name to IP allocated.
	ipAllocationMap   map[apimachinerytypes.NamespacedName]*ipAllocation
	ipAllocationMutex sync.RWMutex

	serviceInformer     cache.SharedIndexInformer
	serviceLister       corelisters.ServiceLister
	serviceListerSynced cache.InformerSynced
	// queue maintains the Service objects that need to be synced.
	queue workqueue.RateLimitingInterface
}

func NewServiceExternalIPController(
	client clientset.Interface,
	serviceInformer coreinformers.ServiceInformer,
	externalIPAllocator externalippool.ExternalIPAllocator,
) *ServiceExternalIPController {
	c := &ServiceExternalIPController{
		client:              client,
		queue:               workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "serviceExternalIP"),
		serviceInformer:     serviceInformer.Informer(),
		serviceLister:       serviceInformer.Lister(),
		serviceListerSynced: serviceInformer.Informer().HasSynced,
		externalIPAllocator: externalIPAllocator,
		ipAllocationMap:     make(map[apimachinerytypes.NamespacedName]*ipAllocation),
	}

	c.serviceInformer.AddIndexers(cache.Indexers{
		externalIPPoolIndex: func(obj interface{}) ([]string, error) {
			service, ok := obj.(*corev1.Service)
			if !ok {
				return nil, fmt.Errorf("obj is not Service: %+v", obj)
			}
			eipName, ok := service.Annotations[antreaagenttypes.ServiceExternalIPPoolAnnotationKey]
			if !ok {
				return nil, nil
			}
			return []string{eipName}, nil
		},
	})

	c.serviceInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc: c.enqueueService,
			UpdateFunc: func(old, cur interface{}) {
				c.enqueueService(cur)
			},
			DeleteFunc: c.enqueueService,
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

// restoreIPAllocations restores the existing external IPs of Services and records the successful ones in ipAllocationMap.
func (c *ServiceExternalIPController) restoreIPAllocations(services []*corev1.Service) {
	var previousIPAllocations []externalippool.IPAllocation
	for _, svc := range services {
		ipPool := svc.ObjectMeta.Annotations[antreaagenttypes.ServiceExternalIPPoolAnnotationKey]
		if svc.Spec.Type != corev1.ServiceTypeLoadBalancer || ipPool == "" || len(svc.Status.LoadBalancer.Ingress) == 0 {
			continue
		}
		ip := net.ParseIP(svc.Status.LoadBalancer.Ingress[0].IP)
		allocation := externalippool.IPAllocation{
			ObjectReference: v1.ObjectReference{
				Name:      svc.Name,
				Namespace: svc.Namespace,
				Kind:      svc.Kind,
			},
			IPPoolName: ipPool,
			IP:         ip,
		}
		previousIPAllocations = append(previousIPAllocations, allocation)
	}
	succeededAllocations := c.externalIPAllocator.RestoreIPAllocations(previousIPAllocations)
	for _, alloc := range succeededAllocations {
		name := apimachinerytypes.NamespacedName{
			Namespace: alloc.ObjectReference.Namespace,
			Name:      alloc.ObjectReference.Name,
		}
		c.setIPAllocation(name, alloc.IPPoolName, alloc.IP)
		klog.InfoS("Restored external IP", "service", name, "ip", alloc.IP, "pool", alloc.IPPoolName)
	}
}

func (c *ServiceExternalIPController) setIPAllocation(name apimachinerytypes.NamespacedName, ipPool string, ip net.IP) {
	c.ipAllocationMutex.Lock()
	defer c.ipAllocationMutex.Unlock()
	c.ipAllocationMap[name] = &ipAllocation{
		ip:     ip,
		ipPool: ipPool,
	}
}

// worker is a long-running function that will continually call the processNextWorkItem function in
// order to read and process a message on the workqueue.
func (c *ServiceExternalIPController) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *ServiceExternalIPController) processNextWorkItem() bool {
	obj, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(obj)
	if key, ok := obj.(apimachinerytypes.NamespacedName); !ok {
		c.queue.Forget(obj)
		klog.Errorf("Expected NamespacedName in work queue but got %#v", obj)
		return true
	} else if err := c.syncService(key); err == nil {
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

func (c *ServiceExternalIPController) releaseExternalIP(service apimachinerytypes.NamespacedName) error {
	c.ipAllocationMutex.Lock()
	defer c.ipAllocationMutex.Unlock()
	allocation, exists := c.ipAllocationMap[service]
	if exists {
		if err := c.externalIPAllocator.ReleaseIP(allocation.ipPool, allocation.ip); err != nil {
			if err == externalippool.ErrExternalIPPoolNotFound {
				// Ignore the error since the external IP Pool could be deleted.
				klog.Warningf("Failed to release IP %s for service %s: IP Pool %s does not exist", service, allocation.ip, allocation.ipPool)
			} else {
				klog.ErrorS(err, "Failed to release external IP", "service", service, "ip", allocation.ip, "pool", allocation.ipPool)
				return err
			}
		} else {
			klog.InfoS("Released external IP", "service", service, "ip", allocation.ip, "pool", allocation.ipPool)
		}
		delete(c.ipAllocationMap, service)
	}
	return nil
}

func (c *ServiceExternalIPController) getExternalIPAllocation(service apimachinerytypes.NamespacedName) (*ipAllocation, bool) {
	c.ipAllocationMutex.RLock()
	defer c.ipAllocationMutex.RUnlock()
	allocation, exist := c.ipAllocationMap[service]
	return allocation, exist
}

func getServiceExternalIP(service *corev1.Service) string {
	if len(service.Status.LoadBalancer.Ingress) == 0 {
		return ""
	}
	return service.Status.LoadBalancer.Ingress[0].IP
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
			if err := c.releaseExternalIP(key); err != nil {
				return err
			}
			return nil
		}
		return err
	}

	// Service does not need external IP or type has changed.
	if service.Spec.Type != corev1.ServiceTypeLoadBalancer {
		if err := c.releaseExternalIP(key); err != nil {
			return err
		}
		return nil
	}

	currentIPPool := service.ObjectMeta.Annotations[antreaagenttypes.ServiceExternalIPPoolAnnotationKey]
	prevIPAllocation, allocationExists := c.getExternalIPAllocation(key)
	currentExternalIP := getServiceExternalIP(service)

	// If user specifies external IP in spec, we should check whether it matches the current external IP.
	specIPMatched := service.Spec.LoadBalancerIP == "" || service.Spec.LoadBalancerIP == currentExternalIP

	if allocationExists && specIPMatched &&
		c.externalIPAllocator.IPPoolExists(currentIPPool) &&
		c.externalIPAllocator.IPPoolHasIP(currentIPPool, prevIPAllocation.ip) &&
		currentIPPool == prevIPAllocation.ipPool &&
		currentExternalIP == prevIPAllocation.ip.String() {
		return nil
	}

	// The ExternalIPPool does not exist or has been deleted. Reclaim the external IP.
	if currentIPPool != "" && !c.externalIPAllocator.IPPoolExists(currentIPPool) {
		if err := c.releaseExternalIP(key); err != nil {
			return err
		}
		if currentExternalIP != "" {
			toUpdate := service.DeepCopy()
			toUpdate.Status.LoadBalancer.Ingress = nil
			return c.updateServiceStatus(service, toUpdate)
		}
	}

	// the external IP or ExternalIPPool changed somehow. Delete the previous allocation.
	if err := c.releaseExternalIP(key); err != nil {
		return err
	}

	if currentIPPool == "" {
		klog.V(2).InfoS("Ignored Service as required annotation is not found", "service", key)
		return nil
	}

	var newExternalIP net.IP
	var allocated bool
	if service.Spec.LoadBalancerIP != "" {
		// check whether the specified IP is in the desired IP pool or not.
		newExternalIP = net.ParseIP(service.Spec.LoadBalancerIP)
		if !c.externalIPAllocator.IPPoolHasIP(currentIPPool, newExternalIP) {
			klog.ErrorS(nil, "IP pool does not contain required external IP", "ipPool", currentIPPool, "ip", newExternalIP)
			return nil
		}
		err = c.externalIPAllocator.UpdateIPAllocation(currentIPPool, newExternalIP)
	} else {
		// Allocate IP from existing ExternalIPPool.
		newExternalIP, err = c.externalIPAllocator.AllocateIPFromPool(currentIPPool)
		allocated = true
	}
	if err != nil {
		// If the ExternalIPPool does not exist, we can ignore the error since the Service will get requeued by ExternalIPPool change events.
		if errors.Is(err, externalippool.ErrExternalIPPoolNotFound) {
			klog.ErrorS(err, "Error when allocating IP from ExternalIPPool", "service", service, "ip", newExternalIP, "externalIPPool", currentIPPool)
			return nil
		}
		return fmt.Errorf("error when allocating IP %s from ExternalIPPool %s for Service %s: %v", newExternalIP, currentIPPool, key, err)
	}
	klog.InfoS("Allocated external IP for service", "service", key, "ip", newExternalIP, "externalIPPool", currentIPPool)

	toUpdate := service.DeepCopy()
	toUpdate.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{
		{
			IP: newExternalIP.String(),
		},
	}
	if err := c.updateServiceStatus(service, toUpdate); err != nil {
		if allocated {
			if rerr := c.externalIPAllocator.ReleaseIP(currentIPPool, newExternalIP); rerr != nil &&
				rerr != externalippool.ErrExternalIPPoolNotFound {
				klog.ErrorS(rerr, "Failed to release IP", "service", key, "ip", newExternalIP, "externalIPPool", currentIPPool)
			}
		}
		return err
	}
	c.setIPAllocation(key, currentIPPool, newExternalIP)
	return nil
}

// updateService updates the Service status in Kubernetes API.
func (c *ServiceExternalIPController) updateServiceStatus(prev, current *corev1.Service) error {
	if !reflect.DeepEqual(prev.Status, current.Status) {
		_, err := c.client.CoreV1().Services(current.Namespace).UpdateStatus(context.TODO(), current, metav1.UpdateOptions{})
		if err != nil {
			return err
		}
	}
	return nil
}
