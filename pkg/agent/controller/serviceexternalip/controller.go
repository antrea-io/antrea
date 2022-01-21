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
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	apimachinerytypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/ipassigner"
	"antrea.io/antrea/pkg/agent/memberlist"
	"antrea.io/antrea/pkg/agent/types"
)

const (
	controllerName = "ServiceExternalIPController"
	// How long to wait before retrying the processing of an Service change.
	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second
	// Default number of workers processing an Service change.
	defaultWorkers = 1
	// Disable resyncing.
	resyncPeriod time.Duration = 0

	externalIPIndex     = "externalIP"
	externalIPPoolIndex = "externalIPPool"

	// ingressDummyDevice is the dummy device that holds the Service external IPs configured to the system by antrea-agent.
	ingressDummyDevice = "antrea-ingress0"
)

type externalIPState struct {
	ip           string
	assignedNode string
}

type ServiceExternalIPController struct {
	nodeName            string
	serviceInformer     cache.SharedIndexInformer
	serviceLister       corelisters.ServiceLister
	serviceListerSynced cache.InformerSynced

	client kubernetes.Interface

	endpointsInformer     cache.SharedIndexInformer
	endpointsLister       corelisters.EndpointsLister
	endpointsListerSynced cache.InformerSynced

	queue workqueue.RateLimitingInterface

	externalIPStates      map[apimachinerytypes.NamespacedName]externalIPState
	externalIPStatesMutex sync.RWMutex

	cluster         memberlist.Interface
	ipAssigner      ipassigner.IPAssigner
	localIPDetector ipassigner.LocalIPDetector
}

func NewServiceExternalIPController(
	nodeName string,
	nodeTransportIP net.IP,
	client kubernetes.Interface,
	cluster memberlist.Interface,
	serviceInformer coreinformers.ServiceInformer,
	endpointsInformer coreinformers.EndpointsInformer,
	localIPDetector ipassigner.LocalIPDetector,
) (*ServiceExternalIPController, error) {
	c := &ServiceExternalIPController{
		nodeName:              nodeName,
		client:                client,
		cluster:               cluster,
		queue:                 workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "AgentServiceExternalIP"),
		serviceInformer:       serviceInformer.Informer(),
		serviceLister:         serviceInformer.Lister(),
		serviceListerSynced:   serviceInformer.Informer().HasSynced,
		endpointsInformer:     endpointsInformer.Informer(),
		endpointsLister:       endpointsInformer.Lister(),
		endpointsListerSynced: endpointsInformer.Informer().HasSynced,
		externalIPStates:      make(map[apimachinerytypes.NamespacedName]externalIPState),
		localIPDetector:       localIPDetector,
	}
	ipAssigner, err := ipassigner.NewIPAssigner(nodeTransportIP, ingressDummyDevice)
	if err != nil {
		return nil, fmt.Errorf("initializing service external IP assigner failed: %v", err)
	}
	c.ipAssigner = ipAssigner

	c.serviceInformer.AddIndexers(cache.Indexers{
		externalIPIndex: func(obj interface{}) ([]string, error) {
			service, ok := obj.(*corev1.Service)
			if !ok {
				return nil, fmt.Errorf("obj is not Service: %+v", obj)
			}
			if len(service.Status.LoadBalancer.Ingress) == 0 {
				return nil, nil
			}
			return []string{service.Status.LoadBalancer.Ingress[0].IP}, nil
		},
		externalIPPoolIndex: func(obj interface{}) ([]string, error) {
			service, ok := obj.(*corev1.Service)
			if !ok {
				return nil, fmt.Errorf("obj is not Service: %+v", obj)
			}
			eipName, ok := service.Annotations[types.ServiceExternalIPPoolAnnotationKey]
			if !ok {
				return nil, nil
			}
			return []string{eipName}, nil
		}},
	)

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

	c.endpointsInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc: c.enqueueServiceForEndpoints,
			UpdateFunc: func(old, cur interface{}) {
				c.enqueueServiceForEndpoints(cur)
			},
			DeleteFunc: c.enqueueServiceForEndpoints,
		},
		resyncPeriod,
	)

	c.localIPDetector.AddEventHandler(c.onLocalIPUpdate)
	c.cluster.AddClusterEventHandler(c.enqueueServicesByExternalIPPool)
	return c, nil
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
	key := apimachinerytypes.NamespacedName{
		Namespace: service.Namespace,
		Name:      service.Name,
	}
	c.queue.Add(key)
}

func (c *ServiceExternalIPController) enqueueServiceForEndpoints(obj interface{}) {
	endpoints, ok := obj.(*corev1.Endpoints)
	if !ok {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Received unexpected object: %v", obj)
			return
		}
		endpoints, ok = deletedState.Obj.(*corev1.Endpoints)
		if !ok {
			klog.Errorf("DeletedFinalStateUnknown contains non-Endpoint object: %v", deletedState.Obj)
			return
		}
	}
	service, err := c.serviceLister.Services(endpoints.Namespace).Get(endpoints.Name)
	if err != nil {
		klog.ErrorS(err, "failed to get Service for Endpoint", "namespace", endpoints.Namespace, "name", endpoints.Name)
		return
	}
	// we only care services with ServiceExternalTrafficPolicy setting to local.
	if service.Spec.ExternalTrafficPolicy != corev1.ServiceExternalTrafficPolicyTypeLocal || service.Spec.Type != corev1.ServiceTypeLoadBalancer {
		return
	}
	c.queue.Add(apimachinerytypes.NamespacedName{
		Namespace: service.Namespace,
		Name:      service.Name,
	})
}

// enqueueServicesByExternalIPPool enqueues all services that refer to the provided ExternalIPPool,
// the ExternalIPPool is affected by a Node update/create/delete event or Node leaves/join cluster
// event or ExternalIPPool changed event.
func (c *ServiceExternalIPController) enqueueServicesByExternalIPPool(eipName string) {
	objects, _ := c.serviceInformer.GetIndexer().ByIndex(externalIPPoolIndex, eipName)
	for _, object := range objects {
		service := object.(*corev1.Service)
		c.queue.Add(apimachinerytypes.NamespacedName{
			Namespace: service.Namespace,
			Name:      service.Name,
		})
	}
	klog.InfoS("Detected ExternalIPPool event", "ExternalIPPool", eipName, "enqueueServiceNum", len(objects))
}

// Run will create defaultWorkers workers (go routines) which will process the Service events from the
// workqueue.
func (c *ServiceExternalIPController) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	klog.Infof("Starting %s", controllerName)
	defer klog.Infof("Shutting down %s", controllerName)

	if !cache.WaitForNamedCacheSync(controllerName, stopCh, c.serviceListerSynced, c.endpointsListerSynced) {
		return
	}

	c.removeStaleExternalIPs()

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}
	<-stopCh
}

// removeStaleExternalIPs unassigns stale external IPs that shouldn't be present on this Node.
// This function will only delete IPs which are caused by Service changes when the agent on this Node was
// not running. Those IPs should be deleted caused by migration will be deleted by processNextWorkItem.
func (c *ServiceExternalIPController) removeStaleExternalIPs() {
	desiredExternalIPs := sets.NewString()
	services, _ := c.serviceLister.List(labels.Everything())
	for _, service := range services {
		if service.Spec.Type == corev1.ServiceTypeLoadBalancer &&
			service.ObjectMeta.Annotations[types.ServiceExternalIPPoolAnnotationKey] != "" &&
			len(service.Status.LoadBalancer.Ingress) != 0 {
			desiredExternalIPs.Insert(service.Status.LoadBalancer.Ingress[0].IP)
		}
	}
	actualExternalIPs := c.ipAssigner.AssignedIPs()
	for ip := range actualExternalIPs.Difference(desiredExternalIPs) {
		if err := c.ipAssigner.UnassignIP(ip); err != nil {
			klog.ErrorS(err, "Failed to clean up stale service external IP", "ip", ip)
		}
	}
}

func (c *ServiceExternalIPController) onLocalIPUpdate(ip string, added bool) {
	services, _ := c.serviceInformer.GetIndexer().ByIndex(externalIPIndex, ip)
	if len(services) == 0 {
		return
	}
	if added {
		klog.Infof("Detected service external IP address %s added to this Node", ip)
	} else {
		klog.Infof("Detected service external IP address %s deleted from this Node", ip)
	}
	for _, s := range services {
		c.enqueueService(s)
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
		klog.ErrorS(err, "Error syncing Service", "Service", key)
	}
	return true
}

func (c *ServiceExternalIPController) deleteService(service apimachinerytypes.NamespacedName) error {
	c.externalIPStatesMutex.Lock()
	defer c.externalIPStatesMutex.Unlock()
	var state externalIPState
	var exist bool
	if state, exist = c.externalIPStates[service]; !exist {
		return nil
	}
	if err := c.ipAssigner.UnassignIP(state.ip); err != nil {
		return err
	}
	delete(c.externalIPStates, service)
	return nil
}

func (c *ServiceExternalIPController) getServiceState(service *corev1.Service) (externalIPState, bool) {
	c.externalIPStatesMutex.RLock()
	defer c.externalIPStatesMutex.RUnlock()
	name := apimachinerytypes.NamespacedName{
		Namespace: service.Namespace,
		Name:      service.Name,
	}
	state, exist := c.externalIPStates[name]
	return state, exist
}

func (c *ServiceExternalIPController) saveServiceState(service *corev1.Service, state externalIPState) {
	c.externalIPStatesMutex.Lock()
	defer c.externalIPStatesMutex.Unlock()
	name := apimachinerytypes.NamespacedName{
		Namespace: service.Namespace,
		Name:      service.Name,
	}
	c.externalIPStates[name] = state
}

func (c *ServiceExternalIPController) getServiceExternalIPAndHostname(service *corev1.Service) (string, string) {
	if len(service.Status.LoadBalancer.Ingress) == 0 {
		return "", ""
	}
	return service.Status.LoadBalancer.Ingress[0].IP, service.Status.LoadBalancer.Ingress[0].Hostname
}

func (c *ServiceExternalIPController) syncService(key apimachinerytypes.NamespacedName) error {
	startTime := time.Now()
	defer func() {
		klog.V(4).Infof("Finished syncing Service for %s. (%v)", key, time.Since(startTime))
	}()

	service, err := c.serviceLister.Services(key.Namespace).Get(key.Name)
	if err != nil {
		if errors.IsNotFound(err) {
			return c.deleteService(key)
		}
		return err
	}

	if service.Spec.Type != corev1.ServiceTypeLoadBalancer {
		return c.deleteService(key)
	}

	state, exist := c.getServiceState(service)
	currentExternalIP, currentHostname := c.getServiceExternalIPAndHostname(service)
	if exist && state.ip != currentExternalIP {
		// External IP of the Service has changed. Delete the previous assigned IP if exists.
		if err := c.deleteService(key); err != nil {
			return err
		}
	}

	ipPool := service.ObjectMeta.Annotations[types.ServiceExternalIPPoolAnnotationKey]
	if currentExternalIP == "" || ipPool == "" {
		return nil
	}

	selectNode := true
	var filters []func(string) bool
	if service.Spec.ExternalTrafficPolicy == corev1.ServiceExternalTrafficPolicyTypeLocal {
		nodes, err := c.nodesHasHealthyServiceEndpoint(service)
		if err != nil {
			return err
		}
		// Avoid unnecessary migration caused by Endpoints changes.
		if currentHostname != "" && c.cluster.AliveNodes().Has(currentHostname) && nodes.Has(currentHostname) {
			selectNode = false
			state = externalIPState{
				ip:           currentExternalIP,
				assignedNode: currentHostname,
			}
			c.saveServiceState(service, state)
		} else {
			filters = append(filters, func(s string) bool {
				return nodes.Has(s)
			})
		}
	}

	if selectNode {
		nodeName, err := c.cluster.SelectNodeForIP(currentExternalIP, ipPool, filters...)
		if err != nil {
			if err == memberlist.ErrNoNodeAvailable {
				// No Node is available for the moment. The Service will be requeued by Endpoints, Node, or Memberlist update events.
				klog.InfoS("No Node available", "ip", currentExternalIP, "ipPool", ipPool)
				return nil
			}
			return err
		}
		klog.InfoS("Select Node for IP", "service", key, "nodeName", nodeName, "currentExternalIP", currentExternalIP, "ipPool", ipPool)
		state = externalIPState{
			ip:           currentExternalIP,
			assignedNode: nodeName,
		}
		c.saveServiceState(service, state)
	}
	// Update the hostname field of Service status and assign the external IP if this Node is selected.
	if state.assignedNode == c.nodeName {
		if service.Status.LoadBalancer.Ingress[0].Hostname != state.assignedNode {
			serviceToUpdate := service.DeepCopy()
			serviceToUpdate.Status.LoadBalancer.Ingress[0].Hostname = state.assignedNode
			if _, err = c.client.CoreV1().Services(serviceToUpdate.Namespace).UpdateStatus(context.TODO(), serviceToUpdate, v1.UpdateOptions{}); err != nil {
				return err
			}
		}
		return c.ipAssigner.AssignIP(currentExternalIP)
	}
	return c.ipAssigner.UnassignIP(currentExternalIP)
}

// nodesHasHealthyServiceEndpoint returns the set of Nodes which has at least one healthy endpoint.
func (c *ServiceExternalIPController) nodesHasHealthyServiceEndpoint(service *corev1.Service) (sets.String, error) {
	nodes := sets.NewString()
	endpoints, err := c.endpointsLister.Endpoints(service.Namespace).Get(service.Name)
	if err != nil {
		return nodes, err
	}
	for _, subset := range endpoints.Subsets {
		for _, ep := range subset.Addresses {
			if ep.NodeName == nil {
				continue
			}
			nodes.Insert(*ep.NodeName)
		}
	}
	return nodes, nil
}
