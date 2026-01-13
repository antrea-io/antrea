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
	"fmt"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	apimachinerytypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	discoveryinformers "k8s.io/client-go/informers/discovery/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	discoverylisters "k8s.io/client-go/listers/discovery/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/apis"
	"antrea.io/antrea/pkg/agent/ipassigner"
	"antrea.io/antrea/pkg/agent/ipassigner/linkmonitor"
	"antrea.io/antrea/pkg/agent/memberlist"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/querier"
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
)

type externalIPState struct {
	ip           string
	ipPool       string
	assignedNode string
}

type ServiceExternalIPController struct {
	nodeName            string
	serviceInformer     cache.SharedIndexInformer
	serviceLister       corelisters.ServiceLister
	serviceListerSynced cache.InformerSynced

	endpointSliceInformer     cache.SharedIndexInformer
	endpointSliceLister       discoverylisters.EndpointSliceLister
	endpointSliceListerSynced cache.InformerSynced

	queue workqueue.TypedRateLimitingInterface[apimachinerytypes.NamespacedName]

	externalIPStates      map[apimachinerytypes.NamespacedName]externalIPState
	externalIPStatesMutex sync.RWMutex

	cluster    memberlist.Interface
	ipAssigner ipassigner.IPAssigner

	assignedIPs      map[string]sets.Set[string]
	assignedIPsMutex sync.Mutex

	linkMonitor linkmonitor.Interface
}

var _ querier.ServiceExternalIPStatusQuerier = (*ServiceExternalIPController)(nil)

func NewServiceExternalIPController(
	nodeName string,
	nodeTransportInterface string,
	cluster memberlist.Interface,
	serviceInformer coreinformers.ServiceInformer,
	endpointSliceInformer discoveryinformers.EndpointSliceInformer,
	linkMonitor linkmonitor.Interface,
) (*ServiceExternalIPController, error) {
	c := &ServiceExternalIPController{
		nodeName: nodeName,
		cluster:  cluster,
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.NewTypedItemExponentialFailureRateLimiter[apimachinerytypes.NamespacedName](minRetryDelay, maxRetryDelay),
			workqueue.TypedRateLimitingQueueConfig[apimachinerytypes.NamespacedName]{
				Name: "AgentServiceExternalIP",
			},
		),
		serviceInformer:           serviceInformer.Informer(),
		serviceLister:             serviceInformer.Lister(),
		serviceListerSynced:       serviceInformer.Informer().HasSynced,
		endpointSliceInformer:     endpointSliceInformer.Informer(),
		endpointSliceLister:       endpointSliceInformer.Lister(),
		endpointSliceListerSynced: endpointSliceInformer.Informer().HasSynced,
		externalIPStates:          make(map[apimachinerytypes.NamespacedName]externalIPState),
		assignedIPs:               make(map[string]sets.Set[string]),
		linkMonitor:               linkMonitor,
	}
	ipAssigner, err := ipassigner.NewIPAssigner(nodeTransportInterface, "", linkMonitor, false)
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

	c.endpointSliceInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc: c.enqueueServiceForEndpointSlice,
			UpdateFunc: func(old, cur interface{}) {
				c.enqueueServiceForEndpointSlice(cur)
			},
			DeleteFunc: c.enqueueServiceForEndpointSlice,
		},
		resyncPeriod,
	)

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

func (c *ServiceExternalIPController) enqueueServiceForEndpointSlice(obj interface{}) {
	endpointSlice, ok := obj.(*discoveryv1.EndpointSlice)
	if !ok {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Received unexpected object: %v", obj)
			return
		}
		endpointSlice, ok = deletedState.Obj.(*discoveryv1.EndpointSlice)
		if !ok {
			klog.Errorf("DeletedFinalStateUnknown contains non-EndpointSlice object: %v", deletedState.Obj)
			return
		}
	}
	// Get the service name from the EndpointSlice label
	serviceName, ok := endpointSlice.Labels[discoveryv1.LabelServiceName]
	if !ok {
		// EndpointSlice doesn't have the service name label, skip it
		klog.V(5).InfoS("EndpointSlice doesn't have the service name label, skip it", "EndpointSlice", klog.KObj(endpointSlice))
		return
	}
	service, err := c.serviceLister.Services(endpointSlice.Namespace).Get(serviceName)
	if err != nil {
		// The only possible error Lister.Get can return is NotFound.
		// It's fine to ignore the error as the Service's add event will enqueue it when the Service is synced.
		klog.V(5).InfoS("Failed to get Service for EndpointSlice", "EndpointSlice", klog.KObj(endpointSlice), "err", err)
		return
	}
	// we only care services with ServiceExternalTrafficPolicy setting to local.
	if service.Spec.ExternalTrafficPolicy != corev1.ServiceExternalTrafficPolicyLocal || service.Spec.Type != corev1.ServiceTypeLoadBalancer {
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
	go c.ipAssigner.Run(stopCh)

	klog.Infof("Starting %s", controllerName)
	defer klog.Infof("Shutting down %s", controllerName)

	if !cache.WaitForNamedCacheSync(controllerName, stopCh, c.serviceListerSynced, c.endpointSliceListerSynced, c.linkMonitor.HasSynced) {
		return
	}

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}
	<-stopCh
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
	if err := c.unassignIP(state.ip, service); err != nil {
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

func (c *ServiceExternalIPController) saveServiceState(service *corev1.Service, state *externalIPState) {
	c.externalIPStatesMutex.Lock()
	defer c.externalIPStatesMutex.Unlock()
	name := apimachinerytypes.NamespacedName{
		Namespace: service.Namespace,
		Name:      service.Name,
	}
	c.externalIPStates[name] = *state
}

func (c *ServiceExternalIPController) getServiceExternalIP(service *corev1.Service) string {
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
		if errors.IsNotFound(err) {
			return c.deleteService(key)
		}
		return err
	}

	if service.Spec.Type != corev1.ServiceTypeLoadBalancer {
		return c.deleteService(key)
	}

	prevState, exist := c.getServiceState(service)
	currentExternalIP := c.getServiceExternalIP(service)
	if exist && prevState.ip != currentExternalIP {
		// External IP of the Service has changed. Delete the previous assigned IP if exists.
		if err := c.deleteService(key); err != nil {
			return err
		}
	}

	ipPool := service.ObjectMeta.Annotations[types.ServiceExternalIPPoolAnnotationKey]
	state := &externalIPState{
		ip:     currentExternalIP,
		ipPool: ipPool,
	}
	defer c.saveServiceState(service, state)

	if currentExternalIP == "" || ipPool == "" {
		return nil
	}

	var filters []func(string) bool
	if service.Spec.ExternalTrafficPolicy == corev1.ServiceExternalTrafficPolicyLocal {
		nodes, err := c.nodesHasHealthyServiceEndpoint(service)
		if err != nil {
			return err
		}
		filters = append(filters, func(s string) bool {
			return nodes.Has(s)
		})
	}

	nodeName, err := c.cluster.SelectNodeForIP(currentExternalIP, ipPool, filters...)
	if err != nil {
		if err == memberlist.ErrNoNodeAvailable {
			// No Node is available at the moment. The Service will be requeued by EndpointSlice, Node, or Memberlist update events.
			klog.InfoS("No Node available", "ip", currentExternalIP, "ipPool", ipPool)
			return nil
		}
		return err
	}
	klog.InfoS("Select Node for IP", "service", key, "nodeName", nodeName, "currentExternalIP", currentExternalIP, "ipPool", ipPool)

	state.assignedNode = nodeName

	if state.assignedNode == c.nodeName {
		return c.assignIP(currentExternalIP, key)
	}
	return c.unassignIP(currentExternalIP, key)
}

func (c *ServiceExternalIPController) assignIP(ip string, service apimachinerytypes.NamespacedName) error {
	c.assignedIPsMutex.Lock()
	defer c.assignedIPsMutex.Unlock()
	if _, ok := c.assignedIPs[ip]; !ok {
		if _, err := c.ipAssigner.AssignIP(ip, nil, true); err != nil {
			return err
		}
		c.assignedIPs[ip] = sets.New(service.String())
	} else {
		c.assignedIPs[ip].Insert(service.String())
	}
	return nil
}

func (c *ServiceExternalIPController) unassignIP(ip string, service apimachinerytypes.NamespacedName) error {
	c.assignedIPsMutex.Lock()
	defer c.assignedIPsMutex.Unlock()
	assigned, ok := c.assignedIPs[ip]
	if !ok {
		return nil
	}
	if assigned.Len() == 1 && assigned.Has(service.String()) {
		if _, err := c.ipAssigner.UnassignIP(ip); err != nil {
			return err
		}
		delete(c.assignedIPs, ip)
		return nil
	}
	assigned.Delete(service.String())
	return nil
}

// nodesHasHealthyServiceEndpoint returns the set of Nodes which has at least one healthy endpoint.
func (c *ServiceExternalIPController) nodesHasHealthyServiceEndpoint(service *corev1.Service) (sets.Set[string], error) {
	nodes := sets.New[string]()
	// List all EndpointSlices for this service using the label selector
	labelSelector := labels.SelectorFromSet(labels.Set{
		discoveryv1.LabelServiceName: service.Name,
	})
	endpointSlices, err := c.endpointSliceLister.EndpointSlices(service.Namespace).List(labelSelector)
	if err != nil {
		return nodes, err
	}
	for _, endpointSlice := range endpointSlices {
		for _, ep := range endpointSlice.Endpoints {
			if ep.NodeName == nil {
				continue
			}
			// Check the ready condition first to respect the Service's publishNotReadyAddresses setting.
			// The ready condition is true when:
			// - publishNotReadyAddresses is true (all endpoints are considered ready), OR
			// - the endpoint is serving AND not terminating
			// If ready is true (or nil, which means true), we can use this endpoint.
			if ep.Conditions.Ready == nil || *ep.Conditions.Ready {
				nodes.Insert(*ep.NodeName)
				continue
			}
			// If ready is false, fall back to checking the serving condition directly.
			// This handles cases where the endpoint might still be serving but is marked not ready
			// (e.g., during termination but still draining connections).
			if ep.Conditions.Serving == nil || *ep.Conditions.Serving {
				nodes.Insert(*ep.NodeName)
			}
		}
	}
	return nodes, nil
}

func (c *ServiceExternalIPController) GetServiceExternalIPStatus() []apis.ServiceExternalIPInfo {
	c.externalIPStatesMutex.RLock()
	defer c.externalIPStatesMutex.RUnlock()
	info := make([]apis.ServiceExternalIPInfo, 0, len(c.externalIPStates))
	for k, v := range c.externalIPStates {
		info = append(info, apis.ServiceExternalIPInfo{
			ServiceName:    k.Name,
			Namespace:      k.Namespace,
			ExternalIP:     v.ip,
			ExternalIPPool: v.ipPool,
			AssignedNode:   v.assignedNode,
		})
	}
	return info
}
