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
	"k8s.io/apimachinery/pkg/api/errors"
	apimachinerytypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/apis"
	"antrea.io/antrea/pkg/agent/ipassigner"
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

	client kubernetes.Interface

	endpointsInformer     cache.SharedIndexInformer
	endpointsLister       corelisters.EndpointsLister
	endpointsListerSynced cache.InformerSynced

	queue workqueue.RateLimitingInterface

	externalIPStates      map[apimachinerytypes.NamespacedName]externalIPState
	externalIPStatesMutex sync.RWMutex

	cluster    memberlist.Interface
	ipAssigner ipassigner.IPAssigner

	assignedIPs      map[string]sets.Set[string]
	assignedIPsMutex sync.Mutex
}

var _ querier.ServiceExternalIPStatusQuerier = (*ServiceExternalIPController)(nil)

func NewServiceExternalIPController(
	nodeName string,
	nodeTransportInterface string,
	client kubernetes.Interface,
	cluster memberlist.Interface,
	serviceInformer coreinformers.ServiceInformer,
	endpointsInformer coreinformers.EndpointsInformer,
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
		assignedIPs:           make(map[string]sets.Set[string]),
	}
	ipAssigner, err := ipassigner.NewIPAssigner(nodeTransportInterface, "")
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
		// The only possible error Lister.Get can return is NotFound.
		// It's normal that some Endpoints don't have Service. For example, kube-scheduler and kube-controller-manager
		// may use Endpoints for leader election. Even if the Endpoints should have a Service but it's not received yet,
		// it's fine to ignore the error as the Service's add event will enqueue it.
		klog.V(5).InfoS("Failed to get Service for Endpoints", "Endpoints", klog.KObj(endpoints), "err", err)
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
	go c.ipAssigner.Run(stopCh)

	klog.Infof("Starting %s", controllerName)
	defer klog.Infof("Shutting down %s", controllerName)

	if !cache.WaitForNamedCacheSync(controllerName, stopCh, c.serviceListerSynced, c.endpointsListerSynced) {
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
	if service.Spec.ExternalTrafficPolicy == corev1.ServiceExternalTrafficPolicyTypeLocal {
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
			// No Node is available at the moment. The Service will be requeued by Endpoints, Node, or Memberlist update events.
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
		c.assignedIPs[ip] = sets.New[string](service.String())
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
