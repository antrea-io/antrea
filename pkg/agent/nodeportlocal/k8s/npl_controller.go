// +build !windows

// Copyright 2020 Antrea Authors
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

package k8s

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/vmware-tanzu/antrea/pkg/agent/nodeportlocal/portcache"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
)

const (
	controllerName = "AntreaAgentNPLController"
	minRetryDelay  = 2 * time.Second
	maxRetryDelay  = 120 * time.Second
	numWorkers     = 4
)

type NPLController struct {
	portTable   *portcache.PortTable
	kubeClient  clientset.Interface
	queue       workqueue.RateLimitingInterface
	podInformer cache.SharedIndexInformer
	podLister   corelisters.PodLister
	svcInformer cache.SharedIndexInformer
	podToIP     map[string]string
	podIPLock   sync.RWMutex
}

func NewNPLController(kubeClient clientset.Interface,
	podInformer cache.SharedIndexInformer,
	svcInformer cache.SharedIndexInformer,
	resyncPeriod time.Duration,
	pt *portcache.PortTable) *NPLController {
	c := NPLController{
		kubeClient:  kubeClient,
		portTable:   pt,
		podInformer: podInformer,
		podLister:   corelisters.NewPodLister(podInformer.GetIndexer()),
		svcInformer: svcInformer,
		podToIP:     make(map[string]string),
	}

	podInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.enqueuePod,
			DeleteFunc: c.enqueuePod,
			UpdateFunc: func(old, cur interface{}) { c.enqueuePod(cur) },
		},
		resyncPeriod,
	)

	svcInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.enqueueSvc,
			DeleteFunc: c.enqueueSvc,
			UpdateFunc: c.enqueueSvcUpdate,
		},
		resyncPeriod,
	)
	svcInformer.AddIndexers(
		cache.Indexers{
			NPLEnabledAnnotationIndex: func(obj interface{}) ([]string, error) {
				svc, ok := obj.(*corev1.Service)
				if !ok {
					return []string{}, nil
				}
				if val, ok := svc.GetAnnotations()[NPLEnabledAnnotationKey]; ok {
					return []string{val}, nil
				}
				return []string{}, nil
			},
		},
	)

	c.queue = workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "nodeportlocal")
	return &c
}

func podKeyFunc(pod *corev1.Pod) string {
	return pod.Namespace + "/" + pod.Name
}

// Run starts to watch and process Pod updates for the Node where Antrea Agent is running.
// It starts a queue and a fixed number of workers to process the objects from the queue.
func (c *NPLController) Run(stopCh <-chan struct{}) {
	defer func() {
		klog.Infof("Shutting down %s", controllerName)
		c.queue.ShutDown()
	}()

	klog.Infof("Starting %s", controllerName)
	go c.podInformer.Run(stopCh)
	if !cache.WaitForNamedCacheSync(controllerName, stopCh, c.podInformer.HasSynced, c.svcInformer.HasSynced) {
		return
	}

	for i := 0; i < numWorkers; i++ {
		go wait.Until(c.Worker, time.Second, stopCh)
	}

	<-stopCh
}

func (c *NPLController) syncPod(key string) error {
	obj, exists, err := c.podInformer.GetIndexer().GetByKey(key)
	if err != nil {
		return err
	} else if exists {
		return c.handleAddUpdatePod(key, obj)
	} else {
		return c.handleRemovePod(key)
	}
}

func (c *NPLController) checkDeletedPod(obj interface{}) (*corev1.Pod, error) {
	deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
	if !ok {
		return nil, fmt.Errorf("received unexpected object: %v", obj)

	}
	pod, ok := deletedState.Obj.(*corev1.Pod)
	if !ok {
		return nil, fmt.Errorf("DeletedFinalStateUnknown object is not of type Pod: %v", deletedState.Obj)
	}
	return pod, nil
}

func (c *NPLController) enqueuePod(obj interface{}) {
	pod, isPod := obj.(*corev1.Pod)
	if !isPod {
		var err error
		pod, err = c.checkDeletedPod(obj)
		if err != nil {
			klog.Errorf("Got error while processing event update: %v", err)
			return
		}
	}
	podKey := podKeyFunc(pod)
	c.queue.Add(podKey)
}

func (c *NPLController) checkDeletedSvc(obj interface{}) (*corev1.Service, error) {
	deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
	if !ok {
		return nil, fmt.Errorf("received unexpected object: %v", obj)
	}
	svc, ok := deletedState.Obj.(*corev1.Service)
	if !ok {
		return nil, fmt.Errorf("DeletedFinalStateUnknown object is not of type Service: %v", deletedState.Obj)
	}
	return svc, nil
}

func (c *NPLController) enqueueSvcUpdate(oldObj, newObj interface{}) {
	// In case where the app selector in Service gets updated from one valid selector to another
	// both sets of Pods (corresponding to old and new selector) need to be considered.
	newSvc := newObj.(*corev1.Service)
	oldSvc := oldObj.(*corev1.Service)

	oldSvcAnnotation := oldSvc.Annotations[NPLEnabledAnnotationKey]
	newSvcAnnotation := newSvc.Annotations[NPLEnabledAnnotationKey]
	// Return if both Services do not have the NPL annotation.
	if oldSvcAnnotation != "true" && newSvcAnnotation != "true" {
		return
	}

	podKeys := sets.String{}
	if oldSvcAnnotation != newSvcAnnotation {
		// Process Pods corresponding to Service with valid NPL annotation.
		if oldSvcAnnotation == "true" {
			podKeys = sets.NewString(c.getPodsFromService(oldSvc)...)
		} else if newSvcAnnotation == "true" {
			podKeys = sets.NewString(c.getPodsFromService(newSvc)...)
		}
	} else if !reflect.DeepEqual(oldSvc.Spec.Selector, newSvc.Spec.Selector) {
		// Disjunctive union of Pods from both Service sets.
		oldPodSet := sets.NewString(c.getPodsFromService(oldSvc)...)
		newPodSet := sets.NewString(c.getPodsFromService(newSvc)...)
		podKeys = oldPodSet.Difference(newPodSet).Union(newPodSet.Difference(oldPodSet))
	}

	for podKey := range podKeys {
		c.queue.Add(podKey)
	}
}

func (c *NPLController) enqueueSvc(obj interface{}) {
	svc, isSvc := obj.(*corev1.Service)
	if !isSvc {
		var err error
		svc, err = c.checkDeletedSvc(obj)
		if err != nil {
			klog.Errorf("Got error while processing event update: %v", err)
			return
		}
	}

	// Process Pods corresponding to Service with valid NPL annotation.
	if svc.Annotations[NPLEnabledAnnotationKey] == "true" {
		for _, podKey := range c.getPodsFromService(svc) {
			c.queue.Add(podKey)
		}
	}
}

func (c *NPLController) getPodsFromService(svc *corev1.Service) []string {
	var pods []string

	// Handling Service without selectors.
	if len(svc.Spec.Selector) == 0 {
		return pods
	}

	podList, err := c.podLister.List(labels.SelectorFromSet(labels.Set(svc.Spec.Selector)))
	if err != nil {
		klog.Errorf("Got error while listing Pods: %v", err)
		return pods
	}
	for _, pod := range podList {
		pods = append(pods, podKeyFunc(pod))
	}
	return pods
}

func (c *NPLController) isNPLEnabledForServiceOfPod(obj interface{}) bool {
	pod := obj.(*corev1.Pod)
	services, err := c.svcInformer.GetIndexer().ByIndex(NPLEnabledAnnotationIndex, "true")
	if err != nil {
		klog.Errorf("Got error while listing Services with annotation %s: %v", NPLEnabledAnnotationKey, err)
		return false
	}

	for _, service := range services {
		svc, isSvc := service.(*corev1.Service)
		// Selecting Services NOT of type NodePort, with Service selector matching Pod labels.
		if isSvc && svc.Spec.Type != corev1.ServiceTypeNodePort {
			if matchSvcSelectorPodLabels(svc.Spec.Selector, pod.GetLabels()) {
				return true
			}
		}
	}
	return false
}

// matchSvcSelectorPodLabels verifies that all key/value pairs present in Service's selector
// are also present in Pod's labels.
func matchSvcSelectorPodLabels(svcSelector, podLabel map[string]string) bool {
	// Handling Service without selectors.
	if len(svcSelector) == 0 {
		return false
	}

	for selectorKey, selectorVal := range svcSelector {
		if labelVal, ok := podLabel[selectorKey]; !ok || selectorVal != labelVal {
			return false
		}
	}
	return true
}

func (c *NPLController) Worker() {
	for c.processNextWorkItem() {
	}
}

func (c *NPLController) processNextWorkItem() bool {
	obj, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(obj)

	if key, ok := obj.(string); !ok {
		c.queue.Forget(obj)
		klog.Errorf("Expected string in work queue but got %#v", obj)
		return true
	} else if err := c.syncPod(key); err == nil {
		klog.V(2).Infof("Successfully processed key: %s, in queue", key)
		c.queue.Forget(key)
	} else {
		c.queue.AddRateLimited(key)
		klog.Errorf("Error syncing Pod %s, requeuing. Error: %v", key, err)
	}
	return true
}

func (c *NPLController) getPodIPFromCache(key string) (string, bool) {
	c.podIPLock.RLock()
	defer c.podIPLock.RUnlock()
	podIP, found := c.podToIP[key]
	return podIP, found
}

func (c *NPLController) addPodIPToCache(key, podIP string) {
	c.podIPLock.Lock()
	defer c.podIPLock.Unlock()
	c.podToIP[key] = podIP
}

func (c *NPLController) deletePodIPFromCache(key string) {
	c.podIPLock.Lock()
	defer c.podIPLock.Unlock()
	delete(c.podToIP, key)
}

func (c *NPLController) deleteAllPortRulesIfAny(podIP string) error {
	data := c.portTable.GetDataForPodIP(podIP)
	for _, d := range data {
		err := c.portTable.DeleteRule(d.PodIP, int(d.PodPort))
		if err != nil {
			return err
		}
	}
	return nil
}

// handleRemovePod removes rules from port table and
// rules programmed in the system based on implementation type (e.g. IPTABLES).
// This also removes pod annotation from pods that are not selected by service annotation.
func (c *NPLController) handleRemovePod(key string) error {
	klog.V(2).Infof("Got delete event for Pod: %s", key)
	podIP, found := c.getPodIPFromCache(key)
	if !found {
		klog.Infof("IP address not found for Pod: %s", key)
		return nil
	}

	if err := c.deleteAllPortRulesIfAny(podIP); err != nil {
		return err
	}

	c.deletePodIPFromCache(key)

	return nil
}

// handleAddUpdatePod handles Pod Add, Update events and updates annotation if required.
func (c *NPLController) handleAddUpdatePod(key string, obj interface{}) error {
	pod := obj.(*corev1.Pod)
	klog.V(2).Infof("Got add/update event for Pod: %s", key)

	podIP := pod.Status.PodIP
	if podIP == "" {
		klog.Infof("IP address not set for Pod: %s", key)
		return nil
	}
	c.addPodIPToCache(key, podIP)

	if !c.isNPLEnabledForServiceOfPod(obj) {
		if err := c.deleteAllPortRulesIfAny(podIP); err != nil {
			return err
		}
		if _, exists := pod.Annotations[NPLAnnotationKey]; exists {
			return CleanupNPLAnnotationForPod(c.kubeClient, *pod)
		}
		return nil
	}
	klog.V(2).Infof("Pod %s is selected by a Service for which NodePortLocal is enabled", key)

	var err error
	var updatePodAnnotation bool
	var nodePort int
	podPorts := make(map[int]struct{})
	podContainers := pod.Spec.Containers
	nplAnnotations := []NPLAnnotation{}

	podAnnotation, nplExists := pod.GetAnnotations()[NPLAnnotationKey]
	if nplExists {
		if err := json.Unmarshal([]byte(podAnnotation), &nplAnnotations); err != nil {
			klog.Warningf("Unable to unmarshal NodePortLocal annotation for Pod %s/%s",
				pod.Namespace, pod.Name)
			return nil
		}
	}

	for _, container := range podContainers {
		for _, cport := range container.Ports {
			port := int(cport.ContainerPort)
			podPorts[port] = struct{}{}
			if !c.portTable.RuleExists(podIP, int(cport.ContainerPort)) {
				nodePort, err = c.portTable.AddRule(podIP, port)
				if err != nil {
					return fmt.Errorf("failed to add rule for Pod %s: %v", key, err)
				}
				updatePodAnnotation = IsNPLAnnotationRequired(pod.Annotations, pod.Status.HostIP, port, nodePort)
				if updatePodAnnotation {
					nplAnnotations = append(nplAnnotations, NPLAnnotation{
						PodPort:  port,
						NodeIP:   pod.Status.HostIP,
						NodePort: nodePort,
					})
				}
			}
		}
	}

	entries := c.portTable.GetDataForPodIP(podIP)
	if nplExists {
		for _, data := range entries {
			if _, exists := podPorts[data.PodPort]; !exists {
				nplAnnotations = removeFromNPLAnnotation(nplAnnotations, data.PodPort)
				err := c.portTable.DeleteRule(podIP, int(data.PodPort))
				if err != nil {
					return fmt.Errorf("failed to delete rule for Pod IP %s, Pod Port %d: %s", podIP, data.PodPort, err.Error())
				}
				updatePodAnnotation = true
			}
		}
	}
	if updatePodAnnotation {
		return c.updatePodNPLAnnotation(pod, nplAnnotations)
	}
	return nil
}
