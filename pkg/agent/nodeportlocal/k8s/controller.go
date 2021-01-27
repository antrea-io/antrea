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
			UpdateFunc: func(old, cur interface{}) {
				oldPod := old.(*corev1.Pod)
				curPod := cur.(*corev1.Pod)
				// Pod fields to watch for: ContainerPort, HostIP, PodIP,
				// Labels, Annotations (NPLAnnotationKey).
				if oldPod.ResourceVersion != curPod.ResourceVersion {
					c.enqueuePod(cur)
				}
			},
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
	} else if exists && c.isNPLEnabledForServiceOfPod(obj) {
		return c.handleAddUpdatePod(key, obj)
	} else {
		return c.handleRemovePod(key, obj)
	}
}

func (c *NPLController) checkDeletedPod(obj interface{}) (*corev1.Pod, error) {
	deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
	if !ok {
		return nil, fmt.Errorf("Received unexpected object: %v", obj)

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
		return nil, fmt.Errorf("Received unexpected object: %v", obj)
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

	// Return if Service ResourceVersions don't change.
	if oldSvc.ResourceVersion == newSvc.ResourceVersion {
		return
	}

	oldSvcAnnotation := oldSvc.Annotations[NPLEnabledAnnotationKey]
	newSvcAnnotation := newSvc.Annotations[NPLEnabledAnnotationKey]
	// Return if both Services donot have the NPL annotation.
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
		klog.Errorf("Got error while listing Services with annotation: %v", err)
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

// handleRemovePod removes rules from port table and
// rules programmed in the system based on implementation type (e.g. IPTABLES).
// This also removes pod annotation from pods that are not selected by service annotation.
func (c *NPLController) handleRemovePod(key string, obj interface{}) error {
	klog.Infof("Got delete event for Pod: %s", key)
	podIP, found := c.getPodIPFromCache(key)
	if !found {
		klog.Infof("IP address not found for Pod: %s", key)
		return nil
	}
	data := c.portTable.GetDataForPodIP(podIP)
	for _, d := range data {
		err := c.portTable.DeleteRule(d.PodIP, int(d.PodPort))
		if err != nil {
			return err
		}
	}

	if obj != nil {
		newPod := obj.(*corev1.Pod).DeepCopy()
		removePodAnnotation(newPod)
		return c.updatePodAnnotation(newPod)
	}
	return nil
}

// handleAddUpdatePod handles Pod Add, Update events and updates annotation if required.
func (c *NPLController) handleAddUpdatePod(key string, obj interface{}) error {
	newPod := obj.(*corev1.Pod).DeepCopy()
	klog.Infof("Got add/update event for pod: %s", key)

	podIP := newPod.Status.PodIP
	if podIP == "" {
		klog.Infof("IP address not found for pod: %s/%s", newPod.Namespace, newPod.Name)
		return nil
	}
	c.addPodIPToCache(key, podIP)

	var err error
	var updatePodAnnotation bool
	var nodePort int
	newPodPorts := make(map[int]struct{})
	newPodContainers := newPod.Spec.Containers
	for _, container := range newPodContainers {
		for _, cport := range container.Ports {
			port := int(cport.ContainerPort)
			newPodPorts[port] = struct{}{}
			if !c.portTable.RuleExists(podIP, int(cport.ContainerPort)) {
				nodePort, err = c.portTable.AddRule(podIP, port)
				if err != nil {
					return fmt.Errorf("failed to add rule for Pod %s/%s: %s", newPod.Namespace, newPod.Name, err.Error())
				}
				assignPodAnnotation(newPod, newPod.Status.HostIP, port, nodePort)
				updatePodAnnotation = true
			}
		}
	}

	var annotations []NPLAnnotation
	podAnnotation := newPod.GetAnnotations()
	entries := c.portTable.GetDataForPodIP(podIP)
	if podAnnotation != nil {
		if err := json.Unmarshal([]byte(podAnnotation[NPLAnnotationKey]), &annotations); err != nil {
			klog.Warningf("Unable to unmarshal NodePortLocal annotation")
			return nil
		}
		for _, data := range entries {
			if _, exists := newPodPorts[data.PodPort]; !exists {
				removeFromPodAnnotation(newPod, data.PodPort)
				err := c.portTable.DeleteRule(podIP, int(data.PodPort))
				if err != nil {
					return fmt.Errorf("failed to delete rule for Pod IP %s, Pod Port %d: %s", podIP, data.PodPort, err.Error())
				}
				updatePodAnnotation = true
			}
		}
	}

	if updatePodAnnotation {
		return c.updatePodAnnotation(newPod)
	}
	return nil
}
