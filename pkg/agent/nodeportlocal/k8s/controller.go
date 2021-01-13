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
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/vmware-tanzu/antrea/pkg/agent/nodeportlocal/portcache"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
)

const (
	minRetryDelay = 2 * time.Second
	maxRetryDelay = 120 * time.Second
	numWorkers    = 4
)

type Controller struct {
	NodeName      string
	portTable     *portcache.PortTable
	kubeClient    clientset.Interface
	queue         workqueue.RateLimitingInterface
	PodController cache.Controller
	PodCacheStore cache.Store
	SvcController cache.Controller
	SvcCacheStore cache.Store
	PodToIP       map[string]string
	podIPLock     sync.RWMutex
}

func NewNPLController(kubeClient clientset.Interface, pt *portcache.PortTable) *Controller {
	nplCtrl := Controller{
		kubeClient: kubeClient,
		portTable:  pt,
		PodToIP:    make(map[string]string),
	}
	nplCtrl.queue = workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "nodeportlocal")
	return &nplCtrl
}

func podKeyFunc(pod *corev1.Pod) string {
	return pod.Namespace + "/" + pod.Name
}

// Run starts to watch and process Pod updates for the Node where Antrea Agent is running.
// It starts a queue and a fixed number of workers to process the objects from the queue.
func (c *Controller) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()
	for i := 0; i < numWorkers; i++ {
		go wait.Until(c.Worker, time.Second, stopCh)
	}

	go c.PodController.Run(stopCh)
	go c.SvcController.Run(stopCh)
	cache.WaitForCacheSync(stopCh, c.PodController.HasSynced)
	cache.WaitForCacheSync(stopCh, c.SvcController.HasSynced)
	<-stopCh
}

func (c *Controller) syncPod(key string) error {
	obj, exists, err := c.PodCacheStore.GetByKey(key)
	if err != nil {
		return err
	} else if exists && c.isNPLEnabledForServiceOfPod(obj) {
		return c.handleAddUpdatePod(key, obj)
	} else {
		return c.handleRemovePod(key, obj)
	}
}

func (c *Controller) checkDeletedPod(obj interface{}) (*corev1.Pod, error) {
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

func (c *Controller) EnqueuePod(obj interface{}) {
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

func (c *Controller) checkDeletedSvc(obj interface{}) (*corev1.Service, error) {
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

func (c *Controller) EnqueueSvcUpdate(oldObj, newObj interface{}) {
	// In case where the app selector in Service gets updated from one valid selector to another
	// both set of pods (corresponding to old and new selector) need to be considered
	newSvc, isSvc := newObj.(*corev1.Service)
	if !isSvc {
		var err error
		newSvc, err = c.checkDeletedSvc(newObj)
		if err != nil {
			klog.Errorf("Got error while processing event update: %v", err)
			return
		}
	}

	oldSvc := oldObj.(*corev1.Service)
	if oldSvc.ResourceVersion == newSvc.ResourceVersion {
		return
	}

	podKeys := append(c.getPodsFromService(oldSvc), c.getPodsFromService(newSvc)...)
	for _, podKey := range podKeys {
		c.queue.Add(podKey)
	}
}

func (c *Controller) EnqueueSvc(obj interface{}) {
	svc, isSvc := obj.(*corev1.Service)
	if !isSvc {
		var err error
		svc, err = c.checkDeletedSvc(obj)
		if err != nil {
			klog.Errorf("Got error while processing event update: %v", err)
			return
		}
	}

	for _, podKey := range c.getPodsFromService(svc) {
		c.queue.Add(podKey)
	}
}

func (c *Controller) getPodsFromService(svc *corev1.Service) []string {
	var pods []string
	annotations := svc.GetAnnotations()
	if val, ok := annotations[NPLServiceAnnotation]; !ok || (ok && val != "true") {
		return pods
	}

	appSelectorValue, ok := svc.Spec.Selector["app"]
	if !ok {
		return pods
	}

	listOptions := metav1.ListOptions{
		LabelSelector: labels.SelectorFromSet(labels.Set{"app": appSelectorValue}).String(),
		FieldSelector: fields.OneTermEqualSelector("spec.nodeName", c.NodeName).String(),
	}
	podList, err := c.kubeClient.CoreV1().Pods(metav1.NamespaceAll).List(context.TODO(), listOptions)
	if err != nil {
		klog.Errorf("Got error while listing pods: %v", err)
		return pods
	}
	for i := range podList.Items {
		pods = append(pods, podKeyFunc(&podList.Items[i]))
	}
	return pods
}

func (c *Controller) isNPLEnabledForServiceOfPod(obj interface{}) bool {
	pod := obj.(*corev1.Pod)
	appLabelValue, ok := pod.GetLabels()["app"]
	if !ok {
		return false
	}

	for _, service := range c.SvcCacheStore.List() {
		svc, isSvc := service.(*corev1.Service)
		// selecting services NOT of type NodePort, with matching app selector (with pod),
		// having appropriate annotation for enabling NPL
		if isSvc && svc.Spec.Type != corev1.ServiceTypeNodePort {
			if appSelectorVal, ok := svc.Spec.Selector["app"]; ok && appSelectorVal == appLabelValue {
				if val, ok := svc.GetAnnotations()[NPLServiceAnnotation]; ok && val == "true" {
					return true
				}
			}
		}
	}
	return false
}

func (c *Controller) Worker() {
	for c.processNextWorkItem() {
	}
}

func (c *Controller) processNextWorkItem() bool {
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

func (c *Controller) getPodIPFromCache(key string) (string, bool) {
	c.podIPLock.RLock()
	defer c.podIPLock.RUnlock()
	podIP, found := c.PodToIP[key]
	return podIP, found
}

func (c *Controller) addPodIPToCache(key, podIP string) {
	c.podIPLock.Lock()
	defer c.podIPLock.Unlock()
	c.PodToIP[key] = podIP
}

// handleRemovePod removes rules from port table and
// rules programmed in the system based on implementation type (e.g. IPTABLES)
// this also removes pod annotation from pods that are not selected by service annotation
func (c *Controller) handleRemovePod(key string, obj interface{}) error {
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

// handleAddUpdatePod handles Pod Add, Update events and updates annotation if required
func (c *Controller) handleAddUpdatePod(key string, obj interface{}) error {
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
		if err := json.Unmarshal([]byte(podAnnotation[NPLAnnotationStr]), &annotations); err != nil {
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
