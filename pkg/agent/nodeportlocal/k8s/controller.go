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
	"time"

	"github.com/vmware-tanzu/antrea/pkg/agent/nodeportlocal/portcache"

	corev1 "k8s.io/api/core/v1"
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
	portTable  *portcache.PortTable
	kubeClient clientset.Interface
	queue      workqueue.RateLimitingInterface
	Ctrl       cache.Controller
	CacheStore cache.Store
	PodToIP    map[string]string
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

// Run starts to watch and process Pod updates for the Node where Antrea Agent is running.
// It starts a queue and a fixed number of workers to process the objects from the queue.
func (c *Controller) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()
	for i := 0; i < numWorkers; i++ {
		go wait.Until(c.Worker, time.Second, stopCh)
	}
	c.Ctrl.Run(stopCh)
	cache.WaitForCacheSync(stopCh, c.Ctrl.HasSynced)
	<-stopCh
}

func (c *Controller) syncPod(key string) error {
	obj, exists, err := c.CacheStore.GetByKey(key)
	if err != nil {
		return err
	} else if exists {
		return c.HandleAddUpdatePod(key, obj)
	} else {
		return c.HandleDeletePod(key)
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

func (c *Controller) EnqueueObjAdd(obj interface{}) {
	pod, isPod := obj.(*corev1.Pod)
	if !isPod {
		var err error
		pod, err = c.checkDeletedPod(obj)
		if err != nil {
			klog.Errorf("Got error while processing event update: %v", err)
			return
		}
	}
	podKey := pod.Namespace + "/" + pod.Name
	c.queue.Add(podKey)

}

func (c *Controller) EnqueueObjUpdate(oldObj, newObj interface{}) {
	pod, isPod := newObj.(*corev1.Pod)
	if !isPod {
		var err error
		pod, err = c.checkDeletedPod(newObj)
		if err != nil {
			klog.Errorf("Got error while processing event update: %v", err)
			return
		}
	}
	podKey := pod.Namespace + "/" + pod.Name
	c.queue.Add(podKey)

}

func (c *Controller) EnqueueObjDel(obj interface{}) {
	pod, isPod := obj.(*corev1.Pod)
	if !isPod {
		var err error
		pod, err = c.checkDeletedPod(obj)
		if err != nil {
			klog.Errorf("Got error while processing event update: %v", err)
			return
		}
	}
	podKey := pod.Namespace + "/" + pod.Name
	c.queue.Add(podKey)

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

func (c *Controller) addRuleForPod(pod *corev1.Pod) error {
	podIP, nodeIP := pod.Status.PodIP, pod.Status.HostIP
	if podIP == "" || nodeIP == "" {
		return nil
	}
	podContainers := pod.Spec.Containers

	for _, container := range podContainers {
		for _, cport := range container.Ports {
			port := int(cport.ContainerPort)
			if c.portTable.RuleExists(podIP, port) {
				continue
			}
			nodePort, err := c.portTable.AddRule(podIP, port)
			if err != nil {
				return err
			}
			assignPodAnnotation(pod, nodeIP, port, nodePort)
		}
	}
	return nil
}

// HandleDeletePod Removes rules from port table and
// rules programmed in the system based on implementation type (e.g. IPTABLES)
func (c *Controller) HandleDeletePod(key string) error {
	klog.Infof("Got delete event for Pod: %s", key)
	podIP, found := c.PodToIP[key]
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
	return nil
}

// HandleAddUpdatePod handles Pod Add, Update events and updates annotation if required
func (c *Controller) HandleAddUpdatePod(key string, obj interface{}) error {
	newPod := obj.(*corev1.Pod).DeepCopy()
	klog.Infof("Got add/update event for pod: %s", key)

	podIP := newPod.Status.PodIP
	if podIP == "" {
		klog.Infof("IP address not found for pod: %s/%s", newPod.Namespace, newPod.Name)
		return nil
	}
	c.PodToIP[key] = podIP

	var err error
	var updatePodAnnotation bool
	newPodPorts := make(map[int]struct{})
	newPodContainers := newPod.Spec.Containers
	for _, container := range newPodContainers {
		for _, cport := range container.Ports {
			port := int(cport.ContainerPort)
			newPodPorts[port] = struct{}{}
			if !c.portTable.RuleExists(podIP, int(cport.ContainerPort)) {
				err = c.addRuleForPod(newPod)
				if err != nil {
					return fmt.Errorf("Failed to add rule for Pod %s/%s: %s", newPod.Namespace, newPod.Name, err.Error())
				}
				updatePodAnnotation = true
			}
		}
	}

	var annotations []NPLAnnotation
	podAnnotation := newPod.GetAnnotations()
	entries := c.portTable.GetDataForPodIP(podIP)
	if podAnnotation != nil {
		if err := json.Unmarshal([]byte(podAnnotation[NPLAnnotationStr]), &annotations); err != nil {
			klog.Warningf("Unable to unmarshal NodePorLocal annotation")
			return nil
		}
		for _, data := range entries {
			if _, exists := newPodPorts[data.PodPort]; !exists {
				removeFromPodAnnotation(newPod, data.PodPort)
				err := c.portTable.DeleteRule(podIP, int(data.PodPort))
				if err != nil {
					return fmt.Errorf("Failed to delete rule for Pod IP %s, Pod Port %d: %s", podIP, data.PodPort, err.Error())
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
