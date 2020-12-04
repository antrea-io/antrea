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
	"fmt"
	"hash/fnv"
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

func bkt(key string, numWorkers uint32) uint32 {
	h := fnv.New32a()
	h.Write([]byte(key))
	bkt := h.Sum32() & (numWorkers - 1)
	return bkt
}

type Controller struct {
	portTable   *portcache.PortTable
	kubeClient  clientset.Interface
	queue       workqueue.RateLimitingInterface
	Ctrl        cache.Controller
	CacheStore  cache.Store
	OldObjStore cache.Store
}

func NewNPLController(kubeClient clientset.Interface, pt *portcache.PortTable) *Controller {
	nplCtrl := Controller{
		kubeClient:  kubeClient,
		portTable:   pt,
		OldObjStore: cache.NewStore(cache.MetaNamespaceKeyFunc),
	}
	nplCtrl.queue = workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "nodeportlocal")
	return &nplCtrl
}

// Run starts to watching and process Pod updates for the Node where Antrea Agent is running.
// It starts a fixed numbers of queues and one worker per queue to process the objects.
// Each object is mapped to one queue based on the hash of the object key. This ensures that
// update for one object always gets processes by the same worker.
func (c *Controller) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()
	for i := 0; i < numWorkers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
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
		return c.HandleAddPod(key, obj)
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
	//Add the old object so that this can be compared with the new object later.
	c.OldObjStore.Add(oldObj)
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
	//The old object data would be used to delete corresponding rules programmed in the system.
	c.OldObjStore.Add(obj)
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

func (c *Controller) worker() {
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
		klog.V(2).Infof("Successfully proceed key: %s, in queue", key)
		c.queue.Forget(key)
	} else {
		c.queue.AddRateLimited(key)
		klog.Errorf("Error syncing pod %s, requeuing. Error: %v", key, err)
	}
	return true
}
