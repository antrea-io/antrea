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

package crdmirroring

import (
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/controller/crdmirroring/types"
)

const (
	// maxRetries is the number of times a legacy CRD resource will be retried
	// before it is dropped out of the queue.
	maxRetries = 15

	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second

	defaultWorkers = 4
)

type Controller struct {
	informer           cache.SharedInformer
	listerSycned       cache.InformerSynced
	legacyInformer     cache.SharedInformer
	legacyListerSynced cache.InformerSynced

	workerLoopPeriod time.Duration
	queue            workqueue.RateLimitingInterface

	mirroringHandler types.MirroringHandler
	crdName          string
}

func NewController(informer, legacyInformer cache.SharedInformer, mirroringHandler types.MirroringHandler, crdName string) *Controller {
	c := &Controller{
		informer:         informer,
		legacyInformer:   legacyInformer,
		mirroringHandler: mirroringHandler,
		crdName:          crdName,
		queue:            workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), fmt.Sprintf("%v_mirroring", crdName)),
		workerLoopPeriod: time.Second,
	}

	handlers := cache.ResourceEventHandlerFuncs{
		AddFunc:    c.onNewCRDAdd,
		UpdateFunc: c.onNewCRDUpdate,
		DeleteFunc: c.onNewCRDDelete,
	}
	legacyHandlers := cache.ResourceEventHandlerFuncs{
		AddFunc:    c.onLegacyCRDAdd,
		UpdateFunc: c.onLegacyCRDUpdate,
		DeleteFunc: c.onLegacyCRDDelete,
	}

	c.informer.AddEventHandler(handlers)
	c.listerSycned = c.informer.HasSynced
	c.legacyInformer.AddEventHandler(legacyHandlers)
	c.legacyListerSynced = c.legacyInformer.HasSynced

	return c
}

func (c *Controller) Run(stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	klog.Infof("Starting %vMirroringController", c.crdName)
	defer klog.Infof("Shutting down %vMirroringController", c.crdName)

	if !cache.WaitForNamedCacheSync(fmt.Sprintf("%vMirroringController", c.crdName), stopCh, c.listerSycned, c.legacyListerSynced) {
		return
	}

	klog.Infof("Starting %d worker threads", defaultWorkers)
	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.worker, c.workerLoopPeriod, stopCh)
	}

	<-stopCh
}

func (c *Controller) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *Controller) processNextWorkItem() bool {
	cKey, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(cKey)

	err := c.syncMirroring(cKey.(string))
	c.handleErr(err, cKey)

	return true
}

func (c *Controller) syncMirroring(key string) error {
	startTime := time.Now()
	defer func() {
		klog.V(4).Infof("Finished syncing for %q legacy CRD. (%v)", key, time.Since(startTime))
	}()

	klog.V(4).Infof("Sync mirroring CRD (%q)", key)
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}

	// Get the legacy object, and if got an error that is not "IsNotFound", return the error
	legacyExist := true
	legacyObj, err := c.mirroringHandler.GetLegacyObject(namespace, name)
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to get legacy %s %s/%s: %v", c.crdName, namespace, name, err)
		} else {
			legacyExist = false
		}
	}

	// Get the new object, and if got an error that is not "IsNotFound", return the error
	newExist := true
	newObj, err := c.mirroringHandler.GetNewObject(namespace, name)
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to get new %s %s/%s: %v", c.crdName, namespace, name, err)
		} else {
			newExist = false
		}
	}

	// If neither the old object nor the new object exists, return
	if !legacyExist && !newExist {
		return nil
	}

	// If the legacy object annotated with "crd.antrea.io/stop-mirror" exists, and the new object does not
	// exist, create a new object.
	if legacyExist && !newExist {
		_, exist := legacyObj.GetAnnotations()[types.StopMirror]
		if !exist {
			klog.V(4).Infof("New %s %s/%s not found, mirroring a new %s", c.crdName, namespace, name, c.crdName)
			err = c.mirroringHandler.AddNewObject(legacyObj)
			if err != nil {
				return fmt.Errorf("failed to mirror new %s %s/%s：%v", c.crdName, namespace, name, err)
			}
		}
		return nil
	}

	// If the legacy object doesn't exist and the new object annotated with "crd.antrea.io/managed-by" exists,
	// delete the mirrored new object.
	if !legacyExist && newExist {
		_, managedByController := newObj.GetAnnotations()[types.ManagedBy]
		if managedByController {
			klog.V(4).Infof("Legacy %s %s/%s not found, deleting the mirrored new %s", c.crdName, namespace, name, c.crdName)
			err = c.mirroringHandler.DeleteNewObject(namespace, name)
			if err != nil {
				return fmt.Errorf("failed to delete mirrored new %s %s/%s: %v", c.crdName, namespace, name, err)
			}
		}
		return nil
	}

	// If both the legacy object and the new object exist, do something according their annotations.
	_, stopMirror := legacyObj.GetAnnotations()[types.StopMirror]
	_, managedByController := newObj.GetAnnotations()[types.ManagedBy]

	if managedByController {
		if !stopMirror {
			// Sync the legacy object's Spec and Labels to the new object.
			// Sync the new object's Status to the legacy object.
			klog.V(4).Infof("Sync data between legacy and new %s %s/%s", c.crdName, namespace, name)
			err = c.mirroringHandler.SyncObject(legacyObj, newObj)
			if err != nil {
				return fmt.Errorf("failed to sync data between legacy and new %s %s/%s: %v", c.crdName, namespace, name, err)
			}
		} else {
			// If the legacy object annotated with "crd.antrea.io/stop-mirror" and the new object annotated with "crd.antrea.io/managed-by",
			// this means that user wants to stop mirroring.
			klog.V(4).Infof("Update the mirrored new %s %s/%s, then mirroring is stopped", c.crdName, namespace, name)
			newObjCopied := deepCopy(newObj)
			delete(newObjCopied.GetAnnotations(), types.ManagedBy)

			err = c.mirroringHandler.UpdateNewObject(newObjCopied)
			if err != nil {
				return fmt.Errorf("failed to update the mirrored new %s %s/%s: %v", c.crdName, namespace, name, err)
			}
		}
	}

	return nil
}

func (c *Controller) queueCRD(obj interface{}) {
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("couldn't get key for object %+v (type %T): %v", obj, obj, err))
		return
	}
	c.queue.Add(key)
}

func (c *Controller) handleErr(err error, key interface{}) {
	if err == nil {
		c.queue.Forget(key)
		return
	}

	if c.queue.NumRequeues(key) < maxRetries {
		klog.Warningf("Error mirroring object for %q resource, retrying. Error: %v", key, err)
		c.queue.AddRateLimited(key)
		return
	}

	klog.Warningf("Retry budget exceeded, dropping %q resource out of the queue: %v", key, err)
	c.queue.Forget(key)
	utilruntime.HandleError(err)
}

func (c *Controller) onNewCRDAdd(obj interface{}) {
	crd := obj.(metav1.Object)

	_, exist := crd.GetAnnotations()[types.ManagedBy]
	if exist {
		klog.V(4).Infof("Processing mirroring %s %s/%s ADD event", c.crdName, crd.GetNamespace(), crd.GetName())
		c.queueCRD(obj)
	}
}

func (c *Controller) onNewCRDUpdate(prevObj, obj interface{}) {
	crd := obj.(metav1.Object)

	_, exist := crd.GetAnnotations()[types.ManagedBy]
	if exist {
		klog.V(4).Infof("Processing mirroring %s %s/%s UPDATE event", c.crdName, crd.GetNamespace(), crd.GetName())
		c.queueCRD(obj)
	}
}

func (c *Controller) onNewCRDDelete(obj interface{}) {
	crd := getCRDFromDeleteAction(obj)
	if crd == nil {
		return
	}

	_, exist := crd.GetAnnotations()[types.ManagedBy]
	if exist {
		klog.V(4).Infof("Processing mirroring %s %s/%s DELETE event", c.crdName, crd.GetNamespace(), crd.GetName())
		c.queueCRD(obj)
	}
}

func (c *Controller) onLegacyCRDAdd(obj interface{}) {
	crd := obj.(metav1.Object)

	_, exist := crd.GetAnnotations()[types.StopMirror]
	if !exist {
		klog.V(4).Infof("Processing legacy %s %s/%s ADD event", c.crdName, crd.GetNamespace(), crd.GetName())
		c.queueCRD(obj)
	}
}

func (c *Controller) onLegacyCRDUpdate(prevObj, obj interface{}) {
	prevCrd := prevObj.(metav1.Object)

	_, exist := prevCrd.GetAnnotations()[types.StopMirror]
	if !exist {
		klog.V(4).Infof("Processing legacy %s %s/%s UPDATE event", c.crdName, prevCrd.GetNamespace(), prevCrd.GetName())
		c.queueCRD(obj)
	}
}

func (c *Controller) onLegacyCRDDelete(obj interface{}) {
	crd := getCRDFromDeleteAction(obj)
	if crd == nil {
		return
	}

	_, exist := crd.GetAnnotations()[types.StopMirror]
	if !exist {
		klog.V(4).Infof("Processing legacy %s %s/%s DELETE event", c.crdName, crd.GetNamespace(), crd.GetName())
		c.queueCRD(obj)
	}
}

func getCRDFromDeleteAction(obj interface{}) metav1.Object {
	_, ok := obj.(metav1.Object)
	if ok {
		return obj.(metav1.Object)
	}
	tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("couldn't get object from tombstone %#v", obj))
		return nil
	}

	_, ok = tombstone.Obj.(metav1.Object)
	if ok {
		return tombstone.Obj.(metav1.Object)
	}
	utilruntime.HandleError(fmt.Errorf("tombstone contained object that is not an object resource: %#v", obj))
	return nil
}

func deepCopy(obj metav1.Object) metav1.Object {
	return obj.(runtime.Object).DeepCopyObject().(metav1.Object)
}
