// Copyright 2022 Antrea Authors
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

package externalnode

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
	clientset "antrea.io/antrea/pkg/client/clientset/versioned"
	externalnodeinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha1"
	externalentityinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha2"
	externalnodelisters "antrea.io/antrea/pkg/client/listers/crd/v1alpha1"
	externalentitylisters "antrea.io/antrea/pkg/client/listers/crd/v1alpha2"
	"antrea.io/antrea/pkg/util/externalnode"
	"antrea.io/antrea/pkg/util/k8s"
)

const (
	controllerName = "ExternalNodeController"
	// How long to wait before retrying the processing of an ExternalNode change.
	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second
	// Default number of workers processing ExternalNode changes.
	defaultWorkers = 4
	// Set resyncPeriod to 0 to disable resyncing.
	resyncPeriod time.Duration = 0
)

var (
	keyFunc      = cache.DeletionHandlingMetaNamespaceKeyFunc
	splitKeyFunc = cache.SplitMetaNamespaceKey
)

type ExternalNodeController struct {
	crdClient clientset.Interface

	externalNodeInformer     externalnodeinformers.ExternalNodeInformer
	externalNodeLister       externalnodelisters.ExternalNodeLister
	externalNodeListerSynced cache.InformerSynced

	externalEntityInformer     externalentityinformers.ExternalEntityInformer
	externalEntityLister       externalentitylisters.ExternalEntityLister
	externalEntityListerSynced cache.InformerSynced

	syncedExternalNode cache.Store
	// queue maintains the ExternalNode objects that need to be synced.
	queue workqueue.RateLimitingInterface
}

func NewExternalNodeController(crdClient clientset.Interface, externalNodeInformer externalnodeinformers.ExternalNodeInformer,
	externalEntityInformer externalentityinformers.ExternalEntityInformer) *ExternalNodeController {
	c := &ExternalNodeController{
		crdClient: crdClient,

		externalNodeInformer:     externalNodeInformer,
		externalNodeLister:       externalNodeInformer.Lister(),
		externalNodeListerSynced: externalNodeInformer.Informer().HasSynced,

		externalEntityInformer:     externalEntityInformer,
		externalEntityLister:       externalEntityInformer.Lister(),
		externalEntityListerSynced: externalEntityInformer.Informer().HasSynced,

		syncedExternalNode: cache.NewStore(keyFunc),
		queue:              workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "externalnode"),
	}
	c.externalNodeInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.enqueueExternalNodeAdd,
			UpdateFunc: c.enqueueExternalNodeUpdate,
			DeleteFunc: c.enqueueExternalNodeDelete,
		},
		resyncPeriod)
	return c
}

func (c *ExternalNodeController) enqueueExternalNodeAdd(obj interface{}) {
	en := obj.(*v1alpha1.ExternalNode)
	key, _ := keyFunc(en)
	c.queue.Add(key)
	klog.InfoS("Enqueued ExternalNode ADD event", "ExternalNode", klog.KObj(en))
}

func (c *ExternalNodeController) enqueueExternalNodeUpdate(oldObj interface{}, newObj interface{}) {
	en := newObj.(*v1alpha1.ExternalNode)
	key, _ := keyFunc(en)
	c.queue.Add(key)
	klog.InfoS("Enqueued ExternalNode UPDATE event", "ExternalNode", klog.KObj(en))
}

func (c *ExternalNodeController) enqueueExternalNodeDelete(obj interface{}) {
	en := obj.(*v1alpha1.ExternalNode)
	key, _ := keyFunc(en)
	c.queue.Add(key)
	klog.InfoS("Enqueued ExternalNode DELETE event", "ExternalNode", klog.KObj(en))
}

// Run will create defaultWorkers workers (goroutines) which will process the ExternalEntity events from the work queue.
func (c *ExternalNodeController) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	klog.InfoS("Starting", "controllerName", controllerName)
	defer klog.InfoS("Shutting down", "controllerName", controllerName)

	if !cache.WaitForNamedCacheSync(controllerName, stopCh, c.externalNodeListerSynced, c.externalEntityListerSynced) {
		return
	}
	if err := c.reconcileExternalNodes(); err != nil {
		klog.ErrorS(err, "Failed to reconcile ExternalNodes")
		return
	}

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}
	<-stopCh
}

// reconcileExternalNodes reconciles all the existing ExternalNodes and cleans up the stale ExternalEntities.
func (c *ExternalNodeController) reconcileExternalNodes() error {
	externalNodes, err := c.externalNodeLister.List(labels.Everything())
	if err != nil {
		return err
	}
	enUIDEENameMap := make(map[types.UID]string)
	for _, en := range externalNodes {
		if err = c.addExternalNode(en); err != nil {
			return err
		}
		eeName, err := externalnode.GenExternalEntityName(en)
		if err != nil {
			return err
		}
		enUIDEENameMap[en.UID] = eeName
	}
	externalEntities, err := c.externalEntityLister.List(labels.Everything())
	if err != nil {
		return err
	}
	for _, ee := range externalEntities {
		if (len(ee.OwnerReferences) > 0) && (ee.OwnerReferences[0].Kind == "ExternalNode") {
			// Clean up stale ExternalEntities when ExternalNode no longer exists or
			// when interface[0] name is changed.
			if eeName, ok := enUIDEENameMap[ee.OwnerReferences[0].UID]; !ok || (ok && (eeName != ee.Name)) {
				err = c.crdClient.CrdV1alpha2().ExternalEntities(ee.Namespace).Delete(context.TODO(), ee.Name, metav1.DeleteOptions{})
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// worker is a long-running function that will continually call the processNextWorkItem function in
// order to read and process a message on the work queue.
func (c *ExternalNodeController) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *ExternalNodeController) processNextWorkItem() bool {
	obj, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(obj)

	if key, ok := obj.(string); !ok {
		c.queue.Forget(obj)
		klog.Errorf("Expected string in ExternalNode work queue but got %#v", obj)
		return true
	} else if err := c.syncExternalNode(key); err == nil {
		// If no error occurs we Forget this item so it does not get queued again until
		// another change happens.
		c.queue.Forget(key)
	} else {
		// Put the item back on the workqueue to handle any transient errors.
		c.queue.AddRateLimited(key)
		klog.ErrorS(err, "Error syncing ExternalNode", "ExternalNode", key)
	}
	return true
}

func (c *ExternalNodeController) syncExternalNode(key string) error {
	namespace, name, err := splitKeyFunc(key)
	if err != nil {
		// This err should not occur.
		return err
	}
	en, err := c.externalNodeLister.ExternalNodes(namespace).Get(name)
	if errors.IsNotFound(err) {
		return c.deleteExternalNode(namespace, name)
	}

	preEn, exists, _ := c.syncedExternalNode.GetByKey(key)
	if !exists {
		return c.addExternalNode(en)
	} else {
		return c.updateExternalNode(preEn.(*v1alpha1.ExternalNode), en)
	}
}

// addExternalNode creates ExternalEntity for each NetworkInterface in the ExternalNode.
// Only one interface is supported for now and there should be one ExternalEntity generated for one ExternalNode.
func (c *ExternalNodeController) addExternalNode(en *v1alpha1.ExternalNode) error {
	eeName, err := externalnode.GenExternalEntityName(en)
	if err != nil {
		return err
	}
	ee, err := genExternalEntity(eeName, en)
	if err != nil {
		return err
	}
	err = c.createExternalEntity(ee)
	if err != nil {
		return err
	}
	c.syncedExternalNode.Add(en)
	return nil
}

func (c *ExternalNodeController) createExternalEntity(ee *v1alpha2.ExternalEntity) error {
	_, err := c.crdClient.CrdV1alpha2().ExternalEntities(ee.Namespace).Create(context.TODO(), ee, metav1.CreateOptions{})
	if errors.IsAlreadyExists(err) {
		klog.InfoS("Update ExternalEntity instead of creating it as it already exists", "ExternalEntity", klog.KObj(ee))
		return c.updateExternalEntity(ee)
	}
	return err
}

func (c *ExternalNodeController) updateExternalNode(preEn *v1alpha1.ExternalNode, curEn *v1alpha1.ExternalNode) error {
	if reflect.DeepEqual(preEn.Spec.Interfaces, curEn.Spec.Interfaces) && reflect.DeepEqual(preEn.Labels, curEn.Labels) {
		return nil
	}
	// Delete the previous ExternalEntity and create a new one if the name of the generated ExternalEntity is changed.
	// Otherwise, update the ExternalEntity.
	preEEName, err := externalnode.GenExternalEntityName(preEn)
	if err != nil {
		return err
	}
	curEEName, err := externalnode.GenExternalEntityName(curEn)
	if err != nil {
		return err
	}

	if preEEName != curEEName {
		if err = c.deleteExternalEntity(preEn.Namespace, preEEName); err != nil {
			return err
		}
		curEE, err := genExternalEntity(curEEName, curEn)
		if err != nil {
			return err
		}
		if err = c.createExternalEntity(curEE); err != nil {
			return err
		}

	} else {
		preIPs := sets.New[string](preEn.Spec.Interfaces[0].IPs...)
		curIPs := sets.New[string](curEn.Spec.Interfaces[0].IPs...)
		if (!reflect.DeepEqual(preEn.Labels, curEn.Labels)) || (!preIPs.Equal(curIPs)) {
			updatedEE, err := genExternalEntity(curEEName, curEn)
			if err != nil {
				return err
			}
			if err = c.updateExternalEntity(updatedEE); err != nil {
				return err
			}
		}
	}
	c.syncedExternalNode.Update(curEn)
	return nil
}
func (c *ExternalNodeController) updateExternalEntity(ee *v1alpha2.ExternalEntity) error {
	// resourceVersion must be specified for update operation,
	// so it gets the existing ExternalEntity and modifies the changed fields.
	existingEE, err := c.crdClient.CrdV1alpha2().ExternalEntities(ee.Namespace).Get(context.TODO(), ee.Name, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			_, err = c.crdClient.CrdV1alpha2().ExternalEntities(ee.Namespace).Create(context.TODO(), ee, metav1.CreateOptions{})
			if err != nil {
				klog.ErrorS(err, "Failed to create ExternalEntity", "entityName", ee.Name, "entityNamespace", ee.Namespace)
				return err
			}
			return nil
		}
		klog.ErrorS(err, "Failed to get ExternalEntity", "entityName", ee.Name, "entityNamespace", ee.Namespace)
		return err
	}
	isChanged := false
	if !reflect.DeepEqual(existingEE.Spec, ee.Spec) {
		existingEE.Spec = ee.Spec
		isChanged = true
	}
	if !reflect.DeepEqual(existingEE.Labels, ee.Labels) {
		existingEE.Labels = ee.Labels
		isChanged = true
	}
	if isChanged {
		_, err := c.crdClient.CrdV1alpha2().ExternalEntities(ee.Namespace).Update(context.TODO(), existingEE, metav1.UpdateOptions{})
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *ExternalNodeController) deleteExternalNode(namespace string, name string) error {
	obj, exists, _ := c.syncedExternalNode.GetByKey(k8s.NamespacedName(namespace, name))
	if !exists {
		klog.InfoS("Skipping deleting ExternalNode as it does not exist", "enName", namespace, "enNamespace", namespace)
		return nil
	}
	en := obj.(*v1alpha1.ExternalNode)
	eeName, err := externalnode.GenExternalEntityName(en)
	if err != nil {
		return err
	}
	err = c.deleteExternalEntity(namespace, eeName)
	if err != nil {
		return err
	}
	c.syncedExternalNode.Delete(en)
	return nil
}

func (c *ExternalNodeController) deleteExternalEntity(namespace string, name string) error {
	err := c.crdClient.CrdV1alpha2().ExternalEntities(namespace).Delete(context.TODO(), name, metav1.DeleteOptions{})
	if errors.IsNotFound(err) {
		klog.InfoS("Skipping deleting ExternalEntity as it is not found", "eeName", name, "eeNamespace", namespace)
		return nil
	}
	return err
}

func genExternalEntity(eeName string, en *v1alpha1.ExternalNode) (*v1alpha2.ExternalEntity, error) {
	ownerRef := &metav1.OwnerReference{
		APIVersion: "crd.antrea.io/v1alpha1",
		Kind:       externalnode.EntityOwnerKind,
		Name:       en.GetName(),
		UID:        en.GetUID(),
	}
	endpoints := make([]v1alpha2.Endpoint, 0)
	if len(en.Spec.Interfaces[0].IPs) == 0 {
		// This should not happen since openAPIV3Schema checks it.
		return nil, fmt.Errorf("failed to get IPs form Interfaces[0] from ExternalNode %s", en.Name)
	}
	// Generate one/multiple endpoint(s) if one/multiple IP(s) are specified for interface[0]
	for _, ip := range en.Spec.Interfaces[0].IPs {
		endpoints = append(endpoints, v1alpha2.Endpoint{
			IP:   ip,
			Name: en.Spec.Interfaces[0].Name,
		})
	}
	ee := &v1alpha2.ExternalEntity{
		ObjectMeta: metav1.ObjectMeta{
			Name:            eeName,
			Namespace:       en.Namespace,
			OwnerReferences: []metav1.OwnerReference{*ownerRef},
			Labels:          en.Labels,
		},
		Spec: v1alpha2.ExternalEntitySpec{
			Endpoints:    endpoints,
			ExternalNode: en.Name,
		},
	}
	return ee, nil
}
