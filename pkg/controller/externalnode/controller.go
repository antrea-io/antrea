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
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/apis/controlplane"
	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
	"antrea.io/antrea/pkg/apiserver/storage"
	clientset "antrea.io/antrea/pkg/client/clientset/versioned"
	eeinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha2"
	eelister "antrea.io/antrea/pkg/client/listers/crd/v1alpha2"
	antreatypes "antrea.io/antrea/pkg/controller/types"
	"antrea.io/antrea/pkg/util/k8s"
)

const (
	controllerName = "ExternalEntityController"
	// How long to wait before retrying the processing of an ExternalEntity change.
	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second
	// Default number of workers processing ExternalEntity changes.
	defaultWorkers = 4
	// Disable resyncing.
	resyncPeriod time.Duration = 0
)

var (
	keyFunc      = cache.DeletionHandlingMetaNamespaceKeyFunc
	splitKeyFunc = cache.SplitMetaNamespaceKey
)

type ExternalEntityController struct {
	crdClient clientset.Interface

	externalEntityInformer     eeinformers.ExternalEntityInformer
	externalEntityLister       eelister.ExternalEntityLister
	externalEntityListerSynced cache.InformerSynced

	externalEntityQueue workqueue.RateLimitingInterface

	externalEntityStore storage.Interface
}

func NewExternalEntityController(crdClient clientset.Interface, externalEntityInformer eeinformers.ExternalEntityInformer, externalEntityStore storage.Interface) *ExternalEntityController {
	c := &ExternalEntityController{
		crdClient:                  crdClient,
		externalEntityInformer:     externalEntityInformer,
		externalEntityLister:       externalEntityInformer.Lister(),
		externalEntityListerSynced: externalEntityInformer.Informer().HasSynced,
		externalEntityQueue:        workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "externalEntity"),
		externalEntityStore:        externalEntityStore,
	}
	c.externalEntityInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc: c.handleExternalEntity,
			UpdateFunc: func(oldObj, newObj interface{}) {
				c.handleExternalEntity(newObj)
			},
			DeleteFunc: c.handleExternalEntity,
		},
		resyncPeriod)
	return c
}

func (c *ExternalEntityController) handleExternalEntity(cur interface{}) {
	ee := cur.(*v1alpha2.ExternalEntity)
	klog.InfoS("Enqueuing K8s ExternalEntity", "ExternalEntity", klog.KObj(ee))
	key := k8s.NamespacedName(ee.Namespace, ee.Name)
	c.externalEntityQueue.Add(key)
}

func (c *ExternalEntityController) Run(stopCh <-chan struct{}) {
	defer c.externalEntityQueue.ShutDown()

	klog.Infof("Starting %s", controllerName)
	defer klog.Infof("Shutting down %s", controllerName)

	if !cache.WaitForNamedCacheSync(controllerName, stopCh, []cache.InformerSynced{c.externalEntityListerSynced}...) {
		return
	}
	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}
	<-stopCh
}

func (c *ExternalEntityController) worker() {
	for c.processExternalEntity() {
	}
}

func (c *ExternalEntityController) processExternalEntity() bool {
	key, quit := c.externalEntityQueue.Get()
	if quit {
		return false
	}
	defer c.externalEntityQueue.Done(key)

	err := c.syncExternalEntity(key.(string))
	if err != nil {
		// Put the item back on the workqueue to handle any transient errors.
		c.externalEntityQueue.AddRateLimited(key)
		klog.Errorf("Failed to sync  %s: %v", key, err)
		return true
	}
	// If no error occurs we Forget this item so it does not get queued again until
	// another change happens.
	c.externalEntityQueue.Forget(key)
	return true
}

func (c *ExternalEntityController) syncExternalEntity(key string) error {
	namespace, name := k8s.SplitNamespacedName(key)
	ee, err := c.externalEntityLister.ExternalEntities(namespace).Get(name)
	if err != nil {
		if errors.IsNotFound(err) {
			return c.externalEntityStore.Delete(key)
		} else {
			return err
		}
	}
	internalEE := c.convertExternalEntity(ee)
	_, found, _ := c.externalEntityStore.Get(key)
	if found {
		c.externalEntityStore.Update(internalEE)
	} else {
		c.externalEntityStore.Create(internalEE)
	}
	return nil
}

func (c *ExternalEntityController) convertExternalEntity(ee *v1alpha2.ExternalEntity) *antreatypes.ExternalEntity {
	var internalEndpoints []controlplane.Endpoint
	var internalPorts []controlplane.NamedPort
	for _, ep := range ee.Spec.Endpoints {
		internalEndpoints = append(internalEndpoints, controlplane.Endpoint{
			IP:   ep.IP,
			Name: ep.Name,
		})
	}
	for _, port := range ee.Spec.Ports {
		internalPorts = append(internalPorts, controlplane.NamedPort{
			Port:     port.Port,
			Name:     port.Name,
			Protocol: controlplane.Protocol(port.Protocol),
		})
	}
	internalEE := &antreatypes.ExternalEntity{
		Namespace:    ee.Namespace,
		Name:         ee.Name,
		UID:          ee.UID,
		Endpoints:    internalEndpoints,
		Ports:        internalPorts,
		ExternalNode: ee.Spec.ExternalNode,
		SpanMeta:     antreatypes.SpanMeta{NodeNames: sets.NewString(ee.Spec.ExternalNode)},
	}
	return internalEE
}
