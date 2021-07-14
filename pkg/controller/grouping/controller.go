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

package grouping

import (
	"sync/atomic"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
	crdv1a2informers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha2"
	"antrea.io/antrea/pkg/features"
)

const (
	controllerName = "GroupEntityController"
	// Set resyncPeriod to 0 to disable resyncing.
	resyncPeriod time.Duration = 0
)

// eventsCounter is used to keep track of the number of occurrences of an event type. It uses the
// low-level atomic memory primitives from the sync/atomic package to provide atomic operations
// (Increment and Load).
// There is a known-bug on 32-bit architectures for sync/atomic:
// On ARM, 386, and 32-bit MIPS, it is the caller's responsibility to arrange for 64-bit alignment
// of 64-bit words accessed atomically. The first word in a variable or in an allocated struct,
// array, or slice can be relied upon to be 64-bit aligned.
// As a result, instances of eventsCounter should be allocated when using them in structs; they
// should not be embedded directly.
type eventsCounter struct {
	count uint64
}

func (c *eventsCounter) Increment() {
	atomic.AddUint64(&c.count, 1)
}

func (c *eventsCounter) Load() uint64 {
	return atomic.LoadUint64(&c.count)
}

type GroupEntityController struct {
	podInformer coreinformers.PodInformer
	// podListerSynced is a function which returns true if the Pod shared informer has been synced at least once.
	podListerSynced cache.InformerSynced
	// podAddEvents tracks the number of Pod Add events that have been processed.
	podAddEvents *eventsCounter

	externalEntityInformer crdv1a2informers.ExternalEntityInformer
	// externalEntityListerSynced is a function which returns true if the ExternalEntity shared informer has been synced at least once.
	externalEntityListerSynced cache.InformerSynced
	// externalEntityAddEvents tracks the number of ExternalEntity Add events that have been processed.
	externalEntityAddEvents *eventsCounter

	namespaceInformer coreinformers.NamespaceInformer
	// namespaceListerSynced is a function which returns true if the Namespace shared informer has been synced at least once.
	namespaceListerSynced cache.InformerSynced
	// namespaceAddEvents tracks the number of Namespace Add events that have been processed.
	namespaceAddEvents *eventsCounter

	groupEntityIndex *GroupEntityIndex
}

func NewGroupEntityController(groupEntityIndex *GroupEntityIndex,
	podInformer coreinformers.PodInformer,
	namespaceInformer coreinformers.NamespaceInformer,
	externalEntityInformer crdv1a2informers.ExternalEntityInformer) *GroupEntityController {
	c := &GroupEntityController{
		groupEntityIndex:           groupEntityIndex,
		podInformer:                podInformer,
		podListerSynced:            podInformer.Informer().HasSynced,
		podAddEvents:               new(eventsCounter),
		namespaceInformer:          namespaceInformer,
		namespaceListerSynced:      namespaceInformer.Informer().HasSynced,
		namespaceAddEvents:         new(eventsCounter),
		externalEntityInformer:     externalEntityInformer,
		externalEntityListerSynced: externalEntityInformer.Informer().HasSynced,
		externalEntityAddEvents:    new(eventsCounter),
	}
	// Add handlers for Pod events.
	podInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.addPod,
			UpdateFunc: c.updatePod,
			DeleteFunc: c.deletePod,
		},
		resyncPeriod,
	)
	// Add handlers for Namespace events.
	namespaceInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.addNamespace,
			UpdateFunc: c.updateNamespace,
			DeleteFunc: c.deleteNamespace,
		},
		resyncPeriod,
	)
	if features.DefaultFeatureGate.Enabled(features.AntreaPolicy) {
		// Add handlers for ExternalEntity events.
		externalEntityInformer.Informer().AddEventHandlerWithResyncPeriod(
			cache.ResourceEventHandlerFuncs{
				AddFunc:    c.addExternalEntity,
				UpdateFunc: c.updateExternalEntity,
				DeleteFunc: c.deleteExternalEntity,
			},
			resyncPeriod,
		)
	}
	return c
}

func (c *GroupEntityController) Run(stopCh <-chan struct{}) {
	klog.Infof("Starting %s", controllerName)
	defer klog.Infof("Shutting down %s", controllerName)

	cacheSyncs := []cache.InformerSynced{c.podListerSynced, c.namespaceListerSynced}
	// Wait for externalEntityListerSynced when AntreaPolicy feature gate is enabled.
	if features.DefaultFeatureGate.Enabled(features.AntreaPolicy) {
		cacheSyncs = append(cacheSyncs, c.externalEntityListerSynced)
	}
	if !cache.WaitForNamedCacheSync(controllerName, stopCh, cacheSyncs...) {
		return
	}
	// Get the number of initial resources after all cache are synced. The numbers will be used to determine whether
	// the groupEntityIndex has been initialized with the full list of each kind.
	initialPodCount := len(c.podInformer.Informer().GetStore().List())
	initialNamespaceCount := len(c.namespaceInformer.Informer().GetStore().List())
	initialExternalEntityCount := 0
	if features.DefaultFeatureGate.Enabled(features.AntreaPolicy) {
		initialExternalEntityCount = len(c.externalEntityInformer.Informer().GetStore().List())
	}

	// Wait until all event handlers process the initial resources before setting groupEntityIndex as synced.
	if err := wait.PollImmediateUntil(100*time.Millisecond, func() (done bool, err error) {
		if uint64(initialPodCount) > c.podAddEvents.Load() {
			return false, nil
		}
		if uint64(initialNamespaceCount) > c.namespaceAddEvents.Load() {
			return false, nil
		}
		if features.DefaultFeatureGate.Enabled(features.AntreaPolicy) {
			if uint64(initialExternalEntityCount) > c.externalEntityAddEvents.Load() {
				return false, nil
			}
		}
		return true, nil
	}, stopCh); err == nil {
		c.groupEntityIndex.setSynced(true)
	}

	<-stopCh
}

func (c *GroupEntityController) addPod(obj interface{}) {
	pod := obj.(*v1.Pod)
	klog.V(2).Infof("Processing Pod %s/%s ADD event, labels: %v", pod.Namespace, pod.Name, pod.Labels)
	c.groupEntityIndex.AddPod(pod)
	c.podAddEvents.Increment()
}

func (c *GroupEntityController) updatePod(_, curObj interface{}) {
	curPod := curObj.(*v1.Pod)
	klog.V(2).Infof("Processing Pod %s/%s UPDATE event, labels: %v", curPod.Namespace, curPod.Name, curPod.Labels)
	c.groupEntityIndex.AddPod(curPod)
}

func (c *GroupEntityController) deletePod(old interface{}) {
	pod, ok := old.(*v1.Pod)
	if !ok {
		tombstone, ok := old.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Error decoding object when deleting Pod, invalid type: %v", old)
			return
		}
		pod, ok = tombstone.Obj.(*v1.Pod)
		if !ok {
			klog.Errorf("Error decoding object tombstone when deleting Pod, invalid type: %v", tombstone.Obj)
			return
		}
	}
	c.groupEntityIndex.DeletePod(pod)
}

func (c *GroupEntityController) addNamespace(obj interface{}) {
	namespace := obj.(*v1.Namespace)
	klog.V(2).Infof("Processing Namespace %s ADD event, labels: %v", namespace.Name, namespace.Labels)
	c.groupEntityIndex.AddNamespace(namespace)
	c.namespaceAddEvents.Increment()
}

func (c *GroupEntityController) updateNamespace(_, curObj interface{}) {
	curNamespace := curObj.(*v1.Namespace)
	klog.V(2).Infof("Processing Namespace %s UPDATE event, labels: %v", curNamespace.Name, curNamespace.Labels)
	c.groupEntityIndex.AddNamespace(curNamespace)
}

func (c *GroupEntityController) deleteNamespace(old interface{}) {
	namespace, ok := old.(*v1.Namespace)
	if !ok {
		tombstone, ok := old.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Error decoding object when deleting Namespace, invalid type: %v", old)
			return
		}
		namespace, ok = tombstone.Obj.(*v1.Namespace)
		if !ok {
			klog.Errorf("Error decoding object tombstone when deleting Namespace, invalid type: %v", tombstone.Obj)
			return
		}
	}
	klog.V(2).Infof("Processing Namespace %s DELETE event, labels: %v", namespace.Name, namespace.Labels)
	c.groupEntityIndex.DeleteNamespace(namespace)
}

func (c *GroupEntityController) addExternalEntity(obj interface{}) {
	ee := obj.(*v1alpha2.ExternalEntity)
	klog.V(2).Infof("Processing ExternalEntity %s/%s ADD event, labels: %v", ee.GetNamespace(), ee.GetName(), ee.GetLabels())
	c.groupEntityIndex.AddExternalEntity(ee)
	c.externalEntityAddEvents.Increment()
}

func (c *GroupEntityController) updateExternalEntity(_, curObj interface{}) {
	curEE := curObj.(*v1alpha2.ExternalEntity)
	klog.V(2).Infof("Processing ExternalEntity %s/%s UPDATE event, labels: %v", curEE.GetNamespace(), curEE.GetName(), curEE.GetLabels())
	c.groupEntityIndex.AddExternalEntity(curEE)
}

func (c *GroupEntityController) deleteExternalEntity(old interface{}) {
	ee, ok := old.(*v1alpha2.ExternalEntity)
	if !ok {
		tombstone, ok := old.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Error decoding object when deleting ExternalEntity, invalid type: %v", old)
			return
		}
		ee, ok = tombstone.Obj.(*v1alpha2.ExternalEntity)
		if !ok {
			klog.Errorf("Error decoding object tombstone when deleting ExternalEntity, invalid type: %v", tombstone.Obj)
			return
		}
	}

	klog.V(2).Infof("Processing ExternalEntity %s/%s DELETE event, labels: %v", ee.GetNamespace(), ee.GetName(), ee.GetLabels())
	c.groupEntityIndex.DeleteExternalEntity(ee)
}
