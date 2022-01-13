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

// Package networkpolicy provides AntreaIPAMController implementation to manage
// and synchronize the GroupMembers and Namespaces affected by Network Policies and enforce
// their rules.
package ipam

import (
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	appsinformers "k8s.io/client-go/informers/apps/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	crdv1a2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	"antrea.io/antrea/pkg/client/clientset/versioned"
	"antrea.io/antrea/pkg/client/informers/externalversions"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha2"
	crdlisters "antrea.io/antrea/pkg/client/listers/crd/v1alpha2"
	"antrea.io/antrea/pkg/ipam/poolallocator"
	"antrea.io/antrea/pkg/util/k8s"
)

const (
	controllerName = "AntreaIPAMController"

	// TODO: currently these constants are duplicated, move to a shared place
	AntreaIPAMAnnotationKey       = "ipam.antrea.io/ippools"
	AntreaIPAMAnnotationDelimiter = ","

	// StatefulSet index name for IPPool cache.
	statefulSetIndex = "statefulSet"

	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second
)

// AntreaIPAMController is responsible for IP address cleanup
// for StatefulSet objects.
// In future, it will also be responsible for pre-allocation of
// continuous IP range for StatefulSets that do not have dedicated
// IP Pool annotation.
type AntreaIPAMController struct {
	// crdClient is the clientset for CRD API group.
	crdClient versioned.Interface

	// Pool cleanup events triggered by StatefulSet delete
	statefulSetCleanupQueue workqueue.RateLimitingInterface

	// follow changes for StatefulSet objects
	statefulSetInformer     appsinformers.StatefulSetInformer
	statefulSetListerSynced cache.InformerSynced

	// follow changes for IP Pool objects
	ipPoolInformer     crdinformers.IPPoolInformer
	ipPoolLister       crdlisters.IPPoolLister
	ipPoolListerSynced cache.InformerSynced
}

func statefulSetIndexFunc(obj interface{}) ([]string, error) {
	ipPool, ok := obj.(*crdv1a2.IPPool)
	if !ok {
		return nil, fmt.Errorf("obj is not IPPool: %+v", obj)
	}
	statefulSetNames := sets.NewString()
	for _, address := range ipPool.Status.IPAddresses {
		if address.Owner.StatefulSet != nil {
			statefulSetNames.Insert(k8s.NamespacedName(address.Owner.StatefulSet.Namespace, address.Owner.StatefulSet.Name))
		}
	}
	return statefulSetNames.UnsortedList(), nil
}

func NewAntreaIPAMController(crdClient versioned.Interface,
	informerFactory informers.SharedInformerFactory,
	crdInformerFactory externalversions.SharedInformerFactory) *AntreaIPAMController {

	ipPoolInformer := crdInformerFactory.Crd().V1alpha2().IPPools()
	ipPoolInformer.Informer().AddIndexers(cache.Indexers{statefulSetIndex: statefulSetIndexFunc})

	statefulSetInformer := informerFactory.Apps().V1().StatefulSets()

	c := &AntreaIPAMController{
		crdClient:               crdClient,
		statefulSetCleanupQueue: workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "statefulSetCleanup"),
		statefulSetInformer:     statefulSetInformer,
		statefulSetListerSynced: statefulSetInformer.Informer().HasSynced,
		ipPoolInformer:          ipPoolInformer,
		ipPoolLister:            ipPoolInformer.Lister(),
		ipPoolListerSynced:      ipPoolInformer.Informer().HasSynced,
	}

	// Add handlers for Stateful Set events.
	klog.V(2).InfoS("Subscribing for StatefulSet notifications", "controller", controllerName)
	statefulSetInformer.Informer().AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			DeleteFunc: c.enqueueStatefulSetDeleteEvent,
		},
	)

	return c
}

// Enqueue the StatefulSet delete notification to be processed by the worker
func (c *AntreaIPAMController) enqueueStatefulSetDeleteEvent(obj interface{}) {
	ss := obj.(*appsv1.StatefulSet)
	klog.V(2).InfoS("Delete notification", "StatefulSet", ss.Name)

	key := k8s.NamespacedName(ss.Namespace, ss.Name)
	c.statefulSetCleanupQueue.Add(key)
}

// Inspect all IPPools for stale IP Address entries.
// This may happen if controller was down during StatefulSet delete event.
// If such entry is found, enqueue cleanup event for this StatefulSet.
func (c *AntreaIPAMController) cleanupStaleStatefulSets() {
	pools, _ := c.ipPoolLister.List(labels.Everything())
	lister := c.statefulSetInformer.Lister()
	statefulSets, _ := lister.List(labels.Everything())
	statefulSetMap := make(map[string]bool)

	for _, ss := range statefulSets {
		// Prepare map of existing StatefulSets for quick reference below
		statefulSetMap[k8s.NamespacedName(ss.Namespace, ss.Name)] = true
	}

	for _, ipPool := range pools {
		for _, address := range ipPool.Status.IPAddresses {
			if address.Owner.StatefulSet != nil {
				key := k8s.NamespacedName(address.Owner.StatefulSet.Namespace, address.Owner.StatefulSet.Name)
				if _, ok := statefulSetMap[key]; !ok {
					// This entry refers to StatefulSet that no longer exists
					klog.InfoS("IPPool contains stale IPAddress for StatefulSet that no longer exists", "IPPool", ipPool.Name, "StatefulSet", key)
					c.statefulSetCleanupQueue.Add(key)
					// Mark this entry in map to ensure cleanup is enqueued only once
					statefulSetMap[key] = true
				}
			}
		}
	}
}

// Look for an IP Pool associated with this StatefulSet, either a dedicated one or
// annotated to the namespace. If IPPool is found, this routine will clear all IP
// addresses that might be reserved for the pool.
func (c *AntreaIPAMController) cleanIPPoolForStatefulSet(namespacedName string) error {
	klog.InfoS("Processing delete notification", "StatefulSet", namespacedName)
	ipPools, _ := c.ipPoolInformer.Informer().GetIndexer().ByIndex(statefulSetIndex, namespacedName)

	for _, item := range ipPools {
		ipPool := item.(*crdv1a2.IPPool)
		allocator, err := poolallocator.NewIPPoolAllocator(ipPool.Name, c.crdClient, c.ipPoolLister)
		if err != nil {
			// This is not a transient error - log and forget
			klog.ErrorS(err, "Failed to find IP Pool", "IPPool", ipPool.Name)
			continue
		}

		namespace, name := k8s.SplitNamespacedName(namespacedName)
		err = allocator.ReleaseStatefulSet(namespace, name)
		if err != nil {
			// This can be a transient error - worker will retry
			klog.ErrorS(err, "Failed to clean IP allocations", "StatefulSet", namespacedName, "IPPool", ipPool.Name)
			continue
		}
	}

	return nil
}

func (c *AntreaIPAMController) statefulSetWorker() {
	for c.processNextStatefulSetWorkItem() {
	}
}

func (c *AntreaIPAMController) processNextStatefulSetWorkItem() bool {
	key, quit := c.statefulSetCleanupQueue.Get()
	if quit {
		return false
	}

	defer c.statefulSetCleanupQueue.Done(key)
	err := c.cleanIPPoolForStatefulSet(key.(string))

	if err != nil {
		// Put the item back on the workqueue to handle any transient errors.
		c.statefulSetCleanupQueue.AddRateLimited(key)
		klog.ErrorS(err, "Failed to clean IP Pool for StatefulSet", "StatefulSet", key)
		return true
	}

	c.statefulSetCleanupQueue.Forget(key)
	return true
}

// Run begins watching and syncing of a AntreaIPAMController.
func (c *AntreaIPAMController) Run(stopCh <-chan struct{}) {

	defer c.statefulSetCleanupQueue.ShutDown()

	klog.InfoS("Starting", "controller", controllerName)
	defer klog.InfoS("Shutting down", "controller", controllerName)

	cacheSyncs := []cache.InformerSynced{c.statefulSetListerSynced, c.ipPoolListerSynced}
	if !cache.WaitForNamedCacheSync(controllerName, stopCh, cacheSyncs...) {
		return
	}

	// Make sure any stale StatefulSets that might be present in pools are cleaned up
	c.cleanupStaleStatefulSets()

	go wait.Until(c.statefulSetWorker, time.Second, stopCh)

	<-stopCh
}
