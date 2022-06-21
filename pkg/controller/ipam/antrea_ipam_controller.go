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
	"context"
	"fmt"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	appsinformers "k8s.io/client-go/informers/apps/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	crdv1a2 "antrea.io/antrea/pkg/apis/crd/v1alpha2"
	"antrea.io/antrea/pkg/client/clientset/versioned"
	"antrea.io/antrea/pkg/client/informers/externalversions"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha2"
	crdlisters "antrea.io/antrea/pkg/client/listers/crd/v1alpha2"
	annotation "antrea.io/antrea/pkg/ipam"
	"antrea.io/antrea/pkg/ipam/poolallocator"
	"antrea.io/antrea/pkg/util/k8s"
)

const (
	controllerName = "AntreaIPAMController"

	// StatefulSet index name for IPPool cache.
	statefulSetIndex = "statefulSet"

	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second

	garbageCollectionInterval = 10 * time.Minute
)

// AntreaIPAMController is responsible for:
// * reserving continuous IP address space for StatefulSet (if available)
// * periodical cleanup of IP Pools in case stale addresses are present
type AntreaIPAMController struct {
	// crdClient is the clientset for CRD API group.
	crdClient versioned.Interface

	// Pool cleanup events triggered by StatefulSet add/delete
	statefulSetQueue workqueue.RateLimitingInterface

	// follow changes for Namespace objects
	namespaceLister       corelisters.NamespaceLister
	namespaceListerSynced cache.InformerSynced

	// follow changes for StatefulSet objects
	statefulSetInformer     appsinformers.StatefulSetInformer
	statefulSetListerSynced cache.InformerSynced

	// follow changes for Pods
	podLister         corelisters.PodLister
	podInformerSynced cache.InformerSynced

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

	namespaceInformer := informerFactory.Core().V1().Namespaces()
	podInformer := informerFactory.Core().V1().Pods()

	statefulSetInformer := informerFactory.Apps().V1().StatefulSets()

	c := &AntreaIPAMController{
		crdClient:               crdClient,
		statefulSetQueue:        workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "statefulSetPreallocationAndCleanup"),
		namespaceLister:         namespaceInformer.Lister(),
		namespaceListerSynced:   namespaceInformer.Informer().HasSynced,
		statefulSetInformer:     statefulSetInformer,
		statefulSetListerSynced: statefulSetInformer.Informer().HasSynced,
		podLister:               podInformer.Lister(),
		podInformerSynced:       podInformer.Informer().HasSynced,
		ipPoolInformer:          ipPoolInformer,
		ipPoolLister:            ipPoolInformer.Lister(),
		ipPoolListerSynced:      ipPoolInformer.Informer().HasSynced,
	}

	// Add handlers for Stateful Set events.
	// Note that update is not handled here: IP Pool annotation should not be
	// updated without recreating the resource
	klog.V(2).InfoS("Subscribing for StatefulSet notifications", "controller", controllerName)
	statefulSetInformer.Informer().AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.enqueueStatefulSetCreateEvent,
			DeleteFunc: c.enqueueStatefulSetDeleteEvent,
		},
	)

	return c
}

// Enqueue the StatefulSet create notification to be processed by the worker
func (c *AntreaIPAMController) enqueueStatefulSetCreateEvent(obj interface{}) {
	ss := obj.(*appsv1.StatefulSet)
	klog.V(2).InfoS("Create notification", "Namespace", ss.Namespace, "StatefulSet", ss.Name)

	key := k8s.NamespacedName(ss.Namespace, ss.Name)
	c.statefulSetQueue.Add(key)
}

// Enqueue the StatefulSet delete notification to be processed by the worker
func (c *AntreaIPAMController) enqueueStatefulSetDeleteEvent(obj interface{}) {
	ss := obj.(*appsv1.StatefulSet)
	klog.V(2).InfoS("Delete notification", "Namespace", ss.Namespace, "StatefulSet", ss.Name)

	key := k8s.NamespacedName(ss.Namespace, ss.Name)
	c.statefulSetQueue.Add(key)
}

// Inspect all IPPools for stale IP Address entries.
// This may happen if controller was down during StatefulSet delete event.
// If such entry is found, enqueue cleanup event for this StatefulSet.
func (c *AntreaIPAMController) cleanupStaleAddresses() {
	pools, _ := c.ipPoolLister.List(labels.Everything())
	lister := c.statefulSetInformer.Lister()
	statefulSets, _ := lister.List(labels.Everything())
	statefulSetMap := make(map[string]bool)

	klog.InfoS("Cleanup job for IP Pools started")

	for _, ss := range statefulSets {
		// Prepare map of existing StatefulSets for quick reference below
		statefulSetMap[k8s.NamespacedName(ss.Namespace, ss.Name)] = true
	}

	poolsUpdated := 0
	for _, ipPool := range pools {
		updateNeeded := false
		ipPoolCopy := ipPool.DeepCopy()
		var newList []crdv1a2.IPAddressState
		for _, address := range ipPoolCopy.Status.IPAddresses {
			// Cleanup reserved addresses
			if address.Owner.Pod != nil {
				_, err := c.podLister.Pods(address.Owner.Pod.Namespace).Get(address.Owner.Pod.Name)
				if err != nil && errors.IsNotFound(err) {
					klog.InfoS("IPPool contains stale IPAddress for Pod that no longer exists", "IPPool", ipPool.Name, "Namespace", address.Owner.Pod.Namespace, "Pod", address.Owner.Pod.Name)
					address.Owner.Pod = nil
					if address.Owner.StatefulSet != nil {
						address.Phase = crdv1a2.IPAddressPhaseReserved
					}
					updateNeeded = true
				}
			}
			if address.Owner.StatefulSet != nil {
				key := k8s.NamespacedName(address.Owner.StatefulSet.Namespace, address.Owner.StatefulSet.Name)
				if _, ok := statefulSetMap[key]; !ok {
					// This entry refers to StatefulSet that no longer exists
					klog.InfoS("IPPool contains stale IPAddress for StatefulSet that no longer exists", "IPPool", ipPool.Name, "Namespace", address.Owner.StatefulSet.Namespace, "StatefulSet", address.Owner.StatefulSet.Name)
					address.Owner.StatefulSet = nil
					updateNeeded = true

				}
			}

			if address.Owner.StatefulSet != nil || address.Owner.Pod != nil {
				newList = append(newList, address)
			}
		}

		if updateNeeded {
			ipPoolCopy.Status.IPAddresses = newList
			_, err := c.crdClient.CrdV1alpha2().IPPools().UpdateStatus(context.TODO(), ipPoolCopy, metav1.UpdateOptions{})
			if err != nil {
				// Next cleanup job will retry
				klog.ErrorS(err, "Updating IP Pool status failed", "IPPool", ipPool.Name)
			} else {
				poolsUpdated += 1
			}

		}
	}

	klog.InfoS("Cleanup job for IP Pools finished", "updated", poolsUpdated)
}

// Look for an IP Pool associated with this StatefulSet.
// If IPPool is found, this routine will clear all addresses that might be reserved for the pool.
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

// Find IP Pools annotated to StatefulSet via direct annotation or Namespace annotation
func (c *AntreaIPAMController) getIPPoolsForStatefulSet(ss *appsv1.StatefulSet) []string {

	// Inspect pool annotation for the Pods
	// In order to avoid extra API call in IPAM driver, IPAM annotations are defined
	// on Pods rather than on StatefulSet
	annotations, exists := ss.Spec.Template.Annotations[annotation.AntreaIPAMAnnotationKey]
	if exists {
		// Stateful Set Pod is annotated with dedicated IP pool
		return strings.Split(annotations, annotation.AntreaIPAMAnnotationDelimiter)
	}

	// Inspect Namespace
	namespace, err := c.namespaceLister.Get(ss.Namespace)
	if err != nil {
		// Should never happen
		klog.Errorf("Namespace %s not found for StatefulSet %s", ss.Namespace, ss.Name)
		return nil
	}

	annotations, exists = namespace.Annotations[annotation.AntreaIPAMAnnotationKey]
	if exists {
		return strings.Split(annotations, annotation.AntreaIPAMAnnotationDelimiter)
	}

	return nil

}

// Look for an IP Pool associated with this StatefulSet, either a dedicated one or
// annotated to the Namespace. If such IP Pool is found, preallocate IPs for the StatefulSet.
// This function returns error if pool is not found, or allocation fails.
func (c *AntreaIPAMController) preallocateIPPoolForStatefulSet(ss *appsv1.StatefulSet) error {
	klog.InfoS("Processing create notification", "Namespace", ss.Namespace, "StatefulSet", ss.Name)

	ipPools := c.getIPPoolsForStatefulSet(ss)

	if ipPools == nil {
		// nothing to preallocate
		return nil
	}

	if len(ipPools) > 1 {
		return fmt.Errorf("annotation of multiple IP Pools is not supported")
	}

	// Only one pool is supported for now. Dual stack support coming in future.
	ipPoolName := ipPools[0]
	allocator, err := poolallocator.NewIPPoolAllocator(ipPoolName, c.crdClient, c.ipPoolLister)
	if err != nil {
		return fmt.Errorf("failed to find IP Pool %s: %s", ipPoolName, err)
	}

	size := int(*ss.Spec.Replicas)
	// Note that AllocateStatefulSet would not preallocate IPs if this StatefulSet is already present
	// in the pool. This safeguards us from double allocation in case agent allocated IP by the time
	// controller task is executed. Note also that StatefulSet resize will not be handled.
	if size > 0 {
		err = allocator.AllocateStatefulSet(ss.Namespace, ss.Name, size)
		if err != nil {
			return fmt.Errorf("failed to preallocate continuous IP space of size %d from Pool %s: %s", size, ipPoolName, err)
		}
	}

	return nil
}
func (c *AntreaIPAMController) statefulSetWorker() {
	for c.processNextStatefulSetWorkItem() {
	}
}

func (c *AntreaIPAMController) processNextStatefulSetWorkItem() bool {
	key, quit := c.statefulSetQueue.Get()
	if quit {
		return false
	}

	defer c.statefulSetQueue.Done(key)

	namespacedName := key.(string)
	namespace, name := k8s.SplitNamespacedName(namespacedName)
	ss, err := c.statefulSetInformer.Lister().StatefulSets(namespace).Get(name)

	if err != nil {
		if errors.IsNotFound(err) {
			// StatefulSet no longer present - clean up reserved pool IPs
			err = c.cleanIPPoolForStatefulSet(namespacedName)
			if err != nil {
				// Put the item back on the workqueue to handle any transient errors.
				c.statefulSetQueue.AddRateLimited(key)
				klog.ErrorS(err, "Failed to clean IP addresses reserved for StatefulSet from IP Pool", "StatefulSet", key)
				return true
			}
		} else {
			klog.ErrorS(err, "Failed to get StatefulSet", "StatefulSet", key)
		}
	} else {
		// StatefulSet was created - preallocate IPs based on replicas with best effort
		err := c.preallocateIPPoolForStatefulSet(ss)
		if err != nil {
			// Preallocation is best effort - we do not retry even with transient errors,
			// since we don't want to implement logic that would delay Pods while waiting for
			// preallocation.
			klog.ErrorS(err, "No IPs reserved for StatefulSet", "StatefulSet", key)
		}
	}

	c.statefulSetQueue.Forget(key)
	return true
}

// Run begins watching and syncing of a AntreaIPAMController.
func (c *AntreaIPAMController) Run(stopCh <-chan struct{}) {

	defer c.statefulSetQueue.ShutDown()

	klog.InfoS("Starting", "controller", controllerName)
	defer klog.InfoS("Shutting down", "controller", controllerName)

	cacheSyncs := []cache.InformerSynced{c.namespaceListerSynced, c.podInformerSynced, c.statefulSetListerSynced, c.ipPoolListerSynced}
	if !cache.WaitForNamedCacheSync(controllerName, stopCh, cacheSyncs...) {
		return
	}

	// Periodic cleanup IP Pools of stale IP addresses
	go wait.NonSlidingUntil(c.cleanupStaleAddresses, garbageCollectionInterval, stopCh)

	go wait.Until(c.statefulSetWorker, time.Second, stopCh)

	<-stopCh
}
