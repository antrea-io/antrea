// Copyright 2019 Antrea Authors
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

// Package networkpolicy provides NetworkPolicyController implementation to manage
// and synchronize the Pods and Namespaces affected by Network Policies and enforce
// their rules.

package networkpolicy

import (
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	networkinginformers "k8s.io/client-go/informers/networking/v1"
	clientset "k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	networkinglisters "k8s.io/client-go/listers/networking/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
)

const (
	// Interval of synchronizing status from apiserver.
	syncPeriod = 60 * time.Second
	// How long to wait before retrying the processing of a NetworkPolicy change.
	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second
	// Default number of workers processing a NetworkPolicy change.
	defaultWorkers = 4
)

var (
	keyFunc = cache.DeletionHandlingMetaNamespaceKeyFunc
)

// NetworkPolicyController is responsible for synchronizing the Namespaces and Pods
// affected by a Network Policy.
type NetworkPolicyController struct {
	kubeClient  clientset.Interface
	podInformer coreinformers.PodInformer

	// podLister is able to list/get Pods and is populated by the shared informer passed to
	// NewNetworkPolicyController.
	podLister corelisters.PodLister

	// podListerSynced is a function which returns true if the Pod shared informer has been synced at least once.
	podListerSynced cache.InformerSynced

	namespaceInformer coreinformers.NamespaceInformer

	// namespaceLister is able to list/get Namespaces and is populated by the shared informer passed to
	// NewNetworkPolicyController.
	namespaceLister corelisters.NamespaceLister

	// namespaceListerSynced is a function which returns true if the Namespace shared informer has been synced at least once.
	namespaceListerSynced cache.InformerSynced

	networkPolicyInformer networkinginformers.NetworkPolicyInformer

	// networkPolicyLister is able to list/get Network Policies and is populated by the shared informer passed to
	// NewNetworkPolicyController.
	networkPolicyLister networkinglisters.NetworkPolicyLister

	// networkPolicyListerSynced is a function which returns true if the Network Policy shared informer has been synced at least once.
	networkPolicyListerSynced cache.InformerSynced

	// queue maintains the Network Policies that need to be synced.
	queue workqueue.RateLimitingInterface
}

// NewNetworkPolicyController returns a new *NetworkPolicyController.
func NewNetworkPolicyController(kubeClient clientset.Interface, podInformer coreinformers.PodInformer, namespaceInformer coreinformers.NamespaceInformer, networkPolicyInformer networkinginformers.NetworkPolicyInformer) *NetworkPolicyController {
	n := &NetworkPolicyController{
		kubeClient:                kubeClient,
		podInformer:               podInformer,
		podLister:                 podInformer.Lister(),
		podListerSynced:           podInformer.Informer().HasSynced,
		namespaceInformer:         namespaceInformer,
		namespaceLister:           namespaceInformer.Lister(),
		namespaceListerSynced:     namespaceInformer.Informer().HasSynced,
		networkPolicyInformer:     networkPolicyInformer,
		networkPolicyLister:       networkPolicyInformer.Lister(),
		networkPolicyListerSynced: networkPolicyInformer.Informer().HasSynced,
		queue:                     workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "networkpolicy"),
	}
	podInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(cur interface{}) {
			},
			UpdateFunc: func(old, cur interface{}) {
			},
			DeleteFunc: func(old interface{}) {
			},
		},
		syncPeriod,
	)
	namespaceInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(cur interface{}) {
			},
			UpdateFunc: func(old, cur interface{}) {
			},
			DeleteFunc: func(old interface{}) {
			},
		},
		syncPeriod,
	)
	networkPolicyInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(cur interface{}) {
				n.enqueueNetworkPolicy(cur)
			},
			UpdateFunc: func(old, cur interface{}) {
				n.enqueueNetworkPolicy(cur)
			},
			DeleteFunc: func(old interface{}) {
				n.enqueueNetworkPolicy(old)
			},
		},
		syncPeriod,
	)
	return n
}

// enqueueNetworkPolicy adds an object to the controller work queue
// obj could be an *v1.NetworkPolicy, or a DeletionFinalStateUnknown item.
func (n *NetworkPolicyController) enqueueNetworkPolicy(obj interface{}) {
	key, err := keyFunc(obj)
	if err != nil {
		klog.Errorf("Couldn't get key for object %+v: %v", obj, err)
		return
	}

	n.queue.Add(key)
}

// Run begins watching and syncing of a NetworkPolicyController.
func (n *NetworkPolicyController) Run(stopCh <-chan struct{}) {
	defer n.queue.ShutDown()

	klog.Info("Starting NetworkPolicy controller")
	defer klog.Info("Shutting down NetworkPolicy controller")

	klog.Info("Waiting for caches to sync for NetworkPolicy controller")
	if !cache.WaitForCacheSync(stopCh, n.podListerSynced, n.namespaceListerSynced, n.networkPolicyListerSynced) {
		klog.Error("Unable to sync caches for NetworkPolicy controller")
		return
	}
	klog.Info("Caches are synced for NetworkPolicy controller")

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(n.worker, time.Second, stopCh)
	}
	<-stopCh
}

// worker runs a worker thread that just dequeues items, processes them, and marks them done.
// It enforces that the syncNetworkPolicy is never invoked concurrently with the same key.
func (n *NetworkPolicyController) worker() {
	for n.processNextWorkItem() {
	}
}

// processNextWorkItem retrieves a NetworkPolicy object from the WorkQueue until a shutdown signal is received.
func (n *NetworkPolicyController) processNextWorkItem() bool {
	obj, quit := n.queue.Get()
	if quit {
		return false
	}
	// We defer the call to Done so that the workqueue knows we have finished processing this item. We also
	// must remember to call Forget if we do not want this work item being re-queued. For
	// example, we do not call Forget if a transient error occurs, instead the item is put back
	// on the workqueue and attempted again after a back-off period.
	defer n.queue.Done(obj)

	// We expect strings ("NamespaceName/NetworkPolicyName") to come off the workqueue.
	key, ok := obj.(string)
	if !ok {
		// As the item in the workqueue is actually invalid, we call Forget here else we'd
		// go into a loop of attempting to process a work item that is invalid.
		// This should not happen: enqueueNetworkPolicy only enqueues strings.
		n.queue.Forget(obj)
		klog.Errorf("Expected string in work queue but got %#v", obj)
		return true
	}
	err := n.syncNetworkPolicy(key)
	if err != nil {
		// Put the item back on the workqueue to handle any transient errors.
		n.queue.AddRateLimited(key)
		klog.Errorf("Error syncing NetworkPolicy %s, requeuing. Error: %v", key, err)
		return true
	}
	// If no error occurs we Forget this item so it does not get queued again until
	// another change happens.
	n.queue.Forget(key)
	return true
}

func (n *NetworkPolicyController) syncNetworkPolicy(key string) error {
	startTime := time.Now()
	defer func() {
		klog.V(4).Infof("Finished syncing NetworkPolicy %s. (%v)", key, time.Since(startTime))
	}()

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	networkPolicy, err := n.networkPolicyLister.NetworkPolicies(namespace).Get(name)
	if err != nil {
		return fmt.Errorf("failed to get NetworkPolicy %s: %v", key, err)
	}
	klog.Infof("Syncing NetworkPolicy %s: %v", key, networkPolicy.Spec.PodSelector)
	return nil
}
