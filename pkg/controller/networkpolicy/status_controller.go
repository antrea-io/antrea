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

package networkpolicy

import (
	"context"
	"sync"
	"time"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"github.com/vmware-tanzu/antrea/pkg/apis/controlplane"
	secv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/security/v1alpha1"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/storage"
	antreaclientset "github.com/vmware-tanzu/antrea/pkg/client/clientset/versioned"
	secinformers "github.com/vmware-tanzu/antrea/pkg/client/informers/externalversions/security/v1alpha1"
	seclisters "github.com/vmware-tanzu/antrea/pkg/client/listers/security/v1alpha1"
	"github.com/vmware-tanzu/antrea/pkg/controller/metrics"
	antreatypes "github.com/vmware-tanzu/antrea/pkg/controller/types"
)

const (
	statusControllerName = "NetworkPolicyStatusController"
)

// StatusController is responsible for synchronizing the status of Antrea ClusterNetworkPolicy and Antrea NetworkPolicy.
type StatusController struct {
	// npControlInterface knows how to update Antrea NetworkPolicy status.
	npControlInterface networkPolicyControlInterface

	// queue maintains the keys of the NetworkPolicy objects that need to be synced.
	queue workqueue.RateLimitingInterface

	// internalNetworkPolicyStore is the storage where the populated internal Network Policy are stored.
	internalNetworkPolicyStore storage.Interface

	// statuses is a nested map that keeps the realization statuses reported by antrea-agents.
	// The outer map's keys are the NetworkPolicy keys. The inner map's keys are the Node names. The inner map's values
	// are statuses reported by each Node for a NetworkPolicy.
	statuses     map[string]map[string]*controlplane.NetworkPolicyNodeStatus
	statusesLock sync.RWMutex

	// cnpLister is able to list/get ClusterNetworkPolicies and is populated by the shared informer passed to
	// NewClusterNetworkPolicyController.
	cnpLister seclisters.ClusterNetworkPolicyLister
	// cnpListerSynced is a function which returns true if the ClusterNetworkPolicies shared informer has been synced at least once.
	cnpListerSynced cache.InformerSynced
	// anpLister is able to list/get AntreaNetworkPolicies and is populated by the shared informer passed to
	// NewNetworkPolicyController.
	anpLister seclisters.NetworkPolicyLister
	// anpListerSynced is a function which returns true if the AntreaNetworkPolicies shared informer has been synced at least once.
	anpListerSynced cache.InformerSynced
}

func NewStatusController(antreaClient antreaclientset.Interface, internalNetworkPolicyStore storage.Interface, cnpInformer secinformers.ClusterNetworkPolicyInformer, anpInformer secinformers.NetworkPolicyInformer) *StatusController {
	c := &StatusController{
		npControlInterface: &networkPolicyControl{
			antreaClient: antreaClient,
			anpLister:    anpInformer.Lister(),
			cnpLister:    cnpInformer.Lister(),
		},
		queue:                      workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "networkpolicy"),
		internalNetworkPolicyStore: internalNetworkPolicyStore,
		statuses:                   map[string]map[string]*controlplane.NetworkPolicyNodeStatus{},
		cnpListerSynced:            cnpInformer.Informer().HasSynced,
		anpListerSynced:            anpInformer.Informer().HasSynced,
	}
	// To save a "GET" query before each update, UpdateAntreaClusterNetworkPolicyStatus treats the cache of Lister as
	// the state of kube-apiserver. In some cases the cache may not be in sync, then we might skip updating a policy's
	// status by mistake. To resolve it, add update event handlers which trigger resync of a policy if its status is
	// updated. This could also ensure we can reconcile a policy's status if it's updated by other clients by accident.
	// However, a normal update made by the controller itself will trigger resync as well, which could lead to duplicate
	// computation.
	// TODO: Evaluate if we can avoid the duplicate computation by comparing the updated status with some internal state.
	cnpInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			UpdateFunc: c.updateCNP,
		},
		resyncPeriod,
	)
	anpInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			UpdateFunc: c.updateANP,
		},
		resyncPeriod,
	)
	return c
}

func (c *StatusController) updateCNP(old, cur interface{}) {
	curCNP := cur.(*secv1alpha1.ClusterNetworkPolicy)
	oldCNP := old.(*secv1alpha1.ClusterNetworkPolicy)
	if oldCNP.Status == curCNP.Status {
		return
	}
	key := internalNetworkPolicyKeyFunc(oldCNP)
	c.queue.Add(key)
}

func (c *StatusController) updateANP(old, cur interface{}) {
	curANP := cur.(*secv1alpha1.NetworkPolicy)
	oldANP := old.(*secv1alpha1.NetworkPolicy)
	if oldANP.Status == curANP.Status {
		return
	}
	key := internalNetworkPolicyKeyFunc(oldANP)
	c.queue.Add(key)
}

func (c *StatusController) UpdateStatus(status *controlplane.NetworkPolicyStatus) error {
	key := status.Name
	_, found, _ := c.internalNetworkPolicyStore.Get(key)
	if !found {
		klog.Infof("NetworkPolicy %s has been deleted, skip updating its status", key)
		return nil
	}
	func() {
		c.statusesLock.Lock()
		defer c.statusesLock.Unlock()
		statusPerNode, exists := c.statuses[key]
		if !exists {
			statusPerNode = map[string]*controlplane.NetworkPolicyNodeStatus{}
			c.statuses[key] = statusPerNode
		}
		for i := range status.Nodes {
			statusPerNode[status.Nodes[i].NodeName] = &status.Nodes[i]
		}
	}()
	c.queue.Add(key)
	return nil
}

func (c *StatusController) getNodeStatuses(key string) []*controlplane.NetworkPolicyNodeStatus {
	c.statusesLock.RLock()
	defer c.statusesLock.RUnlock()
	statusPerNode, exists := c.statuses[key]
	if !exists {
		return nil
	}
	statuses := make([]*controlplane.NetworkPolicyNodeStatus, 0, len(c.statuses[key]))
	for _, status := range statusPerNode {
		statuses = append(statuses, status)
	}
	return statuses
}

func (c *StatusController) clearStatuses(key string) {
	c.statusesLock.Lock()
	defer c.statusesLock.Unlock()
	delete(c.statuses, key)
}

func (c *StatusController) deleteNodeStatus(key string, nodeName string) {
	c.statusesLock.Lock()
	defer c.statusesLock.Unlock()
	statusPerNode, exists := c.statuses[key]
	if !exists {
		return
	}
	delete(statusPerNode, nodeName)
}

// Run begins watching and syncing of a StatusController.
func (c *StatusController) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	klog.Infof("Starting %s", statusControllerName)
	defer klog.Infof("Shutting down %s", statusControllerName)

	if !cache.WaitForNamedCacheSync(statusControllerName, stopCh, c.cnpListerSynced, c.anpListerSynced) {
		return
	}

	go wait.NonSlidingUntil(c.watchInternalNetworkPolicy, 5*time.Second, stopCh)

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.runWorker, time.Second, stopCh)
	}
	<-stopCh
}

func (c *StatusController) watchInternalNetworkPolicy() {
	watcher, err := c.internalNetworkPolicyStore.Watch(context.TODO(), "", labels.Everything(), fields.Everything())
	if err != nil {
		klog.Errorf("Failed to start watch for internal NetworkPolicy: %v", err)
		return
	}
	defer watcher.Stop()
	resultCh := watcher.ResultChan()
	for {
		select {
		case event, ok := <-resultCh:
			if !ok {
				return
			}
			// Skip handling Bookmark events.
			if event.Type == watch.Bookmark {
				continue
			}
			np := event.Object.(*controlplane.NetworkPolicy)
			if np.SourceRef.Type == controlplane.K8sNetworkPolicy {
				continue
			}
			c.queue.Add(np.Name)
		}
	}
}

func (c *StatusController) runWorker() {
	for c.processNextWorkItem() {
	}
}

// processNextWorkItem deals with one key off the queue.  It returns false when it's time to quit.
func (c *StatusController) processNextWorkItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	err := c.syncHandler(key.(string))
	if err == nil {
		c.queue.Forget(key)
		return true
	}

	klog.Errorf("Failed to sync NetworkPolicy status %s: %v", key, err)
	c.queue.AddRateLimited(key)

	return true
}

// syncHandler calculates the NetworkPolicy status based on the desired state from the internalNetworkPolicyStore and
// the actual state from the statuses map, and syncs it with the Kubernetes API.
// Each status update from agents can trigger syncHandler, however, the status updates' arrival time should not differ
// too much so some of them can be merged in workqueue. Besides, there are a limited number of workers. If there are
// many policies need to sync, some policies will have to wait in workqueue, during which their status updates can be
// merged. Therefore, it shouldn't happen that each status update leads to one CR update.
func (c *StatusController) syncHandler(key string) error {
	klog.V(2).Infof("Syncing NetworkPolicy status for %s", key)
	internalNPObj, found, _ := c.internalNetworkPolicyStore.Get(key)
	if !found {
		// It has been deleted, cleaning its statuses.
		c.clearStatuses(key)
		return nil
	}
	internalNP := internalNPObj.(*antreatypes.NetworkPolicy)

	// It means the NetworkPolicy hasn't been processed once. Set it to Pending to differentiate from NetworkPolicies
	// that spans 0 Node.
	if internalNP.SpanMeta.NodeNames == nil {
		return c.npControlInterface.UpdateAntreaNetworkPolicyStatus(internalNP.SourceRef.Namespace, internalNP.SourceRef.Name, &secv1alpha1.NetworkPolicyStatus{
			Phase:              secv1alpha1.NetworkPolicyPending,
			ObservedGeneration: internalNP.Generation,
		})
	}
	desiredNodes := len(internalNP.SpanMeta.NodeNames)
	currentNodes := 0
	statuses := c.getNodeStatuses(key)
	for _, status := range statuses {
		// The node is no longer in the span of this policy, delete its status.
		if !internalNP.NodeNames.Has(status.NodeName) {
			c.deleteNodeStatus(key, status.NodeName)
			continue
		}
		if status.Generation == internalNP.Generation {
			currentNodes += 1
		}
	}

	phase := secv1alpha1.NetworkPolicyRealizing
	if currentNodes == desiredNodes {
		phase = secv1alpha1.NetworkPolicyRealized
	}

	status := &secv1alpha1.NetworkPolicyStatus{
		Phase:                phase,
		ObservedGeneration:   internalNP.Generation,
		CurrentNodesRealized: int32(currentNodes),
		DesiredNodesRealized: int32(desiredNodes),
	}
	klog.V(2).Infof("Updating NetworkPolicy %s status: %v", internalNP.SourceRef.ToString(), status)
	if internalNP.SourceRef.Type == controlplane.AntreaNetworkPolicy {
		return c.npControlInterface.UpdateAntreaNetworkPolicyStatus(internalNP.SourceRef.Namespace, internalNP.SourceRef.Name, status)
	} else {
		return c.npControlInterface.UpdateAntreaClusterNetworkPolicyStatus(internalNP.SourceRef.Name, status)
	}
}

// networkPolicyControlInterface is an interface that knows how to update Antrea NetworkPolicy status.
// It's created as an interface to allow testing.
type networkPolicyControlInterface interface {
	UpdateAntreaNetworkPolicyStatus(namespace, name string, status *secv1alpha1.NetworkPolicyStatus) error
	UpdateAntreaClusterNetworkPolicyStatus(name string, status *secv1alpha1.NetworkPolicyStatus) error
}

type networkPolicyControl struct {
	antreaClient antreaclientset.Interface
	cnpLister    seclisters.ClusterNetworkPolicyLister
	anpLister    seclisters.NetworkPolicyLister
}

func (c *networkPolicyControl) UpdateAntreaNetworkPolicyStatus(namespace, name string, status *secv1alpha1.NetworkPolicyStatus) error {
	anp, err := c.anpLister.NetworkPolicies(namespace).Get(name)
	if err != nil {
		klog.Infof("Didn't find the original Antrea NetworkPolicy %s/%s, skip updating status", namespace, name)
		return nil
	}
	if anp.Status == *status {
		return nil
	}
	metrics.AntreaNetworkPolicyStatusUpdates.Inc()
	toUpdate := anp.DeepCopy()
	toUpdate.Status = *status
	_, err = c.antreaClient.SecurityV1alpha1().NetworkPolicies(namespace).UpdateStatus(context.TODO(), toUpdate, v1.UpdateOptions{})
	return err
}

func (c *networkPolicyControl) UpdateAntreaClusterNetworkPolicyStatus(name string, status *secv1alpha1.NetworkPolicyStatus) error {
	cnp, err := c.cnpLister.Get(name)
	if err != nil {
		klog.Infof("Didn't find the original Antrea ClusterNetworkPolicy %s, skip updating status", name)
		return nil
	}
	// If the current status equals to the desired status, no need to update.
	if cnp.Status == *status {
		return nil
	}
	metrics.AntreaClusterNetworkPolicyStatusUpdates.Inc()
	toUpdate := cnp.DeepCopy()
	toUpdate.Status = *status
	_, err = c.antreaClient.SecurityV1alpha1().ClusterNetworkPolicies().UpdateStatus(context.TODO(), toUpdate, v1.UpdateOptions{})
	return err
}
