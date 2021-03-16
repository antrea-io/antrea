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

package egress

import (
	"reflect"
	"time"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/apis/controlplane"
	egressv1alpha1 "github.com/vmware-tanzu/antrea/pkg/apis/egress/v1alpha1"
	"github.com/vmware-tanzu/antrea/pkg/apiserver/storage"
	egressinformers "github.com/vmware-tanzu/antrea/pkg/client/informers/externalversions/egress/v1alpha1"
	"github.com/vmware-tanzu/antrea/pkg/controller/grouping"
	antreatypes "github.com/vmware-tanzu/antrea/pkg/controller/types"
)

const (
	controllerName = "EgressController"
	// Set resyncPeriod to 0 to disable resyncing.
	resyncPeriod time.Duration = 0
	// How long to wait before retrying the processing of an Egress change.
	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second
	// Default number of workers processing an Egress change.
	defaultWorkers = 4

	egressGroupType grouping.GroupType = "egressGroup"
)

// EgressController is responsible for synchronizing the EgressGroups selected by Egresses.
type EgressController struct {
	egressInformer egressinformers.EgressInformer
	// egressListerSynced is a function which returns true if the Egresses shared informer has been synced at least once.
	egressListerSynced cache.InformerSynced

	// egressGroupStore is the storage where the EgressGroups are stored.
	egressGroupStore storage.Interface

	// queue maintains the EgressGroup objects that need to be synced.
	queue workqueue.RateLimitingInterface

	// groupingInterface knows Pods that a given group selects.
	groupingInterface grouping.Interface
	// Added as a member to the struct to allow injection for testing.
	groupingInterfaceSynced func() bool
}

// NewEgressController returns a new *EgressController.
func NewEgressController(groupingInterface grouping.Interface,
	egressInformer egressinformers.EgressInformer,
	egressGroupStore storage.Interface) *EgressController {
	c := &EgressController{
		egressInformer:          egressInformer,
		egressListerSynced:      egressInformer.Informer().HasSynced,
		egressGroupStore:        egressGroupStore,
		queue:                   workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "egress"),
		groupingInterface:       groupingInterface,
		groupingInterfaceSynced: groupingInterface.HasSynced,
	}
	c.groupingInterface.AddEventHandler(egressGroupType, c.enqueueEgressGroup)
	// Add handlers for Egress events.
	egressInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.addEgress,
			UpdateFunc: c.updateEgress,
			DeleteFunc: c.deleteEgress,
		},
		resyncPeriod,
	)
	return c
}

// Run begins watching and syncing of an EgressController.
func (c *EgressController) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	klog.Infof("Starting %s", controllerName)
	defer klog.Infof("Shutting down %s", controllerName)

	cacheSyncs := []cache.InformerSynced{c.egressListerSynced, c.groupingInterfaceSynced}
	if !cache.WaitForNamedCacheSync(controllerName, stopCh, cacheSyncs...) {
		return
	}

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.egressGroupWorker, time.Second, stopCh)
	}
	<-stopCh
}

func (c *EgressController) egressGroupWorker() {
	for c.processNextEgressGroupWorkItem() {
	}
}

func (c *EgressController) processNextEgressGroupWorkItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	err := c.syncEgressGroup(key.(string))
	if err != nil {
		// Put the item back on the workqueue to handle any transient errors.
		c.queue.AddRateLimited(key)
		klog.Errorf("Failed to sync EgressGroup %s: %v", key, err)
		return true
	}
	// If no error occurs we Forget this item so it does not get queued again until
	// another change happens.
	c.queue.Forget(key)
	return true
}

func (c *EgressController) syncEgressGroup(key string) error {
	startTime := time.Now()
	defer func() {
		d := time.Since(startTime)
		klog.V(2).Infof("Finished syncing EgressGroup %s. (%v)", key, d)
	}()

	egressGroupObj, found, _ := c.egressGroupStore.Get(key)
	if !found {
		klog.V(2).Infof("EgressGroup %s not found", key)
		return nil
	}

	nodeNames := sets.String{}
	podNum := 0
	memberSetByNode := make(map[string]controlplane.GroupMemberSet)
	egressGroup := egressGroupObj.(*antreatypes.EgressGroup)
	pods, _ := c.groupingInterface.GetEntities(egressGroupType, key)
	for _, pod := range pods {
		// Ignore Pod if it's not scheduled or not running.
		// TODO: If a Pod is scheduled but not running, it can be included in the EgressGroup so that the agent can
		// install its SNAT rule right after the Pod's CNI request is processed, which requires a notification from
		// CNIServer to the agent's EgressController. However the current notification mechanism (the entityUpdate
		// channel) allows only single consumer. Once it allows multiple consumers, we can change the condition to
		// include scheduled Pods that have no IPs.
		if pod.Spec.NodeName == "" || len(pod.Status.PodIPs) == 0 {
			continue
		}
		podNum++
		podSet := memberSetByNode[pod.Spec.NodeName]
		if podSet == nil {
			podSet = controlplane.GroupMemberSet{}
			memberSetByNode[pod.Spec.NodeName] = podSet
		}
		groupMember := &controlplane.GroupMember{
			Pod: &controlplane.PodReference{
				Name:      pod.Name,
				Namespace: pod.Namespace,
			},
		}
		podSet.Insert(groupMember)
		// Update the NodeNames in order to set the SpanMeta for EgressGroup.
		nodeNames.Insert(pod.Spec.NodeName)
	}
	updatedEgressGroup := &antreatypes.EgressGroup{
		UID:               egressGroup.UID,
		Name:              egressGroup.Name,
		GroupMemberByNode: memberSetByNode,
		SpanMeta:          antreatypes.SpanMeta{NodeNames: nodeNames},
	}
	klog.V(2).Infof("Updating existing EgressGroup %s with %d Pods on %d Nodes", key, podNum, nodeNames.Len())
	c.egressGroupStore.Update(updatedEgressGroup)
	return nil
}

func (c *EgressController) enqueueEgressGroup(key string) {
	klog.V(4).Infof("Adding new key %s to EgressGroup queue", key)
	c.queue.Add(key)
}

// createEgressGroup creates an EgressGroup object in store if it is not created already.
func (c *EgressController) registerEgressGroup(egress *egressv1alpha1.Egress) {
	groupSelector := antreatypes.NewGroupSelector("", egress.Spec.AppliedTo.PodSelector, egress.Spec.AppliedTo.NamespaceSelector, nil)
	klog.V(2).Infof("Registering EgressGroup %s with selector (%s)", egress.Name, groupSelector.NormalizedName)
	c.groupingInterface.AddGroup(egressGroupType, egress.Name, groupSelector)
}

// createEgressGroup creates an EgressGroup object in store if it is not created already.
func (c *EgressController) unregisterEgressGroup(egress *egressv1alpha1.Egress) {
	klog.V(2).Infof("Unregistering EgressGroup %s", egress.Name)
	c.groupingInterface.DeleteGroup(egressGroupType, egress.Name)
}

// addEgress receives Egress ADD events and creates corresponding EgressGroup.
func (c *EgressController) addEgress(obj interface{}) {
	egress := obj.(*egressv1alpha1.Egress)
	klog.Infof("Processing Egress %s ADD event", egress.Name)
	// Create an EgressGroup object corresponding to this Egress and enqueue task to the workqueue.
	egressGroup := &antreatypes.EgressGroup{
		Name: egress.Name,
		UID:  egress.UID,
	}
	c.egressGroupStore.Create(egressGroup)
	c.registerEgressGroup(egress)
	c.queue.Add(egress.Name)
}

// updateEgress receives Egress UPDATE events and updates corresponding EgressGroup.
func (c *EgressController) updateEgress(old, cur interface{}) {
	oldEgress := old.(*egressv1alpha1.Egress)
	curEgress := cur.(*egressv1alpha1.Egress)
	klog.Infof("Processing Egress %s UPDATE event", curEgress.Name)
	// Do nothing if AppliedTo doesn't change.
	if reflect.DeepEqual(oldEgress.Spec.AppliedTo, curEgress.Spec.AppliedTo) {
		return
	}

	c.registerEgressGroup(curEgress)
	c.queue.Add(curEgress.Name)
}

// deleteEgress receives Egress DELETED events and deletes corresponding EgressGroup.
func (c *EgressController) deleteEgress(obj interface{}) {
	egress := obj.(*egressv1alpha1.Egress)
	klog.Infof("Processing Egress %s DELETE event", egress.Name)
	c.egressGroupStore.Delete(egress.Name)
	c.unregisterEgressGroup(egress)
}
