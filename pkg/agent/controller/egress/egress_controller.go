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
	"context"
	"fmt"
	"net"
	"reflect"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent"
	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	"github.com/vmware-tanzu/antrea/pkg/agent/route"
	"github.com/vmware-tanzu/antrea/pkg/apis/controlplane/v1beta1"
	"github.com/vmware-tanzu/antrea/pkg/apis/egress/v1alpha1"
	crdinformers "github.com/vmware-tanzu/antrea/pkg/client/informers/externalversions"
	egressinformers "github.com/vmware-tanzu/antrea/pkg/client/informers/externalversions/egress/v1alpha1"
	egresslisters "github.com/vmware-tanzu/antrea/pkg/client/listers/egress/v1alpha1"
)

const (
	// How long to wait before retrying the processing of a egress policy change.
	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second
	// Default number of workers processing a rule change.
	defaultWorkers               = 4
	resyncPeriod   time.Duration = 0
)

func NewEgressController(
	ofClient openflow.Client,
	routeClient route.Interface,
	crdInformerFactory crdinformers.SharedInformerFactory,
	antreaClientGetter agent.AntreaClientProvider,
	ifaceStore interfacestore.InterfaceStore,
) *Controller {
	egressInformer := crdInformerFactory.Egress().V1alpha1().Egresses()
	c := &Controller{
		ofClient:             ofClient,
		ifaceStore:           ifaceStore,
		routeClient:          routeClient,
		antreaClientProvider: antreaClientGetter,
		setByGroup:           make(map[string]v1beta1.GroupMemberSet),
		// snatPktMarkRange takes an 8-bit range of pkt_mark to store the ID of
		// a SNAT IP. The bit range must match SNATIPMarkMask.
		IPAllocator:              newIPAllocator(256),
		queue:                    workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "egressgroup"),
		egressPolicyInformer:     egressInformer,
		egressPolicyLister:       egressInformer.Lister(),
		egressPolicyListerSynced: egressInformer.Informer().HasSynced,
		fullSynced:               false,
	}

	egressInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.addEgressPolicy,
			UpdateFunc: c.updateEgressPolicy,
			DeleteFunc: c.deleteEgressPolicy,
		},
		resyncPeriod,
	)
	return c
}

func (c *Controller) AddEgressGroup(group *v1beta1.EgressGroup) error {
	c.setByGroupLock.Lock()
	defer c.setByGroupLock.Unlock()
	klog.Infof("%#v", group)
	return c.addEgressGroupLocked(group)
}

func (c *Controller) PatchEgressGroup(patch *v1beta1.EgressGroupPatch) error {
	c.setByGroupLock.Lock()
	defer c.setByGroupLock.Unlock()
	klog.Infof("%#v", patch)
	return c.patchEgressGroupLocked(patch)
}

func (c *Controller) patchEgressGroupLocked(patch *v1beta1.EgressGroupPatch) error {
	addedMembers := make([]v1beta1.GroupMember, 0, len(patch.AddedGroupMembers))
	removedMembers := make([]v1beta1.GroupMember, 0, len(patch.RemovedGroupMembers))
	klog.Infof("%#v", c.setByGroup)

	var groupMemberSet v1beta1.GroupMemberSet
	groupMemberSet, exists := c.setByGroup[patch.Name]
	klog.Infof("%#v", groupMemberSet)
	klog.Infof("%#v", exists)
	if !exists {
		groupMemberSet = v1beta1.GroupMemberSet{}
	}
	for i := range patch.AddedGroupMembers {
		if !groupMemberSet.Has(&patch.AddedGroupMembers[i]) {
			addedMembers = append(addedMembers, patch.AddedGroupMembers[i])
		}
		groupMemberSet.Insert(&patch.AddedGroupMembers[i])
	}
	for i := range patch.RemovedGroupMembers {
		if groupMemberSet.Has(&patch.RemovedGroupMembers[i]) {
			removedMembers = append(removedMembers, patch.RemovedGroupMembers[i])
		}
		groupMemberSet.Delete(&patch.RemovedGroupMembers[i])
	}
	klog.Infof("%#v", addedMembers)
	klog.Infof("%#v", removedMembers)
	c.setByGroup[patch.Name] = groupMemberSet
	klog.Infof("%#v", c.setByGroup)

	c.onEgresssAdd(patch.Name, addedMembers)
	c.onEgressRemove(removedMembers)
	return nil
}

func (c *Controller) addEgressGroupLocked(group *v1beta1.EgressGroup) error {
	klog.Infof("%#v", group)
	groupMemberSet := v1beta1.GroupMemberSet{}
	for i := range group.GroupMembers {
		groupMemberSet.Insert(&group.GroupMembers[i])
	}
	oldGroupMemberSet, exists := c.setByGroup[group.Name]
	if exists && oldGroupMemberSet.Equal(groupMemberSet) {
		return nil
	}
	addedMembers := make([]v1beta1.GroupMember, 0, len(group.GroupMembers))
	addedGroupMemberSet := groupMemberSet.Difference(oldGroupMemberSet)
	for i := range addedGroupMemberSet {
		addedMembers = append(addedMembers, *addedGroupMemberSet[i])
		groupMemberSet.Insert(addedGroupMemberSet[i])
	}
	c.setByGroup[group.Name] = groupMemberSet
	klog.Infof("%#v", c.setByGroup)

	c.onEgresssAdd(group.Name, addedMembers)
	return nil
}

func (c *Controller) updateEgressPolicyLocked(policy *v1alpha1.Egress) error {
	c.onEgressGroupRemove(policy.Name)
	c.onEgressGroupAdd(policy.Name)
	return nil
}

func (c *Controller) addEgressPolicyLocked(policy *v1alpha1.Egress) error {
	c.onEgressGroupAdd(policy.Name)
	klog.Infof("%#v", c.setByGroup)
	return nil
}

func (c *Controller) deleteEgressPolicyLocked(policy *v1alpha1.Egress) error {
	c.onEgressGroupRemove(policy.Name)
	delete(c.setByGroup, policy.Name)
	return nil
}

func (c *Controller) ReplaceEgressGroups(groups []*v1beta1.EgressGroup) {
	c.setByGroupLock.Lock()
	defer c.setByGroupLock.Unlock()

	oldGroupKeys := make(sets.String, len(c.setByGroup))
	for key := range c.setByGroup {
		oldGroupKeys.Insert(key)
	}

	for _, group := range groups {
		oldGroupKeys.Delete(group.Name)
		c.addEgressGroupLocked(group)
	}

	for key := range oldGroupKeys {
		delete(c.setByGroup, key)
	}
	return
}

func (c *Controller) DeleteEgressGroup(group *v1beta1.EgressGroup) error {
	c.setByGroupLock.Lock()
	defer c.setByGroupLock.Unlock()
	klog.Infof("%#v", group)
	return c.DeleteEgressGroupLocked(group)
}

func (c *Controller) DeleteEgressGroupLocked(group *v1beta1.EgressGroup) error {
	groupMemberSet := v1beta1.GroupMemberSet{}
	for i := range group.GroupMembers {
		groupMemberSet.Insert(&group.GroupMembers[i])
	}
	oldGroupMemberSet, exist := c.setByGroup[group.Name]
	if !exist {
		return nil
	}
	removedMembers := make([]v1beta1.GroupMember, 0, len(group.GroupMembers))
	NewGroupMemberPodSet := v1beta1.GroupMemberSet{}

	for i := range groupMemberSet {
		if oldGroupMemberSet.Has(groupMemberSet[i]) {
			removedMembers = append(removedMembers, *groupMemberSet[i])
		} else {
			NewGroupMemberPodSet.Insert(groupMemberSet[i])
		}
	}
	c.setByGroup[group.Name] = NewGroupMemberPodSet
	c.onEgressRemove(removedMembers)
	return nil
}

func (c *Controller) onEgresssAdd(groupName string, members []v1beta1.GroupMember) {
	ip, err := c.getPolicyIP(groupName)
	if err != nil {
		klog.Infof(err.Error())
		return
	}
	for i := range members {
		c.enqueueRuleAdd(ip, &members[i])
	}
}

func (c *Controller) onEgressRemove(members []v1beta1.GroupMember) {
	for i := range members {
		c.enqueueRuleDelete(&members[i])
	}
}

func (c *Controller) onEgressGroupAdd(groupName string) {
	ip, err := c.getPolicyIP(groupName)
	if err != nil {
		klog.Infof(err.Error())
		return
	}
	groups, _ := c.setByGroup[groupName]
	for _, member := range groups {
		c.enqueueRuleAdd(ip, member)
	}
}

func (c *Controller) getPolicyIP(name string) (string, error) {
	egresses, err := c.egressPolicyLister.Get(name)
	if err != nil {
		klog.Infof(err.Error())
		return "", err
	}
	klog.Infof(egresses.Spec.EgressIP)
	return egresses.Spec.EgressIP, nil
}

func (c *Controller) onEgressGroupRemove(groupName string) {
	groups, _ := c.setByGroup[groupName]
	for _, member := range groups {
		c.enqueueRuleDelete(member)
	}
}

func (c *Controller) addEgressPolicy(obj interface{}) {
	egress := obj.(*v1alpha1.Egress)
	egressIP := egress.Spec.EgressIP
	klog.Infof(egressIP)
	if isLocalIP(egressIP) {
		id, err := c.IPAllocator.allocateForIP(egressIP)
		if err != nil {
			klog.Errorf(err.Error())
			return
		}
		err2 := c.ofClient.InstallSNATMarkFlows(net.ParseIP(egressIP), id)
		if err2 != nil {
			klog.Errorf(err2.Error())
			return
		}
		errroute := c.routeClient.AddSNATRule(net.ParseIP(egressIP), id)
		if errroute != nil {
			klog.Infof(errroute.Error())
			return
		}
	}
	c.addEgressPolicyLocked(egress)
}

func (c *Controller) updateEgressPolicy(old, cur interface{}) {
	egressOld := old.(*v1alpha1.Egress)
	egressNew := cur.(*v1alpha1.Egress)

	newEgressIP := egressNew.Spec.EgressIP
	oldEgressIP := egressOld.Spec.EgressIP
	if newEgressIP == oldEgressIP {
		return
	}
	if isLocalIP(oldEgressIP) {
		id, errRelease := c.IPAllocator.release(oldEgressIP)
		klog.Infof("%#v\n", c.IPAllocator)

		if errRelease != nil {
			klog.Errorf(errRelease.Error())
			return
		}
		c.ofClient.UninstallSNATMarkFlows(id)
		errroute := c.routeClient.DeleteSNATRule(id)
		if errroute != nil {
			klog.Infof(errroute.Error())
			return
		}

	}
	if isLocalIP(newEgressIP) {
		id, errAllocate := c.IPAllocator.allocateForIP(newEgressIP)
		klog.Infof("%#v\n", c.IPAllocator)

		if errAllocate != nil {
			klog.Errorf(errAllocate.Error())
			return
		}
		errroute2 := c.routeClient.AddSNATRule(net.ParseIP(newEgressIP), id)
		if errroute2 != nil {
			klog.Infof(errroute2.Error())
			return
		}
		c.ofClient.InstallSNATMarkFlows(net.ParseIP(newEgressIP), id)
	}
	c.updateEgressPolicyLocked(egressNew)
}

func (c *Controller) deleteEgressPolicy(obj interface{}) {
	c.setByGroupLock.Lock()
	defer c.setByGroupLock.Unlock()
	egress := obj.(*v1alpha1.Egress)
	klog.Infof("%#v deleted\n", obj)
	if isLocalIP(egress.Spec.EgressIP) {
		id, err := c.IPAllocator.release(egress.Spec.EgressIP)
		klog.Infof("%#v\n", c.IPAllocator)
		if err != nil {
			klog.Errorf(err.Error())
			return
		}
		c.ofClient.UninstallSNATMarkFlows(id)
		errroute := c.routeClient.DeleteSNATRule(id)
		if errroute != nil {
			klog.Infof(errroute.Error())
			return
		}
	}
	c.deleteEgressPolicyLocked(egress)
}

func (c *Controller) Run(stopCh <-chan struct{}) {
	attempts := 0
	if err := wait.PollImmediateUntil(200*time.Millisecond, func() (bool, error) {
		if attempts%10 == 0 {
			klog.Info("Waiting for Antrea client to be ready")
		}
		if _, err := c.antreaClientProvider.GetAntreaClient(); err != nil {
			attempts++
			return false, nil
		}
		return true, nil
	}, stopCh); err != nil {
		klog.Info("Stopped waiting for Antrea client")
		return
	}

	go wait.NonSlidingUntil(c.watch, 5*time.Second, stopCh)
	// Batch install all rules in queue after fullSync is finished.
	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}
	<-stopCh
}

type groupMember struct {
	IP     string
	Member *v1beta1.GroupMember
}

func (c *Controller) enqueueRuleAdd(ip string, group *v1beta1.GroupMember) {
	groupMember := &groupMember{
		IP:     ip,
		Member: group,
	}
	klog.Infof("%#v", groupMember)
	c.queue.Add(groupMember)
}

func (c *Controller) enqueueRuleDelete(group *v1beta1.GroupMember) {
	groupMember := &groupMember{
		IP:     "",
		Member: group,
	}
	klog.Infof("%#v", groupMember)
	c.queue.Add(groupMember)
}

func (c *Controller) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *Controller) processNextWorkItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	gm := key.(*groupMember)
	defer c.queue.Done(key)
	return c.processPodSNATFlows(gm)
}

func (c *Controller) processPodSNATFlows(gm *groupMember) bool {
	interfaces := c.ifaceStore.GetContainerInterfacesByPod(gm.Member.Pod.Name, gm.Member.Pod.Namespace)

	klog.Infof("%#v", gm.Member)
	klog.Infof("%#v", interfaces)
	klog.Infof("%t", isInterfaceOnPod(interfaces))
	if gm.IP != "" {
		if isInterfaceOnPod(interfaces) {
			ofPort := interfaces[0].OFPort
			var mark uint32
			if isLocalIP(gm.IP) {
				mark = 0
				klog.Infof("Installing Pod SNAT Flow for interface %s on the SNAT node", interfaces[0].InterfaceName)
			} else {
				mark = c.IPAllocator.allocatedIPMap[gm.IP]
				klog.Infof("Installing Pod SNAT Flow for interface %s with flow id %d to the tunnel", interfaces[0].InterfaceName, ofPort)
			}
			err := c.ofClient.InstallPodSNATFlows(uint32(ofPort), net.ParseIP(gm.IP), mark)
			if err != nil {
				klog.Infof(err.Error())
				return false
			}
		}
	} else {
		if isInterfaceOnPod(interfaces) {
			ofPort := interfaces[0].OFPort
			klog.Infof("Uninstalling Pod SNAT Flow for interface %s with flow id %d", interfaces[0].InterfaceName, ofPort)
			err := c.ofClient.UninstallPodSNATFlows(uint32(ofPort))
			if err != nil {
				klog.Infof(err.Error())
				return false
			}
			mark := c.IPAllocator.allocatedIPMap[gm.IP]
			errroute := c.routeClient.DeleteSNATRule(mark)
			if err != nil {
				klog.Infof(errroute.Error())
				return false
			}
		}
	}
	return true
}

func isInterfaceOnPod(interfaces []*interfacestore.InterfaceConfig) bool {
	return interfaces != nil && len(interfaces) >= 1
}

func isLocalIP(ip string) bool {
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		addrs, _ := i.Addrs()

		for _, addr := range addrs {
			var localIP net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				localIP = v.IP
			case *net.IPAddr:
				localIP = v.IP
			}
			klog.Infof(localIP.String())
			if ip == localIP.String() {
				return true
			}
		}
	}
	return false
}

func (c *Controller) GetControllerConnectionStatus() bool {
	// When the watchers are connected, controller connection status is true. Otherwise, it is false.
	return c.isConnected()
}

func (c *Controller) isConnected() bool {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.connected
}

func (c *Controller) setConnected(connected bool) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.connected = connected
}

var emptyWatch = watch.NewEmptyWatch()

func (c *Controller) watch() {
	klog.Infof("Starting watch for EgressGroup")
	antreaClient, err := c.antreaClientProvider.GetAntreaClient()
	if err != nil {
		klog.Infof(err.Error())
	}

	watcher, err := antreaClient.ControlplaneV1beta1().EgressGroups().Watch(context.TODO(), metav1.ListOptions{})
	if err != nil {
		klog.Warningf("Failed to start watch for EgressGroup: %v", err)
		return
	}
	if reflect.TypeOf(watcher) == reflect.TypeOf(emptyWatch) {
		klog.Warningf("Failed to start watch for EgressGroup, please ensure antrea service is reachable for the agent")
		return
	}

	klog.Infof("Started watch for EgressGroup")
	c.setConnected(true)
	eventCount := 0
	defer func() {
		klog.Infof("Stopped watch for EgressGroup, total items received: %d", eventCount)
		c.setConnected(false)
		watcher.Stop()
	}()
	var initObjects []runtime.Object
loop:
	for {
		select {
		case event, ok := <-watcher.ResultChan():
			if !ok {
				klog.Warningf("Result channel for EgressGroup was closed")
				return
			}
			switch event.Type {
			case watch.Added:
				klog.V(2).Infof("Added EgressGroup (%#v)", event.Object)
				initObjects = append(initObjects, event.Object)
			case watch.Bookmark:
				break loop
			}
		}
	}
	klog.Infof("Received %d init events for EgressGroup", len(initObjects))

	eventCount += len(initObjects)
	klog.Infof("egress replacing")
	groups := make([]*v1beta1.EgressGroup, len(initObjects))
	var ok bool
	for i := range initObjects {
		groups[i], ok = initObjects[i].(*v1beta1.EgressGroup)
		if !ok {
			klog.Errorf("cannot convert to *v1beta1.EgressGroup: %v", initObjects[i])
		}
		klog.Infof("EgressGroup %s applied to Pods on this Node", groups[i].Name)
	}
	c.ReplaceEgressGroups(groups)
	if !c.fullSynced {
		c.fullSynced = true
	}
	for {
		select {
		case event, ok := <-watcher.ResultChan():
			klog.Infof("%#v\n", event.Object)
			if !ok {
				return
			}
			switch event.Type {
			case watch.Added:
				group, ok := event.Object.(*v1beta1.EgressGroup)
				if !ok {
					return
				}
				klog.Infof("EgressGroup %#v\n applied to Pods on this Node", group)
				c.AddEgressGroup(group)
			case watch.Modified:
				klog.Infof("egress group updating")
				patch, ok := event.Object.(*v1beta1.EgressGroupPatch)
				if !ok {
					return
				}
				c.PatchEgressGroup(patch)
			case watch.Deleted:
				klog.Infof("egress group deleting")
				group, ok := event.Object.(*v1beta1.EgressGroup)
				if !ok {
					return
				}
				c.DeleteEgressGroup(group)
			default:
				errorMsg := fmt.Sprintf("Unknown event: %v", event)
				klog.Errorf(errorMsg)
				return
			}
		}
	}
}

type Controller struct {
	setByGroupLock           sync.RWMutex
	antreaClientProvider     agent.AntreaClientProvider
	IPAllocator              *IPAllocator
	ifaceStore               interfacestore.InterfaceStore
	egressPolicyInformer     egressinformers.EgressInformer
	egressPolicyLister       egresslisters.EgressLister
	egressPolicyListerSynced cache.InformerSynced
	routeClient              route.Interface
	ofClient                 openflow.Client
	queue                    workqueue.RateLimitingInterface
	setByGroup               map[string]v1beta1.GroupMemberSet
	// ReplaceFunc is the function that handles init events.
	connected bool
	// lock protects connected.
	lock sync.RWMutex
	// group to be notified when each watcher receives bookmark event
	// fullSynced indicates if the resource has been synced at least once since agent started.
	fullSynced bool
}
