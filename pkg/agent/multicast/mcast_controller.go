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

package multicast

import (
	"net"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/openflow"
)

type eventType uint8

const (
	groupJoin eventType = iota
	groupLeave

	// Use IGMPv3 for IGMP query message because it is the main version for IGMP.
	// TODO: support sending IGMP query with both v2 and v3 messages
	queryVersion      = 3
	podInterfaceIndex = "podInterface"

	// How long to wait before retrying the processing of a multicast group change.
	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second
)

var (
	workerCount uint8 = 2
)

type mcastGroupEvent struct {
	group net.IP
	eType eventType
	time  time.Time
	iface *interfacestore.InterfaceConfig
}

type GroupMemberStatus struct {
	group net.IP
	// localMembers is a set for the local Pod's interface name which has joined in the multicast group.
	localMembers   sets.String
	lastIGMPReport time.Time
	mutex          sync.RWMutex
}

// eventHandler process the multicast Group membership report or leave messages.
func (c *Controller) eventHandler(stopCh <-chan struct{}) {
	for {
		select {
		case e := <-c.groupEventCh:
			c.addOrUpdateGroupEvent(e)
		case <-stopCh:
			return
		}
	}
}

// addGroupMemberStatus adds the new group into groupCache.
func (c *Controller) addGroupMemberStatus(e *mcastGroupEvent) {
	status := &GroupMemberStatus{
		group:          e.group,
		lastIGMPReport: e.time,
		localMembers:   sets.NewString(e.iface.InterfaceName),
	}
	c.groupCache.Add(status)
	c.queue.Add(e.group.String())
	klog.InfoS("Added new multicast group to cache", "group", e.group, "interface", e.iface.InterfaceName)
	return
}

// updateGroupMemberStatus updates the group status in groupCache. If a "join" message is sent from an existing member,
// only updates the lastIGMPReport time. If a "join" message is sent from an "unknown" member, updates the lastIGMPReport time and
// adds the new member into the group's local member set. If a "leave" message is sent from an existing member, removes
// it from the group's local member set, and if the member is the last one in local cache, a query message on the group
// is sent out to check if there are still local members in the group.
func (c *Controller) updateGroupMemberStatus(obj interface{}, e *mcastGroupEvent) {
	status := obj.(*GroupMemberStatus)
	status.mutex.Lock()
	defer status.mutex.Unlock()
	newStatus := &GroupMemberStatus{
		group:          status.group,
		localMembers:   status.localMembers.Union(nil),
		lastIGMPReport: status.lastIGMPReport,
	}
	exist := status.localMembers.Has(e.iface.InterfaceName)
	switch e.eType {
	case groupJoin:
		newStatus.lastIGMPReport = e.time
		if !exist {
			newStatus.localMembers.Insert(e.iface.InterfaceName)
			klog.InfoS("Added member to multicast group", "group", e.group.String(), "member", e.iface.InterfaceName)
		}
		c.groupCache.Update(newStatus)
		c.queue.Add(newStatus.group.String())
	case groupLeave:
		if exist {
			newStatus.localMembers.Delete(e.iface.InterfaceName)
			c.groupCache.Update(newStatus)
			klog.InfoS("Deleted member from multicast group", "group", e.group.String(), "member", e.iface.InterfaceName)
			if len(newStatus.localMembers) == 0 {
				klog.InfoS("Check last member in multicast group", "group", e.group.String(), "member", e.iface.InterfaceName)
				c.checkLastMember(e.group)
			}
		}
	}
	return
}

// checkLastMember sends out a query message on the group to check if there are still members in the group. If no new
// membership report is received in the max response time, the group is removed from groupCache.
func (c *Controller) checkLastMember(group net.IP) {
	err := c.igmpSnooper.queryIGMP(group, queryVersion)
	if err != nil {
		klog.ErrorS(err, "Failed to send IGMP query message", "group", group.String())
		return
	}
	c.queue.AddAfter(group.String(), igmpMaxResponseTime)
}

// clearStaleGroups checks the stale groups which have not been updated for mcastGroupTimeout, and then notifies worker
// to remove them from groupCache.
func (c *Controller) clearStaleGroups() {
	now := time.Now()
	for _, obj := range c.groupCache.List() {
		status := obj.(*GroupMemberStatus)
		status.mutex.RLock()
		diff := now.Sub(status.lastIGMPReport)
		status.mutex.RUnlock()
		if diff > mcastGroupTimeout {
			c.queue.Add(status.group.String())
		}
	}
}

type Controller struct {
	ofClient     openflow.Client
	nodeConfig   *config.NodeConfig
	igmpSnooper  *IGMPSnooper
	groupEventCh chan *mcastGroupEvent
	groupCache   cache.Indexer
	queue        workqueue.RateLimitingInterface
	// installedGroups saves the groups which are configured on both OVS and the host.
	installedGroups      sets.String
	installedGroupsMutex sync.RWMutex
}

func NewMulticastController(ofClient openflow.Client, nodeConfig *config.NodeConfig, ifaceStore interfacestore.InterfaceStore) *Controller {
	eventCh := make(chan *mcastGroupEvent, workerCount)
	groupSnooper := newSnooper(ofClient, ifaceStore, eventCh)
	groupCache := cache.NewIndexer(getGroupEventKey, cache.Indexers{
		podInterfaceIndex: podInterfaceIndexFunc,
	})
	return &Controller{
		ofClient:        ofClient,
		nodeConfig:      nodeConfig,
		igmpSnooper:     groupSnooper,
		groupEventCh:    eventCh,
		groupCache:      groupCache,
		installedGroups: sets.NewString(),
		queue:           workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "multicastgroup"),
	}
}

func (c *Controller) Initialize() error {
	// Install flows on OVS for IGMP packets and multicast traffic forwarding:
	// 1) send the IGMP report messages to Antrea Agent,
	// 2) forward the IMGP query messages to all local Pods,
	// 3) forward the multicast traffic to antrea-gw0 if no local Pods have joined in the group, and this is to ensure
	//    local Pods can access the external multicast receivers.
	err := c.ofClient.InstallMulticastInitialFlows(uint8(openflow.PacketInReasonMC))
	if err != nil {
		klog.ErrorS(err, "Failed to install multicast initial flows")
		return err
	}
	return nil
}

func (c *Controller) Run(stopCh <-chan struct{}) {
	// Periodically query Multicast Groups on OVS.
	go wait.NonSlidingUntil(func() {
		if err := c.igmpSnooper.queryIGMP(net.IPv4zero, queryVersion); err != nil {
			klog.ErrorS(err, "Failed to send IGMP query")
		}
	}, queryInterval, stopCh)

	// Periodically check the group member status, and remove the groups in which no members exist
	go wait.NonSlidingUntil(c.clearStaleGroups, queryInterval, stopCh)

	go c.eventHandler(stopCh)

	for i := 0; i < int(workerCount); i++ {
		// Process multicast Group membership report or leave messages.
		go wait.Until(c.worker, time.Second, stopCh)
	}
}

func (c *Controller) worker() {
	for c.processNextWorkItem() {
	}
}

// getGroupMemberStatusByGroup returns the GroupMemberStatus according to the given group.
func (c *Controller) getGroupMemberStatusByGroup(group net.IP) *GroupMemberStatus {
	status, ok, _ := c.groupCache.GetByKey(group.String())
	if ok {
		return status.(*GroupMemberStatus)
	}
	return nil
}

// getGroupMemberStatusesByPod returns all GroupMemberStatus that the given podInterface is included in its localMembers.
func (c *Controller) getGroupMemberStatusesByPod(podInterface string) []*GroupMemberStatus {
	groupMembers := make([]*GroupMemberStatus, 0)
	statuses, _ := c.groupCache.ByIndex(podInterfaceIndex, podInterface)
	for _, s := range statuses {
		groupMembers = append(groupMembers, s.(*GroupMemberStatus))
	}
	return groupMembers
}

func (c *Controller) processNextWorkItem() bool {
	obj, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(obj)

	// We expect string (multicast group) to come off the workqueue.
	if key, ok := obj.(string); !ok {
		// As the item in the workqueue is actually invalid, we call Forget here else we'd
		// go into a loop of attempting to process a work item that is invalid.
		// This should not happen.
		c.queue.Forget(obj)
		klog.Errorf("Expected string in work queue but got %#v", obj)
		return true
	} else if err := c.syncGroup(key); err == nil {
		// If no error occurs we Forget this item so it does not get queued again until
		// another change happens.
		c.queue.Forget(key)
	} else {
		// Put the item back on the workqueue to handle any transient errors.
		c.queue.AddRateLimited(key)
		klog.Errorf("Error syncing multicast group %s, requeuing. Error: %v", key, err)
	}
	return true

}

func (c *Controller) syncGroup(groupKey string) error {
	startTime := time.Now()
	defer func() {
		klog.V(4).Infof("Finished syncing GroupMemberStatus for %s. (%v)", groupKey, time.Since(startTime))
	}()
	obj, exists, err := c.groupCache.GetByKey(groupKey)
	if err != nil {
		klog.ErrorS(err, "Failed to get GroupMemberStatus", "group", groupKey)
		return err
	}
	if !exists {
		klog.InfoS("multicast group not found in the cache", "group", groupKey)
		return nil
	}
	status := obj.(*GroupMemberStatus)
	if c.groupHasInstalled(groupKey) {
		status.mutex.Lock()
		defer status.mutex.Unlock()
		if c.groupIsStale(status) {
			// Remove the multicast flow entry if no local Pod is in the group.
			if err := c.ofClient.UninstallMulticastFlow(status.group); err != nil {
				klog.ErrorS(err, "Failed to uninstall multicast flows", "group", groupKey)
				return err
			}
			c.delInstalledGroup(groupKey)
			c.groupCache.Delete(status)
			klog.InfoS("Removed multicast group from cache after all members left", "group", groupKey)
		}
		return nil
	}
	if err := c.ofClient.InstallMulticastFlow(status.group); err != nil {
		klog.ErrorS(err, "Failed to install multicast flows", "group", status.group)
		return err
	}
	c.addInstalledGroup(groupKey)
	return nil
}

// groupIsStale returns true if no local members in the group, or there is no IGMP report received after mcastGroupTimeout.
func (c *Controller) groupIsStale(status *GroupMemberStatus) bool {
	membersCount := len(status.localMembers)
	diff := time.Now().Sub(status.lastIGMPReport)
	if membersCount == 0 || diff > mcastGroupTimeout {
		return true
	}
	return false
}

func (c *Controller) groupHasInstalled(groupKey string) bool {
	c.installedGroupsMutex.RLock()
	defer c.installedGroupsMutex.RUnlock()
	return c.installedGroups.Has(groupKey)
}

func (c *Controller) addInstalledGroup(groupKey string) {
	c.installedGroupsMutex.Lock()
	c.installedGroups.Insert(groupKey)
	c.installedGroupsMutex.Unlock()
}

func (c *Controller) delInstalledGroup(groupKey string) {
	c.installedGroupsMutex.Lock()
	c.installedGroups.Delete(groupKey)
	c.installedGroupsMutex.Unlock()
}

func (c *Controller) addOrUpdateGroupEvent(e *mcastGroupEvent) {
	obj, ok, _ := c.groupCache.GetByKey(e.group.String())
	switch e.eType {
	case groupJoin:
		if !ok {
			c.addGroupMemberStatus(e)
		} else {
			c.updateGroupMemberStatus(obj, e)
		}
	case groupLeave:
		if ok {
			c.updateGroupMemberStatus(obj, e)
		}
	}
}

func podInterfaceIndexFunc(obj interface{}) ([]string, error) {
	groupState := obj.(*GroupMemberStatus)
	podInterfaces := make([]string, 0, len(groupState.localMembers))
	for podInterface := range groupState.localMembers {
		podInterfaces = append(podInterfaces, podInterface)
	}
	return podInterfaces, nil
}

func getGroupEventKey(obj interface{}) (string, error) {
	groupState := obj.(*GroupMemberStatus)
	return groupState.group.String(), nil
}
