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
	"fmt"
	"net"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	apitypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/apis/controlplane/v1beta2"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	"antrea.io/antrea/pkg/util/channel"
	"antrea.io/antrea/pkg/util/k8s"
)

type eventType uint8

const (
	groupJoin eventType = iota
	groupLeave

	podInterfaceIndex = "podInterface"

	// How long to wait before retrying the processing of a multicast group change.
	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second

	// Interval of reprocessing every node.
	nodeResyncPeriod = 60 * time.Second

	// nodeUpdateKey is a key to trigger the Node list operation and update the OpenFlow group buckets to report
	// the local multicast groups to other Nodes.
	nodeUpdateKey = "nodeUpdate"
)

var workerCount uint8 = 2

type mcastGroupEvent struct {
	group net.IP
	eType eventType
	time  time.Time
	iface *interfacestore.InterfaceConfig
	// srcNode is the Node IP where the IGMP report message is sent from. It is set only with encap mode.
	srcNode net.IP
}

type GroupMemberStatus struct {
	group net.IP
	// localMembers is a map for the local Pod member and its last update time, key is the Pod's interface name,
	// and value is its last update time.
	localMembers map[string]time.Time
	// remoteMembers is a set for Nodes which have joined the multicast group in the cluster. The Node's IP is
	// added in the set.
	remoteMembers  sets.Set[string]
	lastIGMPReport time.Time
	ofGroupID      binding.GroupIDType
}

// eventHandler process the multicast Group membership report or leave messages.
func (c *Controller) eventHandler(stopCh <-chan struct{}) {
	for {
		select {
		case e := <-c.groupEventCh:
			if e.group.Equal(types.McastAllHosts) {
				c.updateQueryGroup()
			} else {
				c.addOrUpdateGroupEvent(e)
			}
		case <-stopCh:
			return
		}
	}
}

// addGroupMemberStatus adds the new group into groupCache.
func (c *Controller) addGroupMemberStatus(e *mcastGroupEvent) {
	status := &GroupMemberStatus{
		group:         e.group,
		ofGroupID:     c.v4GroupAllocator.Allocate(),
		remoteMembers: sets.New[string](),
		localMembers:  make(map[string]time.Time),
	}
	status = addGroupMember(status, e)
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
	newStatus := &GroupMemberStatus{
		group:          status.group,
		localMembers:   make(map[string]time.Time),
		remoteMembers:  status.remoteMembers.Union(nil),
		lastIGMPReport: status.lastIGMPReport,
		ofGroupID:      status.ofGroupID,
	}
	for m, t := range status.localMembers {
		newStatus.localMembers[m] = t
	}
	exist := memberExists(status, e)
	switch e.eType {
	case groupJoin:
		newStatus = addGroupMember(newStatus, e)
		c.groupCache.Update(newStatus)
		if !exist {
			klog.InfoS("Added member to multicast group", "group", e.group.String(), "member", e.iface.InterfaceName)
			c.queue.Add(newStatus.group.String())
		}
	case groupLeave:
		if exist {
			newStatus = deleteGroupMember(newStatus, e)
			c.groupCache.Update(newStatus)
			if e.iface.Type == interfacestore.ContainerInterface {
				_, found := c.ifaceStore.GetInterfaceByName(e.iface.InterfaceName)
				// Notify worker immediately about the member leave event if the member doesn't exist on the Node, or there are
				// other local members in the multicast group.
				if !found || len(newStatus.localMembers) > 0 {
					c.queue.Add(newStatus.group.String())
				} else {
					// Check if all local members have left the multicast group.
					klog.InfoS("Check last member in multicast group", "group", e.group.String(), "member", e.iface.InterfaceName)
					c.checkLastMember(e.group)
				}
			} else {
				c.queue.Add(newStatus.group.String())
			}
		}
	}
	return
}

// checkLastMember sends out a query message on the group to check if there are still members in the group. If no new
// membership report is received in the max response time, the group is removed from groupCache.
func (c *Controller) checkLastMember(group net.IP) {
	err := c.igmpSnooper.queryIGMP(group)
	if err != nil {
		klog.ErrorS(err, "Failed to send IGMP query message", "group", group.String())
		return
	}
	c.queue.AddAfter(group.String(), igmpMaxResponseTime)
}

// clearStaleGroups checks the stale group members which have not been updated for c.mcastGroupTimeout, and then notifies worker
// to remove them from groupCache.
func (c *Controller) clearStaleGroups() {
	now := time.Now()
	for _, obj := range c.groupCache.List() {
		status := obj.(*GroupMemberStatus)
		diff := now.Sub(status.lastIGMPReport)
		if diff > c.mcastGroupTimeout {
			// Notify worker to remove the group from groupCache if all its members are not updated before mcastGroupTimeout.
			c.queue.Add(status.group.String())
		} else {
			// Create a "leave" event for a local member if it is not updated before mcastGroupTimeout.
			for member, lastUpdate := range status.localMembers {
				if now.Sub(lastUpdate) > c.mcastGroupTimeout {
					ifConfig := &interfacestore.InterfaceConfig{
						InterfaceName: member,
						Type:          interfacestore.ContainerInterface,
					}
					event := &mcastGroupEvent{
						group: status.group,
						eType: groupLeave,
						time:  now,
						iface: ifConfig,
					}
					c.groupEventCh <- event
				}
			}
		}
	}
}

// removeLocalInterface searches the GroupMemberStatus which the deleted interface has joined, and then triggers a member
// leave event so that Antrea can remove the corresponding interface from local multicast receivers on OVS. This function
// should be called if the removed Pod receiver fails to send IGMP leave message before deletion.
func (c *Controller) removeLocalInterface(podEvent types.PodUpdate) {
	// Ignore Pod creation event.
	if podEvent.IsAdd {
		return
	}
	interfaceName := util.GenerateContainerInterfaceName(podEvent.PodName, podEvent.PodNamespace, podEvent.ContainerID)
	ifConfig := &interfacestore.InterfaceConfig{
		InterfaceName: interfaceName,
		Type:          interfacestore.ContainerInterface,
	}
	groupStatuses := c.getGroupMemberStatusesByPod(interfaceName)
	for _, g := range groupStatuses {
		event := &mcastGroupEvent{
			group: g.group,
			eType: groupLeave,
			time:  time.Now(),
			iface: ifConfig,
		}
		c.groupEventCh <- event
	}
}

type Controller struct {
	ofClient         openflow.Client
	v4GroupAllocator openflow.GroupAllocator
	ifaceStore       interfacestore.InterfaceStore
	nodeConfig       *config.NodeConfig
	igmpSnooper      *IGMPSnooper
	groupEventCh     chan *mcastGroupEvent
	groupCache       cache.Indexer
	queue            workqueue.RateLimitingInterface
	nodeInformer     coreinformers.NodeInformer
	nodeLister       corelisters.NodeLister
	nodeListerSynced cache.InformerSynced
	nodeUpdateQueue  workqueue.RateLimitingInterface
	// installedGroups saves the groups which are configured on OVS.
	// With encap mode, the entries in installedGroups include all multicast groups identified in the cluster.
	installedGroups      sets.Set[string]
	installedGroupsMutex sync.RWMutex
	// installedLocalGroups saves the groups which are configured on OVS and host. The entries in installedLocalGroups
	// include the multicast groups that local Pod members join.
	installedLocalGroups      sets.Set[string]
	installedLocalGroupsMutex sync.RWMutex
	mRouteClient              *MRouteClient
	// queryInterval is the interval to send IGMP query messages.
	queryInterval time.Duration
	// mcastGroupTimeout is the timeout to detect a group as stale if no IGMP report is received within the time.
	mcastGroupTimeout time.Duration
	// the group ID in OVS for group which IGMP queries are sent to
	queryGroupId binding.GroupIDType
	// nodeGroupID is the OpenFlow group ID in OVS which is used to send IGMP report messages to other Nodes.
	nodeGroupID binding.GroupIDType
	// installedNodes is the installed Node set that the IGMP report message is sent to.
	installedNodes      sets.Set[string]
	encapEnabled        bool
	flexibleIPAMEnabled bool
	// ipv4Enabled is the flag that if it is running on IPv4 cluster. An error is returned if IPv4Enabled is false
	// in Initialize as Multicast does not support IPv6 for now.
	// TODO: remove this flag after IPv6 is supported in Multicast.
	ipv4Enabled bool
	// ipv6Enabled is the flag that if it is running on IPv6 cluster.
	// TODO: remove this flag after IPv6 is supported in Multicast.
	ipv6Enabled bool
}

func NewMulticastController(ofClient openflow.Client,
	v4GroupAllocator openflow.GroupAllocator,
	nodeConfig *config.NodeConfig,
	ifaceStore interfacestore.InterfaceStore,
	multicastSocket RouteInterface,
	multicastInterfaces sets.Set[string],
	podUpdateSubscriber channel.Subscriber,
	igmpQueryInterval time.Duration,
	igmpQueryVersions []uint8,
	validator types.McastNetworkPolicyController,
	isEncap bool,
	nodeInformer coreinformers.NodeInformer,
	enableFlexibleIPAM bool,
	ipv4Enabled bool,
	ipv6Enabled bool) *Controller {
	eventCh := make(chan *mcastGroupEvent, workerCount)
	groupSnooper := newSnooper(ofClient, ifaceStore, eventCh, igmpQueryInterval, igmpQueryVersions, validator, isEncap)
	groupCache := cache.NewIndexer(getGroupEventKey, cache.Indexers{
		podInterfaceIndex: podInterfaceIndexFunc,
	})
	multicastRouteClient := newRouteClient(nodeConfig, groupCache, multicastSocket, multicastInterfaces, isEncap, enableFlexibleIPAM)
	c := &Controller{
		ofClient:             ofClient,
		ifaceStore:           ifaceStore,
		v4GroupAllocator:     v4GroupAllocator,
		nodeConfig:           nodeConfig,
		igmpSnooper:          groupSnooper,
		groupEventCh:         eventCh,
		groupCache:           groupCache,
		installedGroups:      sets.New[string](),
		installedLocalGroups: sets.New[string](),
		queue:                workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "multicastgroup"),
		mRouteClient:         multicastRouteClient,
		queryInterval:        igmpQueryInterval,
		mcastGroupTimeout:    igmpQueryInterval * 3,
		queryGroupId:         v4GroupAllocator.Allocate(),
		encapEnabled:         isEncap,
		flexibleIPAMEnabled:  enableFlexibleIPAM,
		ipv4Enabled:          ipv4Enabled,
		ipv6Enabled:          ipv6Enabled,
	}
	if isEncap {
		c.nodeGroupID = v4GroupAllocator.Allocate()
		c.installedNodes = sets.New[string]()
		c.nodeInformer = nodeInformer
		c.nodeLister = c.nodeInformer.Lister()
		c.nodeListerSynced = c.nodeInformer.Informer().HasSynced
		c.nodeUpdateQueue = workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "nodeUpdate")
		c.nodeInformer.Informer().AddEventHandlerWithResyncPeriod(
			cache.ResourceEventHandlerFuncs{
				AddFunc: func(cur interface{}) {
					c.nodeUpdateQueue.Add(nodeUpdateKey)
				},
				UpdateFunc: func(old, cur interface{}) {
					c.checkNodeUpdate(old, cur)
				},
				DeleteFunc: func(old interface{}) {
					c.nodeUpdateQueue.Add(nodeUpdateKey)
				},
			},
			nodeResyncPeriod,
		)
	}
	podUpdateSubscriber.Subscribe(c.memberChanged)
	return c
}

func (c *Controller) Initialize() error {
	if !c.ipv4Enabled {
		return fmt.Errorf("Multicast is not supported on an IPv6-only cluster")
	} else if c.ipv6Enabled {
		klog.InfoS("Multicast only works with IPv4 traffic on a dual-stack cluster")
	}
	err := c.mRouteClient.Initialize()
	if err != nil {
		return err
	}
	err = c.initQueryGroup()
	if err != nil {
		return err
	}
	if c.flexibleIPAMEnabled {
		if err := c.ofClient.InstallMulticastFlexibleIPAMFlows(); err != nil {
			klog.ErrorS(err, "Failed to install OpenFlow flows to handle multicast traffic when flexibleIPAM is enabled")
			return err
		}
	}
	if c.encapEnabled {
		// Install OpenFlow group to send the multicast groups that local Pods joined to all other Nodes in the cluster.
		if err := c.ofClient.InstallMulticastGroup(c.nodeGroupID, nil, nil); err != nil {
			klog.ErrorS(err, "Failed to update OpenFlow group for remote Nodes")
			return err
		}
		if err := c.ofClient.InstallMulticastRemoteReportFlows(c.nodeGroupID); err != nil {
			klog.ErrorS(err, "Failed to install OpenFlow group and flow to send IGMP report to other Nodes")
			return err
		}
	}
	return nil
}

func (c *Controller) Run(stopCh <-chan struct{}) {
	// Periodically query Multicast Groups on OVS.
	go wait.NonSlidingUntil(func() {
		if err := c.igmpSnooper.queryIGMP(net.IPv4zero); err != nil {
			klog.ErrorS(err, "Failed to send IGMP query")
		}
	}, c.queryInterval, stopCh)

	if c.encapEnabled {
		go wait.NonSlidingUntil(c.syncLocalGroupsToOtherNodes, c.queryInterval, stopCh)
		go wait.Until(c.nodeWorker, time.Second, stopCh)
	}

	// Periodically check the group member status, and remove the groups in which no members exist
	go wait.NonSlidingUntil(c.clearStaleGroups, c.queryInterval, stopCh)
	go c.eventHandler(stopCh)

	for i := 0; i < int(workerCount); i++ {
		// Process multicast Group membership report or leave messages.
		go wait.Until(c.worker, time.Second, stopCh)
	}
	go c.mRouteClient.run(stopCh)
}

func (c *Controller) worker() {
	for c.processNextWorkItem() {
	}
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
	memberPorts := make([]uint32, 0, len(status.localMembers)+1)
	if c.flexibleIPAMEnabled {
		memberPorts = append(memberPorts, config.UplinkOFPort, c.nodeConfig.HostInterfaceOFPort)
	} else {
		memberPorts = append(memberPorts, config.HostGatewayOFPort)
	}
	for memberInterfaceName := range status.localMembers {
		obj, found := c.ifaceStore.GetInterfaceByName(memberInterfaceName)
		if !found {
			klog.InfoS("Failed to find interface from cache", "interface", memberInterfaceName)
			continue
		}
		memberPorts = append(memberPorts, uint32(obj.OFPort))
	}
	var remoteNodeReceivers []net.IP
	if c.encapEnabled {
		remoteNodeReceivers = make([]net.IP, 0, len(status.remoteMembers))
		for member := range status.remoteMembers {
			remoteNodeReceivers = append(remoteNodeReceivers, net.ParseIP(member))
		}
	}
	installLocalMulticastGroup := func() error {
		if err := c.mRouteClient.multicastInterfacesJoinMgroup(status.group); err != nil {
			klog.ErrorS(err, "Failed to install multicast group identified with local members", "group", groupKey)
			return err
		}
		if c.encapEnabled {
			if err := c.igmpSnooper.sendIGMPJoinReport([]net.IP{status.group}); err != nil {
				klog.ErrorS(err, "Failed to sync local multicast group to other Nodes", "group", groupKey)
				return err
			}
		}
		c.addInstalledLocalGroup(groupKey)
		klog.InfoS("New local multicast group is added", "group", groupKey)
		return nil
	}
	deleteLocalMulticastGroup := func() error {
		err := c.mRouteClient.deleteInboundMrouteEntryByGroup(status.group)
		if err != nil {
			klog.ErrorS(err, "Cannot delete multicast group", "group", groupKey)
			return err
		}
		klog.InfoS("Removed multicast route entry", "group", status.group)
		err = c.mRouteClient.multicastInterfacesLeaveMgroup(status.group)
		if err != nil {
			klog.ErrorS(err, "Failed to leave multicast group for multicast interfaces", "group", groupKey)
			return err
		}

		if c.encapEnabled {
			group := net.ParseIP(groupKey)
			// Send IGMP leave message to other Nodes to notify the current Node leaves the given multicast group.
			if err := c.igmpSnooper.sendIGMPLeaveReport([]net.IP{group}); err != nil {
				klog.ErrorS(err, "Failed to send IGMP leave message to other Nodes", "group", groupKey)
			}
		}
		c.delInstalledLocalGroup(groupKey)
		return nil
	}
	if c.groupHasInstalled(groupKey) {
		if c.groupIsStale(status) {
			if c.localGroupHasInstalled(groupKey) {
				if err := deleteLocalMulticastGroup(); err != nil {
					return err
				}
			}
			// TODO: add check on the stale multicast group that is joined by the Pods on a different Node.
			// remoteMembers is always empty with noEncap mode.
			if status.remoteMembers.Len() == 0 {
				// Remove the multicast OpenFlow flow and group entries if none Pod member on local or remote Node is in the group.
				if err := c.ofClient.UninstallMulticastFlows(status.group); err != nil {
					klog.ErrorS(err, "Failed to uninstall multicast flows", "group", groupKey)
					return err
				}
				// Remove the multicast flow entry if no local Pod is in the group.
				if err := c.ofClient.UninstallMulticastGroup(status.ofGroupID); err != nil {
					klog.ErrorS(err, "Failed to uninstall multicast group", "group", groupKey)
					return err
				}
				c.v4GroupAllocator.Release(status.ofGroupID)
				c.delInstalledGroup(groupKey)
				c.groupCache.Delete(status)
				klog.InfoS("Removed multicast group from cache after all members left", "group", groupKey)
				return nil
			}
		} else if !c.localGroupHasInstalled(groupKey) {
			// Install multicast flows and routing entries for the multicast group that local Pods join.
			if err := installLocalMulticastGroup(); err != nil {
				return err
			}
		}
		// Reinstall OpenFlow group because either the remote node receivers or local Pod receivers have changed.
		klog.V(2).InfoS("Updating OpenFlow group for receivers in multicast group", "group", groupKey, "ofGroup", status.ofGroupID, "localReceivers", memberPorts, "remoteReceivers", remoteNodeReceivers)
		if err := c.ofClient.InstallMulticastGroup(status.ofGroupID, memberPorts, remoteNodeReceivers); err != nil {
			return err
		}
		klog.InfoS("Updated OpenFlow group for receivers in multicast group", "group", groupKey, "ofGroup", status.ofGroupID, "localReceivers", memberPorts, "remoteReceivers", remoteNodeReceivers)
		return nil
	}
	// Install OpenFlow group for a new multicast group which has local Pod receivers joined.
	if err := c.ofClient.InstallMulticastGroup(status.ofGroupID, memberPorts, remoteNodeReceivers); err != nil {
		return err
	}
	klog.V(2).InfoS("Installed OpenFlow group for multicast group", "group", groupKey, "ofGroup", status.ofGroupID, "localReceivers", memberPorts, "remoteReceivers", remoteNodeReceivers)
	// Install OpenFlow flow to forward packets to local Pod receivers which are included in the group.
	if err := c.ofClient.InstallMulticastFlows(status.group, status.ofGroupID); err != nil {
		klog.ErrorS(err, "Failed to install multicast flows", "group", status.group)
		return err
	}
	klog.InfoS("Installed OpenFlow flows for multicast group", "group", groupKey, "ofGroup", status.ofGroupID, "localReceivers", memberPorts, "remoteReceivers", remoteNodeReceivers)
	if len(status.localMembers) > 0 {
		err := installLocalMulticastGroup()
		if err != nil {
			return err
		}
	}
	c.addInstalledGroup(groupKey)
	return nil
}

// groupIsStale returns true if no local members in the group, or there is no IGMP report received after c.mcastGroupTimeout.
func (c *Controller) groupIsStale(status *GroupMemberStatus) bool {
	membersCount := len(status.localMembers)
	diff := time.Now().Sub(status.lastIGMPReport)
	return membersCount == 0 || diff > c.mcastGroupTimeout
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

func (c *Controller) localGroupHasInstalled(groupKey string) bool {
	c.installedLocalGroupsMutex.RLock()
	defer c.installedLocalGroupsMutex.RUnlock()
	return c.installedLocalGroups.Has(groupKey)
}

func (c *Controller) addInstalledLocalGroup(groupKey string) {
	c.installedLocalGroupsMutex.Lock()
	c.installedLocalGroups.Insert(groupKey)
	c.installedLocalGroupsMutex.Unlock()
}

func (c *Controller) delInstalledLocalGroup(groupKey string) {
	c.installedLocalGroupsMutex.Lock()
	c.installedLocalGroups.Delete(groupKey)
	c.installedLocalGroupsMutex.Unlock()
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

func (c *Controller) memberChanged(e interface{}) {
	podEvent := e.(types.PodUpdate)
	namespace, name := podEvent.PodNamespace, podEvent.PodName

	klog.V(2).InfoS("Pod is updated", "IsAdd", podEvent.IsAdd, "namespace", namespace, "name", name)
	event := &mcastGroupEvent{
		group: types.McastAllHosts,
	}
	c.groupEventCh <- event
	c.removeLocalInterface(podEvent)
}

func (c *Controller) initQueryGroup() error {
	err := c.updateQueryGroup()
	if err != nil {
		return err
	}
	if err = c.ofClient.InstallMulticastFlows(types.McastAllHosts, c.queryGroupId); err != nil {
		klog.ErrorS(err, "Failed to install multicast flows", "group", types.McastAllHosts)
		return err
	}
	return nil
}

// updateQueryGroup gets all containers' interfaces, and add all ofports into IGMP query group.
func (c *Controller) updateQueryGroup() error {
	ifaces := c.ifaceStore.GetInterfacesByType(interfacestore.ContainerInterface)
	memberPorts := make([]uint32, 0, len(ifaces))
	for _, iface := range ifaces {
		memberPorts = append(memberPorts, uint32(iface.OFPort))
	}
	// Install OpenFlow group for a new multicast group which has local Pod receivers joined.
	if err := c.ofClient.InstallMulticastGroup(c.queryGroupId, memberPorts, nil); err != nil {
		return err
	}
	klog.V(2).InfoS("Installed OpenFlow group for local receivers", "group", types.McastAllHosts.String(),
		"ofGroup", c.queryGroupId, "localReceivers", memberPorts)
	return nil
}

// syncLocalGroupsToOtherNodes sends IGMP join message to other Nodes in the same cluster to notify what multicast groups
// are joined by this Node. This function is used only with encap mode.
func (c *Controller) syncLocalGroupsToOtherNodes() {
	if c.installedLocalGroups.Len() == 0 {
		return
	}
	localGroups := make([]net.IP, 0, c.installedLocalGroups.Len())
	c.installedLocalGroupsMutex.RLock()
	for group := range c.installedLocalGroups {
		localGroups = append(localGroups, net.ParseIP(group))
	}
	c.installedLocalGroupsMutex.RUnlock()
	if err := c.igmpSnooper.sendIGMPJoinReport(localGroups); err != nil {
		klog.ErrorS(err, "Failed to sync local multicast groups to other Nodes")
	}
}

func (c *Controller) syncNodes() error {
	startTime := time.Now()
	defer func() {
		klog.V(4).Infof("Finished syncing Node IPs. (%v)", time.Since(startTime))
	}()

	nodes, err := c.nodeLister.List(labels.Everything())
	if err != nil {
		klog.ErrorS(err, "Failed to list Nodes")
		return err
	}
	var updatedNodeIPs []net.IP
	updatedNodeIPSet := sets.New[string]()
	for _, n := range nodes {
		if n.Name == c.nodeConfig.Name {
			continue
		}
		nip, err := k8s.GetNodeTransportAddrs(n)
		if err != nil {
			klog.ErrorS(err, "Failed to retrieve Node IP addresses", "node", n.Name)
			return err
		}
		if nip.IPv4 != nil {
			updatedNodeIPs = append(updatedNodeIPs, nip.IPv4)
			updatedNodeIPSet.Insert(nip.IPv4.String())
		}
	}
	if c.installedNodes.Equal(updatedNodeIPSet) {
		klog.V(2).InfoS("Nodes in the cluster are not changed, ignore the event")
		return nil
	}
	if err := c.ofClient.InstallMulticastGroup(c.nodeGroupID, nil, updatedNodeIPs); err != nil {
		klog.ErrorS(err, "Failed to update OpenFlow group for remote Nodes")
		return err
	}
	c.installedNodes = updatedNodeIPSet
	// Notify local installed multicast groups to other Nodes in the cluster.
	c.syncLocalGroupsToOtherNodes()
	return nil
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

func (c *Controller) CollectIGMPReportNPStats() (igmpANNPStats, igmpACNPStats map[apitypes.UID]map[string]*types.RuleMetric) {
	return c.igmpSnooper.collectStats()
}

func (c *Controller) GetGroupPods() map[string][]v1beta2.PodReference {
	groupPodsMap := make(map[string][]v1beta2.PodReference)
	for _, obj := range c.groupCache.List() {
		status := obj.(*GroupMemberStatus)
		members := make([]v1beta2.PodReference, 0, len(status.localMembers))
		for s := range status.localMembers {
			iface, found := c.ifaceStore.GetInterfaceByName(s)
			if found {
				members = append(members, v1beta2.PodReference{Name: iface.PodName, Namespace: iface.PodNamespace})
			}
		}
		if len(members) > 0 {
			groupPodsMap[status.group.String()] = members
		}
	}
	return groupPodsMap
}

// PodTrafficStats encodes the inbound and outbound multicast statistics of each Pod.
type PodTrafficStats struct {
	Inbound, Outbound uint64
}

func (c *Controller) GetPodStats(podName string, podNamespace string) *PodTrafficStats {
	ifaces := c.ifaceStore.GetContainerInterfacesByPod(podName, podNamespace)
	for _, iface := range ifaces {
		egressPodStats := c.ofClient.MulticastEgressPodMetricsByIP(iface.GetIPv4Addr())
		ingressPodStats := c.ofClient.MulticastIngressPodMetricsByOFPort(iface.OFPort)
		return &PodTrafficStats{Inbound: ingressPodStats.Packets, Outbound: egressPodStats.Packets}
	}
	return nil
}

func (c *Controller) GetAllPodsStats() map[*interfacestore.InterfaceConfig]*PodTrafficStats {
	statsMap := make(map[*interfacestore.InterfaceConfig]*PodTrafficStats)
	egressPodStats := c.ofClient.MulticastEgressPodMetrics()
	for ipStr, stats := range egressPodStats {
		iface, exist := c.ifaceStore.GetInterfaceByIP(ipStr)
		if exist {
			statEntry, ok := statsMap[iface]
			if !ok {
				statsMap[iface] = &PodTrafficStats{Outbound: stats.Packets}
			} else {
				statEntry.Outbound += stats.Packets
			}
		}
	}
	ingressPodStats := c.ofClient.MulticastIngressPodMetrics()
	for ofPort, stats := range ingressPodStats {
		iface, exist := c.ifaceStore.GetInterfaceByOFPort(ofPort)
		if exist {
			statEntry, ok := statsMap[iface]
			if !ok {
				statsMap[iface] = &PodTrafficStats{Inbound: stats.Packets}
			} else {
				statEntry.Inbound += stats.Packets
			}
		}
	}
	return statsMap
}

func (c *Controller) checkNodeUpdate(old interface{}, cur interface{}) {
	oldNode := old.(*corev1.Node)
	if oldNode.Name == c.nodeConfig.Name {
		return
	}
	curNode := cur.(*corev1.Node)
	oldIPs, err := k8s.GetNodeTransportAddrs(oldNode)
	if err != nil {
		klog.ErrorS(err, "Failed to retrieve Node old IP addresses", "node", oldNode.Name)
		return
	}
	newIPs, err := k8s.GetNodeTransportAddrs(curNode)
	if err != nil {
		klog.ErrorS(err, "Failed to retrieve Node current IP addresses", "node", curNode.Name)
		return
	}
	if (*newIPs).Equal(*oldIPs) {
		return
	}
	c.nodeUpdateQueue.Add(nodeUpdateKey)
}

func (c *Controller) nodeWorker() {
	for c.processNextNodeItem() {
	}
}

func (c *Controller) processNextNodeItem() bool {
	obj, quit := c.nodeUpdateQueue.Get()
	if quit {
		return false
	}
	// We call Done here so the workqueue knows we have finished processing this item. We also
	// must remember to call Forget if we do not want this work item being re-queued. For
	// example, we do not call Forget if a transient error occurs, instead the item is put back
	// on the workqueue and attempted again after a back-off period.
	defer c.nodeUpdateQueue.Done(obj)

	// We expect strings (Node name) to come off the workqueue.
	if key, ok := obj.(string); !ok {
		// As the item in the workqueue is actually invalid, we call Forget here else we'd
		// go into a loop of attempting to process a work item that is invalid.
		// This should not happen: only a constant string enqueues nodeUpdateQueue.
		c.nodeUpdateQueue.Forget(obj)
		klog.Errorf("Expected string in work queue but got %#v", obj)
		return true
	} else if err := c.syncNodes(); err == nil {
		// If no error occurs we Forget this item so it does not get queued again until
		// another change happens.
		c.nodeUpdateQueue.Forget(key)
	} else {
		// Put the item back on the workqueue to handle any transient errors.
		c.nodeUpdateQueue.AddRateLimited(key)
		klog.ErrorS(err, "Error syncing Nodes, requeuing")
	}
	return true
}

func memberExists(status *GroupMemberStatus, e *mcastGroupEvent) bool {
	var exist bool
	if e.iface.Type == interfacestore.ContainerInterface {
		_, exist = status.localMembers[e.iface.InterfaceName]
	} else if e.iface.Type == interfacestore.TunnelInterface {
		exist = status.remoteMembers.Has(e.srcNode.String())
	}
	return exist
}

func addGroupMember(status *GroupMemberStatus, e *mcastGroupEvent) *GroupMemberStatus {
	if e.iface.Type == interfacestore.ContainerInterface {
		status.localMembers[e.iface.InterfaceName] = e.time
		status.lastIGMPReport = e.time
		klog.V(2).InfoS("Added local member from multicast group", "group", e.group.String(), "member", e.iface.InterfaceName)
	} else {
		status.remoteMembers.Insert(e.srcNode.String())
		klog.V(2).InfoS("Added remote member from multicast group", "group", e.group.String(), "member", e.srcNode)
	}
	return status
}

func deleteGroupMember(status *GroupMemberStatus, e *mcastGroupEvent) *GroupMemberStatus {
	if e.iface.Type == interfacestore.ContainerInterface {
		delete(status.localMembers, e.iface.InterfaceName)
		klog.V(2).InfoS("Deleted local member from multicast group", "group", e.group.String(), "member", e.iface.InterfaceName)
	} else {
		status.remoteMembers.Delete(e.srcNode.String())
		klog.V(2).InfoS("Deleted remote member from multicast group", "group", e.group.String(), "member", e.srcNode)
	}
	return status
}
