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

package memberlist

import (
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"sync"
	"time"

	"github.com/hashicorp/memberlist"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/consistenthash"
	"antrea.io/antrea/pkg/apis/crd/v1beta1"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1beta1"
	crdlister "antrea.io/antrea/pkg/client/listers/crd/v1beta1"
	"antrea.io/antrea/pkg/util/k8s"
)

const (
	controllerName = "MemberListCluster"
	// Set resyncPeriod to 0 to disable resyncing.
	resyncPeriod time.Duration = 0
	// Set default virtual node replicas num of consistent hash
	// in order to improve the quality of the hash distribution, refs https://github.com/golang/groupcache/issues/29
	defaultVirtualNodeReplicas = 50
	// How long to wait before retrying the processing of an ExternalIPPool change.
	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second
	// Default number of workers processing an ExternalIPPool change.
	defaultWorkers = 4

	nodeEventTypeJoin   nodeEventType = "Join"
	nodeEventTypeLeave  nodeEventType = "Leave"
	nodeEventTypeUpdate nodeEventType = "Update"

	allNodesConsistentHashMapKey = ""
)

// ErrNoNodeAvailable is the error returned if no Node is chosen in SelectNodeForIP and ShouldSelectIP.
var ErrNoNodeAvailable = errors.New("no Node available")

type nodeEventType string

// Default Hash Fn is crc32.ChecksumIEEE.
var defaultHashFn func(data []byte) uint32

var (
	errDecodingObject          = fmt.Errorf("received unexpected object")
	errDecodingObjectTombstone = fmt.Errorf("deletedFinalStateUnknown contains unexpected object")
)

var mapNodeEventType = map[memberlist.NodeEventType]nodeEventType{
	memberlist.NodeJoin:   nodeEventTypeJoin,
	memberlist.NodeLeave:  nodeEventTypeLeave,
	memberlist.NodeUpdate: nodeEventTypeUpdate,
}

var linuxNodeSelector = labels.SelectorFromSet(labels.Set{corev1.LabelOSStable: "linux"})

type ClusterNodeEventHandler func(objName string)

type Interface interface {
	ShouldSelectIP(ip string, pool string, filters ...func(node string) bool) (bool, error)
	SelectNodeForIP(ip, externalIPPool string, filters ...func(string) bool) (string, error)
	AliveNodes() sets.Set[string]
	AddClusterEventHandler(handler ClusterNodeEventHandler)
}

type Memberlist interface {
	Join(existing []string) (int, error)
	Members() []*memberlist.Node
	Leave(timeout time.Duration) error
	Shutdown() error
}

// Cluster implements ClusterInterface.
type Cluster struct {
	bindPort int
	// Name of local Node. Node name must be unique in the cluster.
	nodeName string

	mList Memberlist
	// consistentHash hold the consistentHashMap, when a Node join cluster, use method Add() to add a key to the hash.
	// when a Node leave the cluster, the consistentHashMap should be update.
	consistentHashMap     map[string]*consistenthash.Map
	consistentHashRWMutex sync.RWMutex
	// nodeEventsCh, the Node join/leave events will be notified via it.
	nodeEventsCh chan memberlist.NodeEvent

	// clusterNodeEventHandlers contains eventHandler which will run when consistentHashMap is updated,
	// which caused by an ExternalIPPool or Node event, such as cluster Node status update(leave of join cluster),
	// ExternalIPPool events(create/update/delete).
	// For example, when a new Node joins the cluster, each Node should compute whether it should still hold all
	// its existing Egresses, and when a Node leaves the cluster,
	// each Node should check whether it is now responsible for some of the Egresses from that Node.
	clusterNodeEventHandlers []ClusterNodeEventHandler

	nodeInformer     coreinformers.NodeInformer
	nodeLister       corelisters.NodeLister
	nodeListerSynced cache.InformerSynced

	externalIPPoolInformer          cache.SharedIndexInformer
	externalIPPoolLister            crdlister.ExternalIPPoolLister
	externalIPPoolInformerHasSynced cache.InformerSynced

	// queue maintains the ExternalIPPool names that need to be synced.
	queue workqueue.RateLimitingInterface
}

// NewCluster returns a new *Cluster.
func NewCluster(
	nodeIP net.IP,
	clusterBindPort int,
	nodeName string,
	nodeInformer coreinformers.NodeInformer,
	externalIPPoolInformer crdinformers.ExternalIPPoolInformer,
	ml Memberlist, // Parameterized for testing, could be left nil for production code.
) (*Cluster, error) {
	// The Node join/leave events will be notified via it.
	nodeEventCh := make(chan memberlist.NodeEvent, 1024)
	c := &Cluster{
		bindPort:                        clusterBindPort,
		nodeName:                        nodeName,
		consistentHashMap:               make(map[string]*consistenthash.Map),
		mList:                           ml,
		nodeEventsCh:                    nodeEventCh,
		nodeInformer:                    nodeInformer,
		nodeLister:                      nodeInformer.Lister(),
		nodeListerSynced:                nodeInformer.Informer().HasSynced,
		externalIPPoolInformer:          externalIPPoolInformer.Informer(),
		externalIPPoolLister:            externalIPPoolInformer.Lister(),
		externalIPPoolInformerHasSynced: externalIPPoolInformer.Informer().HasSynced,
		queue:                           workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "externalIPPool"),
	}

	if ml == nil {
		conf := memberlist.DefaultLocalConfig()
		conf.Name = c.nodeName
		conf.BindPort = c.bindPort
		conf.AdvertisePort = c.bindPort
		conf.AdvertiseAddr = nodeIP.String()
		// Setting it to a non-zero value to allow reclaiming Nodes with different addresses for Node IP update case.
		conf.DeadNodeReclaimTime = 10 * time.Millisecond
		conf.Events = &memberlist.ChannelEventDelegate{Ch: nodeEventCh}
		conf.LogOutput = io.Discard
		klog.V(1).InfoS("New memberlist cluster", "config", conf)

		mList, err := memberlist.Create(conf)
		if err != nil {
			return nil, fmt.Errorf("failed to create memberlist cluster: %v", err)
		}
		c.mList = mList
	}

	nodeInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.handleCreateNode,
			UpdateFunc: c.handleUpdateNode,
			DeleteFunc: c.handleDeleteNode,
		},
		resyncPeriod,
	)
	externalIPPoolInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc: c.enqueueExternalIPPool,
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldExternalIPPool := oldObj.(*v1beta1.ExternalIPPool)
				curExternalIPPool := newObj.(*v1beta1.ExternalIPPool)
				if !reflect.DeepEqual(oldExternalIPPool.Spec.NodeSelector, curExternalIPPool.Spec.NodeSelector) {
					c.enqueueExternalIPPool(newObj)
				}
			},
			DeleteFunc: c.enqueueExternalIPPool,
		},
		resyncPeriod,
	)
	return c, nil
}

func shouldJoinCluster(node *corev1.Node) bool {
	// non-Linux Nodes should not join the memberlist cluster as all features relying on it is only supported on Linux.
	return linuxNodeSelector.Matches(labels.Set(node.Labels))
}

func (c *Cluster) handleCreateNode(obj interface{}) {
	node := obj.(*corev1.Node)
	if !shouldJoinCluster(node) {
		return
	}
	// Ignore the Node itself.
	if node.Name == c.nodeName {
		return
	}
	if member, err := c.newClusterMember(node); err == nil {
		_, err := c.mList.Join([]string{member})
		if err != nil {
			klog.InfoS("Processing Node CREATE event error, join cluster failed, will retry later", "error", errors.Unwrap(err), "member", member)
		}
	} else {
		klog.ErrorS(err, "Processing Node CREATE event error", "nodeName", node.Name)
	}

	affectedEIPs := c.filterEIPsFromNodeLabels(node)
	c.enqueueExternalIPPools(affectedEIPs.Insert(allNodesConsistentHashMapKey))
	klog.V(2).InfoS("Processed Node CREATE event", "nodeName", node.Name, "affectedExternalIPPoolNum", affectedEIPs.Len())
}

func (c *Cluster) handleDeleteNode(obj interface{}) {
	node, ok := obj.(*corev1.Node)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.ErrorS(errDecodingObject, "Processing Node DELETE event error", "obj", obj)
			return
		}
		node, ok = tombstone.Obj.(*corev1.Node)
		if !ok {
			klog.ErrorS(errDecodingObjectTombstone, "Processing Node DELETE event error", "obj", tombstone.Obj)
			return
		}
	}
	if !shouldJoinCluster(node) {
		return
	}
	affectedEIPs := c.filterEIPsFromNodeLabels(node)
	c.enqueueExternalIPPools(affectedEIPs.Insert(allNodesConsistentHashMapKey))
	klog.V(2).InfoS("Processed Node DELETE event", "nodeName", node.Name, "affectedExternalIPPoolNum", affectedEIPs.Len())
}

func (c *Cluster) handleUpdateNode(oldObj, newObj interface{}) {
	node := newObj.(*corev1.Node)
	if !shouldJoinCluster(node) {
		return
	}
	oldNode := oldObj.(*corev1.Node)
	if reflect.DeepEqual(node.GetLabels(), oldNode.GetLabels()) {
		klog.V(2).InfoS("Processed Node UPDATE event, labels not changed", "nodeName", node.Name)
		return
	}
	oldMatches, newMatches := c.filterEIPsFromNodeLabels(oldNode), c.filterEIPsFromNodeLabels(node)
	if oldMatches.Equal(newMatches) {
		klog.V(2).InfoS("Processed Node UPDATE event, Node cluster status not changed", "nodeName", node.Name)
		return
	}
	affectedEIPs := oldMatches.Union(newMatches)
	c.enqueueExternalIPPools(affectedEIPs)
	klog.V(2).InfoS("Processed Node UPDATE event", "nodeName", node.Name, "affectedExternalIPPoolNum", affectedEIPs.Len())
}

func (c *Cluster) enqueueExternalIPPools(eips sets.Set[string]) {
	for eip := range eips {
		c.queue.Add(eip)
	}
}

func (c *Cluster) enqueueExternalIPPool(obj interface{}) {
	eip, ok := obj.(*v1beta1.ExternalIPPool)
	if !ok {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.ErrorS(errDecodingObject, "Processing ExternalIPPool DELETE event error", "obj", obj)
			return
		}
		eip, ok = deletedState.Obj.(*v1beta1.ExternalIPPool)
		if !ok {
			klog.ErrorS(errDecodingObjectTombstone, "Processing ExternalIPPool DELETE event error", "obj", deletedState.Obj)
			return
		}
	}
	c.queue.Add(eip.Name)
}

// newClusterMember gets the Node's IP and returns it as a cluster member for memberlist cluster to join.
func (c *Cluster) newClusterMember(node *corev1.Node) (string, error) {
	nodeAddrs, err := k8s.GetNodeAddrs(node)
	if err != nil {
		return "", fmt.Errorf("obtain IP addresses from K8s Node failed: %v", err)
	}
	nodeAddr := nodeAddrs.IPv4
	if nodeAddr == nil {
		nodeAddr = nodeAddrs.IPv6
	}
	return nodeAddr.String(), nil
}

func (c *Cluster) filterEIPsFromNodeLabels(node *corev1.Node) sets.Set[string] {
	pools := sets.New[string]()
	eips, _ := c.externalIPPoolLister.List(labels.Everything())
	for _, eip := range eips {
		nodeSelector, _ := metav1.LabelSelectorAsSelector(&eip.Spec.NodeSelector)
		if nodeSelector.Matches(labels.Set(node.GetLabels())) {
			pools.Insert(eip.Name)
		}
	}
	return pools
}

// Run will join all the other K8s Nodes in a memberlist cluster
// and will create defaultWorkers workers (go routines) which will process the ExternalIPPool or Node events
// from the work queue.
func (c *Cluster) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()
	// In order to exit the cluster more gracefully, call Leave prior to shutting down.
	defer close(c.nodeEventsCh)
	defer c.mList.Shutdown()
	defer c.mList.Leave(time.Second)

	klog.InfoS("Starting", "controllerName", controllerName)
	defer klog.InfoS("Shutting down", "controllerName", controllerName)

	if !cache.WaitForNamedCacheSync(controllerName, stopCh, c.externalIPPoolInformerHasSynced, c.nodeListerSynced) {
		return
	}

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}

	go func() {
		for {
			select {
			case <-stopCh:
				return
			case nodeEvent := <-c.nodeEventsCh:
				c.handleClusterNodeEvents(&nodeEvent)
			}
		}
	}()

	// Rejoin Nodes periodically in case some Nodes are removed from the member list because of long downtime.
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				c.RejoinNodes()
			}
		}
	}()

	<-stopCh
}

// RejoinNodes rejoins Nodes that were removed from the member list by memberlist because they were unreachable for more
// than 15 seconds (the GossipToTheDeadTime we are using). Without it, once there is a network downtime lasting more
// than 15 seconds, the agent wouldn't try to reach any other Node and would think it's the only alive Node until it's
// restarted.
func (c *Cluster) RejoinNodes() {
	nodes, _ := c.nodeLister.List(linuxNodeSelector)
	aliveNodes := c.AliveNodes()
	var membersToJoin []string
	for _, node := range nodes {
		if !aliveNodes.Has(node.Name) {
			member, err := c.newClusterMember(node)
			if err != nil {
				klog.ErrorS(err, "Failed to generate cluster member to join", "Node", node.Name)
				continue
			}
			membersToJoin = append(membersToJoin, member)
		}
	}
	// Every known Node is alive, do nothing.
	if len(membersToJoin) == 0 {
		return
	}
	// The Join method returns an error only when none could be reached.
	numSuccess, err := c.mList.Join(membersToJoin)
	if err != nil {
		klog.ErrorS(err, "Failed to rejoin any members", "members", membersToJoin)
	} else if numSuccess != len(membersToJoin) {
		klog.ErrorS(err, "Failed to rejoin some members", "members", membersToJoin, "numSuccess", numSuccess)
	} else {
		klog.InfoS("Rejoined all members", "members", membersToJoin)
	}
}

func (c *Cluster) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *Cluster) processNextWorkItem() bool {
	obj, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(obj)

	// We expect strings (ExternalIPPool name) to come off the work queue.
	if key, ok := obj.(string); !ok {
		// As the item in the work queue is actually invalid, we call Forget here else we'd
		// go into a loop of attempting to process a work item that is invalid.
		// This should not happen.
		c.queue.Forget(obj)
		klog.Errorf("Expected string in work queue but got %#v", obj)
		return true
	} else if err := c.syncConsistentHash(key); err == nil {
		// If no error occurs we Forget this item so it does not get queued again until
		// another change happens.
		c.queue.Forget(key)
	} else {
		// Put the item back on the work queue to handle any transient errors.
		c.queue.AddRateLimited(key)
		klog.ErrorS(err, "Syncing consistentHash by ExternalIPPool failed, requeue", "ExternalIPPool", key)
	}
	return true
}

func (c *Cluster) syncConsistentHash(eipName string) error {
	startTime := time.Now()
	defer func() {
		klog.V(4).InfoS("Finished syncing consistentHash", "ExternalIPPool", eipName, "durationTime", time.Since(startTime))
	}()

	if eipName == allNodesConsistentHashMapKey {
		allAgentNodes := c.AliveNodes()
		allKNodes, err := c.nodeLister.List(labels.Everything())
		if err != nil {
			return err
		}
		var allNodes []string
		for _, node := range allKNodes {
			nodeName := node.Name
			if allAgentNodes.Has(nodeName) {
				allNodes = append(allNodes, nodeName)
			}
		}
		allNodesConsistentHashMap := NewNodeConsistentHashMap()
		allNodesConsistentHashMap.Add(allNodes...)
		c.consistentHashRWMutex.Lock()
		defer c.consistentHashRWMutex.Unlock()
		c.consistentHashMap[allNodesConsistentHashMapKey] = allNodesConsistentHashMap
		return nil
	}

	eip, err := c.externalIPPoolLister.Get(eipName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			c.consistentHashRWMutex.Lock()
			defer c.consistentHashRWMutex.Unlock()
			delete(c.consistentHashMap, eipName)
			return nil
		}
		return err
	}

	// updateConsistentHash refreshes the consistentHashMap.
	updateConsistentHash := func(eip *v1beta1.ExternalIPPool) error {
		nodeSel, err := metav1.LabelSelectorAsSelector(&eip.Spec.NodeSelector)
		if err != nil {
			return fmt.Errorf("labelSelectorAsSelector error: %v", err)
		}
		nodes, err := c.nodeLister.List(nodeSel)
		if err != nil {
			return fmt.Errorf("listing Nodes error: %v", err)
		}
		aliveNodes := c.AliveNodes()
		// Node alive and Node labels match ExternalIPPool nodeSelector.
		var aliveAndMatchedNodes []string
		for _, node := range nodes {
			nodeName := node.Name
			if aliveNodes.Has(nodeName) {
				aliveAndMatchedNodes = append(aliveAndMatchedNodes, nodeName)
			}
		}
		consistentHashMap := NewNodeConsistentHashMap()
		consistentHashMap.Add(aliveAndMatchedNodes...)
		c.consistentHashRWMutex.Lock()
		defer c.consistentHashRWMutex.Unlock()
		c.consistentHashMap[eip.Name] = consistentHashMap
		c.notify(eip.Name)
		return nil
	}

	if err := updateConsistentHash(eip); err != nil {
		return err
	}
	return nil
}

func NewNodeConsistentHashMap() *consistenthash.Map {
	return consistenthash.New(defaultVirtualNodeReplicas, defaultHashFn)
}

func (c *Cluster) handleClusterNodeEvents(nodeEvent *memberlist.NodeEvent) {
	node, event := nodeEvent.Node, nodeEvent.Event
	switch event {
	case memberlist.NodeJoin, memberlist.NodeLeave:
		// When a Node joins cluster, all matched ExternalIPPools consistentHash should be updated;
		// when a Node leaves cluster, the Node may have failed or have been deleted,
		// if the Node has been deleted, affected ExternalIPPool should be enqueued, and deleteNode handler has been executed,
		// if the Node has failed, ExternalIPPools consistentHash maybe changed, and affected ExternalIPPool should be enqueued.
		coreNode, err := c.nodeLister.Get(node.Name)
		if err != nil {
			// It means the Node has been deleted, no further processing is needed as handleDeleteNode has enqueued
			// related ExternalIPPools.
			klog.InfoS("Received a Node event but did not find the Node object", "eventType", mapNodeEventType[event], "nodeName", node.Name)
			return
		}
		affectedEIPs := c.filterEIPsFromNodeLabels(coreNode)
		c.enqueueExternalIPPools(affectedEIPs.Insert(allNodesConsistentHashMapKey))
		klog.InfoS("Processed Node event", "eventType", mapNodeEventType[event], "nodeName", node.Name, "affectedExternalIPPoolNum", len(affectedEIPs))
	default:
		klog.InfoS("Processed Node event", "eventType", mapNodeEventType[event], "nodeName", node.Name)
	}
}

// AliveNodes returns the list of nodeNames in the cluster.
func (c *Cluster) AliveNodes() sets.Set[string] {
	nodes := sets.New[string]()
	for _, node := range c.mList.Members() {
		nodes.Insert(node.Name)
	}
	return nodes
}

// ShouldSelectIP returns true if the local Node selected as the owner Node of the IP in the specific
// ExternalIPPool. The local Node in the cluster holds the same consistent hash ring for each ExternalIPPool,
// consistentHash.Get gets the closest item (Node name) in the hash to the provided key (IP), if the name of
// the local Node is equal to the name of the selected Node, returns true.
func (c *Cluster) ShouldSelectIP(ip, externalIPPool string, filters ...func(string) bool) (bool, error) {
	if externalIPPool == "" || ip == "" {
		return false, nil
	}
	c.consistentHashRWMutex.RLock()
	defer c.consistentHashRWMutex.RUnlock()
	consistentHash, ok := c.consistentHashMap[externalIPPool]
	if !ok {
		return false, fmt.Errorf("local Node consistentHashMap has not synced, ExternalIPPool %s", externalIPPool)
	}
	node := consistentHash.GetWithFilters(ip, filters...)
	return node == c.nodeName, nil
}

// SelectNodeForIP returns the closest item (Node name) in the hash to the provided key (IP) and ExternalIPPool.
func (c *Cluster) SelectNodeForIP(ip, externalIPPool string, filters ...func(string) bool) (string, error) {
	c.consistentHashRWMutex.RLock()
	defer c.consistentHashRWMutex.RUnlock()
	consistentHash, ok := c.consistentHashMap[externalIPPool]
	if !ok {
		return "", fmt.Errorf("local Node consistentHashMap has not synced, ExternalIPPool %s", externalIPPool)
	}
	node := consistentHash.GetWithFilters(ip, filters...)
	if node == "" {
		return "", ErrNoNodeAvailable
	}
	return node, nil
}

func (c *Cluster) notify(objName string) {
	for _, handler := range c.clusterNodeEventHandlers {
		handler(objName)
	}
}

// AddClusterEventHandler adds a clusterNodeEventHandler, which will run when consistentHashMap is updated,
// due to an ExternalIPPool or Node event.
func (c *Cluster) AddClusterEventHandler(handler ClusterNodeEventHandler) {
	c.clusterNodeEventHandlers = append(c.clusterNodeEventHandlers, handler)
}
