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
	"fmt"
	"io/ioutil"
	"net"
	"reflect"
	"sync"
	"time"

	"github.com/golang/groupcache/consistenthash"
	"github.com/hashicorp/memberlist"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha2"
	crdlister "antrea.io/antrea/pkg/client/listers/crd/v1alpha2"
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
)

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

type clusterNodeEventHandler func(objName string)

// Cluster implements ClusterInterface.
type Cluster struct {
	bindPort int
	// Name of local Node. Node name must be unique in the cluster.
	nodeName string

	mList *memberlist.Memberlist
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
	clusterNodeEventHandlers []clusterNodeEventHandler

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
	clusterBindPort int,
	nodeName string,
	nodeIP net.IP,
	nodeInformer coreinformers.NodeInformer,
	externalIPPoolInformer crdinformers.ExternalIPPoolInformer,
) (*Cluster, error) {
	// The Node join/leave events will be notified via it.
	nodeEventCh := make(chan memberlist.NodeEvent, 1024)
	c := &Cluster{
		bindPort:                        clusterBindPort,
		nodeName:                        nodeName,
		consistentHashMap:               make(map[string]*consistenthash.Map),
		nodeEventsCh:                    nodeEventCh,
		nodeInformer:                    nodeInformer,
		nodeLister:                      nodeInformer.Lister(),
		nodeListerSynced:                nodeInformer.Informer().HasSynced,
		externalIPPoolInformer:          externalIPPoolInformer.Informer(),
		externalIPPoolLister:            externalIPPoolInformer.Lister(),
		externalIPPoolInformerHasSynced: externalIPPoolInformer.Informer().HasSynced,
		queue:                           workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "externalIPPool"),
	}

	conf := memberlist.DefaultLocalConfig()
	conf.Name = c.nodeName
	conf.BindPort = c.bindPort
	conf.AdvertisePort = c.bindPort
	conf.AdvertiseAddr = nodeIP.String()
	conf.Events = &memberlist.ChannelEventDelegate{Ch: nodeEventCh}
	conf.LogOutput = ioutil.Discard
	klog.V(1).InfoS("New memberlist cluster", "config", conf)

	mList, err := memberlist.Create(conf)
	if err != nil {
		return nil, fmt.Errorf("failed to create memberlist cluster: %v", err)
	}
	c.mList = mList

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
				oldExternalIPPool := oldObj.(*v1alpha2.ExternalIPPool)
				curExternalIPPool := newObj.(*v1alpha2.ExternalIPPool)
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

func (c *Cluster) handleCreateNode(obj interface{}) {
	node := obj.(*corev1.Node)
	if member, err := c.newClusterMember(node); err == nil {
		_, err := c.mList.Join([]string{member})
		if err != nil {
			klog.ErrorS(err, "Processing Node CREATE event error, join cluster failed", "member", member)
		}
	} else {
		klog.ErrorS(err, "Processing Node CREATE event error", "nodeName", node.Name)
	}

	affectedEIPs := c.filterEIPsFromNodeLabels(node)
	c.enqueueExternalIPPools(affectedEIPs)
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
	affectedEIPs := c.filterEIPsFromNodeLabels(node)
	c.enqueueExternalIPPools(affectedEIPs)
	klog.V(2).InfoS("Processed Node DELETE event", "nodeName", node.Name, "affectedExternalIPPoolNum", affectedEIPs.Len())
}

func (c *Cluster) handleUpdateNode(oldObj, newObj interface{}) {
	node := newObj.(*corev1.Node)
	oldNode := oldObj.(*corev1.Node)
	if reflect.DeepEqual(node.GetLabels(), oldNode.GetLabels()) {
		klog.V(2).InfoS("Processing Node UPDATE event error, labels not changed", "nodeName", node.Name)
		return
	}
	oldMatches, newMatches := c.filterEIPsFromNodeLabels(oldNode), c.filterEIPsFromNodeLabels(node)
	if oldMatches.Equal(newMatches) {
		klog.V(2).InfoS("Processing Node UPDATE event error, Node cluster status not changed", "nodeName", node.Name)
		return
	}
	affectedEIPs := oldMatches.Union(newMatches)
	c.enqueueExternalIPPools(affectedEIPs)
	klog.V(2).InfoS("Processed Node UPDATE event", "nodeName", node.Name, "affectedExternalIPPoolNum", affectedEIPs.Len())
}

func (c *Cluster) enqueueExternalIPPools(eips sets.String) {
	for eip := range eips {
		c.queue.Add(eip)
	}
}

func (c *Cluster) enqueueExternalIPPool(obj interface{}) {
	eip, ok := obj.(*v1alpha2.ExternalIPPool)
	if !ok {
		deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.ErrorS(errDecodingObject, "Processing ExternalIPPool DELETE event error", "obj", obj)
			return
		}
		eip, ok = deletedState.Obj.(*v1alpha2.ExternalIPPool)
		if !ok {
			klog.ErrorS(errDecodingObjectTombstone, "Processing ExternalIPPool DELETE event error", "obj", deletedState.Obj)
			return
		}
	}
	c.queue.Add(eip.Name)
}

// newClusterMember gets the Node's IP and returns a cluster member "<IP>:<clusterMemberlistPort>"
// representing that Node in the memberlist cluster.
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

func (c *Cluster) allClusterMembers() (clusterNodes []string, err error) {
	nodes, err := c.nodeLister.List(labels.Everything())
	if err != nil {
		return nil, fmt.Errorf("listing Nodes error: %v", err)
	}

	for _, node := range nodes {
		member, err := c.newClusterMember(node)
		if err != nil {
			klog.ErrorS(err, "Get Node failed")
			continue
		}
		clusterNodes = append(clusterNodes, member)
	}
	return
}

func (c *Cluster) filterEIPsFromNodeLabels(node *corev1.Node) sets.String {
	pools := sets.NewString()
	eips, err := c.externalIPPoolLister.List(labels.Everything())
	if err != nil {
		klog.ErrorS(err, "Filter ExternalIPPools from nodeLabels failed")
		return pools
	}
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

	members, err := c.allClusterMembers()
	if err != nil {
		klog.ErrorS(err, "List cluster members failed")
	} else if members != nil {
		_, err := c.mList.Join(members)
		if err != nil {
			klog.ErrorS(err, "Join cluster failed")
		}
	}

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}

	for {
		select {
		case <-stopCh:
			return
		case nodeEvent := <-c.nodeEventsCh:
			c.handleClusterNodeEvents(&nodeEvent)
		}
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

	eip, err := c.externalIPPoolLister.Get(eipName)
	if err != nil {
		if errors.IsNotFound(err) {
			c.consistentHashRWMutex.Lock()
			defer c.consistentHashRWMutex.Unlock()
			delete(c.consistentHashMap, eipName)
			return nil
		}
		return err
	}

	// updateConsistentHash refreshes the consistentHashMap.
	updateConsistentHash := func(eip *v1alpha2.ExternalIPPool) error {
		nodeSel, err := metav1.LabelSelectorAsSelector(&eip.Spec.NodeSelector)
		if err != nil {
			return fmt.Errorf("labelSelectorAsSelector error: %v", err)
		}
		nodes, err := c.nodeLister.List(nodeSel)
		if err != nil {
			return fmt.Errorf("listing Nodes error: %v", err)
		}
		aliveNodes := c.aliveNodes()
		// Node alive and Node labels match ExternalIPPool nodeSelector.
		var aliveAndMatchedNodes []string
		for _, node := range nodes {
			nodeName := node.Name
			if aliveNodes.Has(nodeName) {
				aliveAndMatchedNodes = append(aliveAndMatchedNodes, nodeName)
			}
		}
		consistentHashMap := newNodeConsistentHashMap()
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

func newNodeConsistentHashMap() *consistenthash.Map {
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
			if errors.IsNotFound(err) {
				// Node has been deleted, and deleteNode handler has been executed.
				klog.ErrorS(err, "Processing Node event, not found", "eventType", event)
				return
			}
			klog.ErrorS(err, "Processing Node event, get Node failed", "eventType", event)
			return
		}
		affectedEIPs := c.filterEIPsFromNodeLabels(coreNode)
		c.enqueueExternalIPPools(affectedEIPs)
		klog.InfoS("Processed Node event", "eventType", mapNodeEventType[event], "nodeName", node.Name, "affectedExternalIPPoolNum", len(affectedEIPs))
	default:
		klog.InfoS("Processed Node event", "eventType", mapNodeEventType[event], "nodeName", node.Name)
	}
}

// aliveNodes returns the list of nodeNames in the cluster.
func (c *Cluster) aliveNodes() sets.String {
	nodes := sets.NewString()
	for _, node := range c.mList.Members() {
		nodes.Insert(node.Name)
	}
	return nodes
}

// ShouldSelectIP returns true if the local Node selected as the owner Node of the IP in the specific
// ExternalIPPool. The local Node in the cluster holds the same consistent hash ring for each ExternalIPPool,
// consistentHash.Get gets the closest item (Node name) in the hash to the provided key (IP), if the name of
// the local Node is equal to the name of the selected Node, returns true.
func (c *Cluster) ShouldSelectIP(ip, externalIPPool string) (bool, error) {
	if externalIPPool == "" || ip == "" {
		return false, nil
	}
	c.consistentHashRWMutex.RLock()
	defer c.consistentHashRWMutex.RUnlock()
	consistentHash, ok := c.consistentHashMap[externalIPPool]
	if !ok {
		return false, fmt.Errorf("local Node consistentHashMap has not synced, ExternalIPPool %s", externalIPPool)
	}
	node := consistentHash.Get(ip)
	if node == "" {
		klog.Warningf("No valid Node chosen for IP %s in externalIPPool %s", ip, externalIPPool)
	}
	return node == c.nodeName, nil
}

func (c *Cluster) notify(objName string) {
	for _, handler := range c.clusterNodeEventHandlers {
		handler(objName)
	}
}

// AddClusterEventHandler adds a clusterNodeEventHandler, which will run when consistentHashMap is updated,
// due to an ExternalIPPool or Node event.
func (c *Cluster) AddClusterEventHandler(handler clusterNodeEventHandler) {
	c.clusterNodeEventHandlers = append(c.clusterNodeEventHandlers, handler)
}
