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
	"reflect"
	"sync"
	"time"

	"github.com/golang/groupcache/consistenthash"
	"github.com/hashicorp/memberlist"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	coreinformers "k8s.io/client-go/informers/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha2"
	crdlister "antrea.io/antrea/pkg/client/listers/crd/v1alpha2"
	"antrea.io/antrea/pkg/util/k8s"
)

const (
	controllerName = "MemberListCluster"
	// Set resyncPeriod to 0 to disable resyncing.
	resyncPeriod time.Duration = 0
	// set default virtual node replicas num of consistent hash, refs https://github.com/golang/groupcache/issues/29
	defaultVirtualNodeReplicas = 50
	defaultLeavePeriod         = time.Second
)

// default Hash Fn is crc32.ChecksumIEEE
var defaultHashFn func(data []byte) uint32

var unexpectError = fmt.Errorf("unexpected object")

type ClusterInterface interface {
	Run(stopCh <-chan struct{})
}

type clusterNodeEventHandler func(nodeName string, isJoin bool)

type Cluster struct {
	bindPort int
	// NodeConfig contains nodeName and ipAddr which would be used
	NodeConfig *config.NodeConfig
	// Name of local node. Node name must be unique in the cluster.
	nodeName string

	mlConfig *memberlist.Config
	mList    *memberlist.Memberlist
	// conHash hold the consistenthash.Map, when a node join cluster, use method Add() to add some keys to the hash.
	// when a node leave the cluster, the consistenthash.Map should update
	conHash          *consistenthash.Map
	conHashMapRWLock sync.RWMutex
	// nodeEventsCh, the Node join/leave events will be notified via it.
	nodeEventsCh chan memberlist.NodeEvent

	// ClusterNodeEventHandlers hold the fun that should implement when a node join or leave the cluster
	// for example, when a nwe node join the cluster,
	// each node should recalculate that if it should still hold the existing egresses owned by itself
	// in the same way, when a node leave cluster, each node may get some new egresses from the left node
	ClusterNodeEventHandlers []clusterNodeEventHandler

	// existingMembers contains all node(ip:clusterPort) that should join memberlist cluster
	// the items list from nodelist and filter with externalIPPool nodeSelectors
	// if the local node is not joined Cluster, it should hold the nodes,
	// once local node should join cluster, it will join cluster with those nodes
	memberRWLock    sync.RWMutex
	existingMembers sets.String

	localNodeEventCh chan bool

	nodeInformer     coreinformers.NodeInformer
	nodeLister       corelisters.NodeLister
	nodeListerSynced cache.InformerSynced

	ipPoolInformer          crdinformers.ExternalIPPoolInformer
	ipPoolLister            crdlister.ExternalIPPoolLister
	ipPoolInformerHasSynced cache.InformerSynced
}

// NewCluster return a new *Cluster
func NewCluster(
	clusterBindPort int,
	nodeInformer coreinformers.NodeInformer,
	nodeConfig *config.NodeConfig,
	ipPoolInformer crdinformers.ExternalIPPoolInformer,
) (*Cluster, error) {
	// The Node join/leave events will be notified via it.
	nodeEventCh := make(chan memberlist.NodeEvent, 1024)
	c := &Cluster{
		bindPort:                clusterBindPort,
		NodeConfig:              nodeConfig,
		nodeName:                nodeConfig.Name,
		nodeEventsCh:            nodeEventCh,
		nodeInformer:            nodeInformer,
		nodeLister:              nodeInformer.Lister(),
		nodeListerSynced:        nodeInformer.Informer().HasSynced,
		ipPoolInformer:          ipPoolInformer,
		ipPoolLister:            ipPoolInformer.Lister(),
		ipPoolInformerHasSynced: ipPoolInformer.Informer().HasSynced,
		localNodeEventCh:        make(chan bool, 1),
	}
	c.conHash = newNodeConsistentHashMap()

	bindPort := c.bindPort
	hostIP := c.NodeConfig.NodeIPAddr.IP
	nodeMember := fmt.Sprintf("%s:%d", hostIP.String(), bindPort)
	klog.V(2).InfoS("Add new node", "local node", nodeMember)

	conf := memberlist.DefaultLocalConfig()
	conf.Name = c.nodeName
	conf.BindPort = bindPort
	conf.AdvertisePort = bindPort
	conf.Events = &memberlist.ChannelEventDelegate{Ch: nodeEventCh}
	klog.V(1).Infof("Memberlist cluster configs: %+v", conf)

	mList, err := memberlist.Create(conf)
	if err != nil {
		return nil, fmt.Errorf("failed to create memberlist: %v", err)
	}

	c.mlConfig = conf
	c.mList = mList
	c.existingMembers = sets.NewString(nodeMember)

	nodeInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				node, ok := obj.(*corev1.Node)
				if !ok {
					klog.ErrorS(unexpectError, "Add node callback", "obj", obj)
					return
				}
				klog.V(2).InfoS("Add node event", "nodeName", node.Name)
				shouldJoin := c.shouldJoinCluster(node.Name)
				if shouldJoin {
					c.updateExistingMember(node, true)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				node, ok := newObj.(*corev1.Node)
				oldNode, okOldNode := oldObj.(*corev1.Node)
				if !ok || !okOldNode {
					klog.ErrorS(unexpectError, "Update node callback", "oldObj", oldObj, "newObj", newObj)
					return
				}
				if reflect.DeepEqual(node.GetLabels(), oldNode.GetLabels()) {
					klog.V(2).InfoS("Update node event, labels not changed", "nodeName", node.Name)
					return
				}
				oldMatch, newMatch := c.matchNodeSelectors(oldNode), c.matchNodeSelectors(node)
				if oldMatch == newMatch {
					klog.V(2).InfoS("Update node event, node cluster status not changed", "nodeName", node.Name)
					return
				}
				klog.V(2).InfoS("Update node event", "nodeName", node.Name)
				c.updateExistingMember(node, newMatch && !oldMatch)
			},
			DeleteFunc: func(obj interface{}) {
				node, ok := obj.(*corev1.Node)
				if !ok {
					klog.ErrorS(unexpectError, "Delete node callback", "obj", obj)
					return
				}
				klog.V(2).InfoS("Delete node event", "nodeName", node.Name)
				c.updateExistingMember(node, false)
			},
		},
		resyncPeriod,
	)

	// node handler mainly used to change existing members in local node,
	// when IPPool changed, the existingMember would be used
	// while update node labels, if node is local node, should check if local node will join or leave from cluster
	// add node: process existingMembers
	// update node: process existingMembers, if local node labels update, check if local node should join
	// delete node: process existingMembers

	// ipPool handler should be watch, when it changed, local node may join or leave form cluster
	// add IPPool: check local node selector
	// update IPPool: check local node
	// delete IPPool: check local node

	ipPoolInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				_, ok := obj.(*v1alpha2.ExternalIPPool)
				if !ok {
					klog.ErrorS(unexpectError, "Add ExternalIPPool callback", "obj", obj)
					return
				}
				c.updateLocalNodeStatus()
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				oldIPPool, ok := oldObj.(*v1alpha2.ExternalIPPool)
				if !ok {
					klog.ErrorS(unexpectError, "Update ExternalIPPool callback", "obj", oldObj)
					return
				}
				ipPool, ok := newObj.(*v1alpha2.ExternalIPPool)
				if !ok {
					klog.ErrorS(unexpectError, "Update ExternalIPPool callback", "obj", newObj)
					return
				}
				if reflect.DeepEqual(oldIPPool.Spec.NodeSelector, ipPool.Spec.NodeSelector) {
					return
				}
				c.updateLocalNodeStatus()
			},
			DeleteFunc: func(obj interface{}) {
				_, ok := obj.(*v1alpha2.ExternalIPPool)
				if !ok {
					klog.ErrorS(unexpectError, "Delete ExternalIPPool callback", "obj", obj)
					return
				}
				c.updateLocalNodeStatus()
			},
		},
		resyncPeriod,
	)
	return c, nil
}

func newNodeConsistentHashMap() *consistenthash.Map {
	return consistenthash.New(defaultVirtualNodeReplicas, defaultHashFn)
}

func (c *Cluster) listNodeSelectors() (nodeSelectors []*metav1.LabelSelector, err error) {
	ipPools, err := c.ipPoolLister.List(labels.Everything())
	if err != nil {
		return nil, err
	}
	for _, ipPool := range ipPools {
		nodeSelectors = append(nodeSelectors, &ipPool.Spec.NodeSelector)
	}

	return
}

func (c *Cluster) filterNodes() (nodes []*corev1.Node, err error) {
	nodeSelectors, err := c.listNodeSelectors()
	if err != nil {
		klog.ErrorS(err, "List node selectors of nodes failed")
		return
	}
	nodeSet := sets.String{}
	for _, nodeSelector := range nodeSelectors {
		nodeSel, _ := metav1.LabelSelectorAsSelector(nodeSelector)
		nodeList, _ := c.nodeLister.List(nodeSel)
		for _, node := range nodeList {
			nodeName := node.Name
			if !nodeSet.Has(nodeName) {
				nodeSet.Insert(node.Name)
				nodes = append(nodes, node)
			}
		}
	}
	return
}

func (c *Cluster) syncClusterMembers() (clusterNodes []string) {
	nodes, err := c.filterNodes()
	if err != nil {
		klog.ErrorS(err, "Listing Nodes failed")
		return
	}
	klog.V(3).InfoS("Sync cluster members", "node num", len(nodes))

	for _, node := range nodes {
		nodeAddr, err := k8s.GetNodeAddr(node)
		if err != nil {
			klog.ErrorS(err, "Obtain local IP address from K8s node failed")
			continue
		}
		member := fmt.Sprintf("%s:%d", nodeAddr, c.bindPort)
		clusterNodes = append(clusterNodes, member)
	}
	return
}

func (c *Cluster) shouldJoinCluster(nodeName string) bool {
	node, err := c.nodeLister.Get(nodeName)
	if err != nil {
		klog.ErrorS(err, "Get node failed", "nodeName", nodeName)
		return false
	}
	return c.matchNodeSelectors(node)
}

func (c *Cluster) matchNodeSelectors(node *corev1.Node) bool {
	nodeSelectors, err := c.listNodeSelectors()
	if err != nil {
		klog.ErrorS(err, "matchNodeSelectors failed")
		return false
	}
	if nodeSelectors == nil {
		return true
	}
	for _, ns := range nodeSelectors {
		nodeSelector, _ := metav1.LabelSelectorAsSelector(ns)
		if ns == nil {
			return true
		}
		if nodeSelector.Matches(labels.Set(node.GetLabels())) {
			return true
		}
	}
	return false
}

func (c *Cluster) memberNum() int {
	c.memberRWLock.RLock()
	defer c.memberRWLock.RUnlock()
	return c.existingMembers.Len()
}

func (c *Cluster) addExistingMembers(members ...string) {
	c.memberRWLock.Lock()
	defer c.memberRWLock.Unlock()
	c.existingMembers.Insert(members...)
	klog.V(2).InfoS("Add existingMember", "memberNum", c.existingMembers.Len())
}

func (c *Cluster) updateExistingMember(node *corev1.Node, add bool) {
	c.memberRWLock.Lock()
	defer c.memberRWLock.Unlock()
	nodeAddr, err := k8s.GetNodeAddr(node)
	if err != nil {
		klog.ErrorS(err, "Failed to obtain local IP address")
		return
	}
	member := fmt.Sprintf("%s:%d", nodeAddr, c.bindPort)
	oldNum := c.existingMembers.Len()
	if add {
		c.existingMembers.Insert(member)
		newNum := c.existingMembers.Len()
		klog.V(2).Infof("Add new member (%s) in local existing memberlist, num %d->%d", member, oldNum, newNum)
	} else {
		if !c.existingMembers.Has(member) {
			return
		}
		c.existingMembers.Delete(member)
		newNum := c.existingMembers.Len()
		klog.V(2).Infof("Delete member (%s) in local existing memberlist, num %d->%d", member, oldNum, newNum)
	}
	if c.nodeName == node.Name {
		c.updateLocalNodeStatus()
	}
}

func (c *Cluster) joinOrLeaveCluster(join bool) {
	if join {
		c.memberRWLock.RLock()
		defer c.memberRWLock.RUnlock()
		clusterNodes := c.existingMembers.List()
		n, err := c.mList.Join(clusterNodes)
		if err != nil {
			klog.ErrorS(err, "Join cluster failed, cluster nodes %v", clusterNodes)
			return
		}
		klog.V(2).InfoS("Join cluster", "num", n, "cluster nodes", clusterNodes)
	} else {
		if err := c.localNodeLeave(); err != nil {
			klog.ErrorS(err, "Leave cluster failed")
			return
		}
		klog.V(2).InfoS("Leave cluster", "nodeName", c.nodeName)
	}
}

func (c *Cluster) localNodeLeave() error {
	err := c.mList.Leave(defaultLeavePeriod)
	if err != nil {
		klog.ErrorS(err, "Local node leave cluster failed")
		return err
	}
	if err := c.mList.Shutdown(); err != nil {
		klog.ErrorS(err, "Shutdown cluster failed")
		return err
	}
	newML, err := memberlist.Create(c.mlConfig)
	if err != nil {
		klog.ErrorS(err, "Create cluster failed")
		return err
	}
	c.mList = newML
	return nil
}

func (c *Cluster) Run(stopCh <-chan struct{}) {
	if !cache.WaitForNamedCacheSync(controllerName, stopCh, c.ipPoolInformerHasSynced, c.nodeListerSynced) {
		return
	}

	defer func() {
		if err := c.mList.Shutdown(); err != nil {
			klog.ErrorS(err, "Shut down cluster failed")
		}
		close(c.nodeEventsCh)
	}()
	for {
		select {
		case <-stopCh:
			return
		case nodeEvent := <-c.nodeEventsCh:
			c.updateNodeConsistentHash(&nodeEvent)
		case isJoin := <-c.localNodeEventCh:
			c.handleLocalNodeJoin(isJoin)
		}
	}
}

func (c *Cluster) handleLocalNodeJoin(isJoin bool) {
	if isJoin {
		// filter nodes through nodeSelector from externalIPPools
		otherClusterNodes := c.syncClusterMembers()
		c.addExistingMembers(otherClusterNodes...)
		klog.InfoS("Received a join signal, local node will join cluster", "node name", c.nodeName)
	} else {
		klog.InfoS("Received a leave signal, local node will leave cluster", "node name", c.nodeName)
	}
	c.joinOrLeaveCluster(isJoin)
}

func (c *Cluster) updateNodeConsistentHash(nodeEvent *memberlist.NodeEvent) {
	c.conHashMapRWLock.Lock()
	defer c.conHashMapRWLock.Unlock()
	switch node, event := nodeEvent.Node, nodeEvent.Event; event {
	case memberlist.NodeJoin:
		klog.InfoS("Node event: join node", "node name", node.String())
		c.conHash.Add(node.Name)
		c.notify(node.Name, true)
	case memberlist.NodeLeave:
		klog.InfoS("Node event: leave node", "node name", node.String())
		c.conHash = newNodeConsistentHashMap()
		c.conHash.Add(c.nodeList()...)
		c.notify(node.Name, false)
	default:
		klog.InfoS("Node event: update node", "node name", node.String())
	}
}

func (c *Cluster) updateLocalNodeStatus() {
	if len(c.localNodeEventCh) == 1 {
		return
	}
	shouldJoin := c.shouldJoinCluster(c.nodeName)
	joined := c.localNodeJoined()
	if joined && !shouldJoin {
		c.writeLocalNodeCh(true)
	} else if !joined && shouldJoin {
		c.writeLocalNodeCh(false)
	}
}

func (c *Cluster) writeLocalNodeCh(join bool) {
	select {
	case c.localNodeEventCh <- join:
		klog.InfoS("Write local node status", "result", join)
	default:
		klog.InfoS("Write local node status skip", "result", join)
	}
}

// nodeList return alive nodeName list in cluster
func (c *Cluster) nodeList() []string {
	aliveMembers := c.mList.Members()
	nodes := make([]string, len(aliveMembers))
	for i, node := range aliveMembers {
		nodes[i] = node.Name
	}
	return nodes
}

// localNodeJoined if merbers num in cluster is 1 means local node not joined in other clusters
func (c *Cluster) localNodeJoined() bool {
	// while node joined cluster, num of member will >= 1; if leave cluster, num of member will be 0
	return c.mList.NumMembers() >= 1
}

func (c *Cluster) shouldSelect(name string) bool {
	c.conHashMapRWLock.RLock()
	defer c.conHashMapRWLock.RUnlock()
	myNode := c.nodeName
	hitted := hitNodeByConsistentHash(c.conHash, name, myNode)
	klog.InfoS("Assign egress owner for local node", "egressName", name, "localNode", myNode, "hit", hitted)
	return hitted
}

func hitNodeByConsistentHash(conHash *consistenthash.Map, name, myNode string) bool {
	return conHash.Get(name) == myNode
}

func (c *Cluster) notify(nodeName string, isJoinNode bool) {
	for _, handler := range c.ClusterNodeEventHandlers {
		handler(nodeName, isJoinNode)
	}
}

func (c *Cluster) addClusterNodeEventHandler(handler clusterNodeEventHandler) {
	c.ClusterNodeEventHandlers = append(c.ClusterNodeEventHandlers, handler)
}
