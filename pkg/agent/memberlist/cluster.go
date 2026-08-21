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
	"bytes"
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

	"antrea.io/antrea/v2/pkg/agent/consistenthash"
	"antrea.io/antrea/v2/pkg/apis"
	"antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
	crdinformers "antrea.io/antrea/v2/pkg/client/informers/externalversions/crd/v1beta1"
	crdlister "antrea.io/antrea/v2/pkg/client/listers/crd/v1beta1"
	"antrea.io/antrea/v2/pkg/util/env"
	"antrea.io/antrea/v2/pkg/util/k8s"
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

	// keyQueueItem is the only item ever added to keyQueue: the queue is used purely to serialize
	// and retry the application of the desired gossip keys, which are stored in desiredKeys.
	keyQueueItem = "gossipKeys"

	// missingKeyWarningPeriod is how often WarnUntilReady reports that the memberlist instance has
	// not been created yet. The Egress and ServiceExternalIP features are inactive on this Node
	// until then, so this must not go unnoticed if the key never comes.
	missingKeyWarningPeriod = time.Minute
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
	SelectNodesForIP(ip, externalIPPool string, maxNodes int, filters ...func(string) bool) ([]string, error)
	AliveNodes() sets.Set[string]
	AddClusterEventHandler(handler ClusterNodeEventHandler)
	// Ready reports whether the memberlist instance has been created, which is required for this
	// Node to be able to join any peer. It is false until the gossip key becomes available; until
	// then the caller does not claim any IP, and it should report it to its own users, e.g.
	// periodically while Ready stays false (see WarnUntilReady).
	Ready() bool
}

type Memberlist interface {
	Join(existing []string) (int, error)
	Members() []*memberlist.Node
	Leave(timeout time.Duration) error
	Shutdown() error
}

// KeySource provides the keys used to secure the memberlist gossip traffic. Watch must invoke
// onKeys with the current keys as soon as they are available and again after every change, always
// with at least one key, until stopCh is closed. Invocations must be serialized.
// *memberlistkeys.SecretWatcher is the production implementation.
type KeySource interface {
	Watch(stopCh <-chan struct{}, onKeys func(keys [][]byte))
}

// GossipConfig configures authentication and encryption of the memberlist gossip traffic.
type GossipConfig struct {
	// KeySource provides the keys used to encrypt and decrypt gossip traffic. The key at index 0 is
	// the primary key and is used to encrypt outgoing traffic. The memberlist instance is only
	// created in Run once KeySource has delivered the first keys, so that the gossip traffic is
	// never left unauthenticated; until then, this Node is not a member of any cluster and
	// AliveNodes / ShouldSelectIP report accordingly. Later key deliveries are applied live, without
	// recreating the instance.
	KeySource KeySource
	// VerifyOutgoing encrypts outgoing gossip traffic. VerifyIncoming rejects incoming gossip
	// traffic which is not encrypted.
	//
	// Both must be false while some Nodes in the cluster do not have a key yet: a Node which
	// encrypts its traffic cannot be understood by a Node without a key, and a Node which rejects
	// unencrypted traffic cannot understand such a Node either. Refer to docs/egress.md for the
	// procedure to enable them on a running cluster without partitioning it.
	VerifyOutgoing bool
	VerifyIncoming bool
}

// Cluster implements ClusterInterface.
type Cluster struct {
	bindPort int
	// Name of local Node. Node name must be unique in the cluster.
	nodeName string

	// mListMutex protects mList and keyring, which are set after construction when the memberlist
	// instance is created lazily (see GossipConfig.KeySource). Use memberList() to read mList: it
	// is nil until the instance exists, and all the users must tolerate that, reporting the same
	// state as a Node which has not joined any peer yet.
	mListMutex sync.RWMutex
	mList      Memberlist
	// keyring holds the keys used to secure the gossip traffic, and is shared with the memberlist
	// configuration: mutating it takes effect immediately, without recreating the memberlist
	// instance. It is nil when the gossip traffic is not secured.
	keyring *memberlist.Keyring

	// keySource, when non-nil, provides the gossip keys asynchronously. deferredConf is the
	// memberlist configuration to use when creating the instance once the first keys arrive.
	keySource    KeySource
	deferredConf *memberlist.Config
	// desiredKeys holds the keys most recently delivered by keySource, applied by the keyQueue
	// worker.
	desiredKeysMutex sync.Mutex
	desiredKeys      [][]byte
	// keyQueue is a single-item workqueue which serializes the application of desiredKeys -
	// creating the memberlist instance for the first keys, updating the keyring for later ones -
	// and retries it with rate limiting on failure.
	keyQueue workqueue.TypedRateLimitingInterface[string]
	// keyWorkerWG tracks the goroutine which drains keyQueue, so that Run can wait for it to stop
	// before tearing the memberlist instance down and closing nodeEventsCh.
	keyWorkerWG sync.WaitGroup
	// newMemberlist creates the memberlist instance. It is a field so that tests which exercise the
	// deferred creation can replace it: the real implementation binds sockets and starts exchanging
	// gossip traffic with the rest of the cluster.
	newMemberlist func(conf *memberlist.Config) (Memberlist, error)
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
	queue workqueue.TypedRateLimitingInterface[string]
}

// NewCluster returns a new *Cluster.
//
// gossipConfig determines whether the gossip traffic is authenticated and encrypted. All the Nodes
// must use the same keys, otherwise they will not be able to form a single cluster.
func NewCluster(
	nodeIP net.IP,
	clusterBindPort int,
	nodeName string,
	gossipConfig GossipConfig,
	nodeInformer coreinformers.NodeInformer,
	externalIPPoolInformer crdinformers.ExternalIPPoolInformer,
	ml Memberlist, // Parameterized for testing, could be left nil for production code.
) (*Cluster, error) {
	// The Cluster never creates a memberlist instance without a key, which would leave the gossip
	// traffic unauthenticated: the instance is created in Run, once KeySource has delivered one.
	if ml == nil && gossipConfig.KeySource == nil {
		return nil, fmt.Errorf("GossipConfig.KeySource is required when no Memberlist instance is provided")
	}
	// A KeySource takes care of creating the memberlist instance with the delivered keys, which
	// makes no sense for an instance provided by the caller: the keys could not be applied to it,
	// and the key worker would keep failing.
	if ml != nil && gossipConfig.KeySource != nil {
		return nil, fmt.Errorf("GossipConfig.KeySource cannot be used with a Memberlist instance provided by the caller")
	}
	// The Node join/leave events will be notified via it.
	nodeEventCh := make(chan memberlist.NodeEvent, 1024)
	c := &Cluster{
		bindPort:                        clusterBindPort,
		nodeName:                        nodeName,
		consistentHashMap:               make(map[string]*consistenthash.Map),
		mList:                           ml,
		keySource:                       gossipConfig.KeySource,
		newMemberlist:                   func(conf *memberlist.Config) (Memberlist, error) { return memberlist.Create(conf) },
		nodeEventsCh:                    nodeEventCh,
		nodeInformer:                    nodeInformer,
		nodeLister:                      nodeInformer.Lister(),
		nodeListerSynced:                nodeInformer.Informer().HasSynced,
		externalIPPoolInformer:          externalIPPoolInformer.Informer(),
		externalIPPoolLister:            externalIPPoolInformer.Lister(),
		externalIPPoolInformerHasSynced: externalIPPoolInformer.Informer().HasSynced,
		queue: workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.NewTypedItemExponentialFailureRateLimiter[string](minRetryDelay, maxRetryDelay),
			workqueue.TypedRateLimitingQueueConfig[string]{
				Name: "externalIPPool",
			},
		),
	}
	if gossipConfig.KeySource != nil {
		c.keyQueue = workqueue.NewTypedRateLimitingQueueWithConfig(
			workqueue.NewTypedItemExponentialFailureRateLimiter[string](minRetryDelay, maxRetryDelay),
			workqueue.TypedRateLimitingQueueConfig[string]{
				Name: "memberlistKeys",
			},
		)
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
		conf.GossipVerifyOutgoing = gossipConfig.VerifyOutgoing
		conf.GossipVerifyIncoming = gossipConfig.VerifyIncoming
		if !conf.GossipVerifyIncoming {
			klog.InfoS("Incoming memberlist gossip traffic is not required to be encrypted, which means that it is not authenticated. This is expected while the cluster is being transitioned to encrypted gossip")
		}
		// The instance is created in Run, once the first keys have been delivered. Starting it
		// without a key would leave the gossip traffic unauthenticated.
		c.deferredConf = conf
		klog.InfoS("The memberlist instance will be created once the gossip key is available")
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

// memberList returns the memberlist instance, or nil if it has not been created yet (see
// GossipConfig.KeySource). Callers must handle nil by behaving as a Node which has not joined any
// peer.
func (c *Cluster) memberList() Memberlist {
	c.mListMutex.RLock()
	defer c.mListMutex.RUnlock()
	return c.mList
}

// setDesiredKeys records the keys delivered by the KeySource and triggers their application by the
// keyQueue worker. Storing the keys separately from the queue item makes the worker always apply
// the latest delivery, including when it is retrying an earlier failure.
func (c *Cluster) setDesiredKeys(keys [][]byte) {
	c.desiredKeysMutex.Lock()
	c.desiredKeys = keys
	c.desiredKeysMutex.Unlock()
	c.keyQueue.Add(keyQueueItem)
}

func (c *Cluster) keyWorker() {
	for c.processNextKeyItem() {
	}
}

func (c *Cluster) processNextKeyItem() bool {
	_, quit := c.keyQueue.Get()
	if quit {
		return false
	}
	defer c.keyQueue.Done(keyQueueItem)

	if err := c.syncKeys(); err == nil {
		c.keyQueue.Forget(keyQueueItem)
	} else {
		// Put the item back on the work queue to retry: syncKeys is idempotent, and the keys it
		// applies are read fresh from desiredKeys on every attempt.
		c.keyQueue.AddRateLimited(keyQueueItem)
		klog.ErrorS(err, "Applying the memberlist keys failed, requeue")
	}
	return true
}

func (c *Cluster) syncKeys() error {
	c.desiredKeysMutex.Lock()
	keys := c.desiredKeys
	c.desiredKeysMutex.Unlock()
	if len(keys) == 0 {
		return nil
	}
	if c.memberList() == nil {
		return c.createDeferredMemberlist(keys)
	}
	return c.UpdateKey(keys[0])
}

// createDeferredMemberlist creates the memberlist instance with the first delivered keys, when
// creation was deferred because the Cluster was constructed with a KeySource.
func (c *Cluster) createDeferredMemberlist(keys [][]byte) error {
	// Only the primary key is installed for now: accepting the additional keys would let a Node
	// decrypt traffic encrypted with a key which is no longer primary, but we have no way yet to
	// tell when it is safe to promote a new primary key across the whole cluster.
	keyring, err := memberlist.NewKeyring(nil, keys[0])
	if err != nil {
		return fmt.Errorf("failed to create keyring: %w", err)
	}
	conf := c.deferredConf
	// The Keyring is shared with the Cluster, so that keys can be updated later without recreating
	// the memberlist instance.
	conf.Keyring = keyring
	klog.V(1).InfoS("Creating new memberlist cluster", "name", conf.Name, "addr", conf.AdvertiseAddr, "port", conf.AdvertisePort, "deadNodeReclaimTime", conf.DeadNodeReclaimTime)
	mList, err := c.newMemberlist(conf)
	if err != nil {
		return fmt.Errorf("failed to create memberlist cluster: %w", err)
	}
	c.mListMutex.Lock()
	c.keyring = keyring
	c.mList = mList
	c.mListMutex.Unlock()
	klog.InfoS("Created the memberlist instance, the gossip key is now available")
	// Join the other Nodes: their create events were ignored while the instance did not exist.
	c.RejoinNodes()
	return nil
}

// UpdateKey installs key as the primary key of the keyring and removes all the other keys, unless
// key is already the only installed key, in which case it is a no-op.
//
// Only a single key is supported at the moment, which means that Nodes which have not applied the
// new key yet can no longer exchange gossip traffic with this Node, and that the cluster stays
// partitioned until all the Nodes have converged. We rejoin Nodes right away to shorten that
// window: memberlist does not re-add Nodes which it has already marked as dead, and without this
// the membership would take up to a minute (the RejoinNodes period) to recover.
func (c *Cluster) UpdateKey(key []byte) error {
	c.mListMutex.RLock()
	keyring := c.keyring
	c.mListMutex.RUnlock()
	if keyring == nil {
		return fmt.Errorf("cannot update the key of a cluster which was created without one")
	}
	// GetKeys returns the internal slice of the Keyring, which RemoveKey mutates in place, so we
	// need our own copy to iterate over.
	installedKeys := make([][]byte, len(keyring.GetKeys()))
	copy(installedKeys, keyring.GetKeys())
	if len(installedKeys) == 1 && bytes.Equal(installedKeys[0], key) {
		return nil
	}
	// AddKey validates the length of the key, and is a no-op if the key is already installed.
	if err := keyring.AddKey(key); err != nil {
		return fmt.Errorf("failed to add key to the keyring: %w", err)
	}
	// The primary key cannot be removed, hence we promote the new key before removing the old ones.
	if err := keyring.UseKey(key); err != nil {
		return fmt.Errorf("failed to set the primary key of the keyring: %w", err)
	}
	// Note that RemoveKey shifts the keys in place (append(keys[:i], keys[i+1:]...)), in the very
	// slice which Keyring.GetKeys returns to its callers without copying it. memberlist itself calls
	// GetKeys on the receive path, so removing a key which is not the last one would race with the
	// decryption of an incoming message. This is safe as long as a single key is supported: UseKey
	// leaves the keyring as [new, old], so the loop below only ever removes the last key, which
	// shifts nothing. Supporting multiple keys will require revisiting this, as removing a key from
	// the middle of the keyring would then be possible.
	for _, installedKey := range installedKeys {
		if bytes.Equal(installedKey, key) {
			continue
		}
		if err := keyring.RemoveKey(installedKey); err != nil {
			return fmt.Errorf("failed to remove stale key from the keyring: %w", err)
		}
	}
	klog.InfoS("Updated the key securing the memberlist gossip traffic, the cluster may be partitioned until all Nodes have applied it")
	c.RejoinNodes()
	return nil
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
	// A nil memberlist instance means that we are still waiting for the gossip key:
	// createDeferredMemberlist calls RejoinNodes once the instance exists, which joins this Node.
	if ml := c.memberList(); ml != nil {
		if member, err := c.newClusterMember(node); err == nil {
			_, err := ml.Join([]string{member})
			if err != nil {
				klog.InfoS("Processing Node CREATE event error, join cluster failed, will retry later", "error", errors.Unwrap(err), "member", member)
			}
		} else {
			klog.ErrorS(err, "Processing Node CREATE event error", "nodeName", node.Name)
		}
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
	defer close(c.nodeEventsCh)
	defer func() {
		// The key worker must be stopped before the memberlist instance is shut down and
		// nodeEventsCh is closed: it could otherwise create an instance which we would leave
		// running, and which would deliver its first Node event on a closed channel.
		if c.keyQueue != nil {
			c.keyQueue.ShutDown()
			c.keyWorkerWG.Wait()
		}
		// The instance is nil if the gossip key never became available.
		if ml := c.memberList(); ml != nil {
			// In order to exit the cluster more gracefully, call Leave prior to shutting down.
			ml.Leave(time.Second)
			ml.Shutdown()
		}
	}()

	klog.InfoS("Starting", "controllerName", controllerName)
	defer klog.InfoS("Shutting down", "controllerName", controllerName)

	if !cache.WaitForNamedCacheSync(controllerName, stopCh, c.externalIPPoolInformerHasSynced, c.nodeListerSynced) {
		return
	}

	if c.keySource != nil {
		// The handler runs in the KeySource's watch goroutine and only records the keys and
		// enqueues an item, so it never blocks the watch.
		c.keySource.Watch(stopCh, c.setDesiredKeys)
		c.keyWorkerWG.Add(1)
		go func() {
			defer c.keyWorkerWG.Done()
			wait.Until(c.keyWorker, time.Second, stopCh)
		}()
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
	ml := c.memberList()
	if ml == nil {
		return
	}
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
	numSuccess, err := ml.Join(membersToJoin)
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
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	if err := c.syncConsistentHash(key); err == nil {
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

// Ready returns true once the memberlist instance has been created, i.e. once the gossip key has
// become available. Note that it says nothing about the Node having joined any peer yet.
func (c *Cluster) Ready() bool {
	return c.memberList() != nil
}

// WarnUntilReady logs msg with klog.ErrorS, along with how the situation can be investigated, until
// cluster becomes Ready, then returns. Callers whose function is unavailable until then - e.g.
// because they cannot claim any IP - should run this in a goroutine alongside their own controller,
// so that the condition does not go unnoticed if it never clears. Note that Ready never becomes
// false again, hence it is safe to stop reporting for good.
func WarnUntilReady(cluster Interface, msg string, stopCh <-chan struct{}) {
	ticker := time.NewTicker(missingKeyWarningPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			if cluster.Ready() {
				return
			}
			klog.ErrorS(nil, msg+". Check that antrea-controller is running and that it could provision the Secret holding the gossip key", "secret", klog.KRef(env.GetAntreaNamespace(), apis.AntreaMemberlistSecretName))
		}
	}
}

// AliveNodes returns the list of nodeNames in the cluster. It is empty while the memberlist
// instance has not been created yet (waiting for the gossip key), like for a Node which has not
// joined any peer.
func (c *Cluster) AliveNodes() sets.Set[string] {
	nodes := sets.New[string]()
	ml := c.memberList()
	if ml == nil {
		return nodes
	}
	for _, node := range ml.Members() {
		nodes.Insert(node.Name)
	}
	return nodes
}

// ShouldSelectIP returns true if the local Node is selected as the owner Node of the IP in the specific
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

// SelectNodesForIP returns up to maxNodes Node names for the provided key (IP) and ExternalIPPool, ordered by
// preference. The first Node is the one that SelectNodeForIP returns; the following ones are the Nodes which would be
// selected, in order, if the preceding ones left the cluster. A non-positive maxNodes returns all the eligible Nodes.
//
// It is used to derive a stable, cluster-wide consistent rank for each (IP, Node) pair, e.g. to advertise an IP from
// several Nodes with a different BGP MED value per Node.
func (c *Cluster) SelectNodesForIP(ip, externalIPPool string, maxNodes int, filters ...func(string) bool) ([]string, error) {
	c.consistentHashRWMutex.RLock()
	defer c.consistentHashRWMutex.RUnlock()
	consistentHash, ok := c.consistentHashMap[externalIPPool]
	if !ok {
		return nil, fmt.Errorf("local Node consistentHashMap has not synced, ExternalIPPool %s", externalIPPool)
	}
	nodes := consistentHash.GetNWithFilters(ip, maxNodes, filters...)
	if len(nodes) == 0 {
		return nil, ErrNoNodeAvailable
	}
	return nodes, nil
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
