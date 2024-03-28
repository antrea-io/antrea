// Copyright 2024 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package monitortool

import (
	"net"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"

	coreinformers "k8s.io/client-go/informers/core/v1"
)

type LatencyStore struct {
	// Maybe we need to use small lock for the map
	mutex sync.RWMutex

	nodeInformer  coreinformers.NodeInformer
	connectionMap map[string]*Connection
	nodeInfoMap   map[string]*corev1.Node
}

// TODO1: use LRU cache to store the latency of the connection?
// TODO2: we only support ipv4 now
type Connection struct {
	// The source IP of the connection
	FromIP string
	// The destination IP of the connection
	ToIP string
	// The latency of the connection
	Latency time.Duration
	// The status of the connection
	Status bool
	// The last time the connection was updated
	LastUpdated time.Time
	// The time the connection was created.
	CreatedAt time.Time
}

func NewLatencyStore(nodeInformer coreinformers.NodeInformer) *LatencyStore {
	store := &LatencyStore{
		connectionMap: make(map[string]*Connection),
		nodeInfoMap:   make(map[string]*corev1.Node),
		nodeInformer:  nodeInformer,
	}
	nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    store.OnNodeAdd,
		UpdateFunc: store.OnNodeUpdate,
		DeleteFunc: store.OnNodeDelete,
	})

	return store
}

func (l *LatencyStore) Run(stopCh <-chan struct{}) {
	l.nodeInformer.Informer().Run(stopCh)
}

func (l *LatencyStore) OnNodeAdd(obj interface{}) {
	node := obj.(*corev1.Node)
	l.AddNodeToMap(node)
}

func (l *LatencyStore) OnNodeUpdate(oldObj, newObj interface{}) {
	oldNode := oldObj.(*corev1.Node)
	node := newObj.(*corev1.Node)
	l.UpdateNodeByKey(oldNode.Name, node)
}

func (l *LatencyStore) OnNodeDelete(obj interface{}) {
	node := obj.(*corev1.Node)
	l.DeleteNodeByKey(node.Name)
}

func (l *LatencyStore) GetConnByKey(connKey string) (*Connection, bool) {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	conn, found := l.connectionMap[connKey]

	return conn, found
}

func (l *LatencyStore) DeleteConnByKey(connKey string) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	delete(l.connectionMap, connKey)
}

func (l *LatencyStore) UpdateConnByKey(connKey string, conn *Connection) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	// Judge if the connection is already in the map
	_, found := l.connectionMap[connKey]
	if !found {
		conn.CreatedAt = conn.LastUpdated
	}

	l.connectionMap[connKey] = conn
}

func (l *LatencyStore) ListConns() map[string]*Connection {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	return l.connectionMap
}

func (l *LatencyStore) AddNodeToMap(node *corev1.Node) {
	l.nodeInfoMap[node.Name] = node
}

func (l *LatencyStore) GetNodeByKey(nodeKey string) (*corev1.Node, bool) {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	node, found := l.nodeInfoMap[nodeKey]

	return node, found
}

func (l *LatencyStore) DeleteNodeByKey(nodeKey string) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	// Delete the node from the node info map
	delete(l.nodeInfoMap, nodeKey)
	// Delete the node from the connection map
	delete(l.connectionMap, nodeKey)
}

func (l *LatencyStore) UpdateNodeByKey(nodeKey string, node *corev1.Node) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	l.nodeInfoMap[nodeKey] = node
}

func (l *LatencyStore) ListNodes() []corev1.Node {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	nodes := make([]corev1.Node, 0, len(l.nodeInfoMap))
	for _, node := range l.nodeInfoMap {
		nodes = append(nodes, *node)
	}

	return nodes
}

func (l *LatencyStore) ListNodeIPs() map[string]string {
	nodes := l.ListNodes()
	nodeIPs := make(map[string]string)

	for _, node := range nodes {
		for _, addr := range node.Status.Addresses {
			if addr.Type == corev1.NodeInternalIP || addr.Type == corev1.NodeExternalIP {
				if net.ParseIP(addr.Address) != nil {
					nodeIPs[addr.Address] = node.Name
				}
			}
		}
	}

	return nodeIPs
}
