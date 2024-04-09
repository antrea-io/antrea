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
	"errors"
	"net"
	"sync"
	"time"

	"github.com/containernetworking/plugins/pkg/ip"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	coreinformers "k8s.io/client-go/informers/core/v1"
)

type LatencyStore struct {
	// Maybe we need to use small lock for the map
	mutex sync.RWMutex

	// The map of node name to node info, it will changed to gw0 watcher
	nodeInformer coreinformers.NodeInformer
	// The map of node ip to connection
	connectionMap map[string]*Connection
	// The map of node ip to node name
	nodeGW0Map map[string]string
}

// TODO1: use LRU cache to store the latency of the connection?
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
		nodeGW0Map:    make(map[string]string),
		nodeInformer:  nodeInformer,
	}
	nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    store.onNodeAdd,
		UpdateFunc: store.onNodeUpdate,
		DeleteFunc: store.onNodeDelete,
	})

	return store
}

func (l *LatencyStore) Run(stopCh <-chan struct{}) {
	l.nodeInformer.Informer().Run(stopCh)
}

func (l *LatencyStore) onNodeAdd(obj interface{}) {
	node := obj.(*corev1.Node)
	l.addNode(node)
}

func (l *LatencyStore) onNodeUpdate(oldObj, newObj interface{}) {
	oldNode := oldObj.(*corev1.Node)
	node := newObj.(*corev1.Node)
	l.updateNode(oldNode, node)
}

func (l *LatencyStore) onNodeDelete(obj interface{}) {
	// Check if the object is a not a node
	node, ok := obj.(*corev1.Node)
	if !ok {
		return
	}

	l.deleteNode(node)
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

func (l *LatencyStore) addNode(node *corev1.Node) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	gw0IP, err := getGW0IP(node)
	if err != nil {
		return
	}

	// Add the node to the node IP map
	l.nodeGW0Map[node.Name] = gw0IP
}

func (l *LatencyStore) deleteNode(node *corev1.Node) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	// Delete the node from the node IP map
	delete(l.nodeGW0Map, node.Name)
	// Delete the node from the connection map
	delete(l.connectionMap, node.Name)
}

func (l *LatencyStore) updateNode(old *corev1.Node, new *corev1.Node) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	gw0IP, err := getGW0IP(new)
	if err != nil {
		return
	}

	// Update the new node to the node IP map
	l.nodeGW0Map[new.Name] = gw0IP
}

func getGW0IP(node *corev1.Node) (string, error) {
	podCIDRStrs := getPodCIDRsOnNode(node)
	if len(podCIDRStrs) == 0 {
		// Skip the node if it does not have a PodCIDR.
		klog.Warningf("Node %s does not have a PodCIDR", node.Name)
		return "", errors.New("node does not have a PodCIDR")
	}

	for _, podCIDR := range podCIDRStrs {
		if podCIDR == "" {
			klog.Errorf("PodCIDR is empty for Node %s", node.Name)
		}

		peerPodCIDRAddr, _, err := net.ParseCIDR(podCIDR)
		if err != nil {
			klog.Errorf("Failed to parse PodCIDR %s for Node %s", podCIDR, node.Name)
			continue
		}

		// Add first ip in CIDR to the map
		peerGatewayIP := ip.NextIP(peerPodCIDRAddr)
		if peerGatewayIP.To4() != nil && peerGatewayIP.To16() != nil {
			return peerGatewayIP.String(), nil
		}
	}

	klog.Warningf("Node %s does not have a valid PodCIDR", node.Name)
	return "", errors.New("node does not have a valid PodCIDR")
}

func getPodCIDRsOnNode(node *corev1.Node) []string {
	if node.Spec.PodCIDRs != nil {
		return node.Spec.PodCIDRs
	}

	if node.Spec.PodCIDR == "" {
		// Does not help to return an error and trigger controller retries.
		return nil
	}
	return []string{node.Spec.PodCIDR}
}

func (l *LatencyStore) ListNodeIPs() map[string]string {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	return l.nodeGW0Map
}
