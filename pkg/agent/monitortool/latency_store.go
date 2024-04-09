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

	"antrea.io/antrea/pkg/util/k8s"

	coreinformers "k8s.io/client-go/informers/core/v1"
)

// LatencyStore is a store for latency information of connections between nodes.
type LatencyStore struct {
	// Maybe we need to use small lock for the map
	mutex sync.RWMutex

	// isNetworkPolicyOnly is the flag to indicate if the Antrea Agent is running in network policy only mode.
	isNetworkPolicyOnly bool
	// The map of node name to node info, it will changed to gw0 watcher
	nodeInformer coreinformers.NodeInformer
	// The map of node ip to connection
	connectionMap map[string][]*Connection
	// The map of node ip to node name, it will be changed to gw0 watcher
	nodeGW0Map map[string][]net.IP
}

// TODO1: use LRU cache to store the latency of the connection?
type Connection struct {
	// The destination IP of the connection
	ToIP net.IP
	// The latency of the connection
	Latency time.Duration
	// The status of the connection
	Status bool
	// The last time the connection was updated
	LastUpdated time.Time
	// The time the connection was created.
	CreatedAt time.Time
}

// Key returns the key of the connection.
func (c *Connection) Key() net.IP {
	return c.ToIP
}

func NewLatencyStore(nodeInformer coreinformers.NodeInformer, isNetworkPolicyOnly bool) *LatencyStore {
	store := &LatencyStore{
		connectionMap:       make(map[string][]*Connection),
		nodeGW0Map:          make(map[string][]net.IP),
		nodeInformer:        nodeInformer,
		isNetworkPolicyOnly: isNetworkPolicyOnly,
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

func (l *LatencyStore) GetConnsByKey(connKey string) ([]*Connection, bool) {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	conn, found := l.connectionMap[connKey]

	return conn, found
}

func (l *LatencyStore) DeleteConnsByKey(connKey string) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	delete(l.connectionMap, connKey)
}

func (l *LatencyStore) UpdateConnByKey(connKey string, conn *Connection) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	// Judge if the connection is already in the map
	conns, found := l.connectionMap[connKey]
	if !found {
		// Add the connection to the map
		l.connectionMap[connKey] = []*Connection{conn}
		return
	}

	// Update the connection in the map, make sure ip is not changed
	updated := false
	for i, c := range conns {
		if c.ToIP.Equal(conn.ToIP) {
			conns[i] = conn
			updated = true
			break
		}
	}

	if !updated {
		conns = append(conns, conn)
	}

	// Update the connection map
	l.connectionMap[connKey] = conns
}

func (l *LatencyStore) GetConnByIP(ip net.IP) (*Connection, bool) {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	for _, conn := range l.connectionMap {
		for _, c := range conn {
			if c.ToIP.Equal(ip) {
				return c, true
			}
		}
	}

	return nil, false
}

func (l *LatencyStore) ListConns() map[string][]*Connection {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	return l.connectionMap
}

func (l *LatencyStore) addNode(node *corev1.Node) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	l.updateNodeMap(node)
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

	// Node name will not be changed in the same node
	l.updateNodeMap(new)
}

func (l *LatencyStore) updateNodeMap(node *corev1.Node) {
	if l.isNetworkPolicyOnly {
		transportIPs, err := getTransportIPs(node)
		if err != nil {
			return
		}

		// Add the node to the connection map
		l.nodeGW0Map[node.Name] = transportIPs
	} else {
		gw0IPs, err := getGW0IPs(node)
		if err != nil {
			return
		}

		// Add the node to the node IP map
		l.nodeGW0Map[node.Name] = gw0IPs
	}
}

func getTransportIPs(node *corev1.Node) ([]net.IP, error) {
	var transportIPs []net.IP
	dualIP, err := k8s.GetNodeTransportAddrs(node)
	if err != nil {
		return transportIPs, err
	}

	if dualIP.IPv4 != nil {
		transportIPs = append(transportIPs, dualIP.IPv4)
	}
	if dualIP.IPv6 != nil {
		transportIPs = append(transportIPs, dualIP.IPv6)
	}

	return transportIPs, nil
}

func getGW0IPs(node *corev1.Node) ([]net.IP, error) {
	var gw0IPs []net.IP

	podCIDRStrs := getPodCIDRsOnNode(node)
	if len(podCIDRStrs) == 0 {
		// Skip the node if it does not have a PodCIDR.
		klog.Warningf("Node %s does not have a PodCIDR", node.Name)
		return gw0IPs, errors.New("node does not have a PodCIDR")
	}

	// the 0th entry must match the podCIDR field. It may contain at most 1 value for
	// each of IPv4 and IPv6.
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

		// Only add the IP if it is an IPv4 or IPv6 address.
		if peerGatewayIP.To4() != nil || peerGatewayIP.To16() != nil {
			gw0IPs = append(gw0IPs, peerGatewayIP)
		}
	}

	return gw0IPs, nil
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

func (l *LatencyStore) ListNodeIPs() map[string][]net.IP {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	return l.nodeGW0Map
}

func (l *LatencyStore) CleanUp() {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	l.connectionMap = make(map[string][]*Connection)
	l.nodeGW0Map = make(map[string][]net.IP)
}
