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
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/util/k8s"
)

// LatencyStore is a store for latency information of connections between Nodes.
type LatencyStore struct {
	// Lock for the latency store
	mutex sync.RWMutex

	// Whether the agent is running in networkPolicyOnly mode
	isNetworkPolicyOnly bool
	// The map of Node IP to latency entry, it will be changed by latency monitor
	nodeIPLatencyMap map[string]*NodeIPLatencyEntry
	// The map of Node name to Node IP(s), it will be changed by Node watcher
	// If the agent is running in networkPolicyOnly mode, the value will be the transport IP of the Node.
	// Otherwise, the value will be the gateway IP of the Node
	nodeTargetIPsMap map[string][]net.IP
}

// NodeIPLatencyEntry is the entry of the latency map.
type NodeIPLatencyEntry struct {
	// The timestamp of the last sent packet
	LastSendTime time.Time
	// The timestamp of the last received packet
	LastRecvTime time.Time
	// The last valid rtt of the connection
	LastMeasuredRTT time.Duration
}

// NewLatencyStore creates a new LatencyStore.
func NewLatencyStore(isNetworkPolicyOnly bool) *LatencyStore {
	store := &LatencyStore{
		nodeIPLatencyMap:    make(map[string]*NodeIPLatencyEntry),
		nodeTargetIPsMap:    make(map[string][]net.IP),
		isNetworkPolicyOnly: isNetworkPolicyOnly,
	}

	return store
}

// getNodeIPLatencyEntry returns the NodeIPLatencyEntry for the given Node IP
// For now, it is only used for testing purposes.
func (l *LatencyStore) getNodeIPLatencyEntry(nodeIP string) (*NodeIPLatencyEntry, bool) {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	entry, ok := l.nodeIPLatencyMap[nodeIP]

	return entry, ok
}

// DeleteNodeIPLatencyEntry deletes the NodeIPLatencyEntry for the given Node IP
func (l *LatencyStore) DeleteNodeIPLatencyEntry(nodeIP string) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	delete(l.nodeIPLatencyMap, nodeIP)
}

// SetNodeIPLatencyEntry sets the NodeIPLatencyEntry for the given Node IP
func (l *LatencyStore) SetNodeIPLatencyEntry(nodeIP string, mutator func(entry *NodeIPLatencyEntry)) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	entry, ok := l.nodeIPLatencyMap[nodeIP]
	if !ok {
		entry = &NodeIPLatencyEntry{}
		l.nodeIPLatencyMap[nodeIP] = entry
	}

	mutator(entry)
}

// addNode adds a Node to the latency store
func (l *LatencyStore) addNode(node *corev1.Node) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	l.updateNodeMap(node)
}

// deleteNode deletes a Node from the latency store
func (l *LatencyStore) deleteNode(node *corev1.Node) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	nodeIPs, ok := l.nodeTargetIPsMap[node.Name]
	if !ok {
		klog.ErrorS(nil, "Failed to get IPs for Node", "nodeName", node.Name)
		return
	}

	for _, ip := range nodeIPs {
		delete(l.nodeIPLatencyMap, ip.String())
	}

	delete(l.nodeTargetIPsMap, node.Name)
}

// updateNode updates a Node name in the latency store
func (l *LatencyStore) updateNode(new *corev1.Node) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	// Node name will not be changed in the same Node update operation.
	l.updateNodeMap(new)
}

// updateNodeMap updates the nodeTargetIPsMap with the IPs of the given Node.
func (l *LatencyStore) updateNodeMap(node *corev1.Node) {
	nodeIPs, err := l.getNodeIPs(node)
	if err != nil {
		klog.ErrorS(err, "Failed to get IPs for Node", "nodeName", node.Name)
		return
	}

	l.nodeTargetIPsMap[node.Name] = nodeIPs
}

// getNodeIPs returns the target IPs of the given Node based on the agent mode.
func (l *LatencyStore) getNodeIPs(node *corev1.Node) ([]net.IP, error) {
	if l.isNetworkPolicyOnly {
		transportIPs, err := getTransportIPs(node)
		if err != nil {
			return nil, err
		}

		return transportIPs, nil
	} else {
		gw0IPs, err := getGWIPs(node)
		if err != nil {
			return nil, err
		}

		return gw0IPs, nil
	}
}

// getTransportIPs returns the transport IPs of the given Node.
func getTransportIPs(node *corev1.Node) ([]net.IP, error) {
	var transportIPs []net.IP
	ips, err := k8s.GetNodeTransportAddrs(node)
	if err != nil {
		return transportIPs, err
	}

	if ips.IPv4 != nil {
		transportIPs = append(transportIPs, ips.IPv4)
	}
	if ips.IPv6 != nil {
		transportIPs = append(transportIPs, ips.IPv6)
	}

	return transportIPs, nil
}

// getGWIPs returns the gateway IPs of the given Node.
func getGWIPs(node *corev1.Node) ([]net.IP, error) {
	var gwIPs []net.IP

	podCIDRStrs := getPodCIDRsOnNode(node)
	if len(podCIDRStrs) == 0 {
		return nil, errors.New("node does not have a PodCIDR")
	}

	for _, podCIDR := range podCIDRStrs {
		peerPodCIDRAddr, _, err := net.ParseCIDR(podCIDR)
		if err != nil {
			return nil, err
		}

		// Add first IP in CIDR to the map
		peerGatewayIP := ip.NextIP(peerPodCIDRAddr)
		gwIPs = append(gwIPs, peerGatewayIP)
	}

	return gwIPs, nil
}

// getPodCIDRsOnNode returns the PodCIDRs of the given Node.
func getPodCIDRsOnNode(node *corev1.Node) []string {
	if node.Spec.PodCIDRs != nil {
		return node.Spec.PodCIDRs
	}

	if node.Spec.PodCIDR == "" {
		return nil
	}
	return []string{node.Spec.PodCIDR}
}

// GetNodeIPs returns the target IPs of the given Node.
func (l *LatencyStore) GetNodeIPs(nodeName string) []net.IP {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	return l.nodeTargetIPsMap[nodeName]
}

// ListNodeIPs returns the list of all Node IPs in the latency store.
func (l *LatencyStore) ListNodeIPs() []net.IP {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	// Allocate a slice with a capacity equal to twice the size of the map,
	// as we can have up to 2 IP addresses per Node in dual-stack case.
	nodeIPs := make([]net.IP, 0, 2*len(l.nodeTargetIPsMap))
	for _, ips := range l.nodeTargetIPsMap {
		nodeIPs = append(nodeIPs, ips...)
	}

	return nodeIPs
}
