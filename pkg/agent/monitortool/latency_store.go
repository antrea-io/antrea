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
	// The map of Node name to Node IP, it will be changed by Node watcher
	// If the agent is running in networkPolicyOnly mode, the value will be the transport IP of the Node
	// If the agent is running in normal mode, the value will be the gateway IP of the Node
	nodeTargetIPsMap map[string][]net.IP
}

// NodeIPLatencyEntry is the entry of the latency map.
type NodeIPLatencyEntry struct {
	// The timestamp of the last send packet
	LastSendTime time.Time
	// The timestamp of the last receive packet
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
// Now it used for testing purpose and it is not exported, so we just return a pointer
func (l *LatencyStore) getNodeIPLatencyEntry(key string) (*NodeIPLatencyEntry, bool) {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	entry, ok := l.nodeIPLatencyMap[key]
	return entry, ok
}

// DeleteNodeIPLatencyEntry deletes the NodeIPLatencyEntry for the given Node IP
func (l *LatencyStore) DeleteNodeIPLatencyEntry(key string) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	delete(l.nodeIPLatencyMap, key)
}

// SetNodeIPLatencyEntry sets the NodeIPLatencyEntry for the given Node IP
func (l *LatencyStore) SetNodeIPLatencyEntry(key string, mutator func(entry *NodeIPLatencyEntry)) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	entry, ok := l.nodeIPLatencyMap[key]
	if !ok {
		// Init the connection entry
		entry = &NodeIPLatencyEntry{}
		l.nodeIPLatencyMap[key] = entry
	}

	// Update the connection entry
	mutator(entry)
}

// ListLatencies returns the map of Node IP to latency entry
func (l *LatencyStore) ListLatencies() map[string]*NodeIPLatencyEntry {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	return l.nodeIPLatencyMap
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

	// Delete from the node IP map
	delete(l.nodeTargetIPsMap, node.Name)

	// Delete from the NodeIPLatencyEntry map
	getNodeIPs, err := l.getNodeIPs(node)
	if err != nil {
		klog.ErrorS(err, "Failed to get IPs for Node", "nodeName", node.Name)
		return
	}

	for _, ip := range getNodeIPs {
		delete(l.nodeIPLatencyMap, ip.String())
	}
}

// updateNode updates a Node in the latency store
func (l *LatencyStore) updateNode(old *corev1.Node, new *corev1.Node) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	// Delete from the node IP map
	delete(l.nodeTargetIPsMap, old.Name)

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
		// Skip the Node if it does not have a PodCIDR.
		err := errors.New("node does not have a PodCIDR")
		klog.ErrorS(err, "Node does not have a PodCIDR", "Node name", node.Name)
		return gwIPs, err
	}

	// the 0th entry must match the podCIDR field. It may contain at most 1 value for
	// each of IPv4 and IPv6.
	// Both podCIDRStrs need to be parsed to get the gateway IP.
	for _, podCIDR := range podCIDRStrs {
		if podCIDR == "" {
			err := errors.New("PodCIDR is empty")
			klog.ErrorS(err, "PodCIDR is empty", "Node name", node.Name)
			return gwIPs, err
		}

		peerPodCIDRAddr, _, err := net.ParseCIDR(podCIDR)
		if err != nil {
			klog.ErrorS(err, "Failed to parse PodCIDR", "Node name", node.Name)
			return gwIPs, err
		}

		// Add first IP in CIDR to the map
		peerGatewayIP := ip.NextIP(peerPodCIDRAddr)

		// Only add the IP if it is an IPv4 or IPv6 address.
		if peerGatewayIP.To4() != nil || peerGatewayIP.To16() != nil {
			gwIPs = append(gwIPs, peerGatewayIP)
		}
	}

	return gwIPs, nil
}

// getPodCIDRsOnNode returns the PodCIDRs of the given Node.
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

// GetNodeIPs returns the target IPs of the given Node.
func (l *LatencyStore) GetNodeIPs(nodeName string) []net.IP {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	return l.nodeTargetIPsMap[nodeName]
}

// ListNodeIPs returns the map of Node name to target IPs.
func (l *LatencyStore) ListNodeIPs() map[string][]net.IP {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	return l.nodeTargetIPsMap
}

// CleanUp cleans up the latency store.
func (l *LatencyStore) CleanUp() {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	l.nodeIPLatencyMap = make(map[string]*NodeIPLatencyEntry)
	l.nodeTargetIPsMap = make(map[string][]net.IP)
}
