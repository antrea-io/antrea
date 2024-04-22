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

// LatencyStore is a store for latency information of connections between nodes.
type LatencyStore struct {
	// Lock for the latency store
	mutex sync.RWMutex

	// isNetworkPolicyOnly is the flag to indicate if the Antrea Agent is running in network policy only mode.
	isNetworkPolicyOnly bool
	// The map of node ip to latency entry, it will be changed by latency monitor
	nodeIPLatencyMap map[string]*NodeIPLatencyEntry
	// The map of node ip to node name, it will be changed by node watcher
	nodeGatewayMap map[string][]net.IP
}

// NodeIPLatencyEntry is the entry of the latency map.
type NodeIPLatencyEntry struct {
	// The latest sequence ID of the connection
	SeqID uint32
	// The timestamp of the last send packet
	LastSendTime time.Time
	// The timestamp of the last receive packet
	LastRecvTime time.Time
	// The last valid rtt of the connection
	LastMeasuredRTT time.Duration
}

func NewLatencyStore(isNetworkPolicyOnly bool) *LatencyStore {
	store := &LatencyStore{
		nodeIPLatencyMap:    make(map[string]*NodeIPLatencyEntry),
		nodeGatewayMap:      make(map[string][]net.IP),
		isNetworkPolicyOnly: isNetworkPolicyOnly,
	}

	return store
}

func (l *LatencyStore) GetNodeIPLatencyEntryByKey(key string) *NodeIPLatencyEntry {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	return l.nodeIPLatencyMap[key]
}

func (l *LatencyStore) DeleteNodeIPLatencyEntryByKey(key string) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	delete(l.nodeIPLatencyMap, key)
}

func (l *LatencyStore) UpdateNodeIPLatencyEntryByKey(key string, entry *NodeIPLatencyEntry) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	// Update the connection map
	l.nodeIPLatencyMap[key] = entry
}

func (l *LatencyStore) ListLatencies() map[string]*NodeIPLatencyEntry {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	return l.nodeIPLatencyMap
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
	delete(l.nodeGatewayMap, node.Name)
	// Delete the node from the NodeIPLatencyEntry map
	delete(l.nodeIPLatencyMap, node.Name)
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
			klog.Errorf("Failed to get transport IPs for Node %s: %v", node.Name, err)
			return
		}

		// Add the node to the gateway map
		l.nodeGatewayMap[node.Name] = transportIPs
	} else {
		gw0IPs, err := getGWIPs(node)
		if err != nil {
			klog.Errorf("Failed to get gateway IPs for Node %s: %v", node.Name, err)
			return
		}

		// Add the node to the node IP map
		l.nodeGatewayMap[node.Name] = gw0IPs
	}

	klog.Infof("Node %s has gateway IPs %v", node.Name, l.nodeGatewayMap[node.Name])
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

func getGWIPs(node *corev1.Node) ([]net.IP, error) {
	var gwIPs []net.IP

	podCIDRStrs := getPodCIDRsOnNode(node)
	if len(podCIDRStrs) == 0 {
		// Skip the node if it does not have a PodCIDR.
		klog.Errorf("Node %s does not have a PodCIDR", node.Name)
		return gwIPs, errors.New("node does not have a PodCIDR")
	}

	// the 0th entry must match the podCIDR field. It may contain at most 1 value for
	// each of IPv4 and IPv6.
	// Both podCIDRStrs need to be parsed to get the gateway IP.
	for _, podCIDR := range podCIDRStrs {
		if podCIDR == "" {
			klog.Errorf("PodCIDR is empty for Node %s", node.Name)
			return gwIPs, errors.New("PodCIDR is empty")
		}

		peerPodCIDRAddr, _, err := net.ParseCIDR(podCIDR)
		if err != nil {
			klog.Errorf("Failed to parse PodCIDR %s for Node %s", podCIDR, node.Name)
			return gwIPs, err
		}

		// Add first ip in CIDR to the map
		peerGatewayIP := ip.NextIP(peerPodCIDRAddr)

		// Only add the IP if it is an IPv4 or IPv6 address.
		if peerGatewayIP.To4() != nil || peerGatewayIP.To16() != nil {
			gwIPs = append(gwIPs, peerGatewayIP)
		}
	}

	return gwIPs, nil
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

	return l.nodeGatewayMap
}

func (l *LatencyStore) CleanUp() {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	l.nodeIPLatencyMap = make(map[string]*NodeIPLatencyEntry)
	l.nodeGatewayMap = make(map[string][]net.IP)
}
