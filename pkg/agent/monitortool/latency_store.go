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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"

	statsv1alpha1 "antrea.io/antrea/pkg/apis/stats/v1alpha1"
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
func (s *LatencyStore) getNodeIPLatencyEntry(nodeIP string) (NodeIPLatencyEntry, bool) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	entry, ok := s.nodeIPLatencyMap[nodeIP]
	if !ok {
		return NodeIPLatencyEntry{}, ok
	}

	return *entry, ok
}

// getNodeIPLatencyKeys returns the list of Node IPs for which we currently have
// latency measurements.
// It is only used for testing purposes.
func (s *LatencyStore) getNodeIPLatencyKeys() []string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	keys := make([]string, 0, len(s.nodeIPLatencyMap))
	for key := range s.nodeIPLatencyMap {
		keys = append(keys, key)
	}

	return keys
}

// SetNodeIPLatencyEntry sets the NodeIPLatencyEntry for the given Node IP
func (s *LatencyStore) SetNodeIPLatencyEntry(nodeIP string, mutator func(entry *NodeIPLatencyEntry)) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	entry, ok := s.nodeIPLatencyMap[nodeIP]
	if !ok {
		entry = &NodeIPLatencyEntry{}
		s.nodeIPLatencyMap[nodeIP] = entry
	}

	mutator(entry)
}

// addNode adds a Node to the latency store
func (s *LatencyStore) addNode(node *corev1.Node) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.updateNodeMap(node)
}

// deleteNode deletes a Node from the latency store
func (s *LatencyStore) deleteNode(node *corev1.Node) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	delete(s.nodeTargetIPsMap, node.Name)
}

// updateNode updates a Node name in the latency store
func (s *LatencyStore) updateNode(new *corev1.Node) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Node name will not be changed in the same Node update operation.
	s.updateNodeMap(new)
}

// updateNodeMap updates the nodeTargetIPsMap with the IPs of the given Node.
func (s *LatencyStore) updateNodeMap(node *corev1.Node) {
	nodeIPs, err := s.getNodeIPs(node)
	if err != nil {
		klog.ErrorS(err, "Failed to get IPs for Node", "nodeName", node.Name)
		return
	}

	s.nodeTargetIPsMap[node.Name] = nodeIPs
}

// getNodeIPs returns the target IPs of the given Node based on the agent mode.
func (s *LatencyStore) getNodeIPs(node *corev1.Node) ([]net.IP, error) {
	if s.isNetworkPolicyOnly {
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

// ListNodeIPs returns the list of all Node IPs in the latency store.
func (s *LatencyStore) ListNodeIPs() []net.IP {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Allocate a slice with a capacity equal to twice the size of the map,
	// as we can have up to 2 IP addresses per Node in dual-stack case.
	nodeIPs := make([]net.IP, 0, 2*len(s.nodeTargetIPsMap))
	for _, ips := range s.nodeTargetIPsMap {
		nodeIPs = append(nodeIPs, ips...)
	}

	return nodeIPs
}

// DeleteStaleNodeIPs deletes the stale Node IPs from the nodeIPLatencyMap.
func (s *LatencyStore) DeleteStaleNodeIPs() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	nodeIPSet := sets.New[string]()
	for _, ips := range s.nodeTargetIPsMap {
		for _, ip := range ips {
			nodeIPSet.Insert(ip.String())
		}
	}

	for nodeIP := range s.nodeIPLatencyMap {
		if !nodeIPSet.Has(nodeIP) {
			delete(s.nodeIPLatencyMap, nodeIP)
		}
	}
}

// ConvertList converts the latency store to a list of PeerNodeLatencyStats.
func (l *LatencyStore) ConvertList(currentNodeName string) []statsv1alpha1.PeerNodeLatencyStats {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	// PeerNodeLatencyStats should be a list of size N-1, where N is the number of Nodes in the cluster.
	// TargetIPLatencyStats will be a list of size 1 (single-stack case) or 2 (dual-stack case).
	peerNodeLatencyStatsList := make([]statsv1alpha1.PeerNodeLatencyStats, 0, len(l.nodeIPLatencyMap))
	for nodeName, nodeIPs := range l.nodeTargetIPsMap {
		// Even though the current Node should already be excluded from the map, we add an extra check as an additional guarantee.
		if nodeName == currentNodeName {
			continue
		}

		targetIPLatencyStats := make([]statsv1alpha1.TargetIPLatencyStats, 0, len(nodeIPs))
		for _, nodeIP := range nodeIPs {
			nodeIPStr := nodeIP.String()
			latencyEntry, ok := l.nodeIPLatencyMap[nodeIPStr]
			if !ok {
				continue
			}
			entry := statsv1alpha1.TargetIPLatencyStats{
				TargetIP:                   nodeIPStr,
				LastSendTime:               metav1.NewTime(latencyEntry.LastSendTime),
				LastRecvTime:               metav1.NewTime(latencyEntry.LastRecvTime),
				LastMeasuredRTTNanoseconds: latencyEntry.LastMeasuredRTT.Nanoseconds(),
			}
			targetIPLatencyStats = append(targetIPLatencyStats, entry)
		}

		peerNodeLatencyStats := statsv1alpha1.PeerNodeLatencyStats{
			NodeName:             nodeName,
			TargetIPLatencyStats: targetIPLatencyStats,
		}
		peerNodeLatencyStatsList = append(peerNodeLatencyStatsList, peerNodeLatencyStats)
	}

	return peerNodeLatencyStatsList
}
