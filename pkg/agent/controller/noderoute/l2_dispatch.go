// Copyright 2026 Antrea Authors
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

package noderoute

import (
	"fmt"
	"net"
	"sync"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"

	"antrea.io/antrea/v2/pkg/agent/types"
	utilip "antrea.io/antrea/v2/pkg/util/ip"
	"antrea.io/antrea/v2/pkg/util/k8s"
)

// l2DispatchPeerIndices allocates the indices which identify the peer Nodes of the l2 dispatch in packet marks, one
// per Node. It allocates the next free index after the last one it allocated, and wraps around after
// MaxL2DispatchPeerIndex. So an index which was just released is not given to another Node while a feature may still
// carry it in flows that it updates asynchronously: until they are updated, such flows reach the drop rule of the l2
// dispatch instead of another Node. Only the allocated indices have ip rules, so their number stays bounded by the
// number of peer Nodes.
type l2DispatchPeerIndices struct {
	mutex  sync.Mutex
	byNode map[string]uint32
	used   sets.Set[uint32]
	// next is the index from which allocate looks for a free index.
	next uint32
	// routedIPs are the transport IPs which the routing of each Node sends packets to, for the Nodes whose routing is
	// installed. The features which use the l2 dispatch use the index of a Node only while its routing is installed.
	routedIPs map[string]*utilip.DualStackIPs
}

func newL2DispatchPeerIndices() *l2DispatchPeerIndices {
	return &l2DispatchPeerIndices{
		byNode:    map[string]uint32{},
		used:      sets.New[uint32](),
		next:      1,
		routedIPs: map[string]*utilip.DualStackIPs{},
	}
}

// allocate returns the index of the Node, and allocates one if the Node has none.
func (a *l2DispatchPeerIndices) allocate(nodeName string) (uint32, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	if index, exists := a.byNode[nodeName]; exists {
		return index, nil
	}
	for i := uint32(0); i < types.MaxL2DispatchPeerIndex; i++ {
		index := (a.next-1+i)%types.MaxL2DispatchPeerIndex + 1
		if !a.used.Has(index) {
			a.used.Insert(index)
			a.byNode[nodeName] = index
			a.next = index%types.MaxL2DispatchPeerIndex + 1
			return index, nil
		}
	}
	return 0, fmt.Errorf("all %d indices of the l2 dispatch are in use", types.MaxL2DispatchPeerIndex)
}

// skip makes allocate look for a free index after the index, if it would look before it. At agent start, it keeps
// the indices which the previous agent used, and which flows kept across the restart may still carry, from being
// allocated first.
func (a *l2DispatchPeerIndices) skip(index uint32) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	if index >= a.next {
		a.next = index%types.MaxL2DispatchPeerIndex + 1
	}
}

// reserve records the index which the Node had before an agent restart. It returns false if the Node already has
// an index or the index belongs to another Node.
func (a *l2DispatchPeerIndices) reserve(nodeName string, index uint32) bool {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	if _, exists := a.byNode[nodeName]; exists || a.used.Has(index) {
		return false
	}
	a.used.Insert(index)
	a.byNode[nodeName] = index
	return true
}

// release frees the index of the Node.
func (a *l2DispatchPeerIndices) release(nodeName string) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	if index, exists := a.byNode[nodeName]; exists {
		a.used.Delete(index)
		delete(a.byNode, nodeName)
	}
}

// get returns the index of the Node, if it has one.
func (a *l2DispatchPeerIndices) get(nodeName string) (uint32, bool) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	index, exists := a.byNode[nodeName]
	return index, exists
}

// setRouted records that the routing of the Node is installed, with the IPs. It returns true if this changed.
func (a *l2DispatchPeerIndices) setRouted(nodeName string, peerIPs *utilip.DualStackIPs) bool {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	if current, exists := a.routedIPs[nodeName]; exists && current.Equal(*peerIPs) {
		return false
	}
	a.routedIPs[nodeName] = peerIPs
	return true
}

// clearRouted records that the routing of the Node is about to be removed. It returns true if it was installed.
func (a *l2DispatchPeerIndices) clearRouted(nodeName string) bool {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	_, exists := a.routedIPs[nodeName]
	delete(a.routedIPs, nodeName)
	return exists
}

// getRouted returns the index of the Node and the IPs of its routing, if its routing is installed.
func (a *l2DispatchPeerIndices) getRouted(nodeName string) (uint32, *utilip.DualStackIPs, bool) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	peerIPs, exists := a.routedIPs[nodeName]
	if !exists {
		return 0, nil, false
	}
	return a.byNode[nodeName], peerIPs, true
}

// l2DispatchPeerIPs returns the transport IPs of the peer Node which the l2 dispatch can reach: the IPs of the
// enabled IP families which are in the local transport subnets. It returns nil if there is none.
func (c *Controller) l2DispatchPeerIPs(peerNodeIPs *utilip.DualStackIPs) *utilip.DualStackIPs {
	peerIPs := &utilip.DualStackIPs{}
	if c.networkConfig.IPv4Enabled && c.networkConfig.SupportsL2DispatchToPeer(peerNodeIPs.IPv4, c.nodeConfig.NodeTransportIPv4Addr) {
		peerIPs.IPv4 = peerNodeIPs.IPv4
	}
	if c.networkConfig.IPv6Enabled && c.networkConfig.SupportsL2DispatchToPeer(peerNodeIPs.IPv6, c.nodeConfig.NodeTransportIPv6Addr) {
		peerIPs.IPv6 = peerNodeIPs.IPv6
	}
	if peerIPs.IPv4 == nil && peerIPs.IPv6 == nil {
		return nil
	}
	return peerIPs
}

// installL2DispatchPeer installs or updates the l2 dispatch routing to the peer Node, if the l2 dispatch can reach
// it, and returns whether it did. A peer Node keeps its index for as long as it can be reached, so that the flows
// which use the index stay valid.
func (c *Controller) installL2DispatchPeer(nodeName string, peerNodeIPs *utilip.DualStackIPs) (bool, error) {
	if !c.networkConfig.SupportsL2Dispatch() {
		return false, nil
	}
	peerIPs := c.l2DispatchPeerIPs(peerNodeIPs)
	if peerIPs == nil {
		return false, nil
	}
	index, err := c.l2DispatchPeers.allocate(nodeName)
	if err != nil {
		return false, fmt.Errorf("failed to allocate an l2 dispatch index for Node %s: %w", nodeName, err)
	}
	if err := c.routeClient.AddL2DispatchPeerRoutes(index, peerIPs); err != nil {
		return false, fmt.Errorf("failed to install the l2 dispatch routing to Node %s: %w", nodeName, err)
	}
	if c.l2DispatchPeers.setRouted(nodeName, peerIPs) {
		c.notifyL2DispatchPeer(nodeName)
	}
	return true, nil
}

// releaseL2DispatchPeer removes the l2 dispatch routing to the peer Node, if it has any, and frees its index.
func (c *Controller) releaseL2DispatchPeer(nodeName string) error {
	index, exists := c.l2DispatchPeers.get(nodeName)
	if !exists {
		return nil
	}
	// The index is no longer given out, and the features which use it are notified before its routing is removed, so
	// that they stop using it as soon as possible.
	if c.l2DispatchPeers.clearRouted(nodeName) {
		c.notifyL2DispatchPeer(nodeName)
	}
	if err := c.routeClient.DeleteL2DispatchPeerRoutes(index); err != nil {
		return fmt.Errorf("failed to remove the l2 dispatch routing to Node %s: %w", nodeName, err)
	}
	c.l2DispatchPeers.release(nodeName)
	return nil
}

// reconcileL2DispatchPeers keeps the indices which the peer Nodes had before an agent restart, because the OVS flows
// kept across the restart may use them. It removes the routing of the indices whose Node is gone or can no longer be
// reached with the l2 dispatch.
func (c *Controller) reconcileL2DispatchPeers() error {
	if !c.networkConfig.SupportsL2Dispatch() {
		return nil
	}
	installedPeers, err := c.routeClient.ListL2DispatchPeers()
	if err != nil {
		return err
	}
	if len(installedPeers) == 0 {
		return nil
	}
	nodes, err := c.nodeLister.List(labels.Everything())
	if err != nil {
		return fmt.Errorf("error when listing Nodes: %w", err)
	}
	nodeByIP := map[string]string{}
	for _, node := range nodes {
		if node.Name == c.nodeConfig.Name {
			continue
		}
		nodeIPs, err := k8s.GetNodeTransportAddrs(node)
		if err != nil {
			continue
		}
		if peerIPs := c.l2DispatchPeerIPs(nodeIPs); peerIPs != nil {
			for _, peerIP := range []net.IP{peerIPs.IPv4, peerIPs.IPv6} {
				if peerIP != nil {
					nodeByIP[peerIP.String()] = node.Name
				}
			}
		}
	}
	for index, peerIPs := range installedPeers {
		c.l2DispatchPeers.skip(index)
		nodeName := ""
		for _, peerIP := range []net.IP{peerIPs.IPv4, peerIPs.IPv6} {
			if peerIP == nil {
				continue
			}
			if name, exists := nodeByIP[peerIP.String()]; exists {
				nodeName = name
				break
			}
		}
		if nodeName != "" && c.l2DispatchPeers.reserve(nodeName, index) {
			klog.InfoS("Kept the l2 dispatch index of a peer Node across the restart", "node", nodeName, "index", index)
			continue
		}
		if err := c.routeClient.DeleteL2DispatchPeerRoutes(index); err != nil {
			return fmt.Errorf("failed to remove the stale l2 dispatch routing of index %d: %w", index, err)
		}
	}
	return nil
}

// GetL2DispatchPeerIndex returns the index which identifies the peer Node in the l2 dispatch, if the policy routing of
// the index is installed for the IP family. It returns an error if the l2 dispatch cannot reach the Node with the IP
// family: the Node is not known, or has no transport IP of the family in the local transport subnet. When it returns
// neither the index nor an error, the routing is not installed yet, and the handlers added by
// AddL2DispatchPeerEventHandler are called once it is.
func (c *Controller) GetL2DispatchPeerIndex(nodeName string, isIPv6 bool) (uint32, bool, error) {
	if !c.networkConfig.SupportsL2Dispatch() {
		return 0, false, fmt.Errorf("the l2 dispatch is not enabled")
	}
	peerIPOfFamily := func(peerIPs *utilip.DualStackIPs) net.IP {
		if isIPv6 {
			return peerIPs.IPv6
		}
		return peerIPs.IPv4
	}
	if index, peerIPs, routed := c.l2DispatchPeers.getRouted(nodeName); routed && peerIPOfFamily(peerIPs) != nil {
		return index, true, nil
	}
	node, err := c.nodeLister.Get(nodeName)
	if err != nil {
		return 0, false, fmt.Errorf("failed to get Node %s: %w", nodeName, err)
	}
	nodeIPs, err := k8s.GetNodeTransportAddrs(node)
	if err != nil {
		return 0, false, fmt.Errorf("failed to get the transport IPs of Node %s: %w", nodeName, err)
	}
	if peerIPs := c.l2DispatchPeerIPs(nodeIPs); peerIPs == nil || peerIPOfFamily(peerIPs) == nil {
		family, localIP := "IPv4", c.nodeConfig.NodeTransportIPv4Addr
		if isIPv6 {
			family, localIP = "IPv6", c.nodeConfig.NodeTransportIPv6Addr
		}
		switch {
		case peerIPOfFamily(nodeIPs) == nil:
			return 0, false, fmt.Errorf("the l2 dispatch cannot reach Node %s: it has no %s transport IP", nodeName, family)
		case localIP == nil:
			return 0, false, fmt.Errorf("the l2 dispatch cannot reach Node %s: this Node has no %s transport IP",
				nodeName, family)
		}
		return 0, false, fmt.Errorf("the l2 dispatch cannot reach Node %s: its %s transport IP %s is not in the local "+
			"transport subnet %s", nodeName, family, peerIPOfFamily(nodeIPs), localIP)
	}
	return 0, false, nil
}

// AddL2DispatchPeerEventHandler adds a handler which is called with the name of a peer Node when the policy routing of
// its l2 dispatch index is installed, changes, or is about to be removed. It must be called before Run.
func (c *Controller) AddL2DispatchPeerEventHandler(handler func(nodeName string)) {
	c.l2DispatchPeerEventHandlers = append(c.l2DispatchPeerEventHandlers, handler)
}

func (c *Controller) notifyL2DispatchPeer(nodeName string) {
	for _, handler := range c.l2DispatchPeerEventHandlers {
		handler(nodeName)
	}
}
