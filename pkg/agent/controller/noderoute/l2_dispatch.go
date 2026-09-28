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
}

func newL2DispatchPeerIndices() *l2DispatchPeerIndices {
	return &l2DispatchPeerIndices{byNode: map[string]uint32{}, used: sets.New[uint32](), next: 1}
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
// it, and returns the index of the peer Node, or 0 if it did not. A peer Node keeps its index for as long as it can be
// reached, so that the flows which use the index stay valid.
func (c *Controller) installL2DispatchPeer(nodeName string, peerNodeIPs *utilip.DualStackIPs) (uint32, error) {
	if !c.networkConfig.SupportsL2Dispatch() {
		return 0, nil
	}
	peerIPs := c.l2DispatchPeerIPs(peerNodeIPs)
	if peerIPs == nil {
		return 0, nil
	}
	index, err := c.l2DispatchPeers.allocate(nodeName)
	if err != nil {
		return 0, fmt.Errorf("failed to allocate an l2 dispatch index for Node %s: %w", nodeName, err)
	}
	if err := c.routeClient.AddL2DispatchPeerRoutes(index, peerIPs); err != nil {
		return 0, fmt.Errorf("failed to install the l2 dispatch routing to Node %s: %w", nodeName, err)
	}
	return index, nil
}

// releaseL2DispatchPeer removes the l2 dispatch routing to the peer Node, if it has any, and frees its index.
func (c *Controller) releaseL2DispatchPeer(nodeName string) error {
	index, exists := c.l2DispatchPeers.get(nodeName)
	if !exists {
		return nil
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

// dsrPeerNodeMAC returns the MAC address from which the l2 dispatch of DSR accepts traffic from the peer Node, or nil
// if the peer Node cannot send DSR traffic to this Node with the l2 dispatch. DSR supports IPv4 only, so the peer Node
// qualifies if its IPv4 transport address is in the local transport subnet.
func (c *Controller) dsrPeerNodeMAC(peerNodeMAC net.HardwareAddr, peerNodeIPs *utilip.DualStackIPs) net.HardwareAddr {
	if !c.networkConfig.SupportsDSRL2Dispatch() || peerNodeMAC == nil ||
		!c.networkConfig.SupportsL2DispatchToPeer(peerNodeIPs.IPv4, c.nodeConfig.NodeTransportIPv4Addr) {
		return nil
	}
	return peerNodeMAC
}

// updateDSRPeerNodeMAC adds the MAC address of the peer Node to the MAC addresses from which this Node accepts DSR
// traffic that a peer Node has already load-balanced, if the peer Node can use the l2 dispatch to reach this Node. It
// deletes the previous MAC address of the peer Node when it changes or no longer qualifies, and returns the MAC address
// which it added, or nil.
func (c *Controller) updateDSRPeerNodeMAC(previousMAC, peerNodeMAC net.HardwareAddr,
	peerNodeIPs *utilip.DualStackIPs) (net.HardwareAddr, error) {
	desiredMAC := c.dsrPeerNodeMAC(peerNodeMAC, peerNodeIPs)
	if previousMAC != nil && previousMAC.String() != desiredMAC.String() {
		if err := c.routeClient.DeleteDSRPeerNodeMAC(previousMAC); err != nil {
			return nil, fmt.Errorf("failed to delete the previous MAC address %s for the DSR l2 dispatch: %w", previousMAC, err)
		}
	}
	if desiredMAC != nil {
		if err := c.routeClient.AddDSRPeerNodeMAC(desiredMAC); err != nil {
			return nil, fmt.Errorf("failed to add the MAC address %s for the DSR l2 dispatch: %w", desiredMAC, err)
		}
	}
	return desiredMAC, nil
}

// reconcileDSRPeerNodeMACs deletes the MAC addresses of the peer Nodes which are gone or can no longer use the l2
// dispatch of DSR, for example because they were deleted while the agent was not running.
func (c *Controller) reconcileDSRPeerNodeMACs() error {
	if !c.networkConfig.SupportsDSRL2Dispatch() {
		return nil
	}
	nodes, err := c.nodeLister.List(labels.Everything())
	if err != nil {
		return fmt.Errorf("error when listing Nodes: %w", err)
	}
	desiredMACs := sets.New[string]()
	for _, node := range nodes {
		if node.Name == c.nodeConfig.Name {
			continue
		}
		peerNodeMAC, err := getNodeMAC(node)
		if err != nil {
			continue
		}
		peerNodeIPs, err := k8s.GetNodeTransportAddrs(node)
		if err != nil {
			continue
		}
		if mac := c.dsrPeerNodeMAC(peerNodeMAC, peerNodeIPs); mac != nil {
			desiredMACs.Insert(mac.String())
		}
	}
	return c.routeClient.ReconcileDSRPeerNodeMACs(desiredMACs)
}
