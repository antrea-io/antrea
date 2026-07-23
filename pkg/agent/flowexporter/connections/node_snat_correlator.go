// Copyright 2026 Antrea Authors
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

package connections

import (
	"net/netip"
	"sync"
	"time"

	"k8s.io/klog/v2"

	"antrea.io/antrea/v2/pkg/agent/flowexporter/connection"
)

const (
	// nodeSnatTTL is the threshold for expiring connections in the NodeSnatCorrelator.
	nodeSnatTTL = time.Minute
	// nodeSnatCleanUpInterval is how often the background cleanup runs.
	nodeSnatCleanUpInterval = 5 * time.Second
)

// NodeSnatCorrelator correlates Antrea-zone Pod-to-External connections with their
// default-zone (zone 0) counterparts to extract the Node SNAT IP. For Pod-to-External
// flows, Antrea applies a MASQUERADE rule that rewrites the source IP to the node's
// egress IP. The actual SNAT IP is not known to Antrea, but it can be read from the
// default conntrack zone where the reply tuple reveals the post-SNAT source IP.
//
// Zone-0 entry for a Pod-to-External flow (when SNAT is applied):
//
//	TupleOrig: src=<podIP>:<podPort>     dst=<externalIP>:<externalPort>
//	TupleReply: src=<externalIP>:<externalPort> dst=<snatIP>:<snatPort>
//
// The correlation key uses the 5-tuple from the original direction, which is the same
// in both the default zone and the Antrea zone for Pod-to-External flows.
type NodeSnatCorrelator struct {
	connections     map[nodeSnatKey]nodeSnatItem
	lock            sync.Mutex
	ttl             time.Duration
	cleanUpInterval time.Duration
}

// nodeSnatKey identifies a connection for correlation between zones.
// For Pod-to-External flows, the original 5-tuple is the same in both zones.
type nodeSnatKey struct {
	srcIP    netip.Addr
	dstIP    netip.Addr
	srcPort  uint16
	dstPort  uint16
	protocol uint8
}

// nodeSnatItem stores the SNAT IP, port, and a timestamp for TTL expiry.
type nodeSnatItem struct {
	snatIP    netip.Addr
	snatPort  uint16
	timestamp time.Time
}

// NewNodeSnatCorrelator returns a NodeSnatCorrelator with its internal map initialized.
func NewNodeSnatCorrelator() *NodeSnatCorrelator {
	return &NodeSnatCorrelator{
		connections:     map[nodeSnatKey]nodeSnatItem{},
		ttl:             nodeSnatTTL,
		cleanUpInterval: nodeSnatCleanUpInterval,
	}
}

// Run runs the TTL cleanup loop until stopCh is closed.
func (c *NodeSnatCorrelator) Run(stopCh <-chan struct{}) {
	ticker := time.NewTicker(c.cleanUpInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			c.cleanup()
		}
	}
}

// IngestDefaultZoneFlow stores the SNAT IP and port from a default-zone connection.
// Only connections where SNAT was applied (reply destination != original source) are stored.
func (c *NodeSnatCorrelator) IngestDefaultZoneFlow(conn *connection.Connection) {
	if conn == nil || conn.Zone != DefaultZone {
		return
	}
	// Check if SNAT was applied: the ProxySnatIP field is already populated by
	// NetlinkFlowToAntreaConnection when TupleReply.dst != TupleOrig.src.
	if !conn.ProxySnatIP.IsValid() {
		return
	}
	key := nodeSnatKey{
		srcIP:    conn.FlowKey.SourceAddress,
		dstIP:    conn.FlowKey.DestinationAddress,
		srcPort:  conn.FlowKey.SourcePort,
		dstPort:  conn.FlowKey.DestinationPort,
		protocol: conn.FlowKey.Protocol,
	}
	c.lock.Lock()
	defer c.lock.Unlock()
	c.connections[key] = nodeSnatItem{
		snatIP:    conn.ProxySnatIP,
		snatPort:  conn.ProxySnatPort,
		timestamp: time.Now(),
	}
}

// LookupSnat returns the Node SNAT IP and port for a given Antrea-zone connection, if available.
// Unlike the FromExternalCorrelator, this does not pop (remove) the entry because the
// same zone-0 connection may match multiple export cycles of the same Antrea-zone flow.
func (c *NodeSnatCorrelator) LookupSnat(conn *connection.Connection) (netip.Addr, uint16) {
	if conn == nil {
		return netip.Addr{}, 0
	}
	key := nodeSnatKey{
		srcIP:    conn.FlowKey.SourceAddress,
		dstIP:    conn.FlowKey.DestinationAddress,
		srcPort:  conn.FlowKey.SourcePort,
		dstPort:  conn.FlowKey.DestinationPort,
		protocol: conn.FlowKey.Protocol,
	}
	c.lock.Lock()
	defer c.lock.Unlock()
	item, ok := c.connections[key]
	if !ok {
		return netip.Addr{}, 0
	}
	// Refresh the timestamp so the entry stays alive as long as the flow is being exported.
	c.connections[key] = nodeSnatItem{
		snatIP:    item.snatIP,
		snatPort:  item.snatPort,
		timestamp: time.Now(),
	}
	return item.snatIP, item.snatPort
}

// cleanup removes entries that have exceeded the TTL.
func (c *NodeSnatCorrelator) cleanup() {
	c.lock.Lock()
	defer c.lock.Unlock()

	now := time.Now()
	for key, item := range c.connections {
		if now.Sub(item.timestamp) > c.ttl {
			klog.V(5).InfoS("Removing stale node SNAT correlator entry", "key", key)
			delete(c.connections, key)
		}
	}
}
