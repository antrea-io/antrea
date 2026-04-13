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
	"fmt"
	"net/netip"
	"sync"
	"time"

	"k8s.io/klog/v2"

	"antrea.io/antrea/v2/pkg/agent/flowexporter/connection"
	"antrea.io/antrea/v2/pkg/agent/proxy"
)

// defaultTTL is the Threshold for expiring connections in the FromExternalCorrelator.
var defaultTTL = time.Minute

// defaultCleanUpInterval is the frequency in which we run the cleanup for expiring stale connections.
var defaultCleanUpInterval = time.Second * 5

// FromExternalCorrelator correlates zone-0 (pre-Antrea DNAT/SNAT) connections with Antrea-zone
// connections so external client IP information can be preserved on exported flows.
type FromExternalCorrelator struct {
	connections     map[correlatorKey]connectionItem
	stopCh          chan struct{}
	stopOnce        sync.Once
	lock            sync.Mutex
	ttl             time.Duration
	cleanUpInterval time.Duration
}

// correlatorKey identifies a flow by the Pod (or endpoint) IP and the masquerade reply port used
// to match zone-0 tuples to Antrea-zone tuples.
type correlatorKey struct {
	dstIP netip.Addr
	port  uint16
}

// zoneZeroSnapshot holds only the zone-0 fields needed to patch the Antrea-zone connection during
// correlation. We do not retain a *connection.Connection here to avoid pinning the large
// connection struct (and its string/slice fields) for every in-flight external flow.
type zoneZeroSnapshot struct {
	sourceAddress           netip.Addr
	sourcePort              uint16
	proxySnatIP             netip.Addr
	proxySnatPort           uint16
	originalDestinationAddr netip.Addr
	originalDestinationPort uint16
}

func zoneZeroSnapshotFromConn(conn *connection.Connection) zoneZeroSnapshot {
	return zoneZeroSnapshot{
		sourceAddress:           conn.FlowKey.SourceAddress,
		sourcePort:              conn.FlowKey.SourcePort,
		proxySnatIP:             conn.ProxySnatIP,
		proxySnatPort:           conn.ProxySnatPort,
		originalDestinationAddr: conn.OriginalDestinationAddress,
		originalDestinationPort: conn.OriginalDestinationPort,
	}
}

// connectionItem stores a compact snapshot and expiry metadata for a zone-0 flow.
type connectionItem struct {
	snapshot  zoneZeroSnapshot
	timestamp time.Time
}

// FromExternalCorrelatorOption configures a FromExternalCorrelator.
type FromExternalCorrelatorOption func(*FromExternalCorrelator)

// NewFromExternalCorrelator returns a FromExternalCorrelator with its internal map initialized and
// a goroutine initiated to remove stale connections based on defaultTTL at defaultCleanUpInterval.
func NewFromExternalCorrelator(opts ...FromExternalCorrelatorOption) *FromExternalCorrelator {
	stopCh := make(chan struct{})
	store := FromExternalCorrelator{
		connections:     map[correlatorKey]connectionItem{},
		stopCh:          stopCh,
		ttl:             defaultTTL,
		cleanUpInterval: defaultCleanUpInterval,
	}
	for _, opt := range opts {
		opt(&store)
	}
	go store.cleanUpLoop(stopCh)
	return &store
}

// StopCleanUp stops the background cleanup goroutine. It is safe to call more than once.
func (c *FromExternalCorrelator) StopCleanUp() {
	c.stopOnce.Do(func() {
		if c.stopCh != nil {
			close(c.stopCh)
		}
	})
}

func keyFromZoneZeroConn(conn *connection.Connection) correlatorKey {
	return correlatorKey{dstIP: conn.FlowKey.DestinationAddress, port: conn.ProxySnatPort}
}

func keyFromAntreaZoneConn(conn *connection.Connection) correlatorKey {
	return correlatorKey{dstIP: conn.FlowKey.DestinationAddress, port: conn.FlowKey.SourcePort}
}

// IngestZoneZero stores zone-0 connections that may later pair with Antrea-zone connections.
// Only connections that map to a Service (when antreaProxier is non-nil) are retained.
func (c *FromExternalCorrelator) IngestZoneZero(conn *connection.Connection, antreaProxier proxy.ProxyQuerier) {
	if conn == nil || conn.Zone != 0 {
		return
	}
	// Original destination may be ClusterIP, NodePort, LoadBalancer IP, or ExternalIP. The proxier's
	// ipToServiceMap registers each of these (see getServiceIPStrings in proxier.go): for NodePort
	// services it adds this Node's addresses at the NodePort number, independent of
	// externalTrafficPolicy Local vs Cluster—so Node IP + NodePort lookups succeed either way.
	// Whether conntrack shows proxy SNAT fields for correlation is handled separately (e.g. in
	// NetlinkFlowToAntreaConnection).
	svcIP := conn.OriginalDestinationAddress.String()
	svcPort := conn.OriginalDestinationPort
	protocol, err := lookupServiceProtocol(conn.FlowKey.Protocol)
	if err != nil {
		klog.InfoS("Could not retrieve Service protocol", "error", err, "conn", conn)
		return
	}
	shouldStore := true
	if antreaProxier != nil {
		serviceStr := fmt.Sprintf("%s:%d/%s", svcIP, svcPort, protocol)
		_, shouldStore = antreaProxier.GetServiceByIP(serviceStr)
	}
	if shouldStore {
		c.add(conn)
	}
}

// CorrelateIfExternal returns true if it correlates the connection to its zone-zero counterpart to preserve the SNAT'd source IP.
func (c *FromExternalCorrelator) CorrelateIfExternal(conn *connection.Connection) bool {
	if conn == nil {
		return false
	}
	zoneZero, ok := c.popMatching(conn)
	if !ok {
		return false
	}
	correlateExternal(zoneZero, conn)
	return true
}

// cleanUpLoop runs in an infinite loop and cleans up the store at the given interval.
func (c *FromExternalCorrelator) cleanUpLoop(stopCh <-chan struct{}) {
	ticker := time.NewTicker(c.cleanUpInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			c.cleanup(c.ttl)
		}
	}
}

// cleanup loops through the entire store and deleting connections that exceed the ttl.
func (c *FromExternalCorrelator) cleanup(ttl time.Duration) {
	c.lock.Lock()
	defer c.lock.Unlock()

	now := time.Now()
	for key, record := range c.connections {
		if now.Sub(record.timestamp) > ttl {
			delete(c.connections, key)
		}
	}
}

// add stores the given zone-zero connection.
func (c *FromExternalCorrelator) add(conn *connection.Connection) {
	key := keyFromZoneZeroConn(conn)
	c.lock.Lock()
	defer c.lock.Unlock()

	c.connections[key] = connectionItem{
		snapshot:  zoneZeroSnapshotFromConn(conn),
		timestamp: time.Now(),
	}
}

// popMatching removes and returns the zone-zero snapshot that pairs with this Antrea-zone
// connection, if any.
func (c *FromExternalCorrelator) popMatching(conn *connection.Connection) (zoneZeroSnapshot, bool) {
	key := keyFromAntreaZoneConn(conn)
	c.lock.Lock()
	defer c.lock.Unlock()

	record, exists := c.connections[key]
	if !exists {
		return zoneZeroSnapshot{}, false
	}
	delete(c.connections, key)
	return record.snapshot, true
}

// remove deletes the zone-zero entry left in the map when the Antrea-zone flow expires
// before correlation.
func (c *FromExternalCorrelator) remove(conn *connection.Connection) {
	key := keyFromAntreaZoneConn(conn)
	c.lock.Lock()
	defer c.lock.Unlock()

	delete(c.connections, key)
}

// correlateExternal copies correlation fields from the zone-0 snapshot onto the Antrea-zone connection.
func correlateExternal(zoneZero zoneZeroSnapshot, antreaZone *connection.Connection) {
	antreaZone.FlowKey.SourcePort = zoneZero.sourcePort
	antreaZone.FlowKey.SourceAddress = zoneZero.sourceAddress
	antreaZone.ProxySnatIP = zoneZero.proxySnatIP
	antreaZone.ProxySnatPort = zoneZero.proxySnatPort
	antreaZone.OriginalDestinationAddress = zoneZero.originalDestinationAddr
	antreaZone.OriginalDestinationPort = zoneZero.originalDestinationPort
}
