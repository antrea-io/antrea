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
	"antrea.io/antrea/v2/pkg/agent/nodeportlocal/portcache"
	"antrea.io/antrea/v2/pkg/agent/proxy"
)

const (
	// DefaultZone is the conntrack zone used for pre-NAT (default/zone-0) flows.
	DefaultZone = 0
	// defaultTTL is the threshold for expiring connections in the FromExternalCorrelator.
	defaultTTL = time.Minute
	// defaultCleanUpInterval is how often the background cleanup runs.
	defaultCleanUpInterval = 5 * time.Second
)

// ExternalCorrelator correlates default-zone conntrack with Antrea-zone flows for
// external-to-pod export. Correlation is performed in the poller before fan-out to connection
// store subscribers, so all destinations see the same already-correlated connection state.
type ExternalCorrelator interface {
	IngestDefaultZoneFlow(conn *connection.Connection)
	CorrelateIfExternal(conn *connection.Connection) bool
}

// FromExternalCorrelator correlates default-zone (pre-Antrea DNAT/SNAT) connections with
// Antrea-zone connections so external client IP information can be preserved on exported flows.
type FromExternalCorrelator struct {
	proxier         proxy.ProxyQuerier
	nplQuerier      portcache.NPLQuerier
	connections     map[correlatorKey]connectionItem
	lock            sync.Mutex
	ttl             time.Duration
	cleanUpInterval time.Duration
}

// correlatorKey is the five-tuple used to match a default-zone (pre-NAT) conntrack entry to its
// Antrea-zone counterpart.
//
// SNAT case (standard NodePort):
//   - Zone-0 tuple:      src=<externalClientIP>:<clientPort>  dst=<podIP>:<podPort>  proto=P
//     ProxySnatIP/Port are set to the masquerade (gateway) IP and ephemeral port.
//   - Antrea-zone tuple: src=<gatewayIP>:<snatPort>           dst=<podIP>:<podPort>  proto=P
//     After masquerade, TupleOrig.src becomes the gateway IP, so FlowKey.SourceAddress ==
//     ProxySnatIP and FlowKey.SourcePort == ProxySnatPort.
//   - Key: srcIP=gatewayIP, port=snatPort, dstIP, dstPort, protocol — identical on both sides.
//
// Non-SNAT case (externalTrafficPolicy=Local):
//   - Zone-0 tuple:      src=<externalClientIP>:<clientPort>  dst=<podIP>:<podPort>  proto=P
//     ProxySnatIP/Port are both zero because no masquerade is applied.
//   - Antrea-zone tuple: src=<externalClientIP>:<clientPort>  dst=<podIP>:<podPort>  proto=P
//     DNAT only rewrites the destination; TupleOrig.src is the external client IP in both zones.
//   - Key: srcIP=externalClientIP, port=clientPort, dstIP, dstPort, protocol — identical on both
//     sides.
//
// In both cases srcIP and port are populated with the same conditional:
//   - keyFromDefaultZoneConn: srcIP=ProxySnatIP, port=ProxySnatPort when SNAT is present;
//     srcIP=FlowKey.SourceAddress, port=FlowKey.SourcePort otherwise.
//   - keyFromAntreaZoneConn: srcIP=ProxySnatIP, port=FlowKey.SourcePort when SNAT is present;
//     srcIP=FlowKey.SourceAddress, port=FlowKey.SourcePort otherwise.
//     (ProxySnatPort == FlowKey.SourcePort for SNAT connections so using FlowKey.SourcePort is
//     equivalent and avoids a separate field lookup.)
type correlatorKey struct {
	srcIP    netip.Addr
	dstIP    netip.Addr
	dstPort  uint16
	protocol uint8
	port     uint16
}

// defaultZoneSnapshot holds only the default-zone fields needed to patch the Antrea-zone
// connection during correlation. We do not retain a *connection.Connection here to avoid
// pinning the large connection struct (and its string/slice fields) for every in-flight
// external flow.
type defaultZoneSnapshot struct {
	sourceIP                netip.Addr
	sourcePort              uint16
	proxySnatIP             netip.Addr
	proxySnatPort           uint16
	originalDestinationIP   netip.Addr
	originalDestinationPort uint16
}

func defaultZoneSnapshotFromConn(conn *connection.Connection) defaultZoneSnapshot {
	return defaultZoneSnapshot{
		sourceIP:                conn.FlowKey.SourceAddress,
		sourcePort:              conn.FlowKey.SourcePort,
		proxySnatIP:             conn.ProxySnatIP,
		proxySnatPort:           conn.ProxySnatPort,
		originalDestinationIP:   conn.OriginalDestinationAddress,
		originalDestinationPort: conn.OriginalDestinationPort,
	}
}

// connectionItem stores a compact snapshot and expiry metadata for a default-zone flow.
type connectionItem struct {
	snapshot  defaultZoneSnapshot
	timestamp time.Time
}

// NewFromExternalCorrelator returns a FromExternalCorrelator with its internal map initialized.
// proxier is used for GetServiceByIP during IngestDefaultZoneFlow; if nil, every default-zone flow is
// retained without Service lookup.
// nplQuerier is used to retain default-zone flows whose original destination is a NodePortLocal
// node port (these are not registered in the proxier's Service map); it may be nil.
// Note: The caller should run the cleanup loop with go correlator.Run(stopCh) and close stopCh to stop.
func NewFromExternalCorrelator(proxier proxy.ProxyQuerier, nplQuerier portcache.NPLQuerier) *FromExternalCorrelator {
	return &FromExternalCorrelator{
		proxier:         proxier,
		nplQuerier:      nplQuerier,
		connections:     map[correlatorKey]connectionItem{},
		ttl:             defaultTTL,
		cleanUpInterval: defaultCleanUpInterval,
	}
}

// Run runs the TTL cleanup loop until stopCh is closed.
func (c *FromExternalCorrelator) Run(stopCh <-chan struct{}) {
	c.cleanUpLoop(stopCh)
}

// keyFromDefaultZoneConn builds the correlator key for a default-zone connection.
// For SNAT flows ProxySnatIP/Port hold the gateway IP and port after SNAT; for non-SNAT flows
// they are zero and FlowKey.SourceAddress/SourcePort (the real external client IP/port) are used.
func keyFromDefaultZoneConn(conn *connection.Connection) correlatorKey {
	srcIP := conn.ProxySnatIP
	port := conn.ProxySnatPort
	if port == 0 {
		srcIP = conn.FlowKey.SourceAddress
		port = conn.FlowKey.SourcePort
	}
	return correlatorKey{
		srcIP:    srcIP,
		dstIP:    conn.FlowKey.DestinationAddress,
		dstPort:  conn.FlowKey.DestinationPort,
		protocol: conn.FlowKey.Protocol,
		port:     port,
	}
}

// keyFromAntreaZoneConn builds the correlator key for an Antrea-zone connection.
// For SNAT flows ProxySnatIP is the gateway IP (the masquerade source that also appears in the
// zone-0 key); for non-SNAT flows ProxySnatIP is zero and FlowKey.SourceAddress is the real
// external client IP, matching what keyFromDefaultZoneConn stored for the zone-0 entry.
func keyFromAntreaZoneConn(conn *connection.Connection) correlatorKey {
	srcIP := conn.ProxySnatIP
	if !srcIP.IsValid() {
		srcIP = conn.FlowKey.SourceAddress
	}
	return correlatorKey{
		srcIP:    srcIP,
		dstIP:    conn.FlowKey.DestinationAddress,
		dstPort:  conn.FlowKey.DestinationPort,
		protocol: conn.FlowKey.Protocol,
		port:     conn.FlowKey.SourcePort,
	}
}

// IngestDefaultZoneFlow stores default-zone connections that may later pair with Antrea-zone connections.
// Only connections that map to a Service (when proxier is non-nil) are retained.
func (c *FromExternalCorrelator) IngestDefaultZoneFlow(conn *connection.Connection) {
	if conn == nil || conn.Zone != DefaultZone {
		return
	}
	// Original destination may be ClusterIP, NodePort, LoadBalancer IP, or ExternalIP.
	// GetServiceByIP looks up the proxier's ipToServiceMap built from watched Kubernetes Service
	// objects: it registers ClusterIP:servicePort, nodeIP:NodePort, LB/External IPs, etc.
	// NodePort traffic (including externalTrafficPolicy=Local, which are handled by
	// kube-proxy/iptables on the node) can still resolve here if the default-zone tuple's
	// OriginalDestinationAddress/OriginalDestinationPort matches a map key (e.g.
	// node IP + NodePort, or ClusterIP + service port).
	svcIP := conn.OriginalDestinationAddress.String()
	svcPort := conn.OriginalDestinationPort
	protocol, err := lookupServiceProtocol(conn.FlowKey.Protocol)
	if err != nil {
		klog.V(4).InfoS("Could not retrieve Service protocol for default-zone connection, skipping", "protocol", conn.FlowKey.Protocol)
		return
	}
	// With no proxier, retain every default-zone flow (no Service lookup).
	// With proxier, only retain when GetServiceByIP matches.
	shouldStore := true
	if c.proxier != nil {
		serviceStr := fmt.Sprintf("%s:%d/%s", svcIP, svcPort, protocol)
		_, shouldStore = c.proxier.GetServiceByIP(serviceStr)
		// NodePortLocal node ports are allocated per-Pod by the NPL agent and are not registered
		// in the proxier's Service map, so they are not matched above. Retain the default-zone
		// flow when its original destination is an NPL node port, so the Antrea-zone half can be
		// correlated and its OriginalDestination restored to the node IP/port the client targeted.
		if !shouldStore && c.nplQuerier != nil {
			shouldStore = c.nplQuerier.GetServiceForNPLPort(int(svcPort), string(protocol), conn.OriginalDestinationAddress.Is6()) != ""
		}
	}
	if shouldStore {
		c.add(conn)
	}
}

// CorrelateIfExternal returns true if it correlates the connection to its default-zone counterpart
// to preserve the SNAT'd source IP. The correlator map only ever contains entries that were
// stored by IngestDefaultZoneFlow (which itself only keeps Service flows).
func (c *FromExternalCorrelator) CorrelateIfExternal(conn *connection.Connection) bool {
	if conn == nil || conn.IsFromExternal {
		return false
	}
	snapshot, ok := c.popMatching(conn)
	if !ok {
		return false
	}
	correlateExternal(snapshot, conn)
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

// add stores the given default-zone connection.
func (c *FromExternalCorrelator) add(conn *connection.Connection) {
	key := keyFromDefaultZoneConn(conn)
	c.lock.Lock()
	defer c.lock.Unlock()

	c.connections[key] = connectionItem{
		snapshot:  defaultZoneSnapshotFromConn(conn),
		timestamp: time.Now(),
	}
}

// popMatching removes and returns the default-zone snapshot that pairs with this Antrea-zone
// connection, if any.
func (c *FromExternalCorrelator) popMatching(conn *connection.Connection) (defaultZoneSnapshot, bool) {
	key := keyFromAntreaZoneConn(conn)
	c.lock.Lock()
	defer c.lock.Unlock()

	record, exists := c.connections[key]
	if !exists {
		return defaultZoneSnapshot{}, false
	}
	delete(c.connections, key)
	return record.snapshot, true
}

// correlateExternal copies correlation fields from the default-zone snapshot onto the Antrea-zone
// connection and marks it as from-external. IsFromExternal is set to true unconditionally so that
// ETP=Local flows (where ProxySnatIP is zero) are still correctly identified as from-external
// connections downstream.
func correlateExternal(snap defaultZoneSnapshot, antreaZone *connection.Connection) {
	antreaZone.FlowKey.SourcePort = snap.sourcePort
	antreaZone.FlowKey.SourceAddress = snap.sourceIP
	antreaZone.ProxySnatIP = snap.proxySnatIP
	antreaZone.ProxySnatPort = snap.proxySnatPort
	antreaZone.OriginalDestinationAddress = snap.originalDestinationIP
	antreaZone.OriginalDestinationPort = snap.originalDestinationPort
	antreaZone.IsFromExternal = true
}
