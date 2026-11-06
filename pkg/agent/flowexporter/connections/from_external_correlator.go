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

	"k8s.io/klog/v2"

	"antrea.io/antrea/v2/pkg/agent/flowexporter/connection"
	"antrea.io/antrea/v2/pkg/agent/nodeportlocal/portcache"
	"antrea.io/antrea/v2/pkg/agent/proxy"
)

const (
	// DefaultZone is the conntrack zone used for pre-NAT (default/zone-0) flows.
	DefaultZone = 0
)

// ExternalCorrelator correlates default-zone conntrack with Antrea-zone flows for
// external-to-pod export. Correlation is performed in the poller before fan-out to connection
// store subscribers, so all destinations see the same already-correlated connection state.
type ExternalCorrelator interface {
	// Correlate is called once per poll, with the default-zone and Antrea-zone connections
	// dumped during that poll. It updates the matching Antrea-zone connections in place. The
	// default zone must have been dumped after the Antrea zones, so that the default-zone half
	// of every Antrea-zone connection is included in defaultZoneConns, even for a connection
	// created while the poll was in progress (the default-zone conntrack entry is always
	// committed before its Antrea-zone counterpart).
	Correlate(defaultZoneConns, antreaZoneConns []*connection.Connection)
}

// FromExternalCorrelator correlates default-zone (pre-Antrea DNAT/SNAT) connections with
// Antrea-zone connections so external client IP information can be preserved on exported flows.
//
// It only keeps state across polls for Antrea-zone connections that it has already correlated:
// if the default-zone half of such a connection disappears before the Antrea-zone half (e.g., it
// expires between the Antrea-zone dump and the default-zone dump of a poll), the last default-zone
// snapshot keeps being used for that same Antrea-zone conntrack entry. The snapshot is never
// applied to a different conntrack entry that reuses the same 5-tuple, such as a later host-to-Pod
// connection whose source is the gateway IP and whose source port happens to match a past
// masquerade port.
type FromExternalCorrelator struct {
	proxier    proxy.ProxyQuerier
	nplQuerier portcache.NPLQuerier
	lock       sync.Mutex
	// connections holds the default-zone snapshots ingested during the current poll.
	connections map[correlatorKey]defaultZoneSnapshot
	// matched holds the snapshots used to correlate Antrea-zone connections during the previous
	// poll, along with the identity of the Antrea-zone conntrack entry they were applied to.
	matched map[correlatorKey]matchedSnapshot
	// nextMatched is populated during the current poll, and replaces matched at the end of it.
	nextMatched map[correlatorKey]matchedSnapshot
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
	// nplServicePortName is the namespaced Service name resolved for NodePortLocal flows at ingest
	// time (empty for non-NPL flows). It is carried here so the connection store does not need to
	// repeat the NPL node-port lookup when the Antrea-zone half is correlated. This is the only
	// string retained for NPL flows, so it does not meaningfully affect the compact-snapshot goal
	// described above.
	nplServicePortName string
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

// antreaZoneConnIdentity identifies a single Antrea-zone conntrack entry. Unlike the 5-tuple,
// which can be reused by a later, unrelated connection, the combination of the conntrack ID and
// the conntrack start timestamp is specific to one entry (the conntrack ID alone is derived from
// the entry's address and tuples, so it can be reused when memory is recycled).
type antreaZoneConnIdentity struct {
	zone      uint16
	id        uint32
	startTime int64
}

func antreaZoneConnIdentityFromConn(conn *connection.Connection) antreaZoneConnIdentity {
	identity := antreaZoneConnIdentity{
		zone: conn.Zone,
		id:   conn.ID,
	}
	// StartTime is only zero if conntrack timestamps could not be enabled (in which case we
	// can only rely on the conntrack ID).
	if !conn.StartTime.IsZero() {
		identity.startTime = conn.StartTime.UnixNano()
	}
	return identity
}

// matchedSnapshot is a default-zone snapshot that was used to correlate an Antrea-zone conntrack
// entry.
type matchedSnapshot struct {
	snapshot defaultZoneSnapshot
	identity antreaZoneConnIdentity
}

// NewFromExternalCorrelator returns a FromExternalCorrelator with its internal maps initialized.
// proxier is used for GetServiceByIP when ingesting default-zone flows; if nil, every default-zone
// flow is retained without Service lookup.
// nplQuerier is used to retain default-zone flows whose original destination is a NodePortLocal
// node port (these are not registered in the proxier's Service map); it may be nil.
func NewFromExternalCorrelator(proxier proxy.ProxyQuerier, nplQuerier portcache.NPLQuerier) *FromExternalCorrelator {
	return &FromExternalCorrelator{
		proxier:     proxier,
		nplQuerier:  nplQuerier,
		connections: map[correlatorKey]defaultZoneSnapshot{},
		matched:     map[correlatorKey]matchedSnapshot{},
		nextMatched: map[correlatorKey]matchedSnapshot{},
	}
}

// Correlate implements ExternalCorrelator.
func (c *FromExternalCorrelator) Correlate(defaultZoneConns, antreaZoneConns []*connection.Connection) {
	c.lock.Lock()
	defer c.lock.Unlock()
	for _, conn := range defaultZoneConns {
		c.ingestDefaultZoneFlow(conn)
	}
	for _, conn := range antreaZoneConns {
		c.correlateIfExternal(conn)
	}
	c.finishPoll()
}

// finishPoll discards the default-zone snapshots ingested during the poll which were not used:
// since the default zone is dumped after the Antrea zones, any such snapshot is ingested again
// during the next poll if its connection is still present, so there is no need to retain it (and
// retaining it would risk applying it to an unrelated connection later). The snapshots used during
// the poll are carried over to the next poll.
func (c *FromExternalCorrelator) finishPoll() {
	clear(c.connections)
	c.matched, c.nextMatched = c.nextMatched, c.matched
	clear(c.nextMatched)
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

// ingestDefaultZoneFlow stores default-zone connections that may pair with Antrea-zone connections
// during the current poll. Only connections that map to a Service (when proxier is non-nil) are
// retained. c.lock must be held by the caller.
func (c *FromExternalCorrelator) ingestDefaultZoneFlow(conn *connection.Connection) {
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
	// serviceResolved indicates the destination matched a Service registered in the proxier's map
	// (ClusterIP:port, nodeIP:NodePort, LB/External IP:port, etc). With no proxier, this stays
	// false and every default-zone flow is retained below regardless.
	serviceResolved := false
	if c.proxier != nil {
		serviceStr := fmt.Sprintf("%s:%d/%s", svcIP, svcPort, protocol)
		_, serviceResolved = c.proxier.GetServiceByIP(serviceStr)
	}
	// NodePortLocal node ports are allocated per-Pod by the NPL agent and are not registered in the
	// proxier's Service map, so they are not matched above. This lookup runs whenever the proxier
	// didn't already resolve a Service, independent of whether a proxier is configured.
	// GetServiceForNPLPort also validates svcIP against this Node's own IP, since the NPL port table
	// is keyed by port number alone and would otherwise match unrelated traffic that happens to target
	// the same port number on a different destination.
	// nplServicePortName, if resolved, is carried in the snapshot, so that the connection store does
	// not need to repeat the lookup when the Antrea-zone half is correlated.
	// This means the name reflects the NPL port's owning Service as of the default-zone half, and
	// could be stale if the port's owning Service changes before the Antrea-zone half is
	// correlated; this window is negligible in practice.
	var nplServicePortName string
	if !serviceResolved && c.nplQuerier != nil {
		nplServicePortName = c.nplQuerier.GetServiceForNPLPort(svcIP, int(svcPort), string(protocol), conn.OriginalDestinationAddress.Is6())
	}
	shouldStore := c.proxier == nil || serviceResolved || nplServicePortName != ""
	if shouldStore {
		c.add(conn, nplServicePortName)
	}
}

// correlateIfExternal returns true if it correlates the connection to its default-zone counterpart
// to preserve the SNAT'd source IP. The default-zone snapshot is either one ingested during the
// current poll (which only keeps Service flows), or, if the default-zone half of the connection is
// no longer present, the snapshot used for this same Antrea-zone conntrack entry during the
// previous poll. c.lock must be held by the caller.
func (c *FromExternalCorrelator) correlateIfExternal(conn *connection.Connection) bool {
	if conn == nil || conn.IsFromExternal {
		return false
	}
	key := keyFromAntreaZoneConn(conn)
	identity := antreaZoneConnIdentityFromConn(conn)
	snapshot, ok := c.popMatching(key)
	if !ok {
		// The default-zone conntrack entry is gone, typically because it expired right before the
		// Antrea-zone entry, between the Antrea-zone dump and the default-zone dump of this poll.
		// Only reuse the previous snapshot if it was applied to this very conntrack entry: the
		// 5-tuple may now belong to an unrelated connection (e.g., a host-to-Pod connection using
		// the gateway IP as the source and a source port that matches a past masquerade port).
		m, found := c.matched[key]
		if !found || m.identity != identity {
			return false
		}
		snapshot = m.snapshot
	}
	c.nextMatched[key] = matchedSnapshot{snapshot: snapshot, identity: identity}
	correlateExternal(snapshot, conn)
	return true
}

// add stores the given default-zone connection along with the NPL Service name resolved for it (if
// any; empty for non-NPL flows). c.lock must be held by the caller.
func (c *FromExternalCorrelator) add(conn *connection.Connection, nplServicePortName string) {
	snapshot := defaultZoneSnapshotFromConn(conn)
	snapshot.nplServicePortName = nplServicePortName
	c.connections[keyFromDefaultZoneConn(conn)] = snapshot
}

// popMatching removes and returns the default-zone snapshot ingested during the current poll for
// the given Antrea-zone key, if any. c.lock must be held by the caller.
func (c *FromExternalCorrelator) popMatching(key correlatorKey) (defaultZoneSnapshot, bool) {
	snapshot, exists := c.connections[key]
	if !exists {
		return defaultZoneSnapshot{}, false
	}
	delete(c.connections, key)
	return snapshot, true
}

// correlateExternal copies correlation fields from the default-zone snapshot onto the Antrea-zone
// connection and marks it as from-external. IsFromExternal is set to true unconditionally so that
// ETP=Local flows (where ProxySnatIP is zero) are still correctly identified as from-external
// connections downstream. For NodePortLocal flows the Service name was resolved at ingest time and
// is carried here so the connection store can export destination_service_ip/port without repeating
// the NPL node-port lookup.
func correlateExternal(snap defaultZoneSnapshot, antreaZone *connection.Connection) {
	antreaZone.FlowKey.SourcePort = snap.sourcePort
	antreaZone.FlowKey.SourceAddress = snap.sourceIP
	antreaZone.ProxySnatIP = snap.proxySnatIP
	antreaZone.ProxySnatPort = snap.proxySnatPort
	antreaZone.OriginalDestinationAddress = snap.originalDestinationIP
	antreaZone.OriginalDestinationPort = snap.originalDestinationPort
	antreaZone.IsFromExternal = true
	if snap.nplServicePortName != "" {
		antreaZone.DestinationServicePortName = snap.nplServicePortName
	}
}
