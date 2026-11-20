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

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"

	"antrea.io/antrea/v2/pkg/agent/config"
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
	// default zone must have been dumped after the Antrea zones (see Poller.Poll). Correlate
	// must not be called concurrently: the state carried across calls assumes sequential polls.
	// It returns the default-zone connections which must be reported on their own, as they have
	// no Antrea-zone counterpart (see FromExternalCorrelator.Correlate).
	Correlate(defaultZoneConns, antreaZoneConns []*connection.Connection) []*connection.Connection
}

// FromExternalCorrelator correlates default-zone (pre-Antrea DNAT/SNAT) connections with
// Antrea-zone connections so external client IP information can be preserved on exported flows.
//
// It only keeps state across polls for Antrea-zone connections that it has already correlated:
// if the default-zone half of such a connection disappears before the Antrea-zone half (e.g., it
// expires between the Antrea-zone dump and the default-zone dump of a poll), the last default-zone
// snapshot keeps being used for that same Antrea-zone conntrack entry. As long as conntrack
// timestamps are available, the snapshot is never applied to a different conntrack entry that
// reuses the same 5-tuple, such as a later host-to-Pod connection whose source is the gateway IP
// and whose source port happens to match a past masquerade port (see antreaZoneConnIdentity).
//
// It also identifies the Antrea-zone connections initiated by the host network stack of this Node
// (e.g., by kubelet, or by a hostNetwork Pod), when the IPs of this Node are provided (see
// Correlate). This requires the default zone to be the host's conntrack table, which is only the
// case on Linux. For the same reason, the connections that the host routes to Pods running on other
// Nodes without going through OVS are only reported on Linux (see Correlate).
type FromExternalCorrelator struct {
	proxier    proxy.ProxyQuerier
	nplQuerier portcache.NPLQuerier
	// nodeIPs holds the IPs of this Node known to the agent: its Node IPs, its transport IPs and
	// its gateway IPs. As local addresses, they cannot be the original source address of a
	// connection received by this Node, so a default-zone connection whose original source
	// address is one of them was initiated by the host network stack of this Node.
	nodeIPs sets.Set[netip.Addr]
	// remotePodQuerier identifies the Pods running on other Nodes to which the host routes its
	// traffic without going through OVS. If nil, the connections towards these Pods are not
	// reported by this Node (see Correlate).
	remotePodQuerier RemotePodQuerier
	// defaultZoneOnlyConns holds the default-zone connections ingested during the current poll
	// which are reported from their default-zone entry alone (see isDefaultZoneOnly).
	defaultZoneOnlyConns []*connection.Connection
	// hairpinConns holds the masqueraded source address and port of the default-zone connections
	// ingested during the current poll whose original source is the virtual Service IP, keyed by
	// their original source port and destination (see setHairpinSNAT).
	hairpinConns map[hairpinKey]hairpinSNAT
	// connections holds the default-zone snapshots ingested during the current poll.
	connections map[correlatorKey]defaultZoneSnapshot
	// hostNetworkConns holds the keys of the default-zone connections initiated by the host
	// network of this Node ingested during the current poll (see hostNetworkKeyFromAntreaZoneConn).
	hostNetworkConns map[correlatorKey]struct{}
	// matched holds the snapshots used to correlate Antrea-zone connections during the previous
	// poll, keyed by the identity of the Antrea-zone conntrack entry they were applied to.
	matched map[antreaZoneConnIdentity]defaultZoneSnapshot
	// nextMatched is populated during the current poll, and replaces matched at the end of it.
	nextMatched map[antreaZoneConnIdentity]defaultZoneSnapshot
}

// hairpinKey identifies a connection that OVS sent back to the host after the hairpin SNAT, from its
// source port and its destination. As the hairpin SNAT usually preserves the source port, this is
// also the key of the Antrea-zone connection before correlation (see hairpinKeyFromConn).
type hairpinKey struct {
	srcPort  uint16
	dstIP    netip.Addr
	dstPort  uint16
	protocol uint8
}

// hairpinSNAT is the source address and port of a hairpin connection after the host masqueraded
// it.
type hairpinSNAT struct {
	ip   netip.Addr
	port uint16
}

var (
	// virtualServiceIPv4 and virtualServiceIPv6 are the source addresses of the connections that
	// OVS sends back to the host after the hairpin SNAT.
	virtualServiceIPv4 = netip.AddrFrom4([4]byte(config.VirtualServiceIPv4.To4()))
	virtualServiceIPv6 = netip.AddrFrom16([16]byte(config.VirtualServiceIPv6.To16()))
)

// hairpinKeyFromConn builds the hairpin key of a default-zone connection whose original source is
// the virtual Service IP, or of an Antrea-zone connection. The latter must not have been correlated
// yet: correlation restores the source port used by the client before the host applied SNAT, while
// the hairpin SNAT preserves the source port seen by OVS.
func hairpinKeyFromConn(conn *connection.Connection) hairpinKey {
	return hairpinKey{
		srcPort:  conn.FlowKey.SourcePort,
		dstIP:    conn.FlowKey.DestinationAddress,
		dstPort:  conn.FlowKey.DestinationPort,
		protocol: conn.FlowKey.Protocol,
	}
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
	// serviceUnresolved is true if the original destination was looked up at ingest time, and is
	// neither a Service known to the proxier nor a NodePortLocal port (see
	// connection.Connection.IsServiceUnresolved).
	serviceUnresolved bool
	// isFromHostNetworkTranslatedByHost is true if the connection was initiated by the host network
	// of this Node, and translated by the host (see isTranslatedByHost).
	isFromHostNetworkTranslatedByHost bool
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
// the entry's address and tuples, so it can be reused when memory is recycled). The correlator key
// is also included, as the start timestamp may not be available: without it, the identity would
// only be made of the zone and of a 32-bit ID, and a collision between unrelated connections would
// be likely, as the identity is looked up for most Antrea-zone connections in every poll.
type antreaZoneConnIdentity struct {
	key       correlatorKey
	zone      uint16
	id        uint32
	startTime int64
}

// antreaZoneConnIdentityFromConn returns the identity of the given Antrea-zone connection. key must
// be the correlator key of the connection, computed before the connection is correlated.
func antreaZoneConnIdentityFromConn(conn *connection.Connection, key correlatorKey) antreaZoneConnIdentity {
	identity := antreaZoneConnIdentity{
		key:  key,
		zone: conn.Zone,
		id:   conn.ID,
	}
	// StartTime is only zero if conntrack timestamps could not be enabled (in which case we
	// can only rely on the conntrack ID and the correlator key).
	if !conn.StartTime.IsZero() {
		identity.startTime = conn.StartTime.UnixNano()
	}
	return identity
}

// NewFromExternalCorrelator returns a FromExternalCorrelator with its internal maps initialized.
// proxier is used for GetServiceByIP when ingesting default-zone flows; if nil, every default-zone
// flow is retained without Service lookup, except the flows initiated by the host network of this
// Node which the host did not translate (see ingestDefaultZoneFlow).
// nplQuerier is used to retain default-zone flows whose original destination is a NodePortLocal
// node port (these are not registered in the proxier's Service map); it may be nil.
// nodeIPs holds the IPs of this Node, used to identify the connections initiated by the host
// network of this Node; if empty, these connections are not identified.
// remotePodQuerier identifies the Pods running on other Nodes that the host reaches without going
// through OVS; if nil, the connections towards these Pods are not reported (see Correlate).
func NewFromExternalCorrelator(proxier proxy.ProxyQuerier, nplQuerier portcache.NPLQuerier, nodeIPs sets.Set[netip.Addr], remotePodQuerier RemotePodQuerier) *FromExternalCorrelator {
	return &FromExternalCorrelator{
		proxier:          proxier,
		nplQuerier:       nplQuerier,
		nodeIPs:          nodeIPs,
		remotePodQuerier: remotePodQuerier,
		hairpinConns:     map[hairpinKey]hairpinSNAT{},
		connections:      map[correlatorKey]defaultZoneSnapshot{},
		hostNetworkConns: map[correlatorKey]struct{}{},
		matched:          map[antreaZoneConnIdentity]defaultZoneSnapshot{},
		nextMatched:      map[antreaZoneConnIdentity]defaultZoneSnapshot{},
	}
}

// Correlate implements ExternalCorrelator.
//
// A default-zone connection was initiated by the host network of this Node if its original source
// address is an IP of this Node (see isFromHostNetwork). Only the connections that the host sends
// through antrea-gw0 have an Antrea-zone entry on this Node: the connections to local Pods, to
// Services handled by AntreaProxy, and, when the traffic to the other Node is tunneled, to Pods
// running on other Nodes. The host routes the other connections to Pods running on other Nodes
// through the uplink (in noEncap mode, and in hybrid mode for Nodes in the same subnet) or through
// antrea-wg0 (with WireGuard). For the traffic sent through antrea-gw0, the host selects the
// gateway IP as the source address, unless the client is bound to another IP of this Node (e.g.,
// a hostNetwork Pod using its Node IP), in which case the connection is masqueraded with the
// gateway IP by the host (Antrea's "masquerade LOCAL traffic" rule, or kube-proxy for a Service).
//
// An Antrea-zone connection which is not correlated with a default-zone connection is marked as
// initiated by the host network of this Node (IsFromHostNetwork) if the default zone has such an
// entry for it. A connection initiated by the host is never identified from its Antrea-zone entry
// alone, as an external connection masqueraded with the gateway IP has the same source address,
// and its default-zone half may not have been retained (e.g., for a Service that AntreaProxy
// ignores), or may already be gone (e.g., after an agent restart). Such a connection is not marked
// at all.
//
// A connection correlated with a default-zone connection is also marked as initiated by the host
// network of this Node if the default-zone connection is such an entry: the connection was
// translated by the host (e.g., by kube-proxy for a Service, or by Antrea's masquerade rule). It
// is still treated as a from-external connection, which reports the original source address and,
// for a Service, the original destination. When OVS also translates the destination of such a
// connection (i.e., for a Service handled by AntreaProxy with proxyAll), the default-zone entry is
// keyed on the destination before that translation (see popMatchingTranslatedByHost).
//
// The host routes some connections to Pods running on other Nodes without going through OVS (see
// RemotePodQuerier.IsRemotePodIPRoutedByHost), and the destination Node then sees an IP of this
// Node as their source (or its gateway IP, with WireGuard). For the connections initiated by the
// host network of this Node, and for the ones from external clients translated by the host (e.g.,
// by kube-proxy for a NodePort Service), only this Node can report their source: they have no
// Antrea-zone entry, and are reported from their default-zone entry alone, as the source-Node half
// of the flow (see isDefaultZoneOnly). Correlate returns these connections. With proxyAll, the
// connections to a Service handled by AntreaProxy whose Endpoint is such a Pod do have an
// Antrea-zone entry, but OVS sends them back to the host after the Service translation, and the
// host masquerades them (see setHairpinSNAT).
func (c *FromExternalCorrelator) Correlate(defaultZoneConns, antreaZoneConns []*connection.Connection) []*connection.Connection {
	c.defaultZoneOnlyConns = nil
	for _, conn := range defaultZoneConns {
		c.ingestDefaultZoneFlow(conn)
	}
	for _, conn := range antreaZoneConns {
		if conn == nil {
			continue
		}
		// The hairpin key and the source address seen by OVS must be read before correlation.
		hairpinKey := hairpinKeyFromConn(conn)
		srcIP := conn.FlowKey.SourceAddress
		if !c.correlateIfExternal(conn) {
			c.markIfFromHostNetwork(conn)
		}
		c.setHairpinSNAT(conn, hairpinKey, srcIP)
	}
	c.finishPoll()
	return c.defaultZoneOnlyConns
}

// setHairpinSNAT sets the ProxySnat address and port of the given Antrea-zone connection if OVS sent
// it back to the host after the hairpin SNAT, and the host masqueraded it to route it to a Pod
// running on another Node without going through OVS (e.g., with proxyAll in noEncap mode, for a
// connection to a Service whose Endpoint is such a Pod): this is the tuple seen by the destination
// Node, which the FlowAggregator uses to correlate the records of both Nodes. key and srcIP are the
// hairpin key and the source address of the connection before correlation.
//
// This applies to the connections initiated by the host network of this Node, and to the ones from
// external clients (e.g., to a NodePort Service), which enter OVS through antrea-gw0, but not to the
// ones from Pods, which OVS does not send back to the host. The connection is matched with the
// hairpin connection from its source port and destination: if two hairpin connections with the
// same source port and destination exist at the same time, the hairpin SNAT translates the source
// port of the second one, which can then be matched with the first one. An exact match would
// require dumping the SNAT zone of OVS.
func (c *FromExternalCorrelator) setHairpinSNAT(conn *connection.Connection, key hairpinKey, srcIP netip.Addr) {
	if len(c.hairpinConns) == 0 || c.remotePodQuerier == nil {
		return
	}
	snat, ok := c.hairpinConns[key]
	// If the host did not change the tuple seen by OVS (e.g., when it masquerades a connection
	// whose source is already its gateway IP with WireGuard), the destination Node sees it as is.
	if !ok || (snat.ip == srcIP && snat.port == key.srcPort) {
		return
	}
	if !conn.IsFromHostNetwork && c.remotePodQuerier.IsPodSubnetIP(conn.FlowKey.SourceAddress) {
		return
	}
	if !c.remotePodQuerier.IsRemotePodIPRoutedByHost(conn.FlowKey.DestinationAddress) {
		return
	}
	conn.ProxySnatIP = snat.ip
	conn.ProxySnatPort = snat.port
}

// finishPoll discards the default-zone snapshots ingested during the poll which were not used:
// since the default zone is dumped after the Antrea zones, any such snapshot is ingested again
// during the next poll if its connection is still present, so there is no need to retain it (and
// retaining it would risk applying it to an unrelated connection later). The snapshots used during
// the poll are carried over to the next poll.
func (c *FromExternalCorrelator) finishPoll() {
	clear(c.connections)
	clear(c.hostNetworkConns)
	clear(c.hairpinConns)
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

// hostNetworkKeyFromAntreaZoneConn builds the key used to match an Antrea-zone connection with the
// default-zone connection initiated by the host network of this Node, which is keyed with
// keyFromDefaultZoneConn: the 5-tuple of the packets sent by the host to antrea-gw0, after any NAT
// applied by the host. It is the 5-tuple of the packets received by OVS, before any NAT applied by
// OVS (e.g., when AntreaProxy handles the traffic from the host to a ClusterIP), hence the use of
// the original destination of the Antrea-zone connection. It is used both to identify these
// connections (see markIfFromHostNetwork), and to correlate the ones also translated by the host
// (see popMatchingTranslatedByHost).
func hostNetworkKeyFromAntreaZoneConn(conn *connection.Connection) correlatorKey {
	return correlatorKey{
		srcIP:    conn.FlowKey.SourceAddress,
		dstIP:    conn.OriginalDestinationAddress,
		dstPort:  conn.OriginalDestinationPort,
		protocol: conn.FlowKey.Protocol,
		port:     conn.FlowKey.SourcePort,
	}
}

// isFromHostNetwork returns whether a default-zone connection whose original source address is
// srcIP was initiated by the host network stack of this Node.
func (c *FromExternalCorrelator) isFromHostNetwork(srcIP netip.Addr) bool {
	return c.nodeIPs.Has(srcIP)
}

// isTranslatedByHost returns whether the host applied SNAT or DNAT to the given default-zone
// connection, e.g., when kube-proxy translates a connection to a ClusterIP.
func isTranslatedByHost(conn *connection.Connection) bool {
	return conn.ProxySnatIP.IsValid() ||
		conn.OriginalDestinationAddress != conn.FlowKey.DestinationAddress ||
		conn.OriginalDestinationPort != conn.FlowKey.DestinationPort
}

// ingestDefaultZoneFlow stores default-zone connections that may pair with Antrea-zone connections
// during the current poll. Only connections that map to a Service (when proxier is non-nil), and
// connections initiated by the host network of this Node and translated by the host, are retained
// for correlation. All the connections initiated by the host network of this Node are also
// retained to be identified (see markIfFromHostNetwork). The connections which are reported from
// their default-zone entry alone (see isDefaultZoneOnly), and the hairpin connections (see
// setHairpinSNAT), are retained separately.
func (c *FromExternalCorrelator) ingestDefaultZoneFlow(conn *connection.Connection) {
	if conn == nil || conn.Zone != DefaultZone {
		return
	}
	if c.ingestHairpinFlow(conn) {
		return
	}
	// These are checked first, as these connections are not limited to the Service protocols.
	isFromHostNetwork := c.isFromHostNetwork(conn.FlowKey.SourceAddress)
	if isFromHostNetwork {
		c.hostNetworkConns[keyFromDefaultZoneConn(conn)] = struct{}{}
	}
	isDefaultZoneOnly := c.isDefaultZoneOnly(conn, isFromHostNetwork)
	protocol, err := lookupServiceProtocol(conn.FlowKey.Protocol)
	if err != nil {
		if isDefaultZoneOnly {
			// The connection cannot be a connection to a Service (e.g., an ICMP connection).
			c.addDefaultZoneOnly(conn, "", true)
			return
		}
		klog.V(4).InfoS("Could not retrieve Service protocol for default-zone connection, skipping", "protocol", conn.FlowKey.Protocol)
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
	// A flow resolved to a Service is always retained. Without a proxier, there is no way to tell
	// whether a default-zone flow is a connection to a Service translated by the host (e.g., by
	// kube-proxy), so every other default-zone flow is retained too, except the ones initiated by
	// the host network of this Node. These are retained if and only if the host translated them,
	// regardless of the proxier, so that the source address used by the host before SNAT (e.g., the
	// Node IP of a hostNetwork Pod masqueraded by Antrea's "masquerade LOCAL traffic" rule) and the
	// original destination (e.g., the ClusterIP of a Service that AntreaProxy ignores, or the Node
	// IP and NodePort of a Service handled by AntreaProxy with proxyAll) are reported whether
	// AntreaProxy is enabled or not, and whether it handles the Service or not (see
	// popMatchingTranslatedByHost). Correlating the ones that the host did not translate
	// would not change the 5-tuple, the original destination, or the source address of their
	// Antrea-zone half, but would only treat them as from-external connections, while
	// markIfFromHostNetwork identifies them anyway.
	retainUnresolved := c.proxier == nil
	if isFromHostNetwork {
		retainUnresolved = isTranslatedByHost(conn)
	}
	isService := serviceResolved || nplServicePortName != ""
	// With a proxier, the original destination of a flow retained without being resolved to a
	// Service is not one that the proxier knows about, so the connection store does not look it
	// up again.
	serviceUnresolved := c.proxier != nil && !isService
	if isDefaultZoneOnly {
		c.addDefaultZoneOnly(conn, nplServicePortName, serviceUnresolved)
		return
	}
	if isService || retainUnresolved {
		c.add(conn, nplServicePortName, serviceUnresolved)
	}
}

// ingestHairpinFlow returns whether the given default-zone connection is a connection that OVS sent
// back to the host after the hairpin SNAT, i.e., whose original source is the virtual Service IP.
// If the host masqueraded it, its translated source address and port are retained (see
// setHairpinSNAT). Such a connection is not otherwise ingested: it is the continuation of an
// Antrea-zone connection, rather than a connection received by this Node.
func (c *FromExternalCorrelator) ingestHairpinFlow(conn *connection.Connection) bool {
	if src := conn.FlowKey.SourceAddress; src != virtualServiceIPv4 && src != virtualServiceIPv6 {
		return false
	}
	if conn.ProxySnatIP.IsValid() {
		c.hairpinConns[hairpinKeyFromConn(conn)] = hairpinSNAT{ip: conn.ProxySnatIP, port: conn.ProxySnatPort}
	}
	return true
}

// ipsSeenReply is the IPS_SEEN_REPLY conntrack status bit.
const ipsSeenReply = 1 << 1

// isDefaultZoneOnly returns whether the given default-zone connection must be reported from its
// default-zone entry alone, as the source-Node half of a flow towards a Pod running on another Node
// which the host routes without going through OVS (see Correlate). This is the case if the
// connection was initiated by the host network of this Node (isFromHostNetwork), or if the host
// translated it for a client which is not a Pod (e.g., an external client connecting to a NodePort
// Service handled by kube-proxy). In the latter case, the source address seen by the destination
// Node is the one used by the host after SNAT, which is reported as the ProxySnat address, as for
// the connections from external clients that OVS forwards to other Nodes. The connections from
// Pods go through OVS on this Node, and are reported from their Antrea-zone entry.
//
// The connections which have not seen any reply are ignored: e.g., with WireGuard, the traffic of a
// client bound to the Node IP is not masqueraded on antrea-wg0, and is dropped by the other Node.
func (c *FromExternalCorrelator) isDefaultZoneOnly(conn *connection.Connection, isFromHostNetwork bool) bool {
	if c.remotePodQuerier == nil || conn.StatusFlag&ipsSeenReply == 0 {
		return false
	}
	if !isFromHostNetwork && (!conn.ProxySnatIP.IsValid() || c.remotePodQuerier.IsPodSubnetIP(conn.FlowKey.SourceAddress)) {
		return false
	}
	return c.remotePodQuerier.IsRemotePodIPRoutedByHost(conn.FlowKey.DestinationAddress)
}

// addDefaultZoneOnly retains the given default-zone connection to be reported on its own (see
// isDefaultZoneOnly). It is treated as a correlated from-external connection: its source is the
// original source of the connection, and its original destination may be a Service translated by
// the host. nplServicePortName and serviceUnresolved are as for add.
func (c *FromExternalCorrelator) addDefaultZoneOnly(conn *connection.Connection, nplServicePortName string, serviceUnresolved bool) {
	conn.IsFromExternal = true
	conn.IsFromHostNetwork = c.isFromHostNetwork(conn.FlowKey.SourceAddress)
	conn.IsServiceUnresolved = serviceUnresolved
	conn.DestinationServicePortName = nplServicePortName
	// The mark and labels of the default zone are unrelated to the ones of the Antrea zones,
	// which identify the connections to Services and the NetworkPolicy rules.
	conn.Mark = 0
	conn.Labels = nil
	conn.LabelsMask = nil
	c.defaultZoneOnlyConns = append(c.defaultZoneOnlyConns, conn)
}

// markIfFromHostNetwork sets IsFromHostNetwork on the given Antrea-zone connection if a
// default-zone connection initiated by the host network of this Node and matching it was ingested
// during the current poll. Unlike correlation with a from-external default-zone connection, this
// does not change the 5-tuple of the connection, so if the default-zone connection disappears
// first, the connection store keeps the classification made when it first stored the connection.
func (c *FromExternalCorrelator) markIfFromHostNetwork(conn *connection.Connection) {
	if conn == nil || conn.IsFromExternal || len(c.hostNetworkConns) == 0 {
		return
	}
	if _, ok := c.hostNetworkConns[hostNetworkKeyFromAntreaZoneConn(conn)]; ok {
		conn.IsFromHostNetwork = true
	}
}

// correlateIfExternal returns true if it correlates the connection to its default-zone counterpart
// to preserve the SNAT'd source IP. The default-zone snapshot is either one ingested during the
// current poll (see ingestDefaultZoneFlow for the flows that are retained), or, if the default-zone
// half of the connection is no longer present, the snapshot used for this same Antrea-zone
// conntrack entry during the previous poll.
func (c *FromExternalCorrelator) correlateIfExternal(conn *connection.Connection) bool {
	if conn == nil || conn.IsFromExternal {
		return false
	}
	key := keyFromAntreaZoneConn(conn)
	identity := antreaZoneConnIdentityFromConn(conn, key)
	snapshot, ok := c.popMatching(key)
	if !ok {
		snapshot, ok = c.popMatchingTranslatedByHost(conn)
	}
	if !ok {
		// The default-zone conntrack entry is gone, typically because it expired right before the
		// Antrea-zone entry, between the Antrea-zone dump and the default-zone dump of this poll.
		// Only reuse the previous snapshot for this same conntrack entry (see
		// FromExternalCorrelator).
		snapshot, ok = c.matched[identity]
		if !ok {
			return false
		}
	}
	c.nextMatched[identity] = snapshot
	correlateExternal(snapshot, conn)
	// The connection may have been initiated by the host network of this Node, and translated by
	// the host: see Correlate.
	if c.isFromHostNetwork(snapshot.sourceIP) {
		conn.IsFromHostNetwork = true
	}
	return true
}

// add stores the given default-zone connection along with the NPL Service name resolved for it (if
// any; empty for non-NPL flows), and whether its original destination was looked up and could not
// be resolved to a Service.
func (c *FromExternalCorrelator) add(conn *connection.Connection, nplServicePortName string, serviceUnresolved bool) {
	snapshot := defaultZoneSnapshotFromConn(conn)
	snapshot.nplServicePortName = nplServicePortName
	snapshot.serviceUnresolved = serviceUnresolved
	snapshot.isFromHostNetworkTranslatedByHost = c.isFromHostNetwork(conn.FlowKey.SourceAddress) && isTranslatedByHost(conn)
	c.connections[keyFromDefaultZoneConn(conn)] = snapshot
}

// popMatching removes and returns the default-zone snapshot ingested during the current poll for
// the given Antrea-zone key, if any.
func (c *FromExternalCorrelator) popMatching(key correlatorKey) (defaultZoneSnapshot, bool) {
	snapshot, exists := c.connections[key]
	if !exists {
		return defaultZoneSnapshot{}, false
	}
	delete(c.connections, key)
	return snapshot, true
}

// popMatchingTranslatedByHost removes and returns the default-zone snapshot ingested during the
// current poll for the given Antrea-zone connection, if the connection was initiated by the host
// network of this Node and translated by both the host and OVS. This happens with proxyAll, when
// the host masquerades a connection to a Service handled by AntreaProxy: e.g., a client bound to
// the Node IP which connects to a ClusterIP, or any client which connects to <NodeIP>:<NodePort>,
// whose destination the host also translates to the virtual NodePort DNAT IP. The default-zone
// entry is then keyed on the destination before the translation applied by OVS, i.e., the original
// destination of the Antrea-zone connection, rather than on the Endpoint (see
// hostNetworkKeyFromAntreaZoneConn). The other default-zone entries matching this key are not
// correlated:
//   - The entries of connections from external clients to a NodePort with proxyAll, which are not
//     initiated by the host network of this Node.
//   - The entries of connections from the host network of this Node to a Service handled by
//     AntreaProxy, that the host did not translate (e.g., from the gateway IP to a ClusterIP). As
//     for the ones to a Pod (see ingestDefaultZoneFlow), they are identified by
//     markIfFromHostNetwork instead.
func (c *FromExternalCorrelator) popMatchingTranslatedByHost(conn *connection.Connection) (defaultZoneSnapshot, bool) {
	key := hostNetworkKeyFromAntreaZoneConn(conn)
	snapshot, exists := c.connections[key]
	if !exists || !snapshot.isFromHostNetworkTranslatedByHost {
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
	antreaZone.IsServiceUnresolved = snap.serviceUnresolved
	if snap.nplServicePortName != "" {
		antreaZone.DestinationServicePortName = snap.nplServicePortName
	}
}
