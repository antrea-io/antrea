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

package connections

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"

	"antrea.io/antrea/v2/pkg/agent/flowexporter/connection"
	"antrea.io/antrea/v2/pkg/agent/openflow"
	"antrea.io/antrea/v2/pkg/agent/proxy"
	proxytest "antrea.io/antrea/v2/pkg/agent/proxy/testing"
	objectstoretest "antrea.io/antrea/v2/pkg/util/objectstore/testing"
	k8sproxy "antrea.io/antrea/v2/third_party/proxy"
)

// fakeRemotePodQuerier mimics the RemotePodQuerier of the FlowExporter for a fixed set of Pod
// subnets of other Nodes, to which the traffic is tunneled: an IP is the IP of a Pod running on
// another Node if it belongs to one of them, and is not the gateway IP of that Node.
type fakeRemotePodQuerier struct {
	remotePodSubnets []netip.Prefix
}

func (q *fakeRemotePodQuerier) IsRemotePodIP(ip netip.Addr) bool {
	for _, prefix := range q.remotePodSubnets {
		if prefix.Contains(ip) {
			return ip != prefix.Masked().Addr().Next()
		}
	}
	return false
}

var (
	// This Node's Pod subnets and gateway IPs.
	hostTestLocalGwIPv4  = netip.MustParseAddr("10.244.1.1")
	hostTestLocalGwIPv6  = netip.MustParseAddr("fd00:10:244:1::1")
	hostTestLocalPodIPv4 = netip.MustParseAddr("10.244.1.6")
	hostTestLocalPodIPv6 = netip.MustParseAddr("fd00:10:244:1::6")
	// This Node's other IPs.
	hostTestLocalNodeIPv4      = netip.MustParseAddr("172.18.0.2")
	hostTestLocalNodeIPv6      = netip.MustParseAddr("fd91:8054:ef1f::2")
	hostTestLocalTransportIPv4 = netip.MustParseAddr("192.168.77.2")
	// Another Node's Pod subnets and gateway IPs.
	hostTestRemotePodCIDRv4 = netip.MustParsePrefix("10.244.2.0/24")
	hostTestRemotePodCIDRv6 = netip.MustParsePrefix("fd00:10:244:2::/64")
	hostTestRemoteGwIPv4    = netip.MustParseAddr("10.244.2.1")
	hostTestRemotePodIPv4   = netip.MustParseAddr("10.244.2.6")
	hostTestRemotePodIPv6   = netip.MustParseAddr("fd00:10:244:2::6")
	// Neither a Pod IP nor a gateway IP. hostTestNodeIPv4 is the Node IP of another Node.
	hostTestNodeIPv4     = netip.MustParseAddr("172.18.0.3")
	hostTestExternalIPv4 = netip.MustParseAddr("8.8.8.8")

	// hostTestNodeIPs holds the IPs of this Node.
	hostTestNodeIPs = sets.New(hostTestLocalGwIPv4, hostTestLocalGwIPv6, hostTestLocalNodeIPv4, hostTestLocalNodeIPv6, hostTestLocalTransportIPv4)
)

func newTestRemotePodQuerier() *fakeRemotePodQuerier {
	return &fakeRemotePodQuerier{remotePodSubnets: []netip.Prefix{hostTestRemotePodCIDRv4, hostTestRemotePodCIDRv6}}
}

// TestFromExternalCorrelator_isFromHostNetwork validates the identification of the default-zone
// connections initiated by the host network of this Node from their original source address.
func TestFromExternalCorrelator_isFromHostNetwork(t *testing.T) {
	c := NewFromExternalCorrelator(nil, nil, hostTestNodeIPs)
	tests := []struct {
		ip       netip.Addr
		expected bool
	}{
		{ip: hostTestLocalGwIPv4, expected: true},
		{ip: hostTestLocalGwIPv6, expected: true},
		// For example, a hostNetwork Pod bound to its Node IP.
		{ip: hostTestLocalNodeIPv4, expected: true},
		{ip: hostTestLocalNodeIPv6, expected: true},
		{ip: hostTestLocalTransportIPv4, expected: true},
		// The Node IP of another Node.
		{ip: hostTestNodeIPv4, expected: false},
		{ip: hostTestRemoteGwIPv4, expected: false},
		{ip: hostTestLocalPodIPv4, expected: false},
		{ip: hostTestExternalIPv4, expected: false},
	}
	for _, tc := range tests {
		t.Run(tc.ip.String(), func(t *testing.T) {
			assert.Equal(t, tc.expected, c.isFromHostNetwork(tc.ip))
		})
	}

	// Without the IPs of this Node (e.g., on Windows), no connection is identified.
	c = NewFromExternalCorrelator(nil, nil, nil)
	assert.False(t, c.isFromHostNetwork(hostTestLocalGwIPv4))
}

// TestConntrackConnectionStore_HostNetworkConnections validates which connections initiated by the
// host network of this Node are added to the connection store. These connections are identified
// by the FromExternalCorrelator, which sets IsFromHostNetwork before they reach the store.
func TestConntrackConnectionStore_HostNetworkConnections(t *testing.T) {
	localPod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "local-pod",
			Namespace: "ns1",
			UID:       "local-pod-uid",
		},
	}
	refTime := time.Now()
	hostConn := func(src, dst netip.Addr) connection.Connection {
		return connection.Connection{FlowKey: connection.Tuple{SourceAddress: src, DestinationAddress: dst}, IsFromHostNetwork: true}
	}

	tests := []struct {
		name        string
		withQuerier bool
		// noRemotePodIPs makes the querier identify no remote Pod IP, as when the traffic to
		// the other Nodes is not tunneled.
		noRemotePodIPs    bool
		conn              connection.Connection
		localPodIP        netip.Addr
		expectAdded       bool
		expectFromHostNet bool
	}{
		{
			name:              "local gateway to local Pod",
			withQuerier:       true,
			conn:              hostConn(hostTestLocalGwIPv4, hostTestLocalPodIPv4),
			localPodIP:        hostTestLocalPodIPv4,
			expectAdded:       true,
			expectFromHostNet: true,
		},
		{
			name:              "IPv6 local gateway to local Pod",
			withQuerier:       true,
			conn:              hostConn(hostTestLocalGwIPv6, hostTestLocalPodIPv6),
			localPodIP:        hostTestLocalPodIPv6,
			expectAdded:       true,
			expectFromHostNet: true,
		},
		{
			name:              "local gateway to remote Pod",
			withQuerier:       true,
			conn:              hostConn(hostTestLocalGwIPv4, hostTestRemotePodIPv4),
			expectAdded:       true,
			expectFromHostNet: true,
		},
		{
			name:              "IPv6 local gateway to remote Pod",
			withQuerier:       true,
			conn:              hostConn(hostTestLocalGwIPv6, hostTestRemotePodIPv6),
			expectAdded:       true,
			expectFromHostNet: true,
		},
		{
			// For example, a Service whose Endpoint is a hostNetwork Pod on another Node.
			name:        "local gateway to remote Node IP",
			withQuerier: true,
			conn:        hostConn(hostTestLocalGwIPv4, hostTestNodeIPv4),
			expectAdded: false,
		},
		{
			// The gateway IP of another Node belongs to its Pod subnet, but it is not a Pod.
			name:        "local gateway to remote gateway",
			withQuerier: true,
			conn:        hostConn(hostTestLocalGwIPv4, hostTestRemoteGwIPv4),
			expectAdded: false,
		},
		{
			// For example, in noEncap mode, a connection to a Service handled by AntreaProxy,
			// which the destination Node reports on its own.
			name:           "local gateway to untunneled remote Pod",
			withQuerier:    true,
			noRemotePodIPs: true,
			conn:           hostConn(hostTestLocalGwIPv4, hostTestRemotePodIPv4),
			expectAdded:    false,
		},
		{
			// A connection correlated with its default-zone entry is kept regardless, but it
			// is not exported (see Destination.findHostNetworkFlowType).
			name:           "local Node IP to untunneled remote Pod correlated as from-external",
			withQuerier:    true,
			noRemotePodIPs: true,
			conn: connection.Connection{
				FlowKey:           connection.Tuple{SourceAddress: hostTestLocalNodeIPv4, DestinationAddress: hostTestRemotePodIPv4},
				IsFromExternal:    true,
				IsFromHostNetwork: true,
			},
			expectAdded:       true,
			expectFromHostNet: true,
		},
		{
			// The Pod may have been deleted before the connection was first polled.
			name:        "local gateway to unknown local Pod IP",
			withQuerier: true,
			conn:        hostConn(hostTestLocalGwIPv4, hostTestLocalPodIPv4),
			expectAdded: false,
		},
		{
			// For example, a connection from an external client masqueraded with the gateway
			// IP, which the FromExternalCorrelator could not correlate: it is not identified
			// as a connection from the host network, as it has no default-zone entry whose
			// source is the gateway IP.
			name:        "local gateway to remote Pod not initiated by the host",
			withQuerier: true,
			conn:        connection.Connection{FlowKey: connection.Tuple{SourceAddress: hostTestLocalGwIPv4, DestinationAddress: hostTestRemotePodIPv4}},
			expectAdded: false,
		},
		{
			name:              "local gateway to local Pod not initiated by the host",
			withQuerier:       true,
			conn:              connection.Connection{FlowKey: connection.Tuple{SourceAddress: hostTestLocalGwIPv4, DestinationAddress: hostTestLocalPodIPv4}},
			localPodIP:        hostTestLocalPodIPv4,
			expectAdded:       true,
			expectFromHostNet: false,
		},
		{
			name:        "local gateway to remote Pod without RemotePodQuerier",
			withQuerier: false,
			conn:        hostConn(hostTestLocalGwIPv4, hostTestRemotePodIPv4),
			expectAdded: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockPodStore := objectstoretest.NewMockPodStore(ctrl)
			mockPodStore.EXPECT().GetPodByIPAndTime(gomock.Any(), gomock.Any()).DoAndReturn(
				func(ip string, _ time.Time) (*v1.Pod, bool) {
					if tc.localPodIP.IsValid() && ip == tc.localPodIP.String() {
						return localPod, true
					}
					return nil, false
				}).AnyTimes()
			cfg := testFlowExporterOptions
			if tc.noRemotePodIPs {
				cfg.RemotePodQuerier = &fakeRemotePodQuerier{}
			} else if tc.withQuerier {
				cfg.RemotePodQuerier = newTestRemotePodQuerier()
			}
			cs := NewConntrackConnectionStore(nil, mockPodStore, nil, cfg)

			conn := tc.conn
			conn.FlowKey.Protocol = 6
			conn.FlowKey.SourcePort = 40000
			conn.FlowKey.DestinationPort = 80
			conn.StartTime = refTime
			conn.StopTime = refTime
			conn.Zone = openflow.CtZone
			cs.AddOrUpdateConn(&conn)

			storedConn, exists := cs.GetConnByKey(conn.FlowKey)
			require.Equal(t, tc.expectAdded, exists)
			if !exists {
				return
			}
			assert.Equal(t, tc.expectFromHostNet, storedConn.IsFromHostNetwork)
			_, inQueue := cs.expirePriorityQueue.KeyToItem[conn.FlowKey]
			assert.True(t, inQueue, "Connection should be added to the expire priority queue")
		})
	}
}

// TestFromExternalCorrelator_HostNetwork validates that the Antrea-zone connections initiated by
// the host network of this Node are identified from their default-zone entry, and that the
// connections from external clients masqueraded with the gateway IP are not, even when they cannot
// be correlated.
func TestFromExternalCorrelator_HostNetwork(t *testing.T) {
	const (
		hostPort = 40000
		snatPort = 61000
	)
	clusterIP := netip.MustParseAddr("10.96.0.10")
	nodePortProxier := staticProxier{fmt.Sprintf("%s:30080/TCP", hostTestNodeIPv4): {}}
	clusterIPProxier := staticProxier{fmt.Sprintf("%s:80/TCP", clusterIP): {}}

	// hostDefaultZoneConn returns the default-zone entry of a connection initiated by the host,
	// which is not translated by the host: the destination is the original one.
	hostDefaultZoneConn := func(src, dst netip.Addr, protocol uint8, srcPort, dstPort uint16) *connection.Connection {
		return &connection.Connection{
			Zone:                       DefaultZone,
			FlowKey:                    connection.Tuple{SourceAddress: src, DestinationAddress: dst, Protocol: protocol, SourcePort: srcPort, DestinationPort: dstPort},
			OriginalDestinationAddress: dst,
			OriginalDestinationPort:    dstPort,
		}
	}
	// hostMasqueradedDefaultZoneConn returns the default-zone entry of a connection initiated by
	// the host from src, another IP of this Node than the gateway IP, directly to dst. It is
	// masqueraded with the gateway IP by Antrea's "masquerade LOCAL traffic" rule, but its
	// destination is not translated.
	hostMasqueradedDefaultZoneConn := func(src, dst netip.Addr) *connection.Connection {
		conn := hostDefaultZoneConn(src, dst, 6, hostPort, 80)
		conn.ProxySnatIP = hostTestLocalGwIPv4
		conn.ProxySnatPort = snatPort
		return conn
	}
	// antreaZoneConn returns an Antrea-zone connection whose original destination may be
	// translated by OVS to dst.
	antreaZoneConn := func(src, origDst, dst netip.Addr, protocol uint8, srcPort, origDstPort, dstPort uint16) *connection.Connection {
		return &connection.Connection{
			Zone:                       openflow.CtZone,
			FlowKey:                    connection.Tuple{SourceAddress: src, DestinationAddress: dst, Protocol: protocol, SourcePort: srcPort, DestinationPort: dstPort},
			OriginalDestinationAddress: origDst,
			OriginalDestinationPort:    origDstPort,
		}
	}
	// The default-zone entry of a connection from an external client to a NodePort, masqueraded
	// with the gateway IP and forwarded to a Pod running on another Node.
	masqueradedDefaultZoneConn := &connection.Connection{
		Zone:                       DefaultZone,
		FlowKey:                    connection.Tuple{SourceAddress: hostTestExternalIPv4, DestinationAddress: hostTestRemotePodIPv4, Protocol: 6, SourcePort: 50000, DestinationPort: 80},
		OriginalDestinationAddress: hostTestNodeIPv4,
		OriginalDestinationPort:    30080,
		ProxySnatIP:                hostTestLocalGwIPv4,
		ProxySnatPort:              snatPort,
	}

	// hostServiceDefaultZoneConn returns the default-zone entry of a connection initiated by the
	// host from src to the ClusterIP, translated by kube-proxy to dst, and masqueraded with the
	// gateway IP if masquerade is true.
	hostServiceDefaultZoneConn := func(src, dst netip.Addr, masquerade bool) *connection.Connection {
		conn := &connection.Connection{
			Zone:                       DefaultZone,
			FlowKey:                    connection.Tuple{SourceAddress: src, DestinationAddress: dst, Protocol: 6, SourcePort: hostPort, DestinationPort: 80},
			OriginalDestinationAddress: clusterIP,
			OriginalDestinationPort:    80,
		}
		if masquerade {
			conn.ProxySnatIP = hostTestLocalGwIPv4
			conn.ProxySnatPort = snatPort
		}
		return conn
	}
	// A Pod IP allocated by the primary CNI in networkPolicyOnly mode.
	npoPodIP := netip.MustParseAddr("192.168.10.20")

	tests := []struct {
		name               string
		withNodeIPs        bool
		proxier            proxy.ProxyQuerier
		defaultZoneConns   []*connection.Connection
		antreaZoneConn     *connection.Connection
		expectFromHostNet  bool
		expectFromExternal bool
		// expectServiceUnresolved is whether the original destination was looked up, and is
		// not a Service known to the proxier.
		expectServiceUnresolved bool
		expectedSourceIP        netip.Addr
		// expectedOrigDstIP is the expected original destination IP, if different from the
		// destination IP.
		expectedOrigDstIP netip.Addr
	}{
		{
			name:              "host to local Pod",
			withNodeIPs:       true,
			proxier:           nodePortProxier,
			defaultZoneConns:  []*connection.Connection{hostDefaultZoneConn(hostTestLocalGwIPv4, hostTestLocalPodIPv4, 6, hostPort, 80)},
			antreaZoneConn:    antreaZoneConn(hostTestLocalGwIPv4, hostTestLocalPodIPv4, hostTestLocalPodIPv4, 6, hostPort, 80, 80),
			expectFromHostNet: true,
			expectedSourceIP:  hostTestLocalGwIPv4,
		},
		{
			name:              "IPv6 host to remote Pod",
			withNodeIPs:       true,
			proxier:           nodePortProxier,
			defaultZoneConns:  []*connection.Connection{hostDefaultZoneConn(hostTestLocalGwIPv6, hostTestRemotePodIPv6, 6, hostPort, 80)},
			antreaZoneConn:    antreaZoneConn(hostTestLocalGwIPv6, hostTestRemotePodIPv6, hostTestRemotePodIPv6, 6, hostPort, 80, 80),
			expectFromHostNet: true,
			expectedSourceIP:  hostTestLocalGwIPv6,
		},
		{
			// ICMP is not a Service protocol, but the connection is still identified.
			name:              "ICMP from host to local Pod",
			withNodeIPs:       true,
			proxier:           nodePortProxier,
			defaultZoneConns:  []*connection.Connection{hostDefaultZoneConn(hostTestLocalGwIPv4, hostTestLocalPodIPv4, 1, 0, 0)},
			antreaZoneConn:    antreaZoneConn(hostTestLocalGwIPv4, hostTestLocalPodIPv4, hostTestLocalPodIPv4, 1, 0, 0, 0),
			expectFromHostNet: true,
			expectedSourceIP:  hostTestLocalGwIPv4,
		},
		{
			// The ClusterIP is translated by OVS, not by the host.
			name:              "host to ClusterIP handled by AntreaProxy",
			withNodeIPs:       true,
			proxier:           clusterIPProxier,
			defaultZoneConns:  []*connection.Connection{hostDefaultZoneConn(hostTestLocalGwIPv4, clusterIP, 6, hostPort, 80)},
			antreaZoneConn:    antreaZoneConn(hostTestLocalGwIPv4, clusterIP, hostTestLocalPodIPv4, 6, hostPort, 80, 8080),
			expectFromHostNet: true,
			expectedSourceIP:  hostTestLocalGwIPv4,
			expectedOrigDstIP: clusterIP,
		},
		{
			// Without a proxier, every default-zone connection is retained for correlation,
			// but the ones initiated by the host and not translated by it are not correlated as
			// from-external ones.
			name:              "host to local Pod without proxier",
			withNodeIPs:       true,
			defaultZoneConns:  []*connection.Connection{hostDefaultZoneConn(hostTestLocalGwIPv4, hostTestLocalPodIPv4, 6, hostPort, 80)},
			antreaZoneConn:    antreaZoneConn(hostTestLocalGwIPv4, hostTestLocalPodIPv4, hostTestLocalPodIPv4, 6, hostPort, 80, 80),
			expectFromHostNet: true,
			expectedSourceIP:  hostTestLocalGwIPv4,
		},
		{
			name:             "host to local Pod without Node IPs",
			withNodeIPs:      false,
			proxier:          nodePortProxier,
			defaultZoneConns: []*connection.Connection{hostDefaultZoneConn(hostTestLocalGwIPv4, hostTestLocalPodIPv4, 6, hostPort, 80)},
			antreaZoneConn:   antreaZoneConn(hostTestLocalGwIPv4, hostTestLocalPodIPv4, hostTestLocalPodIPv4, 6, hostPort, 80, 80),
			expectedSourceIP: hostTestLocalGwIPv4,
		},
		{
			// For example, a hostNetwork Pod bound to its Node IP. The connection is retained
			// for correlation, although its destination is not a Service, as it was translated
			// by the host, and the source address used by the host is reported.
			name:                    "host bound to Node IP to local Pod",
			withNodeIPs:             true,
			proxier:                 clusterIPProxier,
			defaultZoneConns:        []*connection.Connection{hostMasqueradedDefaultZoneConn(hostTestLocalNodeIPv4, hostTestLocalPodIPv4)},
			antreaZoneConn:          antreaZoneConn(hostTestLocalGwIPv4, hostTestLocalPodIPv4, hostTestLocalPodIPv4, 6, snatPort, 80, 80),
			expectFromHostNet:       true,
			expectFromExternal:      true,
			expectServiceUnresolved: true,
			expectedSourceIP:        hostTestLocalNodeIPv4,
		},
		{
			name:                    "host bound to transport IP to remote Pod",
			withNodeIPs:             true,
			proxier:                 clusterIPProxier,
			defaultZoneConns:        []*connection.Connection{hostMasqueradedDefaultZoneConn(hostTestLocalTransportIPv4, hostTestRemotePodIPv4)},
			antreaZoneConn:          antreaZoneConn(hostTestLocalGwIPv4, hostTestRemotePodIPv4, hostTestRemotePodIPv4, 6, snatPort, 80, 80),
			expectFromHostNet:       true,
			expectFromExternal:      true,
			expectServiceUnresolved: true,
			expectedSourceIP:        hostTestLocalTransportIPv4,
		},
		{
			// The same as with a proxier, but the original destination is not looked up.
			name:               "host bound to Node IP to local Pod without proxier",
			withNodeIPs:        true,
			defaultZoneConns:   []*connection.Connection{hostMasqueradedDefaultZoneConn(hostTestLocalNodeIPv4, hostTestLocalPodIPv4)},
			antreaZoneConn:     antreaZoneConn(hostTestLocalGwIPv4, hostTestLocalPodIPv4, hostTestLocalPodIPv4, 6, snatPort, 80, 80),
			expectFromHostNet:  true,
			expectFromExternal: true,
			expectedSourceIP:   hostTestLocalNodeIPv4,
		},
		{
			// A connection masqueraded with the gateway IP by the host, but initiated by
			// another Node: it is not identified as a connection from the host network.
			name:             "other Node IP masqueraded with the local gateway IP to local Pod",
			withNodeIPs:      true,
			proxier:          clusterIPProxier,
			defaultZoneConns: []*connection.Connection{hostMasqueradedDefaultZoneConn(hostTestNodeIPv4, hostTestLocalPodIPv4)},
			antreaZoneConn:   antreaZoneConn(hostTestLocalGwIPv4, hostTestLocalPodIPv4, hostTestLocalPodIPv4, 6, snatPort, 80, 80),
			expectedSourceIP: hostTestLocalGwIPv4,
		},
		{
			// For example, after an agent restart, if the default-zone entry has expired.
			name:             "no default-zone entry",
			withNodeIPs:      true,
			proxier:          nodePortProxier,
			antreaZoneConn:   antreaZoneConn(hostTestLocalGwIPv4, hostTestRemotePodIPv4, hostTestRemotePodIPv4, 6, hostPort, 80, 80),
			expectedSourceIP: hostTestLocalGwIPv4,
		},
		{
			name:               "masqueraded external connection to a known Service",
			withNodeIPs:        true,
			proxier:            nodePortProxier,
			defaultZoneConns:   []*connection.Connection{masqueradedDefaultZoneConn},
			antreaZoneConn:     antreaZoneConn(hostTestLocalGwIPv4, hostTestRemotePodIPv4, hostTestRemotePodIPv4, 6, snatPort, 80, 80),
			expectFromExternal: true,
			expectedSourceIP:   hostTestExternalIPv4,
			expectedOrigDstIP:  hostTestNodeIPv4,
		},
		{
			// For example, a Service ignored by AntreaProxy (skipServices): the default-zone
			// entry is not retained, and the connection is not correlated. It must not be
			// identified as a connection from the host network either.
			name:             "masqueraded external connection to an unknown Service",
			withNodeIPs:      true,
			proxier:          clusterIPProxier,
			defaultZoneConns: []*connection.Connection{masqueradedDefaultZoneConn},
			antreaZoneConn:   antreaZoneConn(hostTestLocalGwIPv4, hostTestRemotePodIPv4, hostTestRemotePodIPv4, 6, snatPort, 80, 80),
			expectedSourceIP: hostTestLocalGwIPv4,
		},
		{
			// Without a proxier, every connection which is not initiated by the host is
			// retained for correlation.
			name:               "masqueraded external connection without proxier",
			withNodeIPs:        true,
			defaultZoneConns:   []*connection.Connection{masqueradedDefaultZoneConn},
			antreaZoneConn:     antreaZoneConn(hostTestLocalGwIPv4, hostTestRemotePodIPv4, hostTestRemotePodIPv4, 6, snatPort, 80, 80),
			expectFromExternal: true,
			expectedSourceIP:   hostTestExternalIPv4,
			expectedOrigDstIP:  hostTestNodeIPv4,
		},
		{
			// The connection is reported as from external, with the Node IP as the source,
			// and is also identified as initiated by the host.
			name:               "host to ClusterIP masqueraded by kube-proxy to local Pod",
			withNodeIPs:        true,
			proxier:            clusterIPProxier,
			defaultZoneConns:   []*connection.Connection{hostServiceDefaultZoneConn(hostTestLocalNodeIPv4, hostTestLocalPodIPv4, true)},
			antreaZoneConn:     antreaZoneConn(hostTestLocalGwIPv4, hostTestLocalPodIPv4, hostTestLocalPodIPv4, 6, snatPort, 80, 80),
			expectFromHostNet:  true,
			expectFromExternal: true,
			expectedSourceIP:   hostTestLocalNodeIPv4,
			expectedOrigDstIP:  clusterIP,
		},
		{
			name:               "host to ClusterIP masqueraded by kube-proxy to remote Pod",
			withNodeIPs:        true,
			proxier:            clusterIPProxier,
			defaultZoneConns:   []*connection.Connection{hostServiceDefaultZoneConn(hostTestLocalNodeIPv4, hostTestRemotePodIPv4, true)},
			antreaZoneConn:     antreaZoneConn(hostTestLocalGwIPv4, hostTestRemotePodIPv4, hostTestRemotePodIPv4, 6, snatPort, 80, 80),
			expectFromHostNet:  true,
			expectFromExternal: true,
			expectedSourceIP:   hostTestLocalNodeIPv4,
			expectedOrigDstIP:  clusterIP,
		},
		{
			// Without a proxier (AntreaProxy disabled), the connection is still retained for
			// correlation, as it was translated by the host.
			name:               "host to ClusterIP masqueraded by kube-proxy without proxier",
			withNodeIPs:        true,
			defaultZoneConns:   []*connection.Connection{hostServiceDefaultZoneConn(hostTestLocalNodeIPv4, hostTestRemotePodIPv4, true)},
			antreaZoneConn:     antreaZoneConn(hostTestLocalGwIPv4, hostTestRemotePodIPv4, hostTestRemotePodIPv4, 6, snatPort, 80, 80),
			expectFromHostNet:  true,
			expectFromExternal: true,
			expectedSourceIP:   hostTestLocalNodeIPv4,
			expectedOrigDstIP:  clusterIP,
		},
		{
			// The host uses the gateway IP as the source address, and kube-proxy translates the
			// ClusterIP without masquerade.
			name:               "host gateway IP to ClusterIP translated by kube-proxy without proxier",
			withNodeIPs:        true,
			defaultZoneConns:   []*connection.Connection{hostServiceDefaultZoneConn(hostTestLocalGwIPv4, hostTestLocalPodIPv4, false)},
			antreaZoneConn:     antreaZoneConn(hostTestLocalGwIPv4, hostTestLocalPodIPv4, hostTestLocalPodIPv4, 6, hostPort, 80, 80),
			expectFromHostNet:  true,
			expectFromExternal: true,
			expectedSourceIP:   hostTestLocalGwIPv4,
			expectedOrigDstIP:  clusterIP,
		},
		{
			// A Service ignored by AntreaProxy: the connection is retained for correlation, as
			// it was translated by the host, and the source address used by the host and the
			// ClusterIP are reported, as without a proxier.
			name:                    "host to unknown ClusterIP masqueraded by kube-proxy",
			withNodeIPs:             true,
			proxier:                 nodePortProxier,
			defaultZoneConns:        []*connection.Connection{hostServiceDefaultZoneConn(hostTestLocalNodeIPv4, hostTestRemotePodIPv4, true)},
			antreaZoneConn:          antreaZoneConn(hostTestLocalGwIPv4, hostTestRemotePodIPv4, hostTestRemotePodIPv4, 6, snatPort, 80, 80),
			expectFromHostNet:       true,
			expectFromExternal:      true,
			expectServiceUnresolved: true,
			expectedSourceIP:        hostTestLocalNodeIPv4,
			expectedOrigDstIP:       clusterIP,
		},
		{
			name:                    "host gateway IP to unknown ClusterIP translated by kube-proxy",
			withNodeIPs:             true,
			proxier:                 nodePortProxier,
			defaultZoneConns:        []*connection.Connection{hostServiceDefaultZoneConn(hostTestLocalGwIPv4, hostTestLocalPodIPv4, false)},
			antreaZoneConn:          antreaZoneConn(hostTestLocalGwIPv4, hostTestLocalPodIPv4, hostTestLocalPodIPv4, 6, hostPort, 80, 80),
			expectFromHostNet:       true,
			expectFromExternal:      true,
			expectServiceUnresolved: true,
			expectedSourceIP:        hostTestLocalGwIPv4,
			expectedOrigDstIP:       clusterIP,
		},
		{
			name:               "host to ClusterIP translated by kube-proxy without masquerade",
			withNodeIPs:        true,
			proxier:            clusterIPProxier,
			defaultZoneConns:   []*connection.Connection{hostServiceDefaultZoneConn(hostTestLocalTransportIPv4, hostTestLocalPodIPv4, false)},
			antreaZoneConn:     antreaZoneConn(hostTestLocalTransportIPv4, hostTestLocalPodIPv4, hostTestLocalPodIPv4, 6, hostPort, 80, 80),
			expectFromHostNet:  true,
			expectFromExternal: true,
			expectedSourceIP:   hostTestLocalTransportIPv4,
			expectedOrigDstIP:  clusterIP,
		},
		{
			name:               "host to ClusterIP masqueraded by kube-proxy without Node IPs",
			withNodeIPs:        false,
			proxier:            clusterIPProxier,
			defaultZoneConns:   []*connection.Connection{hostServiceDefaultZoneConn(hostTestLocalNodeIPv4, hostTestLocalPodIPv4, true)},
			antreaZoneConn:     antreaZoneConn(hostTestLocalGwIPv4, hostTestLocalPodIPv4, hostTestLocalPodIPv4, 6, snatPort, 80, 80),
			expectFromExternal: true,
			expectedSourceIP:   hostTestLocalNodeIPv4,
			expectedOrigDstIP:  clusterIP,
		},
		{
			// In networkPolicyOnly mode, the gateway IP is the transport IP of the Node, which
			// the host selects as the source address when connecting to a local Pod through
			// antrea-gw0.
			name:              "networkPolicyOnly mode host to local Pod",
			withNodeIPs:       true,
			proxier:           nodePortProxier,
			defaultZoneConns:  []*connection.Connection{hostDefaultZoneConn(hostTestLocalNodeIPv4, npoPodIP, 6, hostPort, 80)},
			antreaZoneConn:    antreaZoneConn(hostTestLocalNodeIPv4, npoPodIP, npoPodIP, 6, hostPort, 80, 80),
			expectFromHostNet: true,
			expectedSourceIP:  hostTestLocalNodeIPv4,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var nodeIPs sets.Set[netip.Addr]
			if tc.withNodeIPs {
				nodeIPs = hostTestNodeIPs
			}
			correlator := NewFromExternalCorrelator(tc.proxier, nil, nodeIPs)
			conn := tc.antreaZoneConn
			correlator.Correlate(tc.defaultZoneConns, []*connection.Connection{conn})
			assert.Equal(t, tc.expectFromHostNet, conn.IsFromHostNetwork, "Unexpected IsFromHostNetwork")
			assert.Equal(t, tc.expectFromExternal, conn.IsFromExternal, "Unexpected IsFromExternal")
			assert.Equal(t, tc.expectServiceUnresolved, conn.IsServiceUnresolved, "Unexpected IsServiceUnresolved")
			assert.Equal(t, tc.expectedSourceIP, conn.FlowKey.SourceAddress, "Unexpected source IP")
			expectedOrigDstIP := tc.expectedOrigDstIP
			if !expectedOrigDstIP.IsValid() {
				expectedOrigDstIP = conn.FlowKey.DestinationAddress
			}
			assert.Equal(t, expectedOrigDstIP, conn.OriginalDestinationAddress, "Unexpected original destination IP")
			assert.Empty(t, correlator.hostNetworkConns, "The host network connections should be cleared at the end of the poll")
		})
	}
}

// TestFromExternalCorrelator_HostNetworkProxyAll validates the correlation of the connections
// initiated by the host network of this Node to a Service handled by AntreaProxy with proxyAll. The
// host does not translate the ClusterIP, and translates <NodeIP>:<NodePort> to the virtual NodePort
// DNAT IP, so the default-zone entry is keyed on the destination before the translation applied by
// OVS, rather than on the Endpoint. A connection is correlated if the host translated it, so that the
// source address used by the host before SNAT and the original destination are reported, as with
// kube-proxy.
func TestFromExternalCorrelator_HostNetworkProxyAll(t *testing.T) {
	const (
		hostPort     = 40000
		snatPort     = 61000
		clientPort   = 50000
		svcPort      = 80
		nodePort     = 30080
		endpointPort = 8080
	)
	refTime := time.Now()
	clusterIPv4 := netip.MustParseAddr("10.96.0.10")
	clusterIPv6 := netip.MustParseAddr("fd00:10:96::a")
	// The virtual IP to which the host translates the destination of the connections to a NodePort
	// with proxyAll.
	nodePortDNATIP := netip.MustParseAddr("169.254.0.252")
	proxier := staticProxier{
		fmt.Sprintf("%s:%d/TCP", clusterIPv4, svcPort):            {},
		fmt.Sprintf("%s:%d/TCP", clusterIPv6, svcPort):            {},
		fmt.Sprintf("%s:%d/TCP", hostTestLocalNodeIPv4, nodePort): {},
	}
	addrPort := netip.AddrPortFrom

	// defaultZoneConn returns the default-zone entry of a connection from src to origDst, whose
	// destination is translated by the host to dst, and which is masqueraded by the host with snatIP
	// if it is valid.
	defaultZoneConn := func(src, origDst, dst netip.AddrPort, snatIP netip.Addr) *connection.Connection {
		conn := &connection.Connection{
			Zone:                       DefaultZone,
			FlowKey:                    connection.Tuple{SourceAddress: src.Addr(), DestinationAddress: dst.Addr(), Protocol: 6, SourcePort: src.Port(), DestinationPort: dst.Port()},
			OriginalDestinationAddress: origDst.Addr(),
			OriginalDestinationPort:    origDst.Port(),
		}
		if snatIP.IsValid() {
			conn.ProxySnatIP = snatIP
			conn.ProxySnatPort = snatPort
		}
		return conn
	}
	// antreaZoneConn returns the Antrea-zone entry of a connection from src to origDst, translated
	// by OVS to the Endpoint, at endpointIP:endpointPort.
	antreaZoneConn := func(src, origDst netip.AddrPort, endpointIP netip.Addr) *connection.Connection {
		return &connection.Connection{
			ID:                         1,
			Zone:                       openflow.CtZone,
			StartTime:                  refTime,
			FlowKey:                    connection.Tuple{SourceAddress: src.Addr(), DestinationAddress: endpointIP, Protocol: 6, SourcePort: src.Port(), DestinationPort: endpointPort},
			OriginalDestinationAddress: origDst.Addr(),
			OriginalDestinationPort:    origDst.Port(),
		}
	}

	tests := []struct {
		name               string
		defaultZoneConn    *connection.Connection
		antreaZoneConn     *connection.Connection
		expectFromHostNet  bool
		expectFromExternal bool
		expectedSource     netip.AddrPort
		// expectedProxySnat is the zero value if the connection has no ProxySnat address.
		expectedProxySnat netip.AddrPort
		expectedOrigDst   netip.AddrPort
	}{
		{
			// For example, a hostNetwork Pod bound to its Node IP, masqueraded by Antrea's
			// "masquerade LOCAL traffic" rule.
			name:               "host bound to Node IP to ClusterIP with local Endpoint",
			defaultZoneConn:    defaultZoneConn(addrPort(hostTestLocalNodeIPv4, hostPort), addrPort(clusterIPv4, svcPort), addrPort(clusterIPv4, svcPort), hostTestLocalGwIPv4),
			antreaZoneConn:     antreaZoneConn(addrPort(hostTestLocalGwIPv4, snatPort), addrPort(clusterIPv4, svcPort), hostTestLocalPodIPv4),
			expectFromHostNet:  true,
			expectFromExternal: true,
			expectedSource:     addrPort(hostTestLocalNodeIPv4, hostPort),
			expectedProxySnat:  addrPort(hostTestLocalGwIPv4, snatPort),
			expectedOrigDst:    addrPort(clusterIPv4, svcPort),
		},
		{
			// The FlowAggregator keys the record on its ProxySnat address, which is the source
			// address seen by the destination Node.
			name:               "host bound to Node IP to ClusterIP with remote Endpoint",
			defaultZoneConn:    defaultZoneConn(addrPort(hostTestLocalNodeIPv4, hostPort), addrPort(clusterIPv4, svcPort), addrPort(clusterIPv4, svcPort), hostTestLocalGwIPv4),
			antreaZoneConn:     antreaZoneConn(addrPort(hostTestLocalGwIPv4, snatPort), addrPort(clusterIPv4, svcPort), hostTestRemotePodIPv4),
			expectFromHostNet:  true,
			expectFromExternal: true,
			expectedSource:     addrPort(hostTestLocalNodeIPv4, hostPort),
			expectedProxySnat:  addrPort(hostTestLocalGwIPv4, snatPort),
			expectedOrigDst:    addrPort(clusterIPv4, svcPort),
		},
		{
			name:               "IPv6 host bound to Node IP to ClusterIP with local Endpoint",
			defaultZoneConn:    defaultZoneConn(addrPort(hostTestLocalNodeIPv6, hostPort), addrPort(clusterIPv6, svcPort), addrPort(clusterIPv6, svcPort), hostTestLocalGwIPv6),
			antreaZoneConn:     antreaZoneConn(addrPort(hostTestLocalGwIPv6, snatPort), addrPort(clusterIPv6, svcPort), hostTestLocalPodIPv6),
			expectFromHostNet:  true,
			expectFromExternal: true,
			expectedSource:     addrPort(hostTestLocalNodeIPv6, hostPort),
			expectedProxySnat:  addrPort(hostTestLocalGwIPv6, snatPort),
			expectedOrigDst:    addrPort(clusterIPv6, svcPort),
		},
		{
			// The host selects the Node IP as the source address, as the original destination
			// is local, then translates the destination to the virtual NodePort DNAT IP, and
			// masquerades the connection.
			name:               "host to NodePort with local Endpoint",
			defaultZoneConn:    defaultZoneConn(addrPort(hostTestLocalNodeIPv4, hostPort), addrPort(hostTestLocalNodeIPv4, nodePort), addrPort(nodePortDNATIP, nodePort), hostTestLocalGwIPv4),
			antreaZoneConn:     antreaZoneConn(addrPort(hostTestLocalGwIPv4, snatPort), addrPort(nodePortDNATIP, nodePort), hostTestLocalPodIPv4),
			expectFromHostNet:  true,
			expectFromExternal: true,
			expectedSource:     addrPort(hostTestLocalNodeIPv4, hostPort),
			expectedProxySnat:  addrPort(hostTestLocalGwIPv4, snatPort),
			expectedOrigDst:    addrPort(hostTestLocalNodeIPv4, nodePort),
		},
		{
			name:               "host to NodePort with remote Endpoint",
			defaultZoneConn:    defaultZoneConn(addrPort(hostTestLocalNodeIPv4, hostPort), addrPort(hostTestLocalNodeIPv4, nodePort), addrPort(nodePortDNATIP, nodePort), hostTestLocalGwIPv4),
			antreaZoneConn:     antreaZoneConn(addrPort(hostTestLocalGwIPv4, snatPort), addrPort(nodePortDNATIP, nodePort), hostTestRemotePodIPv4),
			expectFromHostNet:  true,
			expectFromExternal: true,
			expectedSource:     addrPort(hostTestLocalNodeIPv4, hostPort),
			expectedProxySnat:  addrPort(hostTestLocalGwIPv4, snatPort),
			expectedOrigDst:    addrPort(hostTestLocalNodeIPv4, nodePort),
		},
		{
			// A client bound to the gateway IP is not masqueraded, but the host still
			// translates the destination, which is reported.
			name:               "host bound to gateway IP to NodePort",
			defaultZoneConn:    defaultZoneConn(addrPort(hostTestLocalGwIPv4, hostPort), addrPort(hostTestLocalNodeIPv4, nodePort), addrPort(nodePortDNATIP, nodePort), netip.Addr{}),
			antreaZoneConn:     antreaZoneConn(addrPort(hostTestLocalGwIPv4, hostPort), addrPort(nodePortDNATIP, nodePort), hostTestLocalPodIPv4),
			expectFromHostNet:  true,
			expectFromExternal: true,
			expectedSource:     addrPort(hostTestLocalGwIPv4, hostPort),
			expectedOrigDst:    addrPort(hostTestLocalNodeIPv4, nodePort),
		},
		{
			// The host translates neither the source nor the destination: the connection is
			// only identified as initiated by the host network, and is not correlated.
			name:              "host gateway IP to ClusterIP",
			defaultZoneConn:   defaultZoneConn(addrPort(hostTestLocalGwIPv4, hostPort), addrPort(clusterIPv4, svcPort), addrPort(clusterIPv4, svcPort), netip.Addr{}),
			antreaZoneConn:    antreaZoneConn(addrPort(hostTestLocalGwIPv4, hostPort), addrPort(clusterIPv4, svcPort), hostTestLocalPodIPv4),
			expectFromHostNet: true,
			expectedSource:    addrPort(hostTestLocalGwIPv4, hostPort),
			expectedOrigDst:   addrPort(clusterIPv4, svcPort),
		},
		{
			// The default-zone entry matches the key of a connection initiated by the host
			// network, but the connection is not: it is left unchanged.
			name:            "external client to NodePort",
			defaultZoneConn: defaultZoneConn(addrPort(hostTestExternalIPv4, clientPort), addrPort(hostTestLocalNodeIPv4, nodePort), addrPort(nodePortDNATIP, nodePort), netip.Addr{}),
			antreaZoneConn:  antreaZoneConn(addrPort(hostTestExternalIPv4, clientPort), addrPort(nodePortDNATIP, nodePort), hostTestLocalPodIPv4),
			expectedSource:  addrPort(hostTestExternalIPv4, clientPort),
			expectedOrigDst: addrPort(nodePortDNATIP, nodePort),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			correlator := NewFromExternalCorrelator(proxier, nil, hostTestNodeIPs)
			expectedDst := netip.AddrPortFrom(tc.antreaZoneConn.FlowKey.DestinationAddress, tc.antreaZoneConn.FlowKey.DestinationPort)
			check := func(t *testing.T, conn *connection.Connection) {
				assert.Equal(t, tc.expectFromHostNet, conn.IsFromHostNetwork, "Unexpected IsFromHostNetwork")
				assert.Equal(t, tc.expectFromExternal, conn.IsFromExternal, "Unexpected IsFromExternal")
				assert.False(t, conn.IsServiceUnresolved, "The Service should be resolved")
				assert.Equal(t, tc.expectedSource, netip.AddrPortFrom(conn.FlowKey.SourceAddress, conn.FlowKey.SourcePort), "Unexpected source")
				assert.Equal(t, expectedDst, netip.AddrPortFrom(conn.FlowKey.DestinationAddress, conn.FlowKey.DestinationPort), "Unexpected destination")
				assert.Equal(t, tc.expectedOrigDst, netip.AddrPortFrom(conn.OriginalDestinationAddress, conn.OriginalDestinationPort), "Unexpected original destination")
				var proxySnat netip.AddrPort
				if conn.ProxySnatIP.IsValid() {
					proxySnat = netip.AddrPortFrom(conn.ProxySnatIP, conn.ProxySnatPort)
				}
				assert.Equal(t, tc.expectedProxySnat, proxySnat, "Unexpected ProxySnat address")
			}

			conn := *tc.antreaZoneConn
			correlator.Correlate([]*connection.Connection{tc.defaultZoneConn}, []*connection.Connection{&conn})
			check(t, &conn)
			assert.Empty(t, correlator.connections, "The default-zone connections should be cleared at the end of the poll")
			if !tc.expectFromExternal {
				return
			}
			// The default-zone entry may be gone before the Antrea-zone entry: the snapshot used
			// for this conntrack entry during the previous poll is used again.
			conn = *tc.antreaZoneConn
			correlator.Correlate(nil, []*connection.Connection{&conn})
			check(t, &conn)
		})
	}
}

// TestConntrackConnectionStore_HostNetworkServiceLookup validates that the connection store only
// looks up the Service of a connection initiated by the host network of this Node and correlated
// with its default-zone entry if the FromExternalCorrelator resolved it to a Service.
func TestConntrackConnectionStore_HostNetworkServiceLookup(t *testing.T) {
	const snatPort = 61000
	clusterIP := netip.MustParseAddr("10.96.0.10")
	svc := k8sproxy.ServicePortName{
		NamespacedName: types.NamespacedName{Namespace: "ns1", Name: "svc1"},
		Port:           "http",
		Protocol:       v1.ProtocolTCP,
	}
	localPod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "local-pod", Namespace: "ns1", UID: "local-pod-uid"}}
	refTime := time.Now()

	localPodAddrPort := netip.AddrPortFrom(hostTestLocalPodIPv4, 80)
	tests := []struct {
		name string
		// origDst is the original destination of the default-zone entry.
		origDst netip.AddrPort
		// hostDst is the destination of the default-zone entry, after the translation applied
		// by the host. If it is not the local Pod, OVS translates it to the local Pod, i.e.,
		// AntreaProxy handles the Service with proxyAll.
		hostDst             netip.AddrPort
		isKnownService      bool
		expectedServiceName string
	}{
		{
			// For example, a hostNetwork Pod bound to its Node IP, masqueraded by Antrea's
			// "masquerade LOCAL traffic" rule.
			name:    "Node IP to local Pod",
			origDst: localPodAddrPort,
			hostDst: localPodAddrPort,
		},
		{
			// For example, a Service ignored by AntreaProxy.
			name:    "Node IP to unknown ClusterIP masqueraded by kube-proxy",
			origDst: netip.AddrPortFrom(clusterIP, 80),
			hostDst: localPodAddrPort,
		},
		{
			name:                "Node IP to known ClusterIP masqueraded by kube-proxy",
			origDst:             netip.AddrPortFrom(clusterIP, 80),
			hostDst:             localPodAddrPort,
			isKnownService:      true,
			expectedServiceName: svc.String(),
		},
		{
			name:                "Node IP to ClusterIP masqueraded by the host with proxyAll",
			origDst:             netip.AddrPortFrom(clusterIP, 80),
			hostDst:             netip.AddrPortFrom(clusterIP, 80),
			isKnownService:      true,
			expectedServiceName: svc.String(),
		},
		{
			// The destination is translated by the host to the virtual NodePort DNAT IP, which
			// is not a Service known to the proxier, while <NodeIP>:<NodePort> is.
			name:                "Node IP to NodePort masqueraded by the host with proxyAll",
			origDst:             netip.AddrPortFrom(hostTestLocalNodeIPv4, 30080),
			hostDst:             netip.AddrPortFrom(netip.MustParseAddr("169.254.0.252"), 30080),
			isKnownService:      true,
			expectedServiceName: svc.String(),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockProxier := proxytest.NewMockProxyQuerier(ctrl)
			serviceStr := fmt.Sprintf("%s:%d/TCP", tc.origDst.Addr(), tc.origDst.Port())
			// The correlator looks up the original destination when it ingests the
			// default-zone entry. The connection store only looks it up again if it is a
			// Service.
			lookups := 1
			if tc.isKnownService {
				lookups = 2
			}
			mockProxier.EXPECT().GetServiceByIP(serviceStr).Return(svc, tc.isKnownService).Times(lookups)
			mockPodStore := objectstoretest.NewMockPodStore(ctrl)
			mockPodStore.EXPECT().GetPodByIPAndTime(gomock.Any(), gomock.Any()).DoAndReturn(
				func(ip string, _ time.Time) (*v1.Pod, bool) {
					if ip == hostTestLocalPodIPv4.String() {
						return localPod, true
					}
					return nil, false
				}).AnyTimes()

			defaultZoneConn := &connection.Connection{
				Zone:                       DefaultZone,
				FlowKey:                    connection.Tuple{SourceAddress: hostTestLocalNodeIPv4, DestinationAddress: tc.hostDst.Addr(), Protocol: 6, SourcePort: 40000, DestinationPort: tc.hostDst.Port()},
				OriginalDestinationAddress: tc.origDst.Addr(),
				OriginalDestinationPort:    tc.origDst.Port(),
				ProxySnatIP:                hostTestLocalGwIPv4,
				ProxySnatPort:              snatPort,
			}
			antreaZoneConn := &connection.Connection{
				Zone:                       openflow.CtZone,
				FlowKey:                    connection.Tuple{SourceAddress: hostTestLocalGwIPv4, DestinationAddress: hostTestLocalPodIPv4, Protocol: 6, SourcePort: snatPort, DestinationPort: 80},
				OriginalDestinationAddress: tc.hostDst.Addr(),
				OriginalDestinationPort:    tc.hostDst.Port(),
				StartTime:                  refTime,
				StopTime:                   refTime,
			}
			correlator := NewFromExternalCorrelator(mockProxier, nil, hostTestNodeIPs)
			correlator.Correlate([]*connection.Connection{defaultZoneConn}, []*connection.Connection{antreaZoneConn})
			require.True(t, antreaZoneConn.IsFromExternal)
			require.True(t, antreaZoneConn.IsFromHostNetwork)

			cs := NewConntrackConnectionStore(nil, mockPodStore, mockProxier, testFlowExporterOptions)
			cs.AddOrUpdateConn(antreaZoneConn)
			storedConn, exists := cs.GetConnByKey(antreaZoneConn.FlowKey)
			require.True(t, exists)
			assert.Equal(t, hostTestLocalNodeIPv4, storedConn.FlowKey.SourceAddress)
			assert.Equal(t, tc.origDst, netip.AddrPortFrom(storedConn.OriginalDestinationAddress, storedConn.OriginalDestinationPort))
			assert.Equal(t, tc.expectedServiceName, storedConn.DestinationServicePortName)
		})
	}
}
