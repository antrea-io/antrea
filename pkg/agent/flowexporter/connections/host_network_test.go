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
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	"antrea.io/antrea/v2/pkg/agent/flowexporter/connection"
	"antrea.io/antrea/v2/pkg/agent/openflow"
	"antrea.io/antrea/v2/pkg/agent/proxy"
	objectstoretest "antrea.io/antrea/v2/pkg/util/objectstore/testing"
)

// fakeNodeRouteQuerier mimics noderoute.Controller.GetNodeIPForPodIP for a fixed set of Pod
// subnets of other Nodes: an IP belongs to the Pod subnet of another Node if it belongs to one of
// them (including the gateway IP of that Node).
type fakeNodeRouteQuerier struct {
	remotePodSubnets []netip.Prefix
}

func (q *fakeNodeRouteQuerier) GetNodeIPForPodIP(ip netip.Addr) (net.IP, bool) {
	for _, prefix := range q.remotePodSubnets {
		if prefix.Contains(ip) {
			return net.IP(hostTestNodeIPv4.AsSlice()), true
		}
	}
	return nil, false
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

func newTestNodeRouteQuerier() *fakeNodeRouteQuerier {
	return &fakeNodeRouteQuerier{remotePodSubnets: []netip.Prefix{hostTestRemotePodCIDRv4, hostTestRemotePodCIDRv6}}
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
		name              string
		withQuerier       bool
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
			// The gateway IP of another Node belongs to its Pod subnet: the connection is
			// kept, but it is never exported (see Destination.findFlowType).
			name:              "local gateway to remote gateway",
			withQuerier:       true,
			conn:              hostConn(hostTestLocalGwIPv4, hostTestRemoteGwIPv4),
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
			name:        "local gateway to remote Pod without NodeRouteQuerier",
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
			if tc.withQuerier {
				cfg.NodeRouteQuerier = newTestNodeRouteQuerier()
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
		expectedSourceIP   netip.Addr
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
			// For example, a hostNetwork Pod bound to its Node IP. The connection is not
			// correlated as a from-external one, as its destination is not a Service.
			name:              "host bound to Node IP to local Pod",
			withNodeIPs:       true,
			proxier:           clusterIPProxier,
			defaultZoneConns:  []*connection.Connection{hostMasqueradedDefaultZoneConn(hostTestLocalNodeIPv4, hostTestLocalPodIPv4)},
			antreaZoneConn:    antreaZoneConn(hostTestLocalGwIPv4, hostTestLocalPodIPv4, hostTestLocalPodIPv4, 6, snatPort, 80, 80),
			expectFromHostNet: true,
			expectedSourceIP:  hostTestLocalGwIPv4,
		},
		{
			name:              "host bound to transport IP to remote Pod",
			withNodeIPs:       true,
			proxier:           clusterIPProxier,
			defaultZoneConns:  []*connection.Connection{hostMasqueradedDefaultZoneConn(hostTestLocalTransportIPv4, hostTestRemotePodIPv4)},
			antreaZoneConn:    antreaZoneConn(hostTestLocalGwIPv4, hostTestRemotePodIPv4, hostTestRemotePodIPv4, 6, snatPort, 80, 80),
			expectFromHostNet: true,
			expectedSourceIP:  hostTestLocalGwIPv4,
		},
		{
			// Without a proxier, the connection is retained for correlation, as it was
			// translated by the host, and the source address used by the host is reported.
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
