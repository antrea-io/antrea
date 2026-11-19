// Copyright 2026 Antrea Authors.
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
	"math"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"antrea.io/antrea/v2/pkg/agent/flowexporter/connection"
	connstesting "antrea.io/antrea/v2/pkg/agent/flowexporter/connections/testing"
	"antrea.io/antrea/v2/pkg/agent/openflow"
	binding "antrea.io/antrea/v2/pkg/ovs/openflow"
	objectstoretest "antrea.io/antrea/v2/pkg/util/objectstore/testing"
	k8sproxy "antrea.io/antrea/v2/third_party/proxy"
)

func TestPoller_Poll(t *testing.T) {
	// Hard-coded conntrack occupancy metrics for test
	const maxConnections = 30000
	tuple1 := connection.Tuple{SourceAddress: netip.MustParseAddr("1.2.3.4"), DestinationAddress: netip.MustParseAddr("4.3.2.1"), Protocol: 6, SourcePort: 65280, DestinationPort: 255}
	tuple2 := connection.Tuple{SourceAddress: netip.MustParseAddr("5.6.7.8"), DestinationAddress: netip.MustParseAddr("4.3.2.1"), Protocol: 6, SourcePort: 60000, DestinationPort: 255}

	getConn := func(tuple connection.Tuple) *connection.Connection {
		return &connection.Connection{
			FlowKey: tuple,
		}
	}

	tests := []struct {
		name  string
		conns []*connection.Connection
	}{
		{
			name:  "no conns during poll",
			conns: []*connection.Connection{},
		}, {
			name:  "has connections",
			conns: []*connection.Connection{getConn(tuple1), getConn(tuple2)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			mockDumper := connstesting.NewMockConnTrackDumper(ctrl)
			// The default zone is polled last (returns no connections for this test).
			mockDumper.EXPECT().DumpFlows(uint16(0)).Return(nil, 0, nil)
			mockDumper.EXPECT().DumpFlows(gomock.Not(uint16(0))).Return(tt.conns, len(tt.conns), nil)
			mockDumper.EXPECT().GetMaxConnections().Return(maxConnections, nil)

			p := NewPoller(mockDumper, nil, nil, 0, true, false, false)
			antreaConns, connsLens, err := p.Poll()
			require.NoError(t, err)
			assert.ElementsMatch(t, tt.conns, antreaConns)
			assert.Equal(t, []int{0, len(tt.conns)}, connsLens)

			// Validate Metrics
			checkTotalConnectionsMetric(t, len(tt.conns))
			checkMaxConnectionsMetric(t, maxConnections)
		})
	}
}

func TestPoller_Poll_zoneZeroNotForwardedWhenCorrelatorNil(t *testing.T) {
	ctrl := gomock.NewController(t)
	z := &connection.Connection{Zone: 0, FlowKey: connection.Tuple{SourceAddress: netip.MustParseAddr("8.8.8.8"), DestinationAddress: netip.MustParseAddr("10.0.0.1"), Protocol: 6, SourcePort: 1, DestinationPort: 2}}
	antrea := &connection.Connection{Zone: 65520, FlowKey: connection.Tuple{SourceAddress: netip.MustParseAddr("10.0.0.2"), DestinationAddress: netip.MustParseAddr("10.0.0.3"), Protocol: 6, SourcePort: 3, DestinationPort: 4}}

	mockDumper := connstesting.NewMockConnTrackDumper(ctrl)
	mockDumper.EXPECT().DumpFlows(uint16(0)).Return([]*connection.Connection{z}, 1, nil)
	mockDumper.EXPECT().DumpFlows(gomock.Not(uint16(0))).Return([]*connection.Connection{antrea}, 1, nil)
	mockDumper.EXPECT().GetMaxConnections().Return(100000, nil)

	p := NewPoller(mockDumper, nil, nil, 0, true, false, false)
	out, lens, err := p.Poll()
	require.NoError(t, err)
	assert.Equal(t, []int{1, 1}, lens, "per-zone lengths should include the default zone")
	require.Len(t, out, 1)
	assert.Same(t, antrea, out[0], "only Antrea-zone connection should be returned")
}

// scriptedConntrack is a ConnTrackDumper which replays a timeline of conntrack entries. Time is
// measured in DumpFlows calls: the n-th call (counting from 0, across all zones and polls) returns
// the entries of the requested zone which are present at step n. This makes it possible to create
// or remove an entry between any two dumps of a poll.
type scriptedConntrack struct {
	entries []scriptedEntry
	step    int
}

// scriptedEntry is a conntrack entry which is present for DumpFlows steps [from, to).
type scriptedEntry struct {
	conn     connection.Connection
	from, to int
}

func (s *scriptedConntrack) DumpFlows(zone uint16) ([]*connection.Connection, int, error) {
	var conns []*connection.Connection
	for i := range s.entries {
		e := &s.entries[i]
		if e.conn.Zone == zone && e.from <= s.step && s.step < e.to {
			// Each dump returns new Connection objects, which may be updated by correlation.
			conn := e.conn
			conns = append(conns, &conn)
		}
	}
	s.step++
	return conns, len(conns), nil
}

func (s *scriptedConntrack) GetMaxConnections() (int, error) {
	return 100000, nil
}

// staticProxier resolves a fixed set of Service strings.
type staticProxier map[string]k8sproxy.ServicePortName

func (p staticProxier) GetServiceFlowKeys(string, string) ([]string, []binding.GroupIDType, bool) {
	return nil, nil, false
}

func (p staticProxier) GetServiceByIP(serviceStr string) (k8sproxy.ServicePortName, bool) {
	svc, ok := p[serviceStr]
	return svc, ok
}

type nodePortTestNetwork struct {
	clientIP, nodeIP, podIP, gatewayIP netip.Addr
	antreaZone                         uint16
}

const (
	testNodePort   = 30080
	testPodPort    = 80
	testClientPort = 52142
	testSNATPort   = 28392
	// hostToPodAntreaZoneConnID is the conntrack ID of the Antrea-zone entry of hostToPodConn.
	hostToPodAntreaZoneConnID = 4
)

var (
	testNetworkIPv4 = nodePortTestNetwork{
		clientIP:   netip.MustParseAddr("203.0.113.5"),
		nodeIP:     netip.MustParseAddr("172.18.0.3"),
		podIP:      netip.MustParseAddr("10.244.1.5"),
		gatewayIP:  netip.MustParseAddr("10.244.1.1"),
		antreaZone: openflow.CtZone,
	}
	testNetworkIPv6 = nodePortTestNetwork{
		clientIP:   netip.MustParseAddr("2001:db8::5"),
		nodeIP:     netip.MustParseAddr("fc00:f853:ccd:e793::3"),
		podIP:      netip.MustParseAddr("fd00:10:244:1::5"),
		gatewayIP:  netip.MustParseAddr("fd00:10:244:1::1"),
		antreaZone: openflow.CtZoneV6,
	}
)

// externalToPodConn returns the default-zone and Antrea-zone conntrack entries of a connection
// from an external client to a local Pod through a NodePort Service, DNAT'd by kube-proxy in the
// default zone, and masqueraded to the gateway IP when snat is true (externalTrafficPolicy
// Cluster).
func (n nodePortTestNetwork) externalToPodConn(snat bool, startTime time.Time) (defaultZone, antreaZone connection.Connection) {
	defaultZone = connection.Connection{
		ID:        1,
		Zone:      DefaultZone,
		StartTime: startTime,
		FlowKey: connection.Tuple{
			SourceAddress:      n.clientIP,
			DestinationAddress: n.podIP,
			Protocol:           6,
			SourcePort:         testClientPort,
			DestinationPort:    testPodPort,
		},
		OriginalDestinationAddress: n.nodeIP,
		OriginalDestinationPort:    testNodePort,
	}
	antreaZone = connection.Connection{
		ID:        2,
		Zone:      n.antreaZone,
		StartTime: startTime,
		FlowKey: connection.Tuple{
			SourceAddress:      n.clientIP,
			DestinationAddress: n.podIP,
			Protocol:           6,
			SourcePort:         testClientPort,
			DestinationPort:    testPodPort,
		},
		OriginalDestinationAddress: n.podIP,
		OriginalDestinationPort:    testPodPort,
		TCPState:                   "ESTABLISHED",
	}
	if snat {
		defaultZone.ProxySnatIP, defaultZone.ProxySnatPort = n.gatewayIP, testSNATPort
		antreaZone.FlowKey.SourceAddress, antreaZone.FlowKey.SourcePort = n.gatewayIP, testSNATPort
	}
	return defaultZone, antreaZone
}

// hostToPodConn returns the conntrack entries of a connection from the Node itself to a local Pod,
// which uses the gateway IP as the source, with a source port equal to testSNATPort.
func (n nodePortTestNetwork) hostToPodConn(startTime time.Time) (defaultZone, antreaZone connection.Connection) {
	tuple := connection.Tuple{
		SourceAddress:      n.gatewayIP,
		DestinationAddress: n.podIP,
		Protocol:           6,
		SourcePort:         testSNATPort,
		DestinationPort:    testPodPort,
	}
	defaultZone = connection.Connection{
		ID:                         3,
		Zone:                       DefaultZone,
		StartTime:                  startTime,
		FlowKey:                    tuple,
		OriginalDestinationAddress: n.podIP,
		OriginalDestinationPort:    testPodPort,
	}
	antreaZone = connection.Connection{
		ID:                         hostToPodAntreaZoneConnID,
		Zone:                       n.antreaZone,
		StartTime:                  startTime,
		FlowKey:                    tuple,
		OriginalDestinationAddress: n.podIP,
		OriginalDestinationPort:    testPodPort,
		TCPState:                   "ESTABLISHED",
	}
	return defaultZone, antreaZone
}

// TestPoller_PollCorrelatesExternalToPodConns verifies that external-to-Pod connections are always
// correlated with their default-zone half, regardless of when, relative to the dumps of a poll,
// their conntrack entries are created or removed. It also verifies that a correlation is never
// applied to an unrelated connection reusing the same 5-tuple.
func TestPoller_PollCorrelatesExternalToPodConns(t *testing.T) {
	const numPolls = 5
	svc := k8sproxy.ServicePortName{
		NamespacedName: types.NamespacedName{Namespace: "ns", Name: "svc"},
		Port:           "http",
		Protocol:       v1.ProtocolTCP,
	}
	pod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pod"}}
	never := math.MaxInt

	// Each scenario returns the conntrack entries for the given position, i.e. the DumpFlows
	// step right after which the entries are created or removed.
	type scenario struct {
		name     string
		snatOnly bool
		entries  func(n nodePortTestNetwork, snat bool, step int) []scriptedEntry
		// wantHostToPod is true if a host-to-Pod connection should be in the connection store,
		// in addition to the external-to-Pod connection.
		wantHostToPod bool
	}
	startTime := time.Now()
	// This is the scenario from https://github.com/antrea-io/antrea/issues/8588.
	createdDuringPoll := scenario{
		name: "connection created during a poll",
		entries: func(n nodePortTestNetwork, snat bool, step int) []scriptedEntry {
			dz, az := n.externalToPodConn(snat, startTime)
			return []scriptedEntry{{dz, step + 1, never}, {az, step + 1, never}}
		},
	}
	scenarios := []scenario{
		createdDuringPoll,
		{
			name: "connection removed during a poll",
			entries: func(n nodePortTestNetwork, snat bool, step int) []scriptedEntry {
				dz, az := n.externalToPodConn(snat, startTime)
				return []scriptedEntry{{dz, 0, step + 1}, {az, 0, step + 1}}
			},
		},
		{
			name: "default-zone half removed before Antrea-zone half",
			entries: func(n nodePortTestNetwork, snat bool, step int) []scriptedEntry {
				dz, az := n.externalToPodConn(snat, startTime)
				return []scriptedEntry{{dz, 0, step + 1}, {az, 0, never}}
			},
		},
		{
			name:     "5-tuple reused by a host-to-Pod connection",
			snatOnly: true,
			entries: func(n nodePortTestNetwork, snat bool, step int) []scriptedEntry {
				dz, az := n.externalToPodConn(snat, startTime)
				hostDZ, hostAZ := n.hostToPodConn(startTime.Add(time.Minute))
				return []scriptedEntry{{dz, 0, step + 1}, {az, 0, step + 1}, {hostDZ, step + 1, never}, {hostAZ, step + 1, never}}
			},
			wantHostToPod: true,
		},
	}

	// Sweep all the positions within the second poll: one per DumpFlows call.
	dumpsPerPoll := len(NewPoller(nil, nil, nil, 0, true, true, false).zones) + 1
	runSubtests := func(n nodePortTestNetwork, family string, snat bool, sc scenario) {
		proxier := staticProxier{fmt.Sprintf("%s:%d/TCP", n.nodeIP, testNodePort): svc}
		for pos := range dumpsPerPoll {
			step := dumpsPerPoll + pos
			name := fmt.Sprintf("%s/SNAT=%t/%s/after dump %d of poll", family, snat, sc.name, pos)
			t.Run(name, func(t *testing.T) {
				ctrl := gomock.NewController(t)
				podStore := objectstoretest.NewMockPodStore(ctrl)
				podStore.EXPECT().GetPodByIPAndTime(gomock.Any(), gomock.Any()).DoAndReturn(
					func(ip string, _ time.Time) (*v1.Pod, bool) {
						return pod, ip == n.podIP.String()
					}).AnyTimes()
				cfg := testFlowExporterOptions
				cfg.NetworkPolicyReadyTime = startTime.Add(time.Hour)
				store := NewConntrackConnectionStore(nil, podStore, proxier, cfg)

				dumper := &scriptedConntrack{entries: sc.entries(n, snat, step)}
				p := NewPoller(dumper, nil, NewFromExternalCorrelator(proxier, nil, nil), 0, true, true, false)
				seen := false
				for i := range numPolls {
					conns, _, err := p.Poll()
					require.NoError(t, err)
					for _, conn := range conns {
						if conn.ID == hostToPodAntreaZoneConnID {
							assert.False(t, conn.IsFromExternal, "poll %d: host-to-Pod connection must not be correlated", i)
							continue
						}
						seen = true
						assert.True(t, conn.IsFromExternal, "poll %d: connection should be correlated", i)
						assert.Equal(t, n.clientIP, conn.FlowKey.SourceAddress, "poll %d: unexpected source IP", i)
						assert.Equal(t, uint16(testClientPort), conn.FlowKey.SourcePort, "poll %d: unexpected source port", i)
						assert.Equal(t, n.nodeIP, conn.OriginalDestinationAddress, "poll %d: unexpected original destination IP", i)
						assert.Equal(t, uint16(testNodePort), conn.OriginalDestinationPort, "poll %d: unexpected original destination port", i)
					}
					require.NoError(t, store.AddOrUpdateConns(conns))
				}
				require.True(t, seen, "the external-to-Pod connection should have been polled")

				// The store should have exactly one record for the external-to-Pod
				// connection, with the Service information.
				wantConns := 1
				if sc.wantHostToPod {
					wantConns = 2
				}
				assert.Len(t, store.connections, wantConns)
				for key, conn := range store.connections {
					if key.SourceAddress == n.gatewayIP {
						assert.True(t, sc.wantHostToPod, "unexpected connection from the gateway IP: %+v", conn)
						assert.False(t, conn.IsFromExternal)
						assert.Empty(t, conn.DestinationServicePortName)
						continue
					}
					assert.True(t, conn.IsFromExternal)
					assert.Equal(t, svc.String(), conn.DestinationServicePortName)
					assert.Equal(t, pod.Name, conn.DestinationPodName)
				}
			})
		}
	}

	for _, snat := range []bool{false, true} {
		for _, sc := range scenarios {
			if sc.snatOnly && !snat {
				continue
			}
			runSubtests(testNetworkIPv4, "IPv4", snat, sc)
		}
	}
	// Correlation does not depend on the IP family, and the poller always dumps both the IPv4 and
	// IPv6 Antrea zones: a single IPv6 scenario is enough to cover the IPv6 addresses and zone.
	runSubtests(testNetworkIPv6, "IPv6", true, createdDuringPoll)
}
