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
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"

	"antrea.io/antrea/v2/pkg/agent/flowexporter/connection"
	"antrea.io/antrea/v2/pkg/agent/nodeportlocal/portcache"
	"antrea.io/antrea/v2/pkg/agent/openflow"
	binding "antrea.io/antrea/v2/pkg/ovs/openflow"
	k8sproxy "antrea.io/antrea/v2/third_party/proxy"
)

func contains(c *FromExternalCorrelator, conn *connection.Connection) bool {
	c.lock.Lock()
	defer c.lock.Unlock()
	_, exists := c.connections[keyFromDefaultZoneConn(conn)]
	return exists
}

func TestFromExternalCorrelator(t *testing.T) {
	t.Run("add", func(t *testing.T) {
		store := NewFromExternalCorrelator(nil, nil)
		refTime := time.Now()
		defaultZoneConn := &connection.Connection{
			StartTime: refTime,
			StopTime:  refTime,
			FlowKey: connection.Tuple{
				SourceAddress:      netip.MustParseAddr("172.18.0.1"),
				DestinationAddress: netip.MustParseAddr("10.244.2.2"),
				Protocol:           6,
				SourcePort:         52142,
				DestinationPort:    80},
			Mark:          openflow.ServiceCTMark.GetValue(),
			ProxySnatIP:   netip.MustParseAddr("172.18.0.2"),
			ProxySnatPort: uint16(28392),
		}
		store.add(defaultZoneConn)
		assert.True(t, contains(store, defaultZoneConn), "Expected store to contain newly added connection")
	})
	t.Run("popMatching", func(t *testing.T) {
		t.Run("Has Match", func(t *testing.T) {
			store := NewFromExternalCorrelator(nil, nil)
			refTime := time.Now()
			defaultZoneConn := &connection.Connection{
				StartTime: refTime,
				StopTime:  refTime,
				FlowKey: connection.Tuple{
					SourceAddress:      netip.MustParseAddr("172.18.0.1"),
					DestinationAddress: netip.MustParseAddr("10.244.2.2"),
					Protocol:           6,
					SourcePort:         52142,
					DestinationPort:    80},
				Mark:          openflow.ServiceCTMark.GetValue(),
				ProxySnatIP:   netip.MustParseAddr("172.18.0.2"),
				ProxySnatPort: uint16(28392),
			}
			antreaZeroConn := &connection.Connection{
				StartTime: refTime,
				StopTime:  refTime,
				FlowKey: connection.Tuple{
					SourceAddress:      netip.MustParseAddr("10.244.2.1"),
					DestinationAddress: netip.MustParseAddr("10.244.2.2"),
					Protocol:           6,
					SourcePort:         28392,
					DestinationPort:    80},
				Mark:          openflow.ServiceCTMark.GetValue(),
				ProxySnatIP:   netip.MustParseAddr("172.18.0.2"),
				ProxySnatPort: uint16(28392),
			}
			store.add(defaultZoneConn)
			match, ok := store.popMatching(antreaZeroConn)
			assert.True(t, ok, "Expected a matching default-zone connection to have been stored")
			assert.Equal(t, defaultZoneSnapshotFromConn(defaultZoneConn), match)
		})
		t.Run("Does Not Have Match", func(t *testing.T) {
			store := NewFromExternalCorrelator(nil, nil)
			refTime := time.Now()
			defaultZoneConn := &connection.Connection{
				StartTime: refTime,
				StopTime:  refTime,
				FlowKey: connection.Tuple{
					SourceAddress:      netip.MustParseAddr("172.18.0.1"),
					DestinationAddress: netip.MustParseAddr("10.244.2.2"),
					Protocol:           6,
					SourcePort:         52142,
					DestinationPort:    80},
				Mark:          openflow.ServiceCTMark.GetValue(),
				ProxySnatIP:   netip.MustParseAddr("172.18.0.2"),
				ProxySnatPort: uint16(28392),
			}
			// Different source port — should not match.
			antreaZeroConn := &connection.Connection{
				StartTime: refTime,
				StopTime:  refTime,
				FlowKey: connection.Tuple{
					SourceAddress:      netip.MustParseAddr("10.244.2.1"),
					DestinationAddress: netip.MustParseAddr("10.244.2.2"),
					Protocol:           6,
					SourcePort:         55555,
					DestinationPort:    80},
				Mark:          openflow.ServiceCTMark.GetValue(),
				ProxySnatIP:   netip.MustParseAddr("172.18.0.2"),
				ProxySnatPort: uint16(28392),
			}
			store.add(defaultZoneConn)
			_, ok := store.popMatching(antreaZeroConn)
			assert.False(t, ok, "Expected store to return no match")
		})
	})
	t.Run("Expires stale records", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			store := NewFromExternalCorrelator(nil, nil)
			stopCh := make(chan struct{})
			t.Cleanup(func() { close(stopCh) })
			go store.Run(stopCh)

			refTime := time.Now()
			defaultZoneConn := &connection.Connection{
				StartTime: refTime,
				StopTime:  refTime,
				FlowKey: connection.Tuple{
					SourceAddress:      netip.MustParseAddr("172.18.0.1"),
					DestinationAddress: netip.MustParseAddr("10.244.2.2"),
					Protocol:           6,
					SourcePort:         52142,
					DestinationPort:    80},
				Mark:          openflow.ServiceCTMark.GetValue(),
				ProxySnatIP:   netip.MustParseAddr("172.18.0.2"),
				ProxySnatPort: uint16(28392),
			}
			store.add(defaultZoneConn)
			assert.True(t, contains(store, defaultZoneConn), "expected entry before expiry")

			// Advance virtual time past defaultTTL and allow cleanUpLoop to tick.
			time.Sleep(defaultTTL + 2*defaultCleanUpInterval)
			synctest.Wait()

			assert.False(t, contains(store, defaultZoneConn), "expected store to expire old records")
		})
	})
}

type mockProxier struct {
}

func (m mockProxier) GetServiceFlowKeys(serviceName, namespace string) ([]string, []binding.GroupIDType, bool) {
	return nil, nil, false
}

func (m mockProxier) GetServiceByIP(serviceStr string) (k8sproxy.ServicePortName, bool) {
	if serviceStr == "172.18.0.111:12345/TCP" {
		return k8sproxy.ServicePortName{}, true
	}
	return k8sproxy.ServicePortName{}, false
}

func TestFromExternalCorrelator_IngestDefaultZoneFlow(t *testing.T) {
	nonDefaultZoneConn := &connection.Connection{Zone: 65220}
	refTime := time.Now()
	defaultZoneConn := &connection.Connection{
		Zone:                       0,
		OriginalDestinationAddress: netip.MustParseAddr("172.18.0.3"),
		OriginalDestinationPort:    12345,
		StartTime:                  refTime.Add(-(time.Second * 50)),
		StopTime:                   refTime.Add(-(time.Second * 30)),
		LastExportTime:             refTime.Add(-(time.Second * 50)),
		FlowKey: connection.Tuple{
			SourceAddress:      netip.MustParseAddr("172.18.0.1"),
			DestinationAddress: netip.MustParseAddr("10.244.2.2"),
			Protocol:           6,
			SourcePort:         52142,
			DestinationPort:    80},
		Mark:          openflow.ServiceCTMark.GetValue(),
		ProxySnatIP:   netip.MustParseAddr("172.18.0.2"),
		ProxySnatPort: uint16(28392),
	}
	invalidProtocolConn := &connection.Connection{
		Zone:                       0,
		OriginalDestinationAddress: netip.MustParseAddr("172.18.0.3"),
		OriginalDestinationPort:    12345,
		StartTime:                  refTime.Add(-(time.Second * 50)),
		StopTime:                   refTime.Add(-(time.Second * 30)),
		LastExportTime:             refTime.Add(-(time.Second * 50)),
		FlowKey: connection.Tuple{
			SourceAddress:      netip.MustParseAddr("172.18.0.1"),
			DestinationAddress: netip.MustParseAddr("10.244.2.2"),
			Protocol:           99,
			SourcePort:         52142,
			DestinationPort:    80},
		Mark:          openflow.ServiceCTMark.GetValue(),
		ProxySnatIP:   netip.MustParseAddr("172.18.0.2"),
		ProxySnatPort: uint16(28392),
	}
	hasServiceConn := &connection.Connection{
		Zone:                       0,
		OriginalDestinationAddress: netip.MustParseAddr("172.18.0.111"),
		OriginalDestinationPort:    12345,
		StartTime:                  refTime.Add(-(time.Second * 50)),
		StopTime:                   refTime.Add(-(time.Second * 30)),
		LastExportTime:             refTime.Add(-(time.Second * 50)),
		FlowKey: connection.Tuple{
			SourceAddress:      netip.MustParseAddr("172.18.0.1"),
			DestinationAddress: netip.MustParseAddr("10.244.2.2"),
			Protocol:           6,
			SourcePort:         52142,
			DestinationPort:    80},
		Mark:          openflow.ServiceCTMark.GetValue(),
		ProxySnatIP:   netip.MustParseAddr("172.18.0.2"),
		ProxySnatPort: uint16(28392),
	}
	mp := mockProxier{}
	testCases := []struct {
		name   string
		conn   *connection.Connection
		stored bool
	}{
		{
			name:   "Non-default-zone connections",
			conn:   nonDefaultZoneConn,
			stored: false,
		},
		{
			name:   "Nil connection",
			conn:   nil,
			stored: false,
		},
		{
			name:   "Nil Proxier",
			conn:   defaultZoneConn,
			stored: true,
		},
		{
			name:   "Unknown protocol",
			conn:   invalidProtocolConn,
			stored: false,
		},
		{
			name:   "No associated service",
			conn:   defaultZoneConn,
			stored: false,
		},
		{
			name:   "Associated service found",
			conn:   hasServiceConn,
			stored: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var correlator *FromExternalCorrelator
			if tc.name == "Nil Proxier" {
				correlator = NewFromExternalCorrelator(nil, nil)
			} else {
				correlator = NewFromExternalCorrelator(mp, nil)
			}
			correlator.IngestDefaultZoneFlow(tc.conn)

			if tc.stored {
				assert.Equal(t, 1, len(correlator.connections), "Expected connection to be stored in correlator")
			} else {
				assert.Equal(t, 0, len(correlator.connections), "Expected connection not to be stored in correlator")
			}
		})
	}
}

// mockNPLQuerier implements portcache.NPLQuerier. It resolves a single known NPL node port.
type mockNPLQuerier struct {
	nodePort int
	protocol string
	service  string
}

var _ portcache.NPLQuerier = mockNPLQuerier{}

func (m mockNPLQuerier) GetServiceForNPLPort(nodePort int, protocol string, isIPv6 bool) string {
	if nodePort == m.nodePort && protocol == m.protocol {
		return m.service
	}
	return ""
}

// TestFromExternalCorrelator_NodePortLocal verifies that a NodePortLocal external-to-Pod flow is
// correlated: the default-zone flow (OriginalDestination = nodeIP:nplPort) is retained via the NPL
// querier, and when the Antrea-zone half arrives, its OriginalDestination is restored to nodeIP:nplPort
// and marked as from-external. This will let the connection store resolve the NPL Service name and
// export destination_service_ip/port correctly.
func TestFromExternalCorrelator_NodePortLocal(t *testing.T) {
	const nplNodePort = 40000
	clientIP := netip.MustParseAddr("172.18.0.1")
	nodeIP := netip.MustParseAddr("172.18.0.5")
	podIP := netip.MustParseAddr("10.244.2.2")
	// The proxier does not know about NPL node ports, so GetServiceByIP always fails here.
	npl := mockNPLQuerier{nodePort: nplNodePort, protocol: "TCP", service: "default/npl-svc"}
	correlator := NewFromExternalCorrelator(mockProxier{}, npl)

	// Default-zone (pre-DNAT) NPL flow: client -> nodeIP:nplPort, DNAT'd to podIP:podPort, no SNAT.
	defaultZoneConn := &connection.Connection{
		Zone:                       DefaultZone,
		OriginalDestinationAddress: nodeIP,
		OriginalDestinationPort:    nplNodePort,
		FlowKey: connection.Tuple{
			SourceAddress:      clientIP,
			DestinationAddress: podIP,
			Protocol:           6,
			SourcePort:         52142,
			DestinationPort:    8080,
		},
	}
	correlator.IngestDefaultZoneFlow(defaultZoneConn)
	assert.Len(t, correlator.connections, 1, "Expected NPL default-zone flow to be retained via the NPL querier")

	// Antrea-zone NPL flow: DNAT already applied, so OriginalDestination is the Pod endpoint and
	// the source IP is still the external client (NPL does not SNAT).
	antreaZoneConn := connection.Connection{
		Zone:                       65520,
		OriginalDestinationAddress: podIP,
		OriginalDestinationPort:    8080,
		FlowKey: connection.Tuple{
			SourceAddress:      clientIP,
			DestinationAddress: podIP,
			Protocol:           6,
			SourcePort:         52142,
			DestinationPort:    8080,
		},
		DestinationPodName:      "pod1",
		DestinationPodNamespace: "ns1",
	}
	got := correlator.CorrelateIfExternal(&antreaZoneConn)
	assert.True(t, got, "Expected the NPL Antrea-zone flow to be correlated")
	assert.True(t, antreaZoneConn.IsFromExternal, "Expected the correlated flow to be marked as from-external")
	assert.Equal(t, clientIP, antreaZoneConn.FlowKey.SourceAddress, "Expected the external client source IP to be preserved")
	assert.Equal(t, nodeIP, antreaZoneConn.OriginalDestinationAddress, "Expected OriginalDestinationAddress to be restored to the node IP")
	assert.Equal(t, uint16(nplNodePort), antreaZoneConn.OriginalDestinationPort, "Expected OriginalDestinationPort to be restored to the NPL node port")
	assert.Len(t, correlator.connections, 0, "Expected the default-zone flow to be consumed by correlation")
}

func TestCorrelateIfExternal(t *testing.T) {
	externalIP := netip.MustParseAddr("172.18.0.1")
	refTime := time.Now()
	hasServiceConn := &connection.Connection{
		Zone:                       0,
		OriginalDestinationAddress: netip.MustParseAddr("172.18.0.111"),
		OriginalDestinationPort:    12345,
		StartTime:                  refTime.Add(-(time.Second * 50)),
		StopTime:                   refTime.Add(-(time.Second * 30)),
		LastExportTime:             refTime.Add(-(time.Second * 50)),
		FlowKey: connection.Tuple{
			SourceAddress:      externalIP,
			DestinationAddress: netip.MustParseAddr("10.244.2.2"),
			Protocol:           6,
			SourcePort:         52142,
			DestinationPort:    80},
		Mark:          openflow.ServiceCTMark.GetValue(),
		ProxySnatIP:   netip.MustParseAddr("172.18.0.2"),
		ProxySnatPort: uint16(28392),
	}
	gatewayIP := netip.MustParseAddr("10.244.2.1")
	snatIP := netip.MustParseAddr("172.18.0.2")
	antreaZoneConn := connection.Connection{
		OriginalDestinationAddress: netip.MustParseAddr("10.244.2.2"),
		OriginalDestinationPort:    80,
		StartTime:                  refTime.Add(-(time.Second * 50)),
		StopTime:                   refTime.Add(-(time.Second * 30)),
		LastExportTime:             refTime.Add(-(time.Second * 50)),
		FlowKey: connection.Tuple{
			SourceAddress:      gatewayIP,
			DestinationAddress: netip.MustParseAddr("10.244.2.2"),
			Protocol:           6,
			SourcePort:         28392,
			DestinationPort:    80},
		Mark:                    openflow.ServiceCTMark.GetValue(),
		Labels:                  []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1},
		ProxySnatIP:             snatIP,
		ProxySnatPort:           uint16(28392),
		Zone:                    65520,
		OriginalPackets:         0xfff,
		DestinationPodName:      "pod1",
		DestinationPodNamespace: "ns1",
	}

	correlator := NewFromExternalCorrelator(mockProxier{}, nil)

	got := correlator.CorrelateIfExternal(nil)
	assert.False(t, got, "Expected invalid connections to not get correlated")

	// Confirm no correlation when no matching default-zone connections previously stored
	got = correlator.CorrelateIfExternal(&antreaZoneConn)
	assert.False(t, got, "Expected no correlation when the store is empty")
	assert.Equal(t, gatewayIP, antreaZoneConn.FlowKey.SourceAddress, "Expected connection to not have changed")

	// Confirm correlation
	correlator.IngestDefaultZoneFlow(hasServiceConn)
	got = correlator.CorrelateIfExternal(&antreaZoneConn)
	assert.True(t, got, "Expected correlation when corresponding zone zero flow added to store")

	assert.Equal(t, externalIP, antreaZoneConn.FlowKey.SourceAddress, "Expected connection to have external source IP")
	assert.Len(t, correlator.connections, 0, "Expected default-zone connection to be popped from store")

	// Simulate the next poll cycle: the kernel still has the zone-0 entry so IngestDefaultZoneFlow
	// re-populates the correlator. CorrelateIfExternal must be a no-op for an already-correlated
	// connection (IsFromExternal == true) so the zone-0 entry is not consumed and no fields are
	// overwritten.
	correlator.IngestDefaultZoneFlow(hasServiceConn)
	assert.Len(t, correlator.connections, 1, "Expected zone-0 entry to be re-populated for next poll cycle")
	got = correlator.CorrelateIfExternal(&antreaZoneConn)
	assert.False(t, got, "Expected already-correlated connection to be skipped")
	assert.Len(t, correlator.connections, 1, "Expected zone-0 entry to remain unconsumed when connection is already correlated")
	assert.Equal(t, externalIP, antreaZoneConn.FlowKey.SourceAddress, "Expected source IP to remain unchanged")
}

// TestCorrelateExternal_SymmetricDefaultZoneClearsAntreaProxySnat documents that when the zone-0
// snapshot has no proxy SNAT (e.g. externalTrafficPolicy Local / symmetric conntrack), correlation
// overwrites any stale ProxySnatIP/ProxySnatPort on the Antrea-zone connection so exported flows
// do not report a spurious masquerade.
func TestCorrelateExternal_SymmetricDefaultZoneClearsAntreaProxySnat(t *testing.T) {
	ext := netip.MustParseAddr("203.0.113.10")
	pod := netip.MustParseAddr("10.244.2.2")
	snap := defaultZoneSnapshot{
		sourceIP:                ext,
		sourcePort:              50000,
		proxySnatIP:             netip.Addr{},
		proxySnatPort:           0,
		originalDestinationIP:   netip.MustParseAddr("172.18.0.50"),
		originalDestinationPort: 30080,
	}
	antrea := &connection.Connection{
		FlowKey: connection.Tuple{
			SourceAddress:      netip.MustParseAddr("10.244.2.1"),
			DestinationAddress: pod,
			Protocol:           6,
			SourcePort:         50000,
			DestinationPort:    80,
		},
		ProxySnatIP:   netip.MustParseAddr("10.244.2.1"),
		ProxySnatPort: 50000,
	}
	correlateExternal(snap, antrea)
	assert.Equal(t, ext, antrea.FlowKey.SourceAddress)
	assert.False(t, antrea.ProxySnatIP.IsValid())
	assert.Equal(t, uint16(0), antrea.ProxySnatPort)
	assert.Equal(t, snap.originalDestinationIP, antrea.OriginalDestinationAddress)
	assert.Equal(t, snap.originalDestinationPort, antrea.OriginalDestinationPort)
	assert.True(t, antrea.IsFromExternal, "IsFromExternal must be set even when no SNAT was applied (ETP=Local)")
}

// TestFromExternalCorrelator_DefaultZoneKeyWithoutProxySNAT verifies that when conntrack has a
// symmetric reply tuple (no kube-proxy/Antrea SNAT), NetlinkFlowToAntreaConnection leaves
// ProxySnatPort at 0 and the correlator indexes the zone-0 entry by the real client source port
// so that keyFromAntreaZoneConn (which always keys by FlowKey.SourcePort) can match it.
func TestFromExternalCorrelator_DefaultZoneKeyWithoutProxySNAT(t *testing.T) {
	podIP := netip.MustParseAddr("10.244.2.2")
	extClient := netip.MustParseAddr("203.0.113.5")
	clientPort := uint16(40000)
	conn := &connection.Connection{
		Zone: 0,
		FlowKey: connection.Tuple{
			SourceAddress:      extClient,
			DestinationAddress: podIP,
			Protocol:           6,
			SourcePort:         clientPort,
			DestinationPort:    80,
		},
		OriginalDestinationAddress: netip.MustParseAddr("172.18.0.111"),
		OriginalDestinationPort:    12345,
		ProxySnatIP:                netip.Addr{},
		ProxySnatPort:              0,
		Mark:                       openflow.ServiceCTMark.GetValue(),
	}
	correlator := NewFromExternalCorrelator(mockProxier{}, nil)
	correlator.IngestDefaultZoneFlow(conn)
	key := keyFromDefaultZoneConn(conn)
	_, exists := correlator.connections[key]
	assert.True(t, exists, "zone-0 entry should be stored when Service lookup succeeds")
	// Non-SNAT: key uses the real client source IP and port so they match what
	// keyFromAntreaZoneConn produces from the Antrea-zone FlowKey.
	assert.Equal(t, extClient, key.srcIP)
	assert.Equal(t, clientPort, key.port)
	assert.Equal(t, conn.FlowKey.DestinationPort, key.dstPort)
	assert.Equal(t, conn.FlowKey.Protocol, key.protocol)
}

// TestFromExternalCorrelator_SingleNodeCorrelation verifies that a zone-0 entry with no proxy
// SNAT (symmetric conntrack, e.g. NodePort externalTrafficPolicy=Local or NodePortLocal) is
// correctly correlated with its Antrea-zone counterpart.
func TestFromExternalCorrelator_SingleNodeCorrelation(t *testing.T) {
	extClient := netip.MustParseAddr("203.0.113.5")
	podIP := netip.MustParseAddr("10.244.2.2")
	nodeIP := netip.MustParseAddr("172.18.0.111")
	clientPort := uint16(40000)

	// Zone-0 connection: no SNAT, ProxySnatPort == 0.
	defaultZoneConn := &connection.Connection{
		Zone: 0,
		FlowKey: connection.Tuple{
			SourceAddress:      extClient,
			DestinationAddress: podIP,
			Protocol:           6,
			SourcePort:         clientPort,
			DestinationPort:    80,
		},
		OriginalDestinationAddress: nodeIP,
		OriginalDestinationPort:    12345,
		ProxySnatIP:                netip.Addr{},
		ProxySnatPort:              0,
		Mark:                       openflow.ServiceCTMark.GetValue(),
	}

	// Antrea-zone connection: no SNAT means TupleOrig.src is unchanged — the real external
	// client IP. ProxySnatIP/Port are both zero (no masquerade).
	antreaZoneConn := &connection.Connection{
		Zone: 65520,
		FlowKey: connection.Tuple{
			SourceAddress:      extClient,
			DestinationAddress: podIP,
			Protocol:           6,
			SourcePort:         clientPort,
			DestinationPort:    80,
		},
		OriginalDestinationAddress: podIP,
		OriginalDestinationPort:    80,
	}

	correlator := NewFromExternalCorrelator(mockProxier{}, nil)
	correlator.IngestDefaultZoneFlow(defaultZoneConn)

	correlated := correlator.CorrelateIfExternal(antreaZoneConn)
	assert.True(t, correlated, "Expected symmetric-NAT zone-0 connection to be correlated")
	assert.Equal(t, extClient, antreaZoneConn.FlowKey.SourceAddress, "Expected original external client IP")
	assert.Equal(t, clientPort, antreaZoneConn.FlowKey.SourcePort, "Expected original client source port")
	assert.Equal(t, nodeIP, antreaZoneConn.OriginalDestinationAddress, "Expected original destination IP (node IP)")
	assert.Equal(t, uint16(12345), antreaZoneConn.OriginalDestinationPort, "Expected original destination port (NodePort)")
	assert.False(t, antreaZoneConn.ProxySnatIP.IsValid(), "Expected no proxy SNAT IP when no SNAT was applied")
	assert.Equal(t, uint16(0), antreaZoneConn.ProxySnatPort, "Expected no proxy SNAT port when no SNAT was applied")
	assert.True(t, antreaZoneConn.IsFromExternal, "Expected IsFromExternal to be set")
	assert.Len(t, correlator.connections, 0, "Expected zone-0 entry to be consumed after correlation")
}

// TestFromExternalCorrelator_NoCollisionOnSamePort verifies that two concurrent flows to the
// same Pod IP sharing the same SNAT/source port but targeting different destination ports or
// using different protocols are stored and correlated independently without colliding in the map.
func TestFromExternalCorrelator_NoCollisionOnSamePort(t *testing.T) {
	podIP := netip.MustParseAddr("10.244.2.2")
	extClientA := netip.MustParseAddr("203.0.113.1")
	extClientB := netip.MustParseAddr("203.0.113.2")
	// Both clients happen to be SNATed to the same ephemeral port.
	snatPort := uint16(45678)

	// Flow A: TCP to port 80.
	defaultZoneA := &connection.Connection{
		Zone: 0,
		FlowKey: connection.Tuple{
			SourceAddress:      extClientA,
			DestinationAddress: podIP,
			Protocol:           6,
			SourcePort:         50001,
			DestinationPort:    80,
		},
		OriginalDestinationAddress: netip.MustParseAddr("172.18.0.111"),
		OriginalDestinationPort:    12345,
		ProxySnatIP:                netip.MustParseAddr("172.18.0.2"),
		ProxySnatPort:              snatPort,
		Mark:                       openflow.ServiceCTMark.GetValue(),
	}

	// Flow B: TCP to port 443 — same dstIP and snatPort as A but different dstPort.
	defaultZoneB := &connection.Connection{
		Zone: 0,
		FlowKey: connection.Tuple{
			SourceAddress:      extClientB,
			DestinationAddress: podIP,
			Protocol:           6,
			SourcePort:         50002,
			DestinationPort:    443,
		},
		OriginalDestinationAddress: netip.MustParseAddr("172.18.0.111"),
		OriginalDestinationPort:    12345,
		ProxySnatIP:                netip.MustParseAddr("172.18.0.2"),
		ProxySnatPort:              snatPort,
		Mark:                       openflow.ServiceCTMark.GetValue(),
	}

	correlator := NewFromExternalCorrelator(nil, nil)
	correlator.add(defaultZoneA)
	correlator.add(defaultZoneB)
	assert.Len(t, correlator.connections, 2, "flows with different dstPorts must occupy separate map entries")

	snatIP := netip.MustParseAddr("172.18.0.2")

	// Antrea-zone counterpart for flow A (TCP/80): ProxySnatIP is the masquerade IP, which is
	// used as srcIP in the correlator key.
	antreaZoneA := &connection.Connection{
		FlowKey: connection.Tuple{
			SourceAddress:      netip.MustParseAddr("10.244.2.1"),
			DestinationAddress: podIP,
			Protocol:           6,
			SourcePort:         snatPort,
			DestinationPort:    80,
		},
		ProxySnatIP:   snatIP,
		ProxySnatPort: snatPort,
	}

	// Antrea-zone counterpart for flow B (TCP/443).
	antreaZoneB := &connection.Connection{
		FlowKey: connection.Tuple{
			SourceAddress:      netip.MustParseAddr("10.244.2.1"),
			DestinationAddress: podIP,
			Protocol:           6,
			SourcePort:         snatPort,
			DestinationPort:    443,
		},
		ProxySnatIP:   snatIP,
		ProxySnatPort: snatPort,
	}

	corrA := correlator.CorrelateIfExternal(antreaZoneA)
	assert.True(t, corrA, "flow A should correlate")
	assert.Equal(t, extClientA, antreaZoneA.FlowKey.SourceAddress, "flow A must resolve to its own external client IP")

	corrB := correlator.CorrelateIfExternal(antreaZoneB)
	assert.True(t, corrB, "flow B should correlate")
	assert.Equal(t, extClientB, antreaZoneB.FlowKey.SourceAddress, "flow B must resolve to its own external client IP")

	assert.Len(t, correlator.connections, 0, "both entries should be consumed after correlation")
}

// TestFromExternalCorrelator_NoCollisionNonSNATDifferentClients verifies that two concurrent non-SNAT
// flows from different external clients to the same Pod IP that happen to share the same source port are
// stored and correlated independently. Without srcIP in the key they would collide.
func TestFromExternalCorrelator_NoCollisionNonSNATDifferentClients(t *testing.T) {
	podIP := netip.MustParseAddr("10.244.2.2")
	nodeIP := netip.MustParseAddr("172.18.0.111")
	extClientA := netip.MustParseAddr("203.0.113.1")
	extClientB := netip.MustParseAddr("203.0.113.2")
	// Both external clients happen to use the same source port.
	clientPort := uint16(40000)

	defaultZoneA := &connection.Connection{
		Zone: 0,
		FlowKey: connection.Tuple{
			SourceAddress:      extClientA,
			DestinationAddress: podIP,
			Protocol:           6,
			SourcePort:         clientPort,
			DestinationPort:    80,
		},
		OriginalDestinationAddress: nodeIP,
		OriginalDestinationPort:    12345,
		ProxySnatIP:                netip.Addr{},
		ProxySnatPort:              0,
		Mark:                       openflow.ServiceCTMark.GetValue(),
	}

	defaultZoneB := &connection.Connection{
		Zone: 0,
		FlowKey: connection.Tuple{
			SourceAddress:      extClientB,
			DestinationAddress: podIP,
			Protocol:           6,
			SourcePort:         clientPort,
			DestinationPort:    80,
		},
		OriginalDestinationAddress: nodeIP,
		OriginalDestinationPort:    12345,
		ProxySnatIP:                netip.Addr{},
		ProxySnatPort:              0,
		Mark:                       openflow.ServiceCTMark.GetValue(),
	}

	correlator := NewFromExternalCorrelator(nil, nil)
	correlator.add(defaultZoneA)
	correlator.add(defaultZoneB)
	assert.Len(t, correlator.connections, 2, "non-SNAT flows from different clients must occupy separate map entries")

	// Antrea-zone counterpart for flow A: no SNAT, so FlowKey.SourceAddress is the real external
	// client IP and ProxySnatIP is zero.
	antreaZoneA := &connection.Connection{
		FlowKey: connection.Tuple{
			SourceAddress:      extClientA,
			DestinationAddress: podIP,
			Protocol:           6,
			SourcePort:         clientPort,
			DestinationPort:    80,
		},
	}

	antreaZoneB := &connection.Connection{
		FlowKey: connection.Tuple{
			SourceAddress:      extClientB,
			DestinationAddress: podIP,
			Protocol:           6,
			SourcePort:         clientPort,
			DestinationPort:    80,
		},
	}

	corrA := correlator.CorrelateIfExternal(antreaZoneA)
	assert.True(t, corrA, "non-SNAT flow A should correlate")
	assert.Equal(t, extClientA, antreaZoneA.FlowKey.SourceAddress, "flow A source IP must remain the external client IP after correlation")

	corrB := correlator.CorrelateIfExternal(antreaZoneB)
	assert.True(t, corrB, "non-SNAT flow B should correlate")
	assert.Equal(t, extClientB, antreaZoneB.FlowKey.SourceAddress, "flow B source IP must remain the external client IP after correlation")

	assert.Len(t, correlator.connections, 0, "both non-SNAT entries should be consumed after correlation")
}
