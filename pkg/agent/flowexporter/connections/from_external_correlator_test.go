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
		store := NewFromExternalCorrelator(nil)
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
			store := NewFromExternalCorrelator(nil)
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
				ProxySnatIP:   netip.MustParseAddr("10.244.2.1"),
				ProxySnatPort: uint16(28392),
			}
			store.add(defaultZoneConn)
			match, ok := store.popMatching(antreaZeroConn)
			assert.True(t, ok, "Expected a matching default-zone connection to have been stored")
			assert.Equal(t, defaultZoneSnapshotFromConn(defaultZoneConn), match)
		})
		t.Run("Does Not Have Match", func(t *testing.T) {
			store := NewFromExternalCorrelator(nil)
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
					SourcePort:         55555,
					DestinationPort:    80},
				Mark:          openflow.ServiceCTMark.GetValue(),
				ProxySnatIP:   netip.MustParseAddr("10.244.2.1"),
				ProxySnatPort: uint16(28392),
			}
			store.add(defaultZoneConn)
			_, ok := store.popMatching(antreaZeroConn)
			assert.False(t, ok, "Expected store to return no match")
		})
	})
	t.Run("Stale entries expire via TTL cleanup loop", func(t *testing.T) {
		// RemoveStaleDefaultZoneFlow was removed: the correlator no longer needs explicit
		// cleanup because correlation now happens in the poller before fan-out. Stale
		// default-zone entries that were never matched are evicted by the TTL cleanup loop.
		// This is covered by the "Expires stale records" sub-test below.
	})
	t.Run("Expires stale records", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			store := NewFromExternalCorrelator(nil)
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
				correlator = NewFromExternalCorrelator(nil)
			} else {
				correlator = NewFromExternalCorrelator(mp)
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
		ProxySnatIP:             netip.MustParseAddr("10.244.2.1"),
		ProxySnatPort:           uint16(28392),
		Zone:                    65520,
		OriginalPackets:         0xfff,
		DestinationPodName:      "pod1",
		DestinationPodNamespace: "ns1",
	}

	correlator := NewFromExternalCorrelator(mockProxier{})

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
	correlator := NewFromExternalCorrelator(mockProxier{})
	correlator.IngestDefaultZoneFlow(conn)
	key := keyFromDefaultZoneConn(conn)
	_, exists := correlator.connections[key]
	assert.True(t, exists, "zone-0 entry should be stored when Service lookup succeeds")
	// Key must use the real client source port (not 0) so it matches keyFromAntreaZoneConn.
	assert.Equal(t, clientPort, key.port)
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

	// Antrea-zone connection: source is the gateway, source port is the real client port
	// (unchanged because no SNAT was applied).
	gatewayIP := netip.MustParseAddr("10.244.2.1")
	antreaZoneConn := &connection.Connection{
		Zone: 65520,
		FlowKey: connection.Tuple{
			SourceAddress:      gatewayIP,
			DestinationAddress: podIP,
			Protocol:           6,
			SourcePort:         clientPort,
			DestinationPort:    80,
		},
		OriginalDestinationAddress: podIP,
		OriginalDestinationPort:    80,
	}

	correlator := NewFromExternalCorrelator(mockProxier{})
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
