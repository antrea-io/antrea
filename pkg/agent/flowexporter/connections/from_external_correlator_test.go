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
	"sync"
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
	_, exists := c.connections[keyFromZoneZeroConn(conn)]
	return exists
}

func TestFromExternalCorrelator(t *testing.T) {
	t.Run("add", func(t *testing.T) {
		store := NewFromExternalCorrelator()
		refTime := time.Now()
		zoneZeroConn := &connection.Connection{
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
		store.add(zoneZeroConn)
		assert.True(t, contains(store, zoneZeroConn), "Expected store to contain newly added connection")
	})
	t.Run("popMatching", func(t *testing.T) {
		t.Run("Has Match", func(t *testing.T) {
			store := NewFromExternalCorrelator()
			refTime := time.Now()
			zoneZeroConn := &connection.Connection{
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
			store.add(zoneZeroConn)
			match, ok := store.popMatching(antreaZeroConn)
			assert.True(t, ok, "Expected a matching zone zero connection to have been stored")
			assert.Equal(t, zoneZeroSnapshotFromConn(zoneZeroConn), match)
		})
		t.Run("Does Not Have Match", func(t *testing.T) {
			store := NewFromExternalCorrelator()
			refTime := time.Now()
			zoneZeroConn := &connection.Connection{
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
			store.add(zoneZeroConn)
			_, ok := store.popMatching(antreaZeroConn)
			assert.False(t, ok, "Expected store to return no match")
		})
	})
	t.Run("remove", func(t *testing.T) {
		store := NewFromExternalCorrelator()
		refTime := time.Now()
		zoneZeroConn := &connection.Connection{
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
		store.add(zoneZeroConn)
		// remove uses the same key as popMatching (Antrea-zone view of the flow).
		antreaConn := &connection.Connection{
			FlowKey: connection.Tuple{
				SourceAddress:      netip.MustParseAddr("10.244.2.1"),
				DestinationAddress: netip.MustParseAddr("10.244.2.2"),
				Protocol:           6,
				SourcePort:         zoneZeroConn.ProxySnatPort,
				DestinationPort:    80,
			},
		}
		store.RemoveStaleZoneZero(antreaConn)
		assert.False(t, contains(store, zoneZeroConn))
	})
	t.Run("Expires stale records", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			store := NewFromExternalCorrelator()
			t.Cleanup(store.StopCleanUp)
			go store.Run()

			refTime := time.Now()
			zoneZeroConn := &connection.Connection{
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
			store.add(zoneZeroConn)
			assert.True(t, contains(store, zoneZeroConn), "expected entry before expiry")

			// Advance virtual time past defaultTTL and allow cleanUpLoop to tick.
			time.Sleep(defaultTTL + 2*defaultCleanUpInterval)
			synctest.Wait()

			assert.False(t, contains(store, zoneZeroConn), "expected store to expire old records")
		})
	})
	t.Run("StopCleanUp is threadsafe", func(t *testing.T) {
		store := NewFromExternalCorrelator()

		var wg sync.WaitGroup
		for range 10 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				store.StopCleanUp()
			}()
		}
		wg.Wait()

		select {
		case <-store.stopCh:
		default:
			t.Fatal("Expected stopCh to be closed, but it was still open")
		}
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

func TestFromExternalCorrelator_IngestZoneZero(t *testing.T) {
	nonZoneZeroConn := &connection.Connection{Zone: 65220}
	refTime := time.Now()
	zoneZeroConn := &connection.Connection{
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
	mockProxier := mockProxier{}
	testCases := []struct {
		name   string
		conn   *connection.Connection
		stored bool
	}{
		{
			name:   "Non-Zone Zero connections",
			conn:   nonZoneZeroConn,
			stored: false,
		},
		{
			name:   "Nil connection",
			conn:   nil,
			stored: false,
		},
		{
			name:   "Nil Proxier",
			conn:   zoneZeroConn,
			stored: true,
		},
		{
			name:   "Unknown protocol",
			conn:   invalidProtocolConn,
			stored: false,
		},
		{
			name:   "No associated service",
			conn:   zoneZeroConn,
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
			correlator := NewFromExternalCorrelator()
			if tc.name == "Nil Proxier" {
				correlator.IngestZoneZero(tc.conn, nil)
			} else {
				correlator.IngestZoneZero(tc.conn, mockProxier)
			}

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

	correlator := NewFromExternalCorrelator()

	got := correlator.CorrelateIfExternal(nil)
	assert.False(t, got, "Expected invalid connections to not get correlated")

	// Confirm no correlation when no matching zone zero connections previously stored
	got = correlator.CorrelateIfExternal(&antreaZoneConn)
	assert.False(t, got, "Expected no correlation when the store is empty")
	assert.Equal(t, gatewayIP, antreaZoneConn.FlowKey.SourceAddress, "Expected connection to not have changed")

	// Confirm correlation
	correlator.IngestZoneZero(hasServiceConn, mockProxier{})
	got = correlator.CorrelateIfExternal(&antreaZoneConn)
	assert.True(t, got, "Expected correlation when corresponding zone zero flow added to store")

	assert.Equal(t, externalIP, antreaZoneConn.FlowKey.SourceAddress, "Expected connection to have external source IP")
	assert.Len(t, correlator.connections, 0, "Expected Zone 0 connection to be popped from store")
}

// TestCorrelateExternal_SymmetricZoneZeroClearsAntreaProxySnat documents that when the zone-0
// snapshot has no proxy SNAT (e.g. externalTrafficPolicy Local / symmetric conntrack), correlation
// overwrites any stale ProxySnatIP/ProxySnatPort on the Antrea-zone connection so exported flows
// do not report a spurious masquerade.
func TestCorrelateExternal_SymmetricZoneZeroClearsAntreaProxySnat(t *testing.T) {
	ext := netip.MustParseAddr("203.0.113.10")
	pod := netip.MustParseAddr("10.244.2.2")
	snap := zoneZeroSnapshot{
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
}

// TestFromExternalCorrelator_ZoneZeroKeyWithoutProxySNAT documents that when conntrack has a
// symmetric reply tuple (no kube-proxy/Antrea SNAT), NetlinkFlowToAntreaConnection leaves
// ProxySnatPort unset; the correlator still indexes such flows by (Pod IP, 0).
func TestFromExternalCorrelator_ZoneZeroKeyWithoutProxySNAT(t *testing.T) {
	podIP := netip.MustParseAddr("10.244.2.2")
	extClient := netip.MustParseAddr("203.0.113.5")
	conn := &connection.Connection{
		Zone: 0,
		FlowKey: connection.Tuple{
			SourceAddress:      extClient,
			DestinationAddress: podIP,
			Protocol:           6,
			SourcePort:         40000,
			DestinationPort:    80,
		},
		OriginalDestinationAddress: netip.MustParseAddr("172.18.0.111"),
		OriginalDestinationPort:    12345,
		ProxySnatIP:                netip.Addr{},
		ProxySnatPort:              0,
		Mark:                       openflow.ServiceCTMark.GetValue(),
	}
	correlator := NewFromExternalCorrelator()
	correlator.IngestZoneZero(conn, mockProxier{})
	key := keyFromZoneZeroConn(conn)
	_, exists := correlator.connections[key]
	assert.True(t, exists, "zone-0 entry should be stored when Service lookup succeeds")
	assert.Equal(t, uint16(0), key.port)
}
