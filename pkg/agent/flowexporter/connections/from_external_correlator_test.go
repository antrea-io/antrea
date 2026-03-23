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
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	"antrea.io/antrea/pkg/agent/openflow"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	k8sproxy "antrea.io/antrea/third_party/proxy"
)

// withTTL overrides the default flow expiration TTL.
func withTTL(ttl time.Duration) option {
	return func(a *fromExternalCorrelator) {
		a.ttl = ttl
	}
}

// withCleanupInterval overrides the default background loop interval.
func withCleanupInterval(interval time.Duration) option {
	return func(a *fromExternalCorrelator) {
		a.cleanUpInterval = interval
	}
}

func contains(c *fromExternalCorrelator, conn *connection.Connection) bool {
	c.lock.Lock()
	defer c.lock.Unlock()
	_, exists := c.connections[c.generateKey(conn)]
	return exists
}

func TestFromExternalCorrelator(t *testing.T) {
	t.Run("add", func(t *testing.T) {
		store := newFromExternalCorrelator()
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
			store := newFromExternalCorrelator()
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
			match := store.popMatching(antreaZeroConn)
			assert.NotNil(t, match, "Expected a matching zone zero connection to have been stored")
			assert.Equal(t, zoneZeroConn, match)
		})
		t.Run("Does Not Have Match", func(t *testing.T) {
			store := newFromExternalCorrelator()
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
			match := store.popMatching(antreaZeroConn)
			assert.Nil(t, match, "Expected store to return a nil match")
		})
	})
	t.Run("remove", func(t *testing.T) {
		store := newFromExternalCorrelator()
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
		store.remove(zoneZeroConn)
		assert.False(t, contains(store, zoneZeroConn))
	})
	t.Run("Expires stale records", func(t *testing.T) {
		store := newFromExternalCorrelator(withTTL(time.Millisecond), withCleanupInterval(time.Millisecond))
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
		time.Sleep(3 * time.Millisecond)
		assert.False(t, contains(store, zoneZeroConn), "Expected store to expire old records")
	})
	t.Run("stopCleanUp is threadsafe", func(t *testing.T) {
		store := newFromExternalCorrelator()

		var wg sync.WaitGroup
		for range 10 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				store.stopCleanUp()
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

func TestFromExternalCorrelator_FilterAndStoreExternalSource(t *testing.T) {
	nonZoneZeroConn := &connection.Connection{Zone: 65220}
	refTime := time.Now()
	zoneZeroConn := &connection.Connection{
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
		want   bool
		stored bool
	}{
		{
			name:   "Non-Zone Zero connections",
			conn:   nonZoneZeroConn,
			want:   false,
			stored: false,
		},
		{
			name:   "Nil connection",
			conn:   nil,
			want:   false,
			stored: false,
		},
		{
			name:   "Nil Proxier",
			conn:   zoneZeroConn,
			want:   true,
			stored: true,
		},
		{
			name:   "Unknown protocol",
			conn:   invalidProtocolConn,
			want:   false,
			stored: false,
		},
		{
			name:   "No associated service",
			conn:   zoneZeroConn,
			want:   true,
			stored: false,
		},
		{
			name:   "Associated service found",
			conn:   hasServiceConn,
			want:   true,
			stored: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			correlator := newFromExternalCorrelator()
			var got bool
			if tc.name == "Nil Proxier" {
				got = correlator.filterAndStoreExternalSource(tc.conn, nil)
			} else {
				got = correlator.filterAndStoreExternalSource(tc.conn, mockProxier)
			}

			if tc.want {
				assert.True(t, got, "Expected connection to be filtered")
			} else {
				assert.False(t, got, "Expected connection to not be filtered")
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

	correlator := newFromExternalCorrelator()

	got := correlator.correlateIfExternal(nil)
	assert.False(t, got, "Expected invalid connections to not get correlated")

	// Confirm no correlation when no matching zone zero connections previously stored
	got = correlator.correlateIfExternal(&antreaZoneConn)
	assert.False(t, got, "Expected no correlation when the store is empty")
	assert.Equal(t, gatewayIP, antreaZoneConn.FlowKey.SourceAddress, "Expected connection to not have changed")

	// Confirm correlation
	correlator.filterAndStoreExternalSource(hasServiceConn, mockProxier{})
	got = correlator.correlateIfExternal(&antreaZoneConn)
	assert.True(t, got, "Expected correlation when corresponding zoen zero flow added to store")

	assert.Equal(t, externalIP, antreaZoneConn.FlowKey.SourceAddress, "Expected connection to have external source IP")
	assert.Len(t, correlator.connections, 0, "Expected Zone 0 connection to be popped from store")
}
