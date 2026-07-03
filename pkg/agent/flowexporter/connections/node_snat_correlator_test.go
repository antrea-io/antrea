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
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"

	"antrea.io/antrea/v2/pkg/agent/flowexporter/connection"
)

func TestNodeSnatCorrelator(t *testing.T) {
	t.Run("Ingest and Lookup", func(t *testing.T) {
		correlator := NewNodeSnatCorrelator()

		podIP := netip.MustParseAddr("10.244.1.5")
		externalIP := netip.MustParseAddr("8.8.8.8")
		snatIP := netip.MustParseAddr("172.18.0.10")

		// 1. Connection with Zone != DefaultZone should not be ingested
		nonDefaultConn := &connection.Connection{
			Zone: 100,
			FlowKey: connection.Tuple{
				SourceAddress:      podIP,
				DestinationAddress: externalIP,
				Protocol:           6,
				SourcePort:         12345,
				DestinationPort:    80,
			},
			ProxySnatIP: snatIP,
		}
		correlator.IngestDefaultZoneFlow(nonDefaultConn)
		assert.Equal(t, 0, len(correlator.connections))

		// 2. Connection with no SNAT (ProxySnatIP not valid) should not be ingested
		noSnatConn := &connection.Connection{
			Zone: DefaultZone,
			FlowKey: connection.Tuple{
				SourceAddress:      podIP,
				DestinationAddress: externalIP,
				Protocol:           6,
				SourcePort:         12345,
				DestinationPort:    80,
			},
		}
		correlator.IngestDefaultZoneFlow(noSnatConn)
		assert.Equal(t, 0, len(correlator.connections))

		// 3. Valid SNAT connection in default zone should be ingested
		snatConn := &connection.Connection{
			Zone: DefaultZone,
			FlowKey: connection.Tuple{
				SourceAddress:      podIP,
				DestinationAddress: externalIP,
				Protocol:           6,
				SourcePort:         12345,
				DestinationPort:    80,
			},
			ProxySnatIP:   snatIP,
			ProxySnatPort: 40000,
		}
		correlator.IngestDefaultZoneFlow(snatConn)
		assert.Equal(t, 1, len(correlator.connections))

		// 4. Lookup of corresponding Antrea-zone connection should return the SNAT IP and port
		antreaConn := &connection.Connection{
			Zone: 65520,
			FlowKey: connection.Tuple{
				SourceAddress:      podIP,
				DestinationAddress: externalIP,
				Protocol:           6,
				SourcePort:         12345,
				DestinationPort:    80,
			},
		}
		resolvedIP, resolvedPort := correlator.LookupSnat(antreaConn)
		assert.Equal(t, snatIP, resolvedIP)
		assert.Equal(t, uint16(40000), resolvedPort)

		// 5. Lookup should not delete/pop the entry because it might be needed for subsequent polls
		assert.Equal(t, 1, len(correlator.connections))

		// 6. Lookup of non-existent connection should return invalid/zero IP and port
		nonExistentConn := &connection.Connection{
			Zone: 65520,
			FlowKey: connection.Tuple{
				SourceAddress:      podIP,
				DestinationAddress: externalIP,
				Protocol:           6,
				SourcePort:         55555, // different source port
				DestinationPort:    80,
			},
		}
		nonExistentIP, nonExistentPort := correlator.LookupSnat(nonExistentConn)
		assert.False(t, nonExistentIP.IsValid())
		assert.Equal(t, uint16(0), nonExistentPort)
	})

	t.Run("Expiry TTL", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			correlator := NewNodeSnatCorrelator()
			correlator.ttl = 100 * time.Millisecond
			correlator.cleanUpInterval = 50 * time.Millisecond

			stopCh := make(chan struct{})
			t.Cleanup(func() { close(stopCh) })
			go correlator.Run(stopCh)

			podIP := netip.MustParseAddr("10.244.1.5")
			externalIP := netip.MustParseAddr("8.8.8.8")
			snatIP := netip.MustParseAddr("172.18.0.10")

			conn := &connection.Connection{
				Zone: DefaultZone,
				FlowKey: connection.Tuple{
					SourceAddress:      podIP,
					DestinationAddress: externalIP,
					Protocol:           6,
					SourcePort:         12345,
					DestinationPort:    80,
				},
				ProxySnatIP: snatIP,
			}
			correlator.IngestDefaultZoneFlow(conn)
			assert.Equal(t, 1, len(correlator.connections))

			// Sleep to exceed the TTL
			time.Sleep(200 * time.Millisecond)
			synctest.Wait()

			assert.Equal(t, 0, len(correlator.connections), "Expected stale connection to be expired and cleaned up")
		})
	})
}
