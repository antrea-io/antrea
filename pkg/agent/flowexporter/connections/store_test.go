package connections

import (
	"container/heap"
	"fmt"
	"maps"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConnStore_updateConnections(t *testing.T) {
	tests := []struct {
		name                    string
		numExistingConns        int
		numIncomingUpdatedConns int
		numNewConns             int
		hasL7Event              bool

		subs            []subscriber
		expectedUpdates int
	}{
		{
			name: "No connections",
		}, {
			name:            "New connections",
			numNewConns:     3,
			expectedUpdates: 3,
		}, {
			name:                    "Updated connections",
			numExistingConns:        4,
			numIncomingUpdatedConns: 3,
			expectedUpdates:         3,
		}, {
			name:        "New connection - notify subscriber",
			numNewConns: 2,
			subs: []subscriber{{
				ch: make(chan UpdateMsg, 1),
			}},
			expectedUpdates: 2,
		}, {
			name:                    "Update connections - notify subscriber",
			numExistingConns:        3,
			numIncomingUpdatedConns: 2,
			subs: []subscriber{{
				ch: make(chan UpdateMsg, 1),
			}},
			expectedUpdates: 2,
		}, {
			name:            "new connections - with l7Events",
			numNewConns:     3,
			hasL7Event:      true,
			expectedUpdates: 3,
			subs: []subscriber{{
				ch: make(chan UpdateMsg, 1),
			}},
		},
		// TODO Andrew: Add test case for multiple existing entries
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.LessOrEqual(t, tt.numIncomingUpdatedConns, tt.numExistingConns)

			existingConns := map[connection.ConnectionKey]*connection.Connection{}
			for i := 0; i < tt.numExistingConns; i++ {
				conn := getNewConn()
				existingConns[conn.FlowKey] = conn
			}

			expectedEntries := maps.Clone(existingConns)

			newConns := make([]*connection.Connection, 0, tt.numNewConns)
			l7Events := make(map[connection.ConnectionKey]L7ProtocolFields)
			for i := 0; i < tt.numNewConns; i++ {
				conn := getNewConn()
				newConns = append(newConns, conn)
				expectedEntries[conn.FlowKey] = conn
				if tt.hasL7Event {
					l7Events[conn.FlowKey] = L7ProtocolFields{
						Http: map[int32]*Http{
							1: {
								Hostname:    "example.com",
								URL:         fmt.Sprintf("example.com/foo/%d", i),
								UserAgent:   "gecko",
								ContentType: "application/json",
								Method:      "PATCH",
								Protocol:    "tcp",
							},
						},
					}
				}
			}

			incomingConns := make([]*connection.Connection, 0, tt.numIncomingUpdatedConns)
			for _, conn := range existingConns {
				if len(incomingConns) == tt.numIncomingUpdatedConns {
					break
				}
				newConn := *conn
				newConn.LastUsedTime = atomic.Int64{}
				newConn.OriginalStats.Packets += 5
				newConn.OriginalStats.Bytes += 20
				newConn.OriginalStats.ReversePackets += 2
				newConn.OriginalStats.ReverseBytes += 10

				incomingConns = append(incomingConns, &newConn)
				expectedEntries[newConn.FlowKey] = &newConn
			}
			incomingConns = append(incomingConns, newConns...)

			cs := &connStore{
				subs:    make(map[*subscriber]struct{}),
				entries: existingConns,
			}

			for _, sub := range tt.subs {
				cs.subs[&sub] = struct{}{}
			}

			now := time.Now()
			cs.updateConnections(incomingConns)

			for _, want := range expectedEntries {
				want.LastUpdateTime = now
				got, ok := cs.entries[want.FlowKey]
				require.True(t, ok)
				assert.True(t, got.IsPresent)
				if !cmp.Equal(got, want,
					cmpopts.IgnoreUnexported(netip.Addr{}),
					cmpopts.EquateApproxTime(1*time.Second),
					cmpopts.IgnoreFields(connection.Connection{}, "IsPresent", "LastUsedTime")) {
					t.Errorf("(-want, +got): %s", cmp.Diff(want, got,
						cmpopts.IgnoreUnexported(netip.Addr{}),
						cmpopts.EquateApproxTime(1*time.Second),
						cmpopts.IgnoreFields(connection.Connection{}, "IsPresent", "LastUsedTime"),
					))
				}
			}

			timeout := time.NewTicker(5 * time.Second)
			defer timeout.Stop()
			for _, sub := range tt.subs {
				select {
				case <-timeout.C:
					t.Fatal("timedout waiting for subscriber to receive update")
				case msg := <-sub.ch:
					assert.Len(t, msg.Conns, tt.expectedUpdates)
					assert.False(t, msg.Deleted)
					if len(l7Events) > 0 {
						assert.Equal(t, msg.L7Events, l7Events)
					}
					// TODO: Check the actual returned item.
				}
			}
		})
	}
}

func TestConnStore_removeStaleConnections(t *testing.T) {
	conn1 := connection.Connection{
		FlowKey: tuple1,
		OriginalStats: connection.Stats{
			Packets:        10,
			Bytes:          1000,
			ReversePackets: 20,
			ReverseBytes:   2000,
		},
	}
	conn1.LastUsedTime.Store((20 * time.Second).Nanoseconds())

	staleConn1 := connection.Connection{
		FlowKey: tuple2,
		OriginalStats: connection.Stats{
			Packets:        20,
			Bytes:          2000,
			ReversePackets: 30,
			ReverseBytes:   3000,
		},
	}
	staleConn1.LastUsedTime.Store((-20 * time.Second).Nanoseconds())

	staleConn2 := connection.Connection{
		FlowKey: tuple3,
		OriginalStats: connection.Stats{
			Packets:        40,
			Bytes:          4000,
			ReversePackets: 50,
			ReverseBytes:   5000,
		},
	}
	staleConn2.LastUsedTime.Store((-30 * time.Second).Nanoseconds())

	tests := []struct {
		name                   string
		staleConnectionTimeout time.Duration
		subs                   []subscriber
		existingEntries        []connection.Connection
		numConnectionRemoved   int
	}{
		{
			name:                   "No connections",
			staleConnectionTimeout: 5 * time.Second,
			numConnectionRemoved:   0,
		}, {
			name:                 "multiple expired connections",
			existingEntries:      []connection.Connection{conn1, staleConn1, staleConn2},
			numConnectionRemoved: 2,
		}, {
			name: "multiple expired connections - notify subs",
			subs: []subscriber{{
				ch: make(chan UpdateMsg, 1),
			}},
			existingEntries:      []connection.Connection{conn1, staleConn1, staleConn2},
			numConnectionRemoved: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs := &connStore{
				subs:    make(map[*subscriber]struct{}),
				entries: make(map[connection.ConnectionKey]*connection.Connection, 1000),
			}
			for _, sub := range tt.subs {
				cs.subs[&sub] = struct{}{}
			}
			now := time.Now()
			for _, entry := range tt.existingEntries {
				cs.entries[entry.FlowKey] = &entry
				heap.Push(&cs.gc, &gcItem{
					conn:     &entry,
					expiryMs: now.UnixNano() + entry.LastUsedTime.Load(),
				})
			}
			cs.removeStaleConnections()
			assert.Len(t, cs.entries, len(tt.existingEntries)-tt.numConnectionRemoved)
		})

		timeout := time.NewTicker(5 * time.Second)
		defer timeout.Stop()
		for _, sub := range tt.subs {
			select {
			case <-timeout.C:
				t.Fatal("timedout waiting for subscriber to receive update")
			case msg := <-sub.ch:
				assert.Len(t, msg.Conns, tt.numConnectionRemoved)
				assert.True(t, msg.Deleted)
			}
		}
	}
}
