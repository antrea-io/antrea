package connections

import (
	"container/heap"
	"net/netip"
	"testing"
	"time"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConnStore_updateConnections(t *testing.T) {
	conn1 := connection.Connection{
		FlowKey: tuple1,
		OriginalStats: connection.Stats{
			Packets:        10,
			Bytes:          1000,
			ReversePackets: 20,
			ReverseBytes:   2000,
		},
	}
	conn2 := connection.Connection{
		FlowKey: tuple2,
		OriginalStats: connection.Stats{
			Packets:        20,
			Bytes:          2000,
			ReversePackets: 30,
			ReverseBytes:   3000,
		},
	}
	conn3 := connection.Connection{
		FlowKey: tuple3,
		OriginalStats: connection.Stats{
			Packets:        40,
			Bytes:          4000,
			ReversePackets: 50,
			ReverseBytes:   5000,
		},
	}
	conn1Updated := connection.Connection{
		FlowKey: tuple1,
		OriginalStats: connection.Stats{
			Packets:        11,
			Bytes:          1100,
			ReversePackets: 22,
			ReverseBytes:   2200,
		},
	}
	conn2Updated := connection.Connection{
		FlowKey: tuple2,
		OriginalStats: connection.Stats{
			Packets:        22,
			Bytes:          2200,
			ReversePackets: 33,
			ReverseBytes:   3300,
		},
	}
	conn3Updated := connection.Connection{
		FlowKey: tuple3,
		OriginalStats: connection.Stats{
			Packets:        44,
			Bytes:          4400,
			ReversePackets: 55,
			ReverseBytes:   5500,
		},
	}

	tests := []struct {
		name                string
		incomingConnections []connection.Connection
		subs                []subscriber
		existingEntries     []connection.Connection
		expectedEntries     []connection.Connection
		expectedUpdates     int
	}{
		{
			name:                "No connections",
			incomingConnections: []connection.Connection{},
			existingEntries:     []connection.Connection{},
		}, {
			name:                "New connections",
			incomingConnections: []connection.Connection{conn1, conn2, conn3},
			expectedEntries:     []connection.Connection{conn1, conn2, conn3},
			expectedUpdates:     3,
		}, {
			name:                "Updated connections",
			incomingConnections: []connection.Connection{conn1Updated, conn2Updated, conn3Updated},
			existingEntries:     []connection.Connection{conn1, conn2, conn3},
			expectedEntries:     []connection.Connection{conn1Updated, conn2Updated, conn3Updated},
			expectedUpdates:     3,
		}, {
			name:                "New connection - notify subscriber",
			incomingConnections: []connection.Connection{conn1, conn2},
			subs: []subscriber{{
				ch: make(chan UpdateMsg, 1),
			}},
			expectedEntries: []connection.Connection{conn1, conn2},
			expectedUpdates: 2,
		}, {
			name:                "Update connections - notify subscriber",
			incomingConnections: []connection.Connection{conn1Updated},
			subs: []subscriber{{
				ch: make(chan UpdateMsg, 1),
			}},
			existingEntries: []connection.Connection{conn1},
			expectedEntries: []connection.Connection{conn1Updated},
			expectedUpdates: 1,
		},
		// TODO Andrew: Add test case for multiple existing entries
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

			for _, entry := range tt.existingEntries {
				cs.entries[entry.FlowKey] = &entry
			}

			now := time.Now()
			cs.updateConnections(tt.incomingConnections)

			for _, want := range tt.expectedEntries {
				want.LastUpdateTime = now
				got, ok := cs.entries[want.FlowKey]
				require.True(t, ok)
				assert.True(t, got.IsPresent)
				if !cmp.Equal(got, &want,
					cmpopts.IgnoreUnexported(netip.Addr{}),
					cmpopts.EquateApproxTime(1*time.Second),
					cmpopts.IgnoreFields(connection.Connection{}, "IsPresent", "LastUsedTime")) {
					t.Errorf("(-want, +got): %s", cmp.Diff(&want, got,
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
					assert.Len(t, msg.Key, tt.expectedUpdates)
					assert.False(t, msg.Deleted)
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
				assert.Len(t, msg.Key, tt.numConnectionRemoved)
				assert.True(t, msg.Deleted)
			}
		}
	}
}
