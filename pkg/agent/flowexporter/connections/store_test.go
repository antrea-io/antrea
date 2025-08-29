package connections

import (
	"testing"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	"github.com/stretchr/testify/assert"
)

func Test_ctStore_updateConnections(t *testing.T) {
	tests := []struct {
		name          string
		existingConns map[connection.ConnectionKey]*connection.Connection
		connections   []connection.Connection
		expectedConns map[connection.ConnectionKey]*connection.Connection
	}{
		{
			name: "add new entry",
			connections: []connection.Connection{
				{FlowKey: tuple1},
			},
			expectedConns: map[connection.ConnectionKey]*connection.Connection{
				tuple1: {FlowKey: tuple1, IsPresent: true},
			},
		}, {
			name: "update existing entry",
			existingConns: map[connection.ConnectionKey]*connection.Connection{
				tuple1: {FlowKey: tuple1, OriginalBytes: 100},
			},
			connections: []connection.Connection{
				{FlowKey: tuple1, OriginalBytes: 200},
			},
			expectedConns: map[connection.ConnectionKey]*connection.Connection{
				tuple1: {FlowKey: tuple1, IsPresent: true, OriginalBytes: 200},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var existingConns map[connection.ConnectionKey]*connection.Connection
			if tt.existingConns == nil {
				existingConns = make(map[connection.ConnectionKey]*connection.Connection)
			} else {
				existingConns = tt.existingConns
			}

			s := &ctStore{
				entries: existingConns,
			}
			s.snapshot.Store(&snapshot{})
			s.updateConnections(tt.connections)

			assert.Len(t, s.entries, len(tt.expectedConns))
			assert.Len(t, s.snapshot.Load().entries, len(tt.expectedConns))
			for k := range tt.expectedConns {
				conn := tt.expectedConns[k]
				assert.Contains(t, s.entries, conn.FlowKey)
				assert.Contains(t, s.snapshot.Load().entries, conn.FlowKey)
				assert.Equal(t, tt.expectedConns[conn.FlowKey], s.entries[conn.FlowKey])
			}
		})
	}
}
