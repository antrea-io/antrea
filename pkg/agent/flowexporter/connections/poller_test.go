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
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"antrea.io/antrea/v2/pkg/agent/flowexporter/connection"
	connstesting "antrea.io/antrea/v2/pkg/agent/flowexporter/connections/testing"
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
			// Zone 0 is always polled first (returns no connections for this test).
			mockDumper.EXPECT().DumpFlows(uint16(0)).Return(nil, 0, nil)
			mockDumper.EXPECT().DumpFlows(gomock.Not(uint16(0))).Return(tt.conns, len(tt.conns), nil)
			mockDumper.EXPECT().GetMaxConnections().Return(maxConnections, nil)

			p := NewPoller(mockDumper, nil, 0, true, false, false)
			conns, connsLens, err := p.Poll()
			require.NoError(t, err)
			assert.ElementsMatch(t, tt.conns, conns)
			assert.Equal(t, []int{0, len(tt.conns)}, connsLens)

			// Validate Metrics
			checkTotalConnectionsMetric(t, len(tt.conns))
			checkMaxConnectionsMetric(t, maxConnections)
		})
	}
}
