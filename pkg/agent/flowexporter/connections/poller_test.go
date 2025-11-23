package connections

import (
	"testing"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	connstesting "antrea.io/antrea/pkg/agent/flowexporter/connections/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestPoller_Poll(t *testing.T) {
	tests := []struct {
		name  string
		conns []*connection.Connection
	}{
		{
			name:  "no conns during poll",
			conns: []*connection.Connection{},
		}, {
			name:  "has connections",
			conns: []*connection.Connection{getNewConn(), getNewConn()},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			// Hard-coded conntrack occupancy metrics for test
			MaxConnections := 300000

			mockDumper := connstesting.NewMockConnTrackDumper(ctrl)
			mockDumper.EXPECT().DumpFlows(gomock.Any()).Return(tt.conns, len(tt.conns), nil)
			mockDumper.EXPECT().GetMaxConnections().Return(MaxConnections, nil)

			p := NewPoller(mockDumper, nil, nil, PollerConfig{
				V4Enabled: true,
			})
			conns, l7EventMap, connsLens, err := p.Poll()
			require.NoError(t, err)
			assert.ElementsMatch(t, tt.conns, conns)
			assert.Len(t, l7EventMap, 0)
			assert.Equal(t, []int{len(tt.conns)}, connsLens)

			// Validate Metrics
			checkTotalConnectionsMetric(t, len(tt.conns))
			checkMaxConnectionsMetric(t, MaxConnections)
		})
	}
}
