// Copyright 2023 Antrea Authors
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
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"k8s.io/component-base/metrics/legacyregistry"
	clocktesting "k8s.io/utils/clock/testing"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	connectionstest "antrea.io/antrea/pkg/agent/flowexporter/connections/testing"
	"antrea.io/antrea/pkg/agent/metrics"
	"antrea.io/antrea/pkg/agent/openflow"
	objectstoretest "antrea.io/antrea/pkg/util/objectstore/testing"

	. "antrea.io/antrea/pkg/agent/flowexporter/testing"
)

func init() {
	metrics.InitializeConnectionMetrics()
}

func checkAntreaConnectionMetrics(t *testing.T, numConns int) {
	expectedAntreaConnectionCount := `
	# HELP antrea_agent_conntrack_antrea_connection_count [ALPHA] Number of connections in the Antrea ZoneID of the conntrack table. This metric gets updated at an interval specified by flowPollInterval, a configuration parameter for the Agent.
	# TYPE antrea_agent_conntrack_antrea_connection_count gauge
	`
	expectedAntreaConnectionCount = expectedAntreaConnectionCount + fmt.Sprintf("antrea_agent_conntrack_antrea_connection_count %d\n", numConns)
	err := testutil.GatherAndCompare(legacyregistry.DefaultGatherer, strings.NewReader(expectedAntreaConnectionCount), "antrea_agent_conntrack_antrea_connection_count")
	assert.NoError(t, err)
}

func checkTotalConnectionsMetric(t *testing.T, numConns int) {
	expectedConnectionCount := `
	# HELP antrea_agent_conntrack_total_connection_count [ALPHA] Number of connections in the conntrack table. This metric gets updated at an interval specified by flowPollInterval, a configuration parameter for the Agent.
	# TYPE antrea_agent_conntrack_total_connection_count gauge
	`
	expectedConnectionCount = expectedConnectionCount + fmt.Sprintf("antrea_agent_conntrack_total_connection_count %d\n", numConns)
	err := testutil.GatherAndCompare(legacyregistry.DefaultGatherer, strings.NewReader(expectedConnectionCount), "antrea_agent_conntrack_total_connection_count")
	assert.NoError(t, err)
}

func checkMaxConnectionsMetric(t *testing.T, maxConns int) {
	expectedMaxConnectionsCount := `
	# HELP antrea_agent_conntrack_max_connection_count [ALPHA] Size of the conntrack table. This metric gets updated at an interval specified by flowPollInterval, a configuration parameter for the Agent.
	# TYPE antrea_agent_conntrack_max_connection_count gauge
	`
	expectedMaxConnectionsCount = expectedMaxConnectionsCount + fmt.Sprintf("antrea_agent_conntrack_max_connection_count %d\n", maxConns)
	err := testutil.GatherAndCompare(legacyregistry.DefaultGatherer, strings.NewReader(expectedMaxConnectionsCount), "antrea_agent_conntrack_max_connection_count")
	assert.NoError(t, err)
}

func checkDenyConnectionMetrics(t *testing.T, numConns int) {
	expectedDenyConnectionCount := `
	# HELP antrea_agent_denied_connection_count [ALPHA] Number of denied connections detected by Flow Exporter deny connections tracking. This metric gets updated when a flow is rejected/dropped by network policy.
	# TYPE antrea_agent_denied_connection_count gauge
	`
	expectedDenyConnectionCount = expectedDenyConnectionCount + fmt.Sprintf("antrea_agent_denied_connection_count %d\n", numConns)
	err := testutil.GatherAndCompare(legacyregistry.DefaultGatherer, strings.NewReader(expectedDenyConnectionCount), "antrea_agent_denied_connection_count")
	assert.NoError(t, err)
}

func TestConnStore_CheckMetrics(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockPodStore := objectstoretest.NewMockPodStore(ctrl)

	conns := []*connection.Connection{GenerateConnectionFn(WithPodInfo("ns", "pod", "ns", "pod"))()}
	maxConns := 20000
	totalConns := 10000

	mockPodStore.EXPECT().GetPodByIPAndTime(gomock.Any(), gomock.Any()).Return(pod1, true).Times(2 * len(conns))
	mockConnDumper := connectionstest.NewMockConnTrackDumper(ctrl)
	mockConnDumper.EXPECT().GetMaxConnections().Return(maxConns, nil)
	mockConnDumper.EXPECT().DumpFlows(uint16(openflow.CtZone)).Return(conns, totalConns, nil)

	store := &ConnStore{
		connDumper: mockConnDumper,
		zones:      []uint16{uint16(openflow.CtZone)},
		clock:      clocktesting.NewFakeClock(time.Now()),
		podStore:   mockPodStore,
		entries:    map[connection.ConnectionKey]*connection.Connection{},
		gc:         gcHeap{keyToItem: map[connection.ConnectionKey]*gcItem{}},
	}

	// Metrics are global. Need to reset it because of test pollution
	metrics.TotalAntreaConnectionsInConnTrackTable.Set(0)
	metrics.TotalConnectionsInConnTrackTable.Set(0)
	metrics.MaxConnectionsInConnTrackTable.Set(0)

	store.PollConntrackAndStore()

	checkAntreaConnectionMetrics(t, len(conns))
	checkTotalConnectionsMetric(t, totalConns)
	checkMaxConnectionsMetric(t, maxConns)
}
