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

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"k8s.io/component-base/metrics/legacyregistry"

	"antrea.io/antrea/pkg/agent/metrics"
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
