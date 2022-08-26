// Copyright 2022 Antrea Authors.
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

package flowaggregator

import (
	"time"

	"antrea.io/antrea/pkg/apis"
)

const (
	DefaultExternalFlowCollectorTransport = "tcp"
	DefaultExternalFlowCollectorPort      = "4739"
	DefaultActiveFlowRecordTimeout        = "60s"
	DefaultInactiveFlowRecordTimeout      = "90s"
	DefaultAggregatorTransportProtocol    = "TLS"
	DefaultFlowAggregatorAddress          = "flow-aggregator.flow-aggregator.svc"
	DefaultRecordFormat                   = "IPFIX"
	DefaultClickHouseDatabase             = "default"
	DefaultClickHouseCommitInterval       = "8s"
	MinClickHouseCommitInterval           = 1 * time.Second
	DefaultClickHouseDatabaseUrl          = "tcp://clickhouse-clickhouse.flow-visibility.svc:9000"
)

func SetConfigDefaults(flowAggregatorConf *FlowAggregatorConfig) {
	if flowAggregatorConf.ActiveFlowRecordTimeout == "" {
		flowAggregatorConf.ActiveFlowRecordTimeout = DefaultActiveFlowRecordTimeout
	}
	if flowAggregatorConf.InactiveFlowRecordTimeout == "" {
		flowAggregatorConf.InactiveFlowRecordTimeout = DefaultInactiveFlowRecordTimeout
	}
	if flowAggregatorConf.AggregatorTransportProtocol == "" {
		flowAggregatorConf.AggregatorTransportProtocol = DefaultAggregatorTransportProtocol
	}
	if flowAggregatorConf.FlowAggregatorAddress == "" {
		flowAggregatorConf.FlowAggregatorAddress = DefaultFlowAggregatorAddress
	}
	if flowAggregatorConf.APIServer.APIPort == 0 {
		flowAggregatorConf.APIServer.APIPort = apis.FlowAggregatorAPIPort
	}
	if flowAggregatorConf.FlowCollector.RecordFormat == "" {
		flowAggregatorConf.FlowCollector.RecordFormat = DefaultRecordFormat
	}
	if flowAggregatorConf.ClickHouse.Database == "" {
		flowAggregatorConf.ClickHouse.Database = DefaultClickHouseDatabase
	}
	if flowAggregatorConf.ClickHouse.DatabaseURL == "" {
		flowAggregatorConf.ClickHouse.DatabaseURL = DefaultClickHouseDatabaseUrl
	}
	if flowAggregatorConf.ClickHouse.Compress == nil {
		flowAggregatorConf.ClickHouse.Compress = new(bool)
		*flowAggregatorConf.ClickHouse.Compress = true
	}
	if flowAggregatorConf.ClickHouse.CommitInterval == "" {
		flowAggregatorConf.ClickHouse.CommitInterval = DefaultClickHouseCommitInterval
	}
}
