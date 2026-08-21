// Copyright 2020 Antrea Authors
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

package querier

import (
	"antrea.io/antrea/v2/pkg/flowaggregator/intermediate"
)

type Metrics struct {
	NumRecordsExported     int64
	NumRecordsReceived     int64
	NumRecordsDropped      int64
	NumFlows               int64
	NumConnToCollector     int64
	WithClickHouseExporter bool
	WithS3Exporter         bool
	WithLogExporter        bool
	WithIPFIXExporter      bool
}

type FlowAggregatorQuerier interface {
	GetFlowRecords(flowKey *intermediate.FlowKey) []map[string]interface{}
	GetRecordMetrics() Metrics
	// FlowStreamServiceReady reports whether FlowStreamService is currently serving, for the Flow
	// Aggregator's own apiserver to expose via readyz/livez. It reports true when the feature is
	// disabled entirely, not just when the (enabled) service happens to be up.
	FlowStreamServiceReady() bool
}

type ExternalFlowCollectorAddr struct {
	Address  string
	Protocol string
}
