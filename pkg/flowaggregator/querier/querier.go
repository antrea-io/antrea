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
	ipfixintermediate "github.com/vmware/go-ipfix/pkg/intermediate"
)

type Metrics struct {
	NumRecordsExported int64
	NumRecordsReceived int64
	NumFlows           int64
	NumConnToCollector int64
}

type FlowAggregatorQuerier interface {
	GetFlowRecords(flowKey *ipfixintermediate.FlowKey) []map[string]interface{}
	GetRecordMetrics() Metrics
}
