// Copyright 2025 Antrea Authors
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
package intermediate
import (
	"time"
	flowpb "antrea.io/antrea/v2/pkg/apis/flow/v1alpha1"
	flowpb "antrea.io/antrea/v2/pkg/apis/flow/v1alpha1"
)
type AggregationProcess interface {
	Start()
	Stop()
	ForAllExpiredFlowRecordsDo(callback FlowKeyRecordMapCallBack) error
	GetExpiryFromExpirePriorityQueue() time.Duration
	GetRecords(flowKey *FlowKey) []map[string]interface{}
	ResetStatAndThroughputElementsInRecord(record *flowpb.Flow) error
	SetCorrelatedFieldsFilled(record *AggregationFlowRecord, isFilled bool)
	AreCorrelatedFieldsFilled(record AggregationFlowRecord) bool
	IsAggregatedRecordIPv4(record AggregationFlowRecord) bool
	SetExternalFieldsFilled(record *AggregationFlowRecord, isFilled bool)
	AreExternalFieldsFilled(record AggregationFlowRecord) bool
	GetNumFlows() int64
}
