// Copyright 2020 Antrea Authors
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

package ipfix

import (
	"time"

	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
	ipfixintermediate "github.com/vmware/go-ipfix/pkg/intermediate"
)

// IPFIXAggregationProcess interface is added to facilitate unit testing without involving the code from go-ipfix library.
type IPFIXAggregationProcess interface {
	Start()
	Stop()
	ForAllExpiredFlowRecordsDo(callback ipfixintermediate.FlowKeyRecordMapCallBack) error
	GetExpiryFromExpirePriorityQueue() time.Duration
	GetRecords(flowKey *ipfixintermediate.FlowKey) []map[string]interface{}
	ResetStatAndThroughputElementsInRecord(record ipfixentities.Record) error
	SetCorrelatedFieldsFilled(record *ipfixintermediate.AggregationFlowRecord, isFilled bool)
	AreCorrelatedFieldsFilled(record ipfixintermediate.AggregationFlowRecord) bool
	IsAggregatedRecordIPv4(record ipfixintermediate.AggregationFlowRecord) bool
	SetExternalFieldsFilled(record *ipfixintermediate.AggregationFlowRecord, isFilled bool)
	AreExternalFieldsFilled(record ipfixintermediate.AggregationFlowRecord) bool
	GetNumFlows() int64
}
