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
	"fmt"
	"time"

	ipfixentities "github.com/vmware/go-ipfix/pkg/entities"
	ipfixintermediate "github.com/vmware/go-ipfix/pkg/intermediate"
)

var _ IPFIXAggregationProcess = new(ipfixAggregationProcess)

// IPFIXAggregationProcess interface is added to facilitate unit testing without involving the code from go-ipfix library.
type IPFIXAggregationProcess interface {
	Start()
	Stop()
	ForAllExpiredFlowRecordsDo(callback ipfixintermediate.FlowKeyRecordMapCallBack) error
	GetExpiryFromExpirePriorityQueue() time.Duration
	ResetStatElementsInRecord(record ipfixentities.Record) error
	SetCorrelatedFieldsFilled(record *ipfixintermediate.AggregationFlowRecord)
	AreCorrelatedFieldsFilled(record ipfixintermediate.AggregationFlowRecord) bool
	IsAggregatedRecordIPv4(record ipfixintermediate.AggregationFlowRecord) bool
	SetExternalFieldsFilled(record *ipfixintermediate.AggregationFlowRecord)
	AreExternalFieldsFilled(record ipfixintermediate.AggregationFlowRecord) bool
}

type ipfixAggregationProcess struct {
	AggregationProcess *ipfixintermediate.AggregationProcess
}

func NewIPFIXAggregationProcess(input ipfixintermediate.AggregationInput) (*ipfixAggregationProcess, error) {
	ap, err := ipfixintermediate.InitAggregationProcess(input)
	if err != nil {
		return nil, fmt.Errorf("error while initializing IPFIX intermediate process: %v", err)
	}

	return &ipfixAggregationProcess{
		AggregationProcess: ap,
	}, nil
}

func (ap *ipfixAggregationProcess) Start() {
	ap.AggregationProcess.Start()
}

func (ap *ipfixAggregationProcess) Stop() {
	ap.AggregationProcess.Stop()
}

func (ap *ipfixAggregationProcess) ForAllExpiredFlowRecordsDo(callback ipfixintermediate.FlowKeyRecordMapCallBack) error {
	err := ap.AggregationProcess.ForAllExpiredFlowRecordsDo(callback)
	return err
}

func (ap *ipfixAggregationProcess) GetExpiryFromExpirePriorityQueue() time.Duration {
	return ap.AggregationProcess.GetExpiryFromExpirePriorityQueue()
}

func (ap *ipfixAggregationProcess) ResetStatElementsInRecord(record ipfixentities.Record) error {
	return ap.AggregationProcess.ResetStatElementsInRecord(record)
}

func (ap *ipfixAggregationProcess) SetCorrelatedFieldsFilled(record *ipfixintermediate.AggregationFlowRecord) {
	ap.AggregationProcess.SetCorrelatedFieldsFilled(record, true)
}

func (ap *ipfixAggregationProcess) AreCorrelatedFieldsFilled(record ipfixintermediate.AggregationFlowRecord) bool {
	return ap.AggregationProcess.AreCorrelatedFieldsFilled(record)
}

func (ap *ipfixAggregationProcess) IsAggregatedRecordIPv4(record ipfixintermediate.AggregationFlowRecord) bool {
	return ap.AggregationProcess.IsAggregatedRecordIPv4(record)
}

func (ap *ipfixAggregationProcess) SetExternalFieldsFilled(record *ipfixintermediate.AggregationFlowRecord) {
	ap.AggregationProcess.SetExternalFieldsFilled(record, true)
}

func (ap *ipfixAggregationProcess) AreExternalFieldsFilled(record ipfixintermediate.AggregationFlowRecord) bool {
	return ap.AggregationProcess.AreExternalFieldsFilled(record)
}
