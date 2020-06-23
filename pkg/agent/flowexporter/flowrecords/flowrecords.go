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

package flowrecords

import (
	"fmt"
	"github.com/vmware-tanzu/antrea/pkg/agent/flowexporter/ipfix"

	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/flowexporter"
	"github.com/vmware-tanzu/antrea/pkg/agent/flowexporter/connections"
)

var _ FlowRecords = new(flowRecords)

type FlowRecords interface {
	BuildFlowRecords() error
	IterateFlowRecordsWithSendCB(callback flowexporter.FlowRecordSend, templateID uint16) error
}

type flowRecords struct {
	// synchronization is not required as there is no concurrency involving this object.
	// Add lock when this is consumed by more than one entity concurrently.
	recordsMap       map[flowexporter.ConnectionKey]flowexporter.FlowRecord
	connStoreBuilder connections.ConnectionStore
}

func NewFlowRecords(connStore connections.ConnectionStore) *flowRecords {
	return &flowRecords{
		make(map[flowexporter.ConnectionKey]flowexporter.FlowRecord),
		connStore,
	}
}

func (fr *flowRecords) BuildFlowRecords() error {
	err := fr.connStoreBuilder.IterateCxnMapWithCB(fr.addOrUpdateFlowRecord)
	if err != nil {
		return fmt.Errorf("error in iterating cxn map: %v", err)
	}
	klog.V(2).Infof("Flow records that are built: %d", len(fr.recordsMap))
	return nil
}

func (fr *flowRecords) IterateFlowRecordsWithSendCB(sendCallback flowexporter.FlowRecordSend, templateID uint16) error {
	for k, v := range fr.recordsMap {
		dataRec := ipfix.NewIPFIXDataRecord(templateID)
		err := sendCallback(dataRec, v)
		if err != nil {
			klog.Errorf("flow record update and send failed for flow with key: %v, cxn: %v", k, v)
			return err
		}
		// Update the flow record after it is sent successfully
		v.PrevPackets = v.Conn.OriginalPackets
		v.PrevBytes = v.Conn.OriginalBytes
		v.PrevReversePackets = v.Conn.ReversePackets
		v.PrevReverseBytes = v.Conn.ReverseBytes
		fr.recordsMap[k] = v
		klog.V(2).Infof("Flow record sent successfully")
	}

	return nil
}

func (fr *flowRecords) addOrUpdateFlowRecord(key flowexporter.ConnectionKey, conn flowexporter.Connection) error {
	record, exists := fr.recordsMap[key]
	if !exists {
		record = flowexporter.FlowRecord{
			&conn,
			0,
			0,
			0,
			0,
		}
	} else {
		record.Conn = &conn
	}
	fr.recordsMap[key] = record
	klog.V(2).Infof("Flow record added or updated: %v", record)
	return nil
}
