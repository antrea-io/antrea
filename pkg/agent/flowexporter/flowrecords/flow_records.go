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
	"sync"
	"time"

	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/flowexporter"
)

type FlowRecords struct {
	recordsMap map[flowexporter.ConnectionKey]flowexporter.FlowRecord
	mutex      sync.Mutex
}

func NewFlowRecords() *FlowRecords {
	return &FlowRecords{
		recordsMap: make(map[flowexporter.ConnectionKey]flowexporter.FlowRecord),
	}
}

// AddOrUpdateFlowRecord adds or updates the flow record in the record map given the connection.
// It makes a copy of the connection object to record, to avoid race conditions between the
// connection store and the flow exporter.
func (fr *FlowRecords) AddOrUpdateFlowRecord(key flowexporter.ConnectionKey, conn *flowexporter.Connection) error {
	// If the connection is in dying state and the corresponding flow records are already
	// exported, then there is no need to add or update the record.
	if flowexporter.IsConnectionDying(conn) && conn.DoneExport {
		return nil
	}

	fr.mutex.Lock()
	defer fr.mutex.Unlock()

	record, exists := fr.recordsMap[key]
	if !exists {
		isIPv6 := false
		if conn.FlowKey.SourceAddress.To4() == nil {
			isIPv6 = true
		}
		record = flowexporter.FlowRecord{
			Conn:               *conn,
			PrevPackets:        0,
			PrevBytes:          0,
			PrevReversePackets: 0,
			PrevReverseBytes:   0,
			IsIPv6:             isIPv6,
			LastExportTime:     conn.StartTime,
			IsActive:           true,
		}
	} else {
		// set IsActive flag to true when there are changes either in stats or TCP state
		if (conn.OriginalPackets > record.PrevPackets) || (conn.ReversePackets > record.PrevReversePackets) || record.Conn.TCPState != conn.TCPState {
			record.IsActive = true
		}
		record.Conn = *conn
	}
	fr.recordsMap[key] = record
	return nil
}

// AddFlowRecordToMap adds the flow record from record map given connection key.
// This is used only for unit tests.
func (fr *FlowRecords) AddFlowRecordToMap(connKey *flowexporter.ConnectionKey, record *flowexporter.FlowRecord) {
	fr.mutex.Lock()
	defer fr.mutex.Unlock()
	fr.recordsMap[*connKey] = *record
}

// GetFlowRecordFromMap gets the flow record from record map given connection key.
// This is used only for unit tests.
func (fr *FlowRecords) GetFlowRecordFromMap(connKey *flowexporter.ConnectionKey) (*flowexporter.FlowRecord, bool) {
	fr.mutex.Lock()
	defer fr.mutex.Unlock()
	record, exists := fr.recordsMap[*connKey]
	return &record, exists
}

// DeleteFlowRecordWithoutLock deletes the record from the record map given
// the connection key without grabbing the lock. Caller is expected to grab lock.
func (fr *FlowRecords) DeleteFlowRecordWithoutLock(connKey flowexporter.ConnectionKey) error {
	_, exists := fr.recordsMap[connKey]
	if !exists {
		return fmt.Errorf("flow record with key %v doesn't exist in map", connKey)
	}
	delete(fr.recordsMap, connKey)
	return nil
}

// ValidateAndUpdateStats validates and updates the flow record given the connection
// key. Caller is expected to grab lock.
func (fr *FlowRecords) ValidateAndUpdateStats(connKey flowexporter.ConnectionKey, record flowexporter.FlowRecord) {
	// Update the stats in flow record after it is sent successfully
	record.PrevPackets = record.Conn.OriginalPackets
	record.PrevBytes = record.Conn.OriginalBytes
	record.PrevReversePackets = record.Conn.ReversePackets
	record.PrevReverseBytes = record.Conn.ReverseBytes
	record.LastExportTime = time.Now()

	fr.recordsMap[connKey] = record

}

// ForAllFlowRecordsDo executes the callback for all records in the flow record map
func (fr *FlowRecords) ForAllFlowRecordsDo(callback flowexporter.FlowRecordCallBack) error {
	fr.mutex.Lock()
	defer fr.mutex.Unlock()
	for k, v := range fr.recordsMap {
		err := callback(k, v)
		if err != nil {
			klog.Errorf("Error when executing callback for flow record: %v", err)
			return err
		}
	}
	return nil
}
