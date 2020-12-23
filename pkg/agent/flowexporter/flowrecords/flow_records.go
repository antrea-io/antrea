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
	"net"

	"k8s.io/klog"

	"github.com/vmware-tanzu/antrea/pkg/agent/flowexporter"
	"github.com/vmware-tanzu/antrea/pkg/agent/flowexporter/connections"
)

type FlowRecords struct {
	// Add lock when this map is consumed by more than one entity concurrently.
	recordsMap map[flowexporter.ConnectionKey]flowexporter.FlowRecord
	connStore  *connections.ConnectionStore
}

func NewFlowRecords(connStore *connections.ConnectionStore) *FlowRecords {
	return &FlowRecords{
		make(map[flowexporter.ConnectionKey]flowexporter.FlowRecord),
		connStore,
	}
}

// BuildFlowRecords builds the flow record map from connection map in connection store
func (fr *FlowRecords) BuildFlowRecords() error {
	addOrUpdateFlowRecord := func(key flowexporter.ConnectionKey, conn flowexporter.Connection) error {
		// If DoExport flag is not set return immediately.
		if !conn.DoExport {
			return nil
		}
		record, exists := fr.recordsMap[key]

		isIPv6 := false
		if net.ParseIP(key[0]).To4() == nil {
			isIPv6 = true
		}
		if !exists {
			record = flowexporter.FlowRecord{
				Conn:               &conn,
				PrevPackets:        0,
				PrevBytes:          0,
				PrevReversePackets: 0,
				PrevReverseBytes:   0,
				IsIPv6:             isIPv6,
			}
		} else {
			record.Conn = &conn
		}
		fr.recordsMap[key] = record
		return nil
	}

	// addOrUpdateFlowRecord method does not return any error, hence no error handling required.
	fr.connStore.ForAllConnectionsDo(addOrUpdateFlowRecord)
	klog.V(2).Infof("No. of flow records built: %d", len(fr.recordsMap))
	return nil
}

// GetFlowRecordByConnKey gets the record from the flow record map given the connection key
func (fr *FlowRecords) GetFlowRecordByConnKey(connKey flowexporter.ConnectionKey) (*flowexporter.FlowRecord, bool) {
	record, found := fr.recordsMap[connKey]
	return &record, found
}

// ValidateAndUpdateStats validates and updates the flow record given the connection key
func (fr *FlowRecords) ValidateAndUpdateStats(connKey flowexporter.ConnectionKey, record flowexporter.FlowRecord) error {
	// Delete the flow record if the corresponding connection is not active, i.e., not present in conntrack table.
	// Delete the corresponding connection in connectionMap as well.
	if !record.Conn.IsActive {
		klog.V(2).Infof("Deleting the inactive connection with key: %v", connKey)
		delete(fr.recordsMap, connKey)
		if err := fr.connStore.DeleteConnectionByKey(connKey); err != nil {
			return err
		}
	} else {
		// Update the stats in flow record after it is sent successfully
		record.PrevPackets = record.Conn.OriginalPackets
		record.PrevBytes = record.Conn.OriginalBytes
		record.PrevReversePackets = record.Conn.ReversePackets
		record.PrevReverseBytes = record.Conn.ReverseBytes
		fr.recordsMap[connKey] = record
	}

	return nil
}

// ForAllFlowRecordsDo executes the callback for all records in the flow record map
func (fr *FlowRecords) ForAllFlowRecordsDo(callback flowexporter.FlowRecordCallBack) error {
	for k, v := range fr.recordsMap {
		err := callback(k, v)
		if err != nil {
			klog.Errorf("Error when executing callback for flow record")
			return err
		}
	}

	return nil
}
