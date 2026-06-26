// Copyright 2026 Antrea Authors
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

package ovsconfig

import (
	"fmt"

	"github.com/TomCodeLV/OVSDB-golang-lib/pkg/dbtransaction"
	"github.com/TomCodeLV/OVSDB-golang-lib/pkg/helpers"
	"github.com/TomCodeLV/OVSDB-golang-lib/pkg/ovsdb"
	"k8s.io/klog/v2"
)

type OVSBridgeData struct {
	Name        string
	ExternalIDs map[string]string
}

// ListOVSBridges returns all OVS bridges with their external IDs.
func ListOVSBridges(ovsdbConn *ovsdb.OVSDB) ([]OVSBridgeData, Error) {
	tx := ovsdbConn.Transaction(openvSwitchSchema)
	tx.Select(dbtransaction.Select{
		Table:   "Bridge",
		Columns: []string{"name", "external_ids"},
	})
	res, err, temporary := tx.Commit()
	if err != nil {
		klog.Error("Transaction failed: ", err)
		return nil, NewTransactionError(err, temporary)
	}
	if len(res) == 0 {
		return nil, nil
	}

	bridges := make([]OVSBridgeData, 0, len(res[0].Rows))
	for _, row := range res[0].Rows {
		bridge, ok := ovsBridgeDataFromRow(row)
		if ok {
			bridges = append(bridges, bridge)
		}
	}
	return bridges, nil
}

// GetOVSBridgeExternalIDs returns the external IDs for an OVS bridge.
func GetOVSBridgeExternalIDs(ovsdbConn *ovsdb.OVSDB, bridgeName string) (map[string]string, bool, Error) {
	tx := ovsdbConn.Transaction(openvSwitchSchema)
	tx.Select(dbtransaction.Select{
		Table:   "Bridge",
		Columns: []string{"name", "external_ids"},
		Where:   [][]interface{}{{"name", "==", bridgeName}},
	})
	res, err, temporary := tx.Commit()
	if err != nil {
		klog.Error("Transaction failed: ", err)
		return nil, false, NewTransactionError(err, temporary)
	}
	if len(res) == 0 || len(res[0].Rows) == 0 {
		return nil, false, nil
	}
	bridge, ok := ovsBridgeDataFromRow(res[0].Rows[0])
	if !ok {
		return nil, false, NewTransactionError(fmt.Errorf("unexpected OVSDB Bridge row for bridge %s", bridgeName), false)
	}
	return bridge.ExternalIDs, true, nil
}

// SetOVSBridgeExternalIDs sets the external IDs for an OVS bridge.
func SetOVSBridgeExternalIDs(ovsdbConn *ovsdb.OVSDB, bridgeName string, externalIDs map[string]interface{}) Error {
	tx := ovsdbConn.Transaction(openvSwitchSchema)
	tx.Update(dbtransaction.Update{
		Table: "Bridge",
		Where: [][]interface{}{{"name", "==", bridgeName}},
		Row: map[string]interface{}{
			"external_ids": helpers.MakeOVSDBMap(externalIDs),
		},
	})
	_, err, temporary := tx.Commit()
	if err != nil {
		klog.Error("Transaction failed: ", err)
		return NewTransactionError(err, temporary)
	}
	return nil
}

func ovsBridgeDataFromRow(row interface{}) (OVSBridgeData, bool) {
	r, ok := row.(map[string]interface{})
	if !ok {
		return OVSBridgeData{}, false
	}
	name, ok := r["name"].(string)
	if !ok {
		return OVSBridgeData{}, false
	}
	externalIDs, ok := r["external_ids"].([]interface{})
	if !ok {
		return OVSBridgeData{}, false
	}
	return OVSBridgeData{Name: name, ExternalIDs: buildMapFromOVSDBMap(externalIDs)}, true
}
