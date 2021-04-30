// +build linux

// Copyright 2021 Antrea Authors
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
	"github.com/TomCodeLV/OVSDB-golang-lib/pkg/dbtransaction"
	"k8s.io/klog"
)

func (br *OVSBridge) SetInterfaceMTU(name string, MTU int) error {
	tx := br.ovsdb.Transaction(openvSwitchSchema)

	tx.Update(dbtransaction.Update{
		Table: "Interface",
		Where: [][]interface{}{{"name", "==", name}},
		Row: map[string]interface{}{
			"mtu_request": MTU,
		},
	})

	_, err, temporary := tx.Commit()
	if err != nil {
		klog.Error("Transaction failed: ", err)
		return NewTransactionError(err, temporary)
	}

	return nil
}
