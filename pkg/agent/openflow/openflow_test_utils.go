// Copyright 2022 Antrea Authors
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

package openflow

import (
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

// InitMockTables is used to init mock tables.
func InitMockTables(tableMap map[*Table]uint8) {
	for ft, id := range tableMap {
		ft.ofTable = binding.NewOFTable(id, ft.name, 0, 0, 0)
	}
}

// InitOFTableCache is used to update ofTableCache in tests.
func InitOFTableCache(tableMap map[*Table]uint8) {
	for ft := range tableMap {
		tableCache.Update(ft)
	}
}

// ResetOFTable is used for integration tests.
func ResetOFTable() {
	binding.ResetTableID()
}

// CleanOFTableCache is used to reset ofTableCache and only used in integration tests. When all integration tests about
// openflow run in batch, unexpected flows could be installed on OVS due to stale ofTableCache, which may cause some tests
// to fail. For example, for TestFuncA, EgressMarkTable is needed; for TestFuncB, EgressMarkTable is not needed. If TestFuncB is run
// after TestFuncA, since ofTableCache (EgressMarkTable is added by TestFuncA) is not reset, default flow of EgressMarkTable will also
// be realized on OVS when running TestFuncB (see "func (c *client) defaultFlows() (flows []binding.Flow)"). Note that,
// the unexpected flows are not included in the map tableCache of OFBridge defined in pkg/ovs/openflow/ofctrl_bridge.go,
// because the bridge will be destroyed after every test. For some tests, function checkOVSFlowMetrics (defined in
// test/integration/agent/openflow_test.go) is used to check the flow number of every installed table. The expected table
// list is read from the map tableCache of OFBridge, but the actual table list is dumped from OVS bridge (including the
// unexpected flow). They are different, and as a result, TestFuncB will fail.
func CleanOFTableCache() {
	objs := tableCache.List()
	for i := 0; i < len(objs); i++ {
		tableCache.Delete(objs[i])
	}
}
