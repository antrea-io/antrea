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

package openflow

import (
	"k8s.io/apimachinery/pkg/util/sets"

	binding "antrea.io/antrea/pkg/ovs/openflow"
)

type featureID int

const (
	Shared featureID = iota
	PodConnectivity
	VMConnectivity
	NetworkPolicy
	Service
	Egress
	Traceflow
)

type ofProtocol int

const (
	ofProtocolIP ofProtocol = iota
	ofProtocolARP
)

type FeatureTable struct {
	name     string
	ofTable  binding.Table
	features sets.Int
}

func newFeatureTable(tableName string) *FeatureTable {
	return &FeatureTable{
		name: tableName,
	}
}

func (c *FeatureTable) GetID() uint8 {
	return c.ofTable.GetID()
}

func (c *FeatureTable) GetNext() uint8 {
	return c.ofTable.GetNext()
}

func (c *FeatureTable) GetName() string {
	return c.name
}

func (c *FeatureTable) GetOFTable() binding.Table {
	return c.ofTable
}

// SetOFTable is only used for test code.
func (c *FeatureTable) SetOFTable(id uint8) {
	c.ofTable = binding.NewOFTable(id, c.name, 0, 0)
}

// A table with a higher priority is assigned with a lower tableID, which means a packet should enter the table
// before others with lower priorities in the same stage.
type tableRequest struct {
	table    *FeatureTable
	priority uint8
}

type pipelineTemplate struct {
	// Declare the tables and the corresponding priorities in the expected stage.
	// If it is expected to enforce a packet to enter other tables in the same stage after leaving the current table,
	// use a higher priority in the tableRequest.
	stageTables map[binding.StageID][]tableRequest
	feature     featureID
}

type feature interface {
	getFeatureID() featureID
	getTemplate(protocol ofProtocol) *pipelineTemplate
}
