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

var pipelineCache = make(map[PipelineID]*ofPipeline)

type ofPipeline struct {
	pipelineID PipelineID
	tableMap   map[StageID][]Table
	tableList  []Table
}

func (p *ofPipeline) GetFirstTableInStage(id StageID) Table {
	tables, ok := p.tableMap[id]
	if ok {
		return tables[0]
	}
	return nil
}

func (p *ofPipeline) GetFirstTable() Table {
	return p.tableList[0]
}

func (p *ofPipeline) IsLastTable(t Table) bool {
	return t.GetID() == p.tableList[len(p.tableList)-1].GetID()
}

func (p *ofPipeline) ListAllTables() []Table {
	return p.tableList
}

func NewPipeline(id PipelineID, ofTables []Table) Pipeline {
	tableMap := make(map[StageID][]Table)
	for _, t := range ofTables {
		sid := t.GetStageID()
		tableMap[sid] = append(tableMap[sid], t)
	}
	p := &ofPipeline{pipelineID: id,
		tableMap:  tableMap,
		tableList: ofTables,
	}
	pipelineCache[id] = p
	return p
}
