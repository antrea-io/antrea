// Copyright 2019 Antrea Authors
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

import "sort"

const (
	AllPipelines uint8 = 255
)

var (
	pipelineCache = make(map[uint8]*ofPipeline)
	pipelineID    uint8
)

type ofPipeline struct {
	pipelineID     uint8
	sortedTableMap map[StageID][]Table
	firstTable     Table
	lastTable      Table
	firstStage     StageID
	lastStage      StageID
}

func (p *ofPipeline) GetNextStage(id StageID) StageID {
	for {
		stage := id + 1
		if stage >= LastStage {
			return LastStage
		}
		if _, ok := p.sortedTableMap[stage]; ok {
			return stage
		}
	}
}

func (p *ofPipeline) GetFirstTableInStage(id StageID) Table {
	tables, ok := p.sortedTableMap[id]
	if ok {
		return tables[0]
	}
	return nil
}

func (p *ofPipeline) ListTablesInStage(id StageID) []Table {
	return p.sortedTableMap[id]
}

func (p *ofPipeline) IsStageValid(stage StageID) bool {
	_, ok := p.sortedTableMap[stage]
	return ok
}

func (p *ofPipeline) GetFirstTable() Table {
	return p.firstTable
}

func (p *ofPipeline) GetLastTable() Table {
	return p.lastTable
}

func (p *ofPipeline) IsLastTable(t Table) bool {
	return t.GetID() == p.lastTable.GetID()
}

func (p *ofPipeline) ListAllTables() []Table {
	tables := make([]Table, 0)
	for _, t := range p.sortedTableMap {
		tables = append(tables, t...)
	}
	sort.Slice(tables, func(i, j int) bool {
		return tables[i].GetID() < tables[j].GetID()
	})
	return tables
}

func NewPipeline(id uint8, stageTableMap map[StageID][]Table) Pipeline {
	p := &ofPipeline{pipelineID: id, sortedTableMap: stageTableMap}
	for s := ClassifierStage; s <= LastStage; s++ {
		if tables, ok := stageTableMap[s]; ok {
			p.firstStage = s
			p.firstTable = tables[0]
			break
		}
	}
	for s := LastStage; true; s-- {
		if tables, ok := stageTableMap[s]; ok {
			p.lastStage = s
			tableCount := len(tables)
			p.lastTable = tables[tableCount-1]
			break
		}
	}
	pipelineCache[id] = p
	return p
}

func NewPipelineID() uint8 {
	pipelineID += 1
	return pipelineID
}
