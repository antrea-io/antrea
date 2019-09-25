// Copyright 2019 OKN Authors
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

package openflow

import "sync"

type commandBridge struct {
	sync.Mutex

	name       string
	tableCache map[TableIDType]Table
}

func (b *commandBridge) CreateTable(id, next TableIDType, missAction missActionType) Table {
	t := &commandTable{
		bridge:     b.name,
		id:         id,
		next:       next,
		missAction: missAction,
	}
	b.Lock()
	defer b.Unlock()

	b.tableCache[t.id] = t
	return t
}

func (b *commandBridge) GetName() string {
	return b.name
}

func (b *commandBridge) DeleteTable(id TableIDType) bool {
	// TODO: no need to delete commandTable currently
	return true
}

func (b *commandBridge) DumpTableStatus() []TableStatus {
	var r []TableStatus
	for _, t := range b.tableCache {
		r = append(r, t.Status())
	}
	return r
}
