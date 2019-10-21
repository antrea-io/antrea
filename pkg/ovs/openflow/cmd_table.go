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

import (
	"sync"
	"time"
)

type commandTable struct {
	sync.Mutex

	bridge     string
	id         TableIDType
	next       TableIDType
	missAction missActionType
	flowCount  uint
	updateTime time.Time
}

func (t *commandTable) GetID() TableIDType {
	return t.id
}

func (t *commandTable) BuildFlow() FlowBuilder {
	fb := new(commandBuilder)
	fb.table = t
	return fb.Switch(t.bridge)
}

func (t *commandTable) Status() TableStatus {
	return TableStatus{
		ID:         uint(t.id),
		FlowCount:  t.flowCount,
		UpdateTime: t.updateTime,
	}
}

func (t *commandTable) GetMissAction() missActionType {
	return t.missAction
}

func (t *commandTable) GetNext() TableIDType {
	return t.next
}

func (t *commandTable) updateStatus(flowCountDelta int) {
	t.Lock()
	defer t.Unlock()

	if flowCountDelta < 0 {
		t.flowCount -= uint(-flowCountDelta)
	} else {
		t.flowCount += uint(flowCountDelta)
	}
	t.updateTime = time.Now()
}
