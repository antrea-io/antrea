// Copyright 2020 Antrea Authors
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

package types

import (
	"sync"

	"github.com/vmware-tanzu/antrea/pkg/agent/proxy/upstream"
	binding "github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
)

type GroupCounter interface {
	Get(svcPortName upstream.ServicePortName) (binding.GroupIDType, bool)
	Recycle(svcPortName upstream.ServicePortName) bool
}

type groupCounter struct {
	mu             sync.Mutex
	groupIDCounter binding.GroupIDType
	recycled       []binding.GroupIDType

	groupMap map[upstream.ServicePortName]binding.GroupIDType
}

func NewGroupCounter() *groupCounter {
	return &groupCounter{groupMap: map[upstream.ServicePortName]binding.GroupIDType{}}
}

func (c *groupCounter) Get(svcPortName upstream.ServicePortName) (binding.GroupIDType, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if id, ok := c.groupMap[svcPortName]; ok {
		return id, false
	} else if len(c.recycled) != 0 {
		id = c.recycled[len(c.recycled)-1]
		c.recycled = c.recycled[:len(c.recycled)-1]
		return id, true
	} else {
		c.groupIDCounter += 1
		c.groupMap[svcPortName] = c.groupIDCounter
		return c.groupIDCounter, true
	}
}

func (c *groupCounter) Recycle(svcPortName upstream.ServicePortName) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if id, ok := c.groupMap[svcPortName]; ok {
		delete(c.groupMap, svcPortName)
		c.recycled = append(c.recycled, id)
		return true
	}
	return false
}
