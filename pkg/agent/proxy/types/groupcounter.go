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
	"fmt"
	"sync"

	binding "antrea.io/antrea/pkg/ovs/openflow"
	k8sproxy "antrea.io/antrea/third_party/proxy"
)

// GroupCounter generates and manages global unique group ID.
type GroupCounter interface {
	// Get generates a global unique group ID for a specific service.
	// If the group ID of the service has been generated, then return the
	// prior one. The bool return value indicates whether the groupID is newly
	// generated.
	Get(svcPortName k8sproxy.ServicePortName, isEndpointsLocal bool) (binding.GroupIDType, bool)
	// Recycle removes a Service Group ID mapping. The recycled groupID can be
	// reused.
	Recycle(svcPortName k8sproxy.ServicePortName, isEndpointsLocal bool) bool
}

type groupCounter struct {
	mu             sync.Mutex
	groupIDCounter binding.GroupIDType
	recycled       []binding.GroupIDType

	groupMap map[string]binding.GroupIDType
}

func NewGroupCounter(isIPv6 bool) *groupCounter {
	var groupIDCounter binding.GroupIDType
	if isIPv6 {
		groupIDCounter = 0x10000000
	}
	return &groupCounter{groupMap: map[string]binding.GroupIDType{}, groupIDCounter: groupIDCounter}
}

func keyString(svcPortName k8sproxy.ServicePortName, isEndpointsLocal bool) string {
	key := svcPortName.String()
	if isEndpointsLocal {
		key = fmt.Sprintf("%s/local", key)
	}
	return key
}

func (c *groupCounter) Get(svcPortName k8sproxy.ServicePortName, isEndpointsLocal bool) (binding.GroupIDType, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := keyString(svcPortName, isEndpointsLocal)
	if id, ok := c.groupMap[key]; ok {
		return id, false
	} else if len(c.recycled) != 0 {
		id = c.recycled[len(c.recycled)-1]
		c.recycled = c.recycled[:len(c.recycled)-1]
		c.groupMap[key] = id
		return id, true
	} else {
		c.groupIDCounter += 1
		c.groupMap[key] = c.groupIDCounter
		return c.groupIDCounter, true
	}
}

func (c *groupCounter) Recycle(svcPortName k8sproxy.ServicePortName, isEndpointsLocal bool) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := keyString(svcPortName, isEndpointsLocal)
	if id, ok := c.groupMap[key]; ok {
		delete(c.groupMap, key)
		c.recycled = append(c.recycled, id)
		return true
	}
	return false
}
