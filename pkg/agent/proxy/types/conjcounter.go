// Copyright 2010 Antrea Authors
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

	k8sproxy "antrea.io/antrea/third_party/proxy"
)

// ConjCounter generates and manages unique conjunction ID for NodePort flows
// at table serviceLBTable
type ConjCounter interface {
	// Get generates a global unique conjunction ID for a specific service.
	// If the conjunction ID has been generated, then return the prior one.
	// The bool return value indicates whether the groupID is newly generated.
	Get(svcPortName k8sproxy.ServicePortName) (uint32, bool)
	// Recycle removes a conjunction ID mapping. The recycled groupID can be
	// reused.
	Recycle(svcPortName k8sproxy.ServicePortName) bool
	// GetAll gets all existing conjunction IDs.
	GetAll() []uint32
}

type conjCounter struct {
	mu            sync.Mutex
	conjIDCounter uint32
	recycled      []uint32

	conjMap map[string]uint32
}

func NewConjCounter(isIPv6 bool) *conjCounter {
	var conjIDCounter uint32
	if isIPv6 {
		conjIDCounter = 0x10000000
	}
	return &conjCounter{conjMap: map[string]uint32{}, conjIDCounter: conjIDCounter}
}

func (c *conjCounter) Get(svcPortName k8sproxy.ServicePortName) (uint32, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := svcPortName.String()
	if id, ok := c.conjMap[key]; ok {
		return id, false
	} else if len(c.recycled) != 0 {
		id = c.recycled[len(c.recycled)-1]
		c.recycled = c.recycled[:len(c.recycled)-1]
		c.conjMap[key] = id
		return id, false
	} else {
		c.conjIDCounter += 1
		c.conjMap[key] = c.conjIDCounter
		return c.conjIDCounter, true
	}
}

func (c *conjCounter) GetAll() []uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()

	conjIDs := make([]uint32, 0, len(c.conjMap))
	for _, conjID := range c.conjMap {
		conjIDs = append(conjIDs, conjID)
	}
	return conjIDs
}

func (c *conjCounter) Recycle(svcPortName k8sproxy.ServicePortName) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := svcPortName.String()
	if id, ok := c.conjMap[key]; ok {
		delete(c.conjMap, key)
		c.recycled = append(c.recycled, id)
		return true
	}
	return false
}
