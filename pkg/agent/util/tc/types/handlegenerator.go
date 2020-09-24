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

package types

import (
	"fmt"
	"net"
	"sync"
)

// HandleGenerator generates and manages unique TC handle ID for every network interface.
type HandleGenerator interface {
	// Get generates a unique handle ID for an interface with TC chain, IP, port
	// and transport protocol.
	Get(chain int, ip net.IP, port uint16, protocol int) int
	// Recycle removes a handle ID mapping. The recycled handle ID can be reused.
	Recycle(chain int, ip net.IP, port uint16, protocol int)
}

type handleGenerator struct {
	mu            sync.Mutex
	handleCounter int
	recycled      []int
	handleMap     map[string]int
}

func NewHandleGenerator() *handleGenerator {
	hg := &handleGenerator{
		handleCounter: 0,
		recycled:      []int{},
		handleMap:     map[string]int{},
	}
	return hg
}

func keyString(chain int, ip net.IP, port uint16, protocol int) string {
	if ip == nil {
		ip = net.ParseIP("0.0.0.0")
	}
	key := fmt.Sprintf("%d/%s/%d/%d", chain, ip.String(), port, protocol)
	return key
}

func (c *handleGenerator) Get(chain int, ip net.IP, port uint16, protocol int) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := keyString(chain, ip, port, protocol)
	if id, ok := c.handleMap[key]; ok {
		return id
	} else if len(c.recycled) != 0 {
		id = c.recycled[len(c.recycled)-1]
		c.recycled = c.recycled[:len(c.recycled)-1]
		c.handleMap[key] = id
		return id
	} else {
		c.handleCounter += 1
		c.handleMap[key] = c.handleCounter
		return c.handleCounter
	}
}

func (c *handleGenerator) Recycle(chain int, ip net.IP, port uint16, protocol int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := keyString(chain, ip, port, protocol)
	if id, ok := c.handleMap[key]; ok {
		delete(c.handleMap, key)
		c.recycled = append(c.recycled, id)
	}
}
