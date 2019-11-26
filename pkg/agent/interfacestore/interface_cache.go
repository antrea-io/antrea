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

package interfacestore

import (
	"sync"

	"github.com/vmware-tanzu/antrea/pkg/agent/util"
)

// Local cache for interfaces created on node, including container, host gateway, and tunnel
// ports, `Type` field is used to differentiate interface category
//  1) For container interface, the fields should include: containerID, podName, namespace, netns,
//     IP, MAC, and OVS Port configurations, and IfaceName is the cache key
//  2) For host gateway/tunnel port, the fields should include: name, IP, MAC, and OVS port
//     configurations, and IfaceName is the cache key
// OVS Port configurations include IfaceName, PortUUID and OFport. OFPort might be filled
// later when it is used to install openflow entry.
// Container interface is added into cache after invocation of cniserver.CmdAdd, and removed
// from cache after invocation of cniserver.CmdDel. For cniserver.CmdCheck, the server would
// check previousResult with local cache.
// Host gateway and tunnel interfaces are added into cache in node initialization phase or
// retrieved from existing OVS ports
// Todo: add periodic task to sync local cache with container veth pair

type interfaceCache struct {
	sync.RWMutex
	cache map[string]*InterfaceConfig
}

func (c *interfaceCache) Initialize(interfaces []*InterfaceConfig) {
	for _, intf := range interfaces {
		c.cache[intf.IfaceName] = intf
	}
}

// AddInterface adds interfaceConfig into localCache
func (c *interfaceCache) AddInterface(ifaceID string, interfaceConfig *InterfaceConfig) {
	c.Lock()
	defer c.Unlock()
	c.cache[ifaceID] = interfaceConfig
}

// DeleteInterface deletes interface from local cache
func (c *interfaceCache) DeleteInterface(ifaceID string) {
	c.Lock()
	defer c.Unlock()
	delete(c.cache, ifaceID)
}

// GetInterface retrieves interface from local cache
func (c *interfaceCache) GetInterface(ifaceID string) (*InterfaceConfig, bool) {
	c.RLock()
	defer c.RUnlock()
	iface, found := c.cache[ifaceID]
	return iface, found
}

func (c *interfaceCache) GetContainerInterfaceNum() int {
	num := 0
	c.RLock()
	defer c.RUnlock()
	for _, v := range c.cache {
		if v.Type == ContainerInterface {
			num++
		}
	}
	return num
}

func (c *interfaceCache) Len() int {
	c.RLock()
	defer c.RUnlock()
	return len(c.cache)
}

func (c *interfaceCache) GetInterfaceIDs() []string {
	c.RLock()
	defer c.RUnlock()
	ids := make([]string, 0, len(c.cache))
	for id := range c.cache {
		ids = append(ids, id)
	}
	return ids
}

// GetPodInterface retrieves interface for Pod filtered by Pod name and Pod namespace.
func (c *interfaceCache) GetContainerInterface(podName string, podNamespace string) (*InterfaceConfig, bool) {
	ovsPortName := util.GenerateContainerInterfaceName(podName, podNamespace)
	c.RLock()
	defer c.RUnlock()
	iface, ok := c.cache[ovsPortName]
	return iface, ok
}

func NewInterfaceStore() InterfaceStore {
	return &interfaceCache{cache: map[string]*InterfaceConfig{}}
}
