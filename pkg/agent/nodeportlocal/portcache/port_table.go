// +build !windows

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

package portcache

import (
	"fmt"
	"sync"

	"antrea.io/antrea/pkg/agent/nodeportlocal/rules"
)

type NodePortData struct {
	NodePort int
	PodPort  int
	PodIP    string
	Status   int
}

type PortTable struct {
	Table        map[int]NodePortData
	StartPort    int
	EndPort      int
	PodPortRules rules.PodPortRules
	tableLock    sync.RWMutex
}

func NewPortTable(start, end int) (*PortTable, bool) {
	var ok bool
	ptable := PortTable{StartPort: start, EndPort: end}
	ptable.Table = make(map[int]NodePortData)
	ptable.PodPortRules = rules.InitRules()

	if ptable.PodPortRules != nil {
		ok = true
	}
	return &ptable, ok
}

func (pt *PortTable) CleanupAllEntries() {
	pt.tableLock.Lock()
	defer pt.tableLock.Unlock()
	pt.Table = make(map[int]NodePortData)
}

func (pt *PortTable) AddUpdateEntry(nodeport, podport int, podip string) {
	pt.tableLock.Lock()
	defer pt.tableLock.Unlock()
	data := NodePortData{NodePort: nodeport, PodPort: podport, PodIP: podip}
	pt.Table[nodeport] = data
}

func (pt *PortTable) DeleteEntry(nodeport int) {
	pt.tableLock.Lock()
	defer pt.tableLock.Unlock()
	delete(pt.Table, nodeport)
}

func (pt *PortTable) DeleteEntryByPodIP(ip string) {
	pt.tableLock.Lock()
	defer pt.tableLock.Unlock()
	for i, data := range pt.Table {
		if data.PodIP == ip {
			delete(pt.Table, i)
		}
	}
}

func (pt *PortTable) DeleteEntryByPodIPPort(ip string, port int) {
	pt.tableLock.Lock()
	defer pt.tableLock.Unlock()
	for i, data := range pt.Table {
		if data.PodIP == ip && data.PodPort == port {
			delete(pt.Table, i)
		}
	}
}

func (pt *PortTable) GetEntry(nodeport int) *NodePortData {
	pt.tableLock.RLock()
	defer pt.tableLock.RUnlock()
	data, _ := pt.Table[nodeport]
	return &data
}

func (pt *PortTable) GetDataForPodIP(ip string) []NodePortData {
	pt.tableLock.RLock()
	defer pt.tableLock.RUnlock()
	var allData []NodePortData
	for _, data := range pt.Table {
		if data.PodIP == ip {
			allData = append(allData, data)
		}
	}
	return allData
}

func (pt *PortTable) GetEntryByPodIPPort(ip string, port int) *NodePortData {
	pt.tableLock.RLock()
	defer pt.tableLock.RUnlock()
	for _, data := range pt.Table {
		if data.PodIP == ip && data.PodPort == port {
			return &data
		}
	}
	return nil
}

func (pt *PortTable) getFreePort(podIP string, podPort int) int {
	pt.tableLock.Lock()
	defer pt.tableLock.Unlock()
	for i := pt.StartPort; i <= pt.EndPort; i++ {
		if _, ok := pt.Table[i]; !ok {
			pt.Table[i] = NodePortData{PodIP: podIP, PodPort: podPort}
			return i
		}
	}
	return -1
}

func (pt *PortTable) AddRule(podIP string, podPort int) (int, error) {
	nodeport := pt.getFreePort(podIP, podPort)
	if nodeport < 0 {
		return 0, fmt.Errorf("no free port found")
	}
	err := pt.PodPortRules.AddRule(nodeport, podIP, podPort)
	if err != nil {
		return 0, err
	}
	pt.AddUpdateEntry(nodeport, podPort, podIP)
	return nodeport, nil
}

func (pt *PortTable) DeleteRule(podIP string, podPort int) error {
	data := pt.GetEntryByPodIPPort(podIP, podPort)
	err := pt.PodPortRules.DeleteRule(data.NodePort, podIP, podPort)
	if err != nil {
		return err
	}
	pt.DeleteEntry(data.NodePort)
	return nil
}

func (pt *PortTable) RuleExists(podIP string, podPort int) bool {
	data := pt.GetEntryByPodIPPort(podIP, podPort)
	if data != nil {
		return true
	}
	return false
}
