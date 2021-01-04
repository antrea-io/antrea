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

	"github.com/vmware-tanzu/antrea/pkg/agent/nodeportlocal/rules"
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

func (pt *PortTable) getFreePort(podip string, podport int) int {
	pt.tableLock.Lock()
	defer pt.tableLock.Unlock()
	for i := pt.StartPort; i <= pt.EndPort; i++ {
		if _, ok := pt.Table[i]; !ok {
			pt.Table[i] = NodePortData{PodIP: podip, PodPort: podport}
			return i
		}
	}
	return -1
}

func (pt *PortTable) AddRule(podip string, podport int) (int, error) {
	nodeport := pt.getFreePort(podip, podport)
	if nodeport < 0 {
		return 0, fmt.Errorf("no free port found")
	}
	err := pt.PodPortRules.AddRule(nodeport, fmt.Sprintf("%s:%d", podip, podport))
	if err != nil {
		return 0, err
	}
	pt.AddUpdateEntry(nodeport, podport, podip)
	return nodeport, nil
}

func (pt *PortTable) DeleteRule(podip string, podport int) error {
	data := pt.GetEntryByPodIPPort(podip, podport)
	err := pt.PodPortRules.DeleteRule(data.NodePort, fmt.Sprintf("%s:%d", podip, podport))
	if err != nil {
		return err
	}
	pt.DeleteEntry(data.NodePort)
	return nil
}

func (pt *PortTable) RuleExists(podip string, podport int) bool {
	data := pt.GetEntryByPodIPPort(podip, podport)
	if data != nil {
		return true
	}
	return false
}
