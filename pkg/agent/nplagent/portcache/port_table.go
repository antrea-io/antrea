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

	nplutils "github.com/vmware-tanzu/antrea/pkg/agent/nplagent/lib"
	"github.com/vmware-tanzu/antrea/pkg/agent/nplagent/rules"
	"k8s.io/klog"
)

const (
	successStatus = 0
	pendingStatus = 1
	failStatus    = 2
)

type NodePortData struct {
	Nodeport int
	Podport  int
	Podip    string
	Status   int
	//podname  string
}

type PortTable struct {
	Table        map[int]NodePortData
	StartPort    int
	EndPort      int
	PodPortRules rules.PodPortRules
	tableLock    sync.RWMutex
}

var once sync.Once
var ptable PortTable

func NewPortTable(start, end int) (*PortTable, bool) {
	var ok bool
	once.Do(func() {
		ptable = PortTable{StartPort: start, EndPort: end}
		ptable.Table = make(map[int]NodePortData)
		ptable.PodPortRules = rules.Initrules()
	})
	if ptable.PodPortRules != nil {
		ok = true
	}
	return &ptable, ok
}

func GetPortTable() *PortTable {
	return &ptable
}

func (pt *PortTable) PopulatePortTable(r rules.PodPortRules) {
	portMap := make(map[int]string)
	ok := r.GetAllRules(portMap)
	if !ok {
		klog.Warningf("Could not populate port table cache")
		return
	}
	table := make(map[int]NodePortData)
	for nodeport, podip := range portMap {
		entry := NodePortData{
			Nodeport: nodeport,
			Podip:    podip,
		}
		table[nodeport] = entry
	}
	pt.tableLock.Lock()
	defer pt.tableLock.Unlock()
	pt.Table = table
}

func (pt *PortTable) AddUpdateEntry(nodeport, podport int, podip string) {
	pt.tableLock.Lock()
	defer pt.tableLock.Unlock()
	data := NodePortData{Nodeport: nodeport, Podport: podport, Podip: podip}
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
		if data.Podip == ip {
			delete(pt.Table, i)
		}
	}
}

func (pt *PortTable) DeleteEntryByPodIPPort(ip string, port int) {
	pt.tableLock.Lock()
	defer pt.tableLock.Unlock()
	for i, data := range pt.Table {
		if data.Podip == ip && data.Podport == port {
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

func (pt *PortTable) GetEntryByPodIPPort(ip string, port int) *NodePortData {
	pt.tableLock.RLock()
	defer pt.tableLock.RUnlock()
	for _, data := range pt.Table {
		if data.Podip == ip && data.Podport == port {
			return &data
		}
	}
	return nil
}

func (pt *PortTable) getFreePort() int {
	pt.tableLock.RLock()
	defer pt.tableLock.RUnlock()
	for i := pt.StartPort; i <= pt.EndPort; i++ {
		if _, ok := pt.Table[i]; !ok && nplutils.IsPortAvailable(i) {
			return i
		}
	}
	return -1
}

func (pt *PortTable) AddRule(podip string, podport int) (int, bool) {
	nodeport := pt.getFreePort()
	if nodeport < 0 {
		return 0, false
	}
	if pt == nil {
		return 0, false
	}
	ok := pt.PodPortRules.AddRule(nodeport, fmt.Sprintf("%s:%d", podip, podport))
	if !ok {
		return 0, false
	}
	pt.AddUpdateEntry(nodeport, podport, podip)
	return nodeport, true
}

func (pt *PortTable) DeleteRule(podip string, podport int) bool {
	data := pt.GetEntryByPodIPPort(podip, podport)
	ok := pt.PodPortRules.DeleteRule(data.Nodeport, fmt.Sprintf("%s:%d", podip, podport))
	if !ok {
		return false
	}
	pt.DeleteEntry(data.Nodeport)
	return true
}

func (pt *PortTable) RuleExists(podip string, podport int) bool {
	data := pt.GetEntryByPodIPPort(podip, podport)
	if data != nil {
		return true
	}
	return false
}
