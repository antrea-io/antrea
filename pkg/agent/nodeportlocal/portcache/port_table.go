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
	"net"
	"sync"

	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/nodeportlocal/rules"
)

type NodePortData struct {
	NodePort int
	PodPort  int
	PodIP    string
	socket   Closeable
}

type LocalPortOpener interface {
	OpenLocalPort(port int) (Closeable, error)
}

type localPortOpener struct{}

type PortTable struct {
	Table           map[int]NodePortData
	StartPort       int
	EndPort         int
	PodPortRules    rules.PodPortRules
	LocalPortOpener LocalPortOpener
	tableLock       sync.RWMutex
}

func NewPortTable(start, end int) (*PortTable, error) {
	ptable := PortTable{StartPort: start, EndPort: end}
	ptable.Table = make(map[int]NodePortData)
	ptable.PodPortRules = rules.InitRules()
	ptable.LocalPortOpener = &localPortOpener{}
	if err := ptable.PodPortRules.Init(); err != nil {
		return nil, err
	}
	return &ptable, nil
}

func (pt *PortTable) CleanupAllEntries() {
	pt.tableLock.Lock()
	defer pt.tableLock.Unlock()
	pt.Table = make(map[int]NodePortData)
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
	return pt.getEntryByPodIPPort(ip, port)
}

func (pt *PortTable) getEntryByPodIPPort(ip string, port int) *NodePortData {
	for _, data := range pt.Table {
		if data.PodIP == ip && data.PodPort == port {
			return &data
		}
	}
	return nil
}

func (pt *PortTable) getFreePort(podIP string, podPort int) int {
	for i := pt.StartPort; i <= pt.EndPort; i++ {
		if _, ok := pt.Table[i]; !ok {
			socket, err := pt.LocalPortOpener.OpenLocalPort(i)
			if err != nil {
				continue
			}
			pt.Table[i] = NodePortData{
				NodePort: i,
				PodIP:    podIP,
				PodPort:  podPort,
				socket:   socket,
			}
			return i
		}
	}
	return -1
}

func (pt *PortTable) AddRule(podIP string, podPort int) (int, error) {
	pt.tableLock.Lock()
	defer pt.tableLock.Unlock()
	nodePort := pt.getFreePort(podIP, podPort)
	if nodePort < 0 {
		return 0, fmt.Errorf("no free port found")
	}
	err := pt.PodPortRules.AddRule(nodePort, fmt.Sprintf("%s:%d", podIP, podPort))
	if err != nil {
		return 0, err
	}
	return nodePort, nil
}

func (pt *PortTable) DeleteRule(podIP string, podPort int) error {
	pt.tableLock.Lock()
	defer pt.tableLock.Unlock()
	data := pt.getEntryByPodIPPort(podIP, podPort)
	if err := pt.PodPortRules.DeleteRule(data.NodePort, fmt.Sprintf("%s:%d", podIP, podPort)); err != nil {
		return err
	}
	if err := data.socket.Close(); err != nil {
		return fmt.Errorf("Error when releasing local port %d: %v", data.NodePort, err)
	}
	delete(pt.Table, data.NodePort)
	return nil
}

func (pt *PortTable) RuleExists(podIP string, podPort int) bool {
	data := pt.GetEntryByPodIPPort(podIP, podPort)
	if data != nil {
		return true
	}
	return false
}

func (pt *PortTable) SyncRules(allNPLPorts []rules.PodNodePort) error {
	validNPLPorts := make([]rules.PodNodePort, 0, len(allNPLPorts))
	pt.tableLock.Lock()
	defer pt.tableLock.Unlock()
	for _, nplPort := range allNPLPorts {
		socket, err := pt.LocalPortOpener.OpenLocalPort(nplPort.NodePort)
		if err != nil {
			// This should be handled gracefully by the NPL controller: if there is an
			// annotation using this port, it will be removed and replaced with a new
			// one with a valid port mapping.
			klog.ErrorS(err, "Cannot bind to local port, skipping it", "port", nplPort.NodePort)
			continue
		}
		data := NodePortData{
			NodePort: nplPort.NodePort,
			PodPort:  nplPort.PodPort,
			PodIP:    nplPort.PodIP,
			socket:   socket,
		}
		pt.Table[nplPort.NodePort] = data
		validNPLPorts = append(validNPLPorts, nplPort)
	}
	return pt.PodPortRules.AddAllRules(validNPLPorts)
}

// openLocalPort binds to the provided port.
// This is inspired by the openLocalPort function in kube-proxy:
// https://github.com/kubernetes/kubernetes/blob/86f8c3ee91b6faec437f97e3991107747d7fc5e8/pkg/proxy/iptables/proxier.go#L1664
func (lpo *localPortOpener) OpenLocalPort(port int) (Closeable, error) {
	// For now, NodePortLocal only supports IPv4 and TCP.
	network := "tcp4"
	listener, err := net.Listen(network, fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}
	klog.V(2).InfoS("Opened local port", "port", port)
	return listener, nil
}
