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
	"io"
	"net"
	"sync"

	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/nodeportlocal/rules"
)

// protocolSocketState represents the state of the socket corresponding to a
// given (Node port, protocol) tuple.
type protocolSocketState int

type ProtocolSocketData struct {
	Protocol string
	State    protocolSocketState
	socket   io.Closer
}

type NodePortData struct {
	NodePort  int
	PodPort   int
	PodIP     string
	Protocols []ProtocolSocketData
}

func (d *NodePortData) FindProtocol(protocol string) *ProtocolSocketData {
	for idx, protocolSocketData := range d.Protocols {
		if protocolSocketData.Protocol == protocol {
			return &d.Protocols[idx]
		}
	}
	return nil
}

func (d *NodePortData) ProtocolInUse(protocol string) bool {
	for _, protocolSocketData := range d.Protocols {
		if protocolSocketData.Protocol == protocol {
			return protocolSocketData.State == stateInUse
		}
	}
	return false
}

type LocalPortOpener interface {
	OpenLocalPort(port int, protocol string) (io.Closer, error)
}

type localPortOpener struct{}

type PortTable struct {
	NodePortTable    map[string]*NodePortData
	PodEndpointTable map[string]*NodePortData
	StartPort        int
	EndPort          int
	PortSearchStart  int
	PodPortRules     rules.PodPortRules
	LocalPortOpener  LocalPortOpener
	tableLock        sync.RWMutex
}

func NewPortTable(start, end int) (*PortTable, error) {
	ptable := PortTable{
		NodePortTable:    make(map[string]*NodePortData),
		PodEndpointTable: make(map[string]*NodePortData),
		StartPort:        start,
		EndPort:          end,
		PortSearchStart:  start,
		PodPortRules:     rules.InitRules(),
		LocalPortOpener:  &localPortOpener{},
	}
	if err := ptable.PodPortRules.Init(); err != nil {
		return nil, err
	}
	return &ptable, nil
}

func (pt *PortTable) CleanupAllEntries() {
	pt.tableLock.Lock()
	defer pt.tableLock.Unlock()
	pt.NodePortTable = make(map[string]*NodePortData)
	pt.PodEndpointTable = make(map[string]*NodePortData)
}

func (pt *PortTable) GetDataForPodIP(ip string) []NodePortData {
	pt.tableLock.RLock()
	defer pt.tableLock.RUnlock()
	return pt.getDataForPodIP(ip)
}

func (pt *PortTable) getDataForPodIP(ip string) []NodePortData {
	var allData []NodePortData
	for i := range pt.NodePortTable {
		if pt.NodePortTable[i].PodIP == ip {
			allData = append(allData, *pt.NodePortTable[i])
		}
	}
	return allData
}

func (pt *PortTable) getEntryByPodIPPort(ip string, port int) *NodePortData {
	return pt.PodEndpointTable[podIPPortFormat(ip, port)]
}

func (pt *PortTable) RuleExists(podIP string, podPort int, protocol string) bool {
	pt.tableLock.RLock()
	defer pt.tableLock.RUnlock()
	if data := pt.getEntryByPodIPPort(podIP, podPort); data != nil {
		return data.ProtocolInUse(protocol)
	}
	return false
}

// nodePortProtoFormat formats the nodeport, protocol to string port:protocol.
func NodePortProtoFormat(nodeport int, protocol string) string {
	return fmt.Sprintf("%d:%s", nodeport, protocol)
}

// podIPPortFormat formats the ip, port to string ip:port.
func podIPPortFormat(ip string, port int) string {
	return fmt.Sprintf("%s:%d", ip, port)
}

// openLocalPort binds to the provided port.
// This is inspired by the openLocalPort function in kube-proxy:
// https://github.com/kubernetes/kubernetes/blob/86f8c3ee91b6faec437f97e3991107747d7fc5e8/pkg/proxy/iptables/proxier.go#L1664
func (lpo *localPortOpener) OpenLocalPort(port int, protocol string) (io.Closer, error) {
	// For now, NodePortLocal only supports IPv4 and TCP/UDP.
	var network string
	var socket io.Closer
	switch protocol {
	case "tcp":
		network = "tcp4"
		listener, err := net.Listen(network, fmt.Sprintf(":%d", port))
		if err != nil {
			return nil, err
		}
		socket = listener
	case "udp":
		network = "udp4"
		addr, err := net.ResolveUDPAddr(network, fmt.Sprintf(":%d", port))
		if err != nil {
			return nil, err
		}
		conn, err := net.ListenUDP(network, addr)
		if err != nil {
			return nil, err
		}
		socket = conn
	}
	klog.V(2).InfoS("Opened local port", "port", port)
	return socket, nil
}
