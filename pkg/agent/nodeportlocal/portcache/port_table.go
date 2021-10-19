//go:build !windows
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
	"time"

	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/nodeportlocal/rules"
)

var (
	supportedProtocols = []string{"tcp", "udp"}
)

// protocolSocketState represents the state of the socket corresponding to a
// given (Node port, protocol) tuple.
type protocolSocketState int

const (
	// stateOpen means that a listening socket has been opened for the
	// protocol (as a means to reserve the port for this protocol), but no
	// NPL rule has been installed for it.
	stateOpen protocolSocketState = iota
	// stateInUse means that a listening socket has been opened AND a NPL
	// rule has been installed.
	stateInUse
	// stateClosed means that the socket has been closed.
	stateClosed
)

type ProtocolSocketData struct {
	Protocol string
	State    protocolSocketState
	socket   Closeable
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

func (d *NodePortData) CloseSockets() error {
	for idx := range d.Protocols {
		protocolSocketData := &d.Protocols[idx]
		switch protocolSocketData.State {
		case stateClosed:
			// already closed
			continue
		case stateInUse:
			// should not happen
			return fmt.Errorf("protocol %s is still in use, cannot release socket", protocolSocketData.Protocol)
		case stateOpen:
			if err := protocolSocketData.socket.Close(); err != nil {
				return fmt.Errorf("error when releasing local port %d with protocol %s: %v", d.NodePort, protocolSocketData.Protocol, err)
			}
			protocolSocketData.State = stateClosed
		default:
			return fmt.Errorf("invalid protocol socket state")
		}
	}
	return nil
}

type LocalPortOpener interface {
	OpenLocalPort(port int, protocol string) (Closeable, error)
}

type localPortOpener struct{}

type PortTable struct {
	NodePortTable    map[int]*NodePortData
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
		NodePortTable:    make(map[int]*NodePortData),
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
	pt.NodePortTable = make(map[int]*NodePortData)
	pt.PodEndpointTable = make(map[string]*NodePortData)
}

func (pt *PortTable) GetEntry(ip string, port int) *NodePortData {
	pt.tableLock.RLock()
	defer pt.tableLock.RUnlock()
	// Return pointer to copy of data from the PodEndpointTable.
	if data := pt.getEntryByPodIPPort(ip, port); data != nil {
		dataCopy := *data
		return &dataCopy
	}
	return nil
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

func openSocketsForPort(localPortOpener LocalPortOpener, port int) ([]ProtocolSocketData, error) {
	// port needs to be available for all supported protocols: we want to use the same port
	// number for all protocols and we don't know at this point which protocols are needed.
	protocols := make([]ProtocolSocketData, 0, len(supportedProtocols))
	for _, protocol := range supportedProtocols {
		socket, err := localPortOpener.OpenLocalPort(port, protocol)
		if err != nil {
			klog.V(4).InfoS("Local port cannot be opened", "port", port, "protocol", protocol)
			return protocols, err
		}
		protocols = append(protocols, ProtocolSocketData{
			Protocol: protocol,
			State:    stateOpen,
			socket:   socket,
		})
	}
	return protocols, nil
}

func closeSockets(protocols []ProtocolSocketData) error {
	for idx := range protocols {
		protocolSocketData := &protocols[idx]
		if protocolSocketData.State != stateOpen {
			continue
		}
		if err := protocolSocketData.socket.Close(); err != nil {
			return err
		}
		protocolSocketData.State = stateClosed

	}
	return nil
}

// closeSocketsOrRetry closes all provided sockets. In case of an error, it
// creates a goroutine to retry asynchronously.
func closeSocketsOrRetry(protocols []ProtocolSocketData) {
	var err error
	if err = closeSockets(protocols); err == nil {
		return
	}
	// Unlikely that there could be transient errors when closing a socket,
	// but just in case, we create a goroutine to retry. We make a copy of
	// the protocols slice, since the calling goroutine may modify the
	// original one.
	protocolsCopy := make([]ProtocolSocketData, len(protocols))
	copy(protocolsCopy, protocols)
	go func() {
		const delay = 5 * time.Second
		for {
			klog.ErrorS(err, "Unexpected error when closing socket(s), will retry", "retryDelay", delay)
			time.Sleep(delay)
			if err = closeSockets(protocolsCopy); err == nil {
				return
			}
		}
	}()
}

func (pt *PortTable) getFreePort(podIP string, podPort int) (int, []ProtocolSocketData, error) {
	klog.V(2).InfoS("Looking for free Node port", "podIP", podIP, "podPort", podPort)
	numPorts := pt.EndPort - pt.StartPort + 1
	for i := 0; i < numPorts; i++ {
		port := pt.PortSearchStart + i
		if port > pt.EndPort {
			// handle wrap around
			port = port - numPorts
		}
		if _, ok := pt.NodePortTable[port]; ok {
			// port is already taken
			continue
		}

		protocols, err := openSocketsForPort(pt.LocalPortOpener, port)
		if err != nil {
			klog.V(4).InfoS("Port cannot be reserved, moving on to the next one", "port", port)
			closeSocketsOrRetry(protocols)
			continue
		}

		pt.PortSearchStart = port + 1
		if pt.PortSearchStart > pt.EndPort {
			pt.PortSearchStart = pt.StartPort
		}
		return port, protocols, nil
	}
	return 0, nil, fmt.Errorf("no free port found")
}

func (pt *PortTable) AddRule(podIP string, podPort int, protocol string) (int, error) {
	pt.tableLock.Lock()
	defer pt.tableLock.Unlock()
	npData := pt.getEntryByPodIPPort(podIP, podPort)
	exists := (npData != nil)
	if !exists {
		var protocols []ProtocolSocketData
		nodePort, protocols, err := pt.getFreePort(podIP, podPort)
		if err != nil {
			return 0, err
		}
		npData = &NodePortData{
			NodePort:  nodePort,
			PodIP:     podIP,
			PodPort:   podPort,
			Protocols: protocols,
		}
	}
	protocolSocketData := npData.FindProtocol(protocol)
	if protocolSocketData == nil {
		return 0, fmt.Errorf("unknown protocol %s", protocol)
	}
	if protocolSocketData.State == stateInUse {
		return 0, fmt.Errorf("rule for %s:%d:%s already exists", podIP, podPort, protocol)
	}
	if protocolSocketData.State == stateClosed {
		return 0, fmt.Errorf("invalid socket state for %s:%d:%s", podIP, podPort, protocol)
	}

	nodePort := npData.NodePort
	if err := pt.PodPortRules.AddRule(nodePort, podIP, podPort, protocol); err != nil {
		return 0, err
	}

	protocolSocketData.State = stateInUse
	if !exists {
		pt.NodePortTable[nodePort] = npData
		pt.PodEndpointTable[podIPPortFormat(podIP, podPort)] = npData
	}
	return npData.NodePort, nil
}

func (pt *PortTable) DeleteRule(podIP string, podPort int, protocol string) error {
	pt.tableLock.Lock()
	defer pt.tableLock.Unlock()
	data := pt.getEntryByPodIPPort(podIP, podPort)
	if data == nil {
		// Delete not required when either the PortTable entry does not exist
		return nil
	}
	numProtocolsInUse := 0
	var protocolSocketData *ProtocolSocketData
	for idx, pData := range data.Protocols {
		if pData.State != stateInUse {
			continue
		}
		numProtocolsInUse++
		if pData.Protocol == protocol {
			protocolSocketData = &data.Protocols[idx]
		}
	}
	if protocolSocketData != nil {
		if err := pt.PodPortRules.DeleteRule(data.NodePort, podIP, podPort, protocol); err != nil {
			return err
		}
		protocolSocketData.State = stateOpen
		numProtocolsInUse--
	}
	if numProtocolsInUse == 0 {
		// Node port is no needed anymore: close all sockets and delete
		// table entries.
		if err := data.CloseSockets(); err != nil {
			return err
		}
		delete(pt.NodePortTable, data.NodePort)
		delete(pt.PodEndpointTable, podIPPortFormat(podIP, podPort))
	}
	return nil
}

func (pt *PortTable) DeleteRulesForPod(podIP string) error {
	pt.tableLock.Lock()
	defer pt.tableLock.Unlock()
	podEntries := pt.getDataForPodIP(podIP)
	for _, podEntry := range podEntries {
		for len(podEntry.Protocols) > 0 {
			protocolSocketData := podEntry.Protocols[0]
			if err := pt.PodPortRules.DeleteRule(podEntry.NodePort, podIP, podEntry.PodPort, protocolSocketData.Protocol); err != nil {
				return err
			}
			if err := protocolSocketData.socket.Close(); err != nil {
				return fmt.Errorf("error when releasing local port %d with protocol %s: %v", podEntry.NodePort, protocolSocketData.Protocol, err)
			}
			podEntry.Protocols = podEntry.Protocols[1:]
		}
		delete(pt.NodePortTable, podEntry.NodePort)
		delete(pt.PodEndpointTable, podIPPortFormat(podIP, podEntry.PodPort))
	}
	return nil
}

func (pt *PortTable) RuleExists(podIP string, podPort int, protocol string) bool {
	pt.tableLock.RLock()
	defer pt.tableLock.RUnlock()
	if data := pt.getEntryByPodIPPort(podIP, podPort); data != nil {
		return data.ProtocolInUse(protocol)
	}
	return false
}

// syncRules ensures that contents of the port table matches the iptables rules present on the Node.
func (pt *PortTable) syncRules() error {
	pt.tableLock.Lock()
	defer pt.tableLock.Unlock()
	nplPorts := make([]rules.PodNodePort, 0, len(pt.NodePortTable))
	for _, npData := range pt.NodePortTable {
		protocols := make([]string, 0, len(supportedProtocols))
		for _, protocol := range npData.Protocols {
			protocols = append(protocols, protocol.Protocol)
		}
		nplPorts = append(nplPorts, rules.PodNodePort{
			NodePort:  npData.NodePort,
			PodPort:   npData.PodPort,
			PodIP:     npData.PodIP,
			Protocols: protocols,
		})
	}
	return pt.PodPortRules.AddAllRules(nplPorts)
}

// RestoreRules should be called on startup to restore a set of NPL rules. It is non-blocking but
// takes as a parameter a channel, synced, which will be closed when the necessary rules have been
// restored successfully. No other operations should be performed on the PortTable until the channel
// is closed.
func (pt *PortTable) RestoreRules(allNPLPorts []rules.PodNodePort, synced chan<- struct{}) error {
	pt.tableLock.Lock()
	defer pt.tableLock.Unlock()
	for _, nplPort := range allNPLPorts {
		protocols, err := openSocketsForPort(pt.LocalPortOpener, nplPort.NodePort)
		if err != nil {
			// This will be handled gracefully by the NPL controller: if there is an
			// annotation using this port, it will be removed and replaced with a new
			// one with a valid port mapping.
			klog.ErrorS(err, "Cannot bind to local port, skipping it", "port", nplPort.NodePort)
			closeSocketsOrRetry(protocols)
			continue
		}

		npData := &NodePortData{
			NodePort:  nplPort.NodePort,
			PodPort:   nplPort.PodPort,
			PodIP:     nplPort.PodIP,
			Protocols: protocols,
		}
		for _, protocol := range nplPort.Protocols {
			protocolSocketData := npData.FindProtocol(protocol)
			if protocolSocketData == nil {
				return fmt.Errorf("unknown protocol %s", protocol)
			}
			protocolSocketData.State = stateInUse
		}
		pt.NodePortTable[nplPort.NodePort] = npData
		pt.PodEndpointTable[podIPPortFormat(nplPort.PodIP, nplPort.PodPort)] = pt.NodePortTable[nplPort.NodePort]
	}
	// retry mechanism as iptables-restore can fail if other components (in Antrea or other
	// software) are accessing iptables.
	go func() {
		defer close(synced)
		var backoffTime = 2 * time.Second
		for {
			if err := pt.syncRules(); err != nil {
				klog.ErrorS(err, "Failed to restore iptables rules", "backoff", backoffTime)
				time.Sleep(backoffTime)
				continue
			}
			break
		}
	}()
	return nil
}

// podIPPortFormat formats the ip, port to string ip:port.
func podIPPortFormat(ip string, port int) string {
	return fmt.Sprintf("%s:%d", ip, port)
}

// openLocalPort binds to the provided port.
// This is inspired by the openLocalPort function in kube-proxy:
// https://github.com/kubernetes/kubernetes/blob/86f8c3ee91b6faec437f97e3991107747d7fc5e8/pkg/proxy/iptables/proxier.go#L1664
func (lpo *localPortOpener) OpenLocalPort(port int, protocol string) (Closeable, error) {
	// For now, NodePortLocal only supports IPv4 and TCP/UDP.
	var network string
	var socket Closeable
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
