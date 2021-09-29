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

type ProtocolSocketData struct {
	Protocol string
	socket   Closeable
}

type NodePortData struct {
	NodePort  int
	PodPort   int
	PodIP     string
	Protocols []ProtocolSocketData
}

func (d *NodePortData) HasProtocol(protocol string) bool {
	for _, p := range d.Protocols {
		if p.Protocol == protocol {
			return true
		}
	}
	return false
}

func (d *NodePortData) DeleteProtocol(protocol string) error {
	for i, p := range d.Protocols {
		if p.Protocol == protocol {
			d.Protocols = append(d.Protocols[:i], d.Protocols[i+1:]...)
			if err := p.socket.Close(); err != nil {
				return fmt.Errorf("error when releasing local port %d: %v", d.NodePort, err)
			}
			return nil
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
	PodPortRules     rules.PodPortRules
	LocalPortOpener  LocalPortOpener
	tableLock        sync.RWMutex
}

func NewPortTable(start, end int) (*PortTable, error) {
	ptable := PortTable{StartPort: start, EndPort: end}
	ptable.NodePortTable = make(map[int]*NodePortData)
	ptable.PodEndpointTable = make(map[string]*NodePortData)
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
	pt.NodePortTable = make(map[int]*NodePortData)
	pt.PodEndpointTable = make(map[string]*NodePortData)
}

func (pt *PortTable) GetEntry(ip string, port int, protocol string) *NodePortData {
	pt.tableLock.RLock()
	defer pt.tableLock.RUnlock()
	return pt.getEntryByPodIPPortProtocol(ip, port, protocol)
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

func (pt *PortTable) getEntryByPodIPPortProtocol(ip string, port int, protocol string) *NodePortData {
	data := pt.PodEndpointTable[podIPPortFormat(ip, port)]
	if data != nil && data.HasProtocol(protocol) {
		return data
	}
	return nil
}

func (pt *PortTable) getEntryByPodIPPort(ip string, port int) *NodePortData {
	return pt.PodEndpointTable[podIPPortFormat(ip, port)]
}

func (pt *PortTable) isNodePortAvailableForPodIPProtocol(ip string, nodeport int, podPort int, protocol string) bool {
	val, ok := pt.NodePortTable[nodeport]
	// A given nodeport, is marked unavailable if an entry for it already exists in the PortTable Table and
	// the nodeport suggested is being used by another Pod or,
	// the nodeport suggested for a Pod has a different podPort binding or,
	// the nodeport suggested for a Pod:podPort has the protocol already configured.
	if ok && (val.PodIP != ip ||
		(val.PodIP == ip && val.PodPort != podPort) ||
		(val.PodIP == ip && val.PodPort == podPort && val.HasProtocol(protocol))) {
		return false
	}
	return true
}

func (pt *PortTable) getFreePort(podIP string, podPort int, protocol string) (int, Closeable, error) {
	npdata := pt.getEntryByPodIPPort(podIP, podPort)
	err := fmt.Errorf("no free port found")
	if npdata != nil && pt.isNodePortAvailableForPodIPProtocol(podIP, npdata.NodePort, podPort, protocol) {
		// Check whether a NodePort is assigned to a Pod. Open the socket for the new protocol on NodePort.
		socket, err := pt.LocalPortOpener.OpenLocalPort(npdata.NodePort, protocol)
		if err == nil {
			return npdata.NodePort, socket, nil
		}
	} else {
		// Try fetching a new NodePort, that is not yet assigned to any Pod.
		for i := pt.StartPort; i <= pt.EndPort; i++ {
			if _, ok := pt.NodePortTable[i]; !ok {
				if socket, socketError := pt.LocalPortOpener.OpenLocalPort(i, protocol); socketError == nil {
					return i, socket, nil
				}
			}
		}
	}
	return 0, nil, err
}

func (pt *PortTable) AddRule(podIP string, podPort int, protocol string) (int, error) {
	pt.tableLock.Lock()
	defer pt.tableLock.Unlock()
	nodePort, socket, err := pt.getFreePort(podIP, podPort, protocol)
	if err != nil {
		return 0, err
	}
	if err := pt.PodPortRules.AddRule(nodePort, podIP, podPort, protocol); err != nil {
		if err := socket.Close(); err != nil {
			klog.ErrorS(err, "Unexpected error when closing socket")
		}
		return 0, err
	}
	if entry, ok := pt.NodePortTable[nodePort]; ok {
		if !entry.HasProtocol(protocol) {
			entry.Protocols = append(entry.Protocols, ProtocolSocketData{
				Protocol: protocol,
				socket:   socket,
			})
		}
		pt.NodePortTable[nodePort] = entry
	} else {
		pt.NodePortTable[nodePort] = &NodePortData{
			NodePort: nodePort,
			PodIP:    podIP,
			PodPort:  podPort,
			Protocols: []ProtocolSocketData{{
				Protocol: protocol,
				socket:   socket,
			}},
		}
	}
	pt.PodEndpointTable[podIPPortFormat(podIP, podPort)] = pt.NodePortTable[nodePort]
	return nodePort, nil
}

func (pt *PortTable) DeleteRule(podIP string, podPort int, protocol string) error {
	pt.tableLock.Lock()
	defer pt.tableLock.Unlock()
	data := pt.getEntryByPodIPPortProtocol(podIP, podPort, protocol)
	if err := pt.PodPortRules.DeleteRule(data.NodePort, podIP, podPort, protocol); err != nil {
		return err
	}
	if err := data.DeleteProtocol(protocol); err != nil {
		return err
	}
	if len(data.Protocols) == 0 {
		delete(pt.NodePortTable, data.NodePort)
		delete(pt.PodEndpointTable, podIPPortFormat(podIP, podPort))
	}
	return nil
}

func (pt *PortTable) DeleteRulesForPod(podIP string) error {
	pt.tableLock.Lock()
	defer pt.tableLock.Unlock()
	data := pt.getDataForPodIP(podIP)
	for _, d := range data {
		nodeport := d.NodePort
		for _, p := range d.Protocols {
			if err := pt.PodPortRules.DeleteRule(nodeport, podIP, d.PodPort, p.Protocol); err != nil {
				return err
			}
		}
		delete(pt.NodePortTable, nodeport)
		delete(pt.PodEndpointTable, podIPPortFormat(podIP, d.PodPort))
	}
	return nil
}

func (pt *PortTable) RuleExists(podIP string, podPort int, protocol string) bool {
	data := pt.GetEntry(podIP, podPort, protocol)
	if data != nil {
		return true
	}
	return false
}

// syncRules ensures that contents of the port table matches the iptables rules present on the Node.
func (pt *PortTable) syncRules() error {
	pt.tableLock.Lock()
	defer pt.tableLock.Unlock()
	nplPorts := make([]rules.PodNodePort, 0, len(pt.NodePortTable))
	for i := range pt.NodePortTable {
		for _, protocol := range (*pt.NodePortTable[i]).Protocols {
			nplPorts = append(nplPorts, rules.PodNodePort{
				NodePort: (*pt.NodePortTable[i]).NodePort,
				PodPort:  (*pt.NodePortTable[i]).PodPort,
				PodIP:    (*pt.NodePortTable[i]).PodIP,
				Protocol: protocol.Protocol,
			})
		}
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
		socket, err := pt.LocalPortOpener.OpenLocalPort(nplPort.NodePort, nplPort.Protocol)
		if err != nil {
			// This will be handled gracefully by the NPL controller: if there is an
			// annotation using this port, it will be removed and replaced with a new
			// one with a valid port mapping.
			klog.ErrorS(err, "Cannot bind to local port, skipping it", "port", nplPort.NodePort)
			continue
		}
		if entry, ok := pt.NodePortTable[nplPort.NodePort]; ok {
			if !entry.HasProtocol(nplPort.Protocol) {
				entry.Protocols = append(entry.Protocols, ProtocolSocketData{
					Protocol: nplPort.Protocol,
					socket:   socket,
				})
			}
			pt.NodePortTable[nplPort.NodePort] = entry
		} else {
			pt.NodePortTable[nplPort.NodePort] = &NodePortData{
				NodePort: nplPort.NodePort,
				PodPort:  nplPort.PodPort,
				PodIP:    nplPort.PodIP,
				Protocols: []ProtocolSocketData{{
					Protocol: nplPort.Protocol,
					socket:   socket,
				}},
			}
		}
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
			klog.V(2).ErrorS(err, "Error while trying to open port")
			return nil, err
		}
		socket = listener
	case "udp":
		network = "udp4"
		addr, err := net.ResolveUDPAddr(network, fmt.Sprintf(":%d", port))
		if err != nil {
			klog.V(2).ErrorS(err, "Error while trying to open port")
			return nil, err
		}
		conn, err := net.ListenUDP(network, addr)
		if err != nil {
			klog.V(2).ErrorS(err, "Error while trying to open port")
			return nil, err
		}
		socket = conn
	}

	return socket, nil
}
