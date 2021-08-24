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
	"strings"
	"sync"
	"time"

	"antrea.io/antrea/pkg/agent/nodeportlocal/rules"
	"antrea.io/antrea/pkg/agent/nodeportlocal/util"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
)

type NodePortData struct {
	NodePort int
	PodPort  int
	PodIP    string
	Protocol string
	socket   Closeable
}

type LocalPortOpener interface {
	OpenLocalPort(port int, protocol string) (Closeable, error)
}

type localPortOpener struct{}

type PortTable struct {
	Table           map[string]NodePortData
	StartPort       int
	EndPort         int
	PodPortRules    rules.PodPortRules
	LocalPortOpener LocalPortOpener
	tableLock       sync.RWMutex
}

func NewPortTable(start, end int) (*PortTable, error) {
	ptable := PortTable{StartPort: start, EndPort: end}
	ptable.Table = make(map[string]NodePortData)
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
	pt.Table = make(map[string]NodePortData)
}

func (pt *PortTable) GetEntry(nodeportProtocol string) *NodePortData {
	pt.tableLock.RLock()
	defer pt.tableLock.RUnlock()
	data, _ := pt.Table[nodeportProtocol]
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

func (pt *PortTable) GetEntryByPodIPPortProtocol(ip string, port int, protocol string) *NodePortData {
	pt.tableLock.RLock()
	defer pt.tableLock.RUnlock()
	return pt.getEntryByPodIPPortProtocol(ip, port, protocol)
}

func (pt *PortTable) getEntryByPodIPPortProtocol(ip string, port int, protocol string) *NodePortData {
	for _, data := range pt.Table {
		if data.PodIP == ip && data.PodPort == port && data.Protocol == protocol {
			return &data
		}
	}
	return nil
}

func (pt *PortTable) isNodePortClaimedForPodIPProtocol(ip string, nodeport int, protocol string) bool {
	var val NodePortData
	ok := false
	// Since NPL supports only TCP and UDP protocols, we can check if an entry corresponding to key `<nodeport>:udp`
	// is present in the PortTable, if the protocol we want to serve is TCP, and vice versa.
	switch protocol {
	case strings.ToLower(string(corev1.ProtocolTCP)):
		val, ok = pt.Table[util.BuildPortProto(fmt.Sprint(nodeport), strings.ToLower(string(corev1.ProtocolUDP)))]
	case strings.ToLower(string(corev1.ProtocolUDP)):
		val, ok = pt.Table[util.BuildPortProto(fmt.Sprint(nodeport), strings.ToLower(string(corev1.ProtocolTCP)))]
	}
	if ok && val.PodIP != ip {
		return false
	}
	return true
}

func (pt *PortTable) getFreePort(podIP string, podPort int, protocol string) (int, Closeable, error) {
	for i := pt.StartPort; i <= pt.EndPort; i++ {
		if _, ok := pt.Table[util.BuildPortProto(fmt.Sprint(i), protocol)]; !ok {
			// This ensures that the NodePort `i` is not taken by any other Pods,
			// irrespective of the protocol.
			if !pt.isNodePortClaimedForPodIPProtocol(podIP, i, protocol) {
				continue
			}
			socket, err := pt.LocalPortOpener.OpenLocalPort(i, protocol)
			if err != nil {
				continue
			}
			return i, socket, nil
		}
	}
	return 0, nil, fmt.Errorf("no free port found")
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
	pt.Table[util.BuildPortProto(fmt.Sprint(nodePort), protocol)] = NodePortData{
		NodePort: nodePort,
		PodIP:    podIP,
		PodPort:  podPort,
		Protocol: protocol,
		socket:   socket,
	}
	return nodePort, nil
}

func (pt *PortTable) DeleteRule(podIP string, podPort int, protocol string) error {
	pt.tableLock.Lock()
	defer pt.tableLock.Unlock()
	data := pt.getEntryByPodIPPortProtocol(podIP, podPort, protocol)
	if err := pt.PodPortRules.DeleteRule(data.NodePort, podIP, podPort, protocol); err != nil {
		return err
	}
	if err := data.socket.Close(); err != nil {
		return fmt.Errorf("Error when releasing local port %d: %v", data.NodePort, err)
	}
	delete(pt.Table, util.BuildPortProto(fmt.Sprint(data.NodePort), data.Protocol))
	return nil
}

func (pt *PortTable) RuleExists(podIP string, podPort int, protocol string) bool {
	data := pt.GetEntryByPodIPPortProtocol(podIP, podPort, protocol)
	if data != nil {
		return true
	}
	return false
}

// syncRules ensures that contents of the port table matches the iptables rules present on the Node.
func (pt *PortTable) syncRules() error {
	pt.tableLock.Lock()
	defer pt.tableLock.Unlock()
	nplPorts := make([]rules.PodNodePort, 0, len(pt.Table))
	for _, data := range pt.Table {
		nplPorts = append(nplPorts, rules.PodNodePort{
			NodePort: data.NodePort,
			PodPort:  data.PodPort,
			PodIP:    data.PodIP,
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
		socket, err := pt.LocalPortOpener.OpenLocalPort(nplPort.NodePort, nplPort.Protocol)
		if err != nil {
			// This will be handled gracefully by the NPL controller: if there is an
			// annotation using this port, it will be removed and replaced with a new
			// one with a valid port mapping.
			klog.ErrorS(err, "Cannot bind to local port, skipping it", "port", nplPort.NodePort)
			continue
		}
		data := NodePortData{
			NodePort: nplPort.NodePort,
			PodPort:  nplPort.PodPort,
			PodIP:    nplPort.PodIP,
			Protocol: nplPort.Protocol,
			socket:   socket,
		}
		pt.Table[util.BuildPortProto(fmt.Sprint(nplPort.NodePort), nplPort.Protocol)] = data
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
