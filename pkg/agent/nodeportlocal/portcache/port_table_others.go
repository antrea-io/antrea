//go:build !windows
// +build !windows

// Copyright 2022 Antrea Authors
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
	"time"

	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/nodeportlocal/rules"
)

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

func openSocketsForPort(localPortOpener LocalPortOpener, port int, protocol string) (ProtocolSocketData, error) {
	// Port only needs to be available for the protocol used by the NPL rule.
	// We don't need to allocate the same nodePort for all protocols anymore.
	socket, err := localPortOpener.OpenLocalPort(port, protocol)
	if err != nil {
		klog.V(4).InfoS("Local port cannot be opened", "port", port, "protocol", protocol)
		return ProtocolSocketData{}, err
	}
	protocolData := ProtocolSocketData{
		Protocol: protocol,
		State:    stateInUse,
		socket:   socket,
	}
	return protocolData, nil
}

func (pt *PortTable) getFreePort(podIP string, podPort int, protocol string) (int, ProtocolSocketData, error) {
	klog.V(2).InfoS("Looking for free Node port", "podIP", podIP, "podPort", podPort)
	numPorts := pt.EndPort - pt.StartPort + 1
	for i := 0; i < numPorts; i++ {
		port := pt.PortSearchStart + i
		if port > pt.EndPort {
			// handle wrap around
			port = port - numPorts
		}
		if _, ok := pt.getPortTableCacheFromNodePortIndex(NodePortProtoFormat(port, protocol)); ok {
			// port is already taken
			continue
		}

		protocolData, err := openSocketsForPort(pt.LocalPortOpener, port, protocol)
		if err != nil {
			klog.V(4).InfoS("Port cannot be reserved, moving on to the next one", "port", port)
			continue
		}

		pt.PortSearchStart = port + 1
		if pt.PortSearchStart > pt.EndPort {
			pt.PortSearchStart = pt.StartPort
		}
		return port, protocolData, nil
	}
	return 0, ProtocolSocketData{}, fmt.Errorf("no free port found")
}

func (d *NodePortData) CloseSockets() error {
	if d.Protocol.Protocol != "" {
		protocolSocketData := &d.Protocol
		switch protocolSocketData.State {
		case stateClosed:
			// already closed
			return nil
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

func (pt *PortTable) AddRule(podIP string, podPort int, protocol string) (int, error) {
	pt.tableLock.Lock()
	defer pt.tableLock.Unlock()
	npData := pt.getEntryByPodIPPortProto(podIP, podPort, protocol)
	exists := (npData != nil)
	if !exists {
		nodePort, protocolData, err := pt.getFreePort(podIP, podPort, protocol)
		if err != nil {
			return 0, err
		}
		npData = &NodePortData{
			NodePort: nodePort,
			PodIP:    podIP,
			PodPort:  podPort,
			Protocol: protocolData,
		}
		nodePort = npData.NodePort
		if err := pt.PodPortRules.AddRule(nodePort, podIP, podPort, protocol); err != nil {
			return 0, err
		}
		pt.addPortTableCache(npData)
	} else {
		// Only add rules if the entry does not exist.
		return 0, fmt.Errorf("existed Linux Nodeport entry for %s:%d:%s", podIP, podPort, protocol)
	}
	return npData.NodePort, nil
}

func (pt *PortTable) DeleteRule(podIP string, podPort int, protocol string) error {
	pt.tableLock.Lock()
	defer pt.tableLock.Unlock()
	data := pt.getEntryByPodIPPortProto(podIP, podPort, protocol)
	if data == nil {
		// Delete not required when the PortTable entry does not exist
		return nil
	}
	if err := pt.PodPortRules.DeleteRule(data.NodePort, podIP, podPort, protocol); err != nil {
		return err
	}
	if err := data.CloseSockets(); err != nil {
		return err
	}
	// We don't need to delete cache from different indexes repeatedly because they map to the same entry.
	pt.deletePortTableCache(data)
	return nil
}

func (pt *PortTable) DeleteRulesForPod(podIP string) error {
	pt.tableLock.Lock()
	defer pt.tableLock.Unlock()
	podEntries := pt.getDataForPodIP(podIP)
	for _, podEntry := range podEntries {
		protocolSocketData := podEntry.Protocol
		if err := pt.PodPortRules.DeleteRule(podEntry.NodePort, podIP, podEntry.PodPort, protocolSocketData.Protocol); err != nil {
			return err
		}
		if err := protocolSocketData.socket.Close(); err != nil {
			return fmt.Errorf("error when releasing local port %d with protocol %s: %v", podEntry.NodePort, protocolSocketData.Protocol, err)
		}
		pt.deletePortTableCache(podEntry)
	}
	return nil
}

// syncRules ensures that contents of the port table matches the iptables rules present on the Node.
func (pt *PortTable) syncRules() error {
	pt.tableLock.Lock()
	defer pt.tableLock.Unlock()
	objs := pt.PortTableCache.List()
	nplPorts := make([]rules.PodNodePort, 0, len(objs))
	for _, obj := range objs {
		npData := obj.(*NodePortData)
		protocols := make([]string, 0, 1)
		protocol := npData.Protocol
		if protocol.State == stateInUse {
			protocols = append(protocols, protocol.Protocol)
		}
		nplPorts = append(nplPorts, rules.PodNodePort{
			NodePort: npData.NodePort,
			PodPort:  npData.PodPort,
			PodIP:    npData.PodIP,
			Protocol: protocols[0],
		})
	}
	if err := pt.PodPortRules.AddAllRules(nplPorts); err != nil {
		return err
	}
	return nil
}

// RestoreRules should be called at Antrea Agent startup to restore a set of NPL rules. It is non-blocking but
// takes a channel parameter - synced, which will be closed when the necessary rules have been
// restored successfully. No other operations should be performed on the PortTable until the channel
// is closed.
func (pt *PortTable) RestoreRules(allNPLPorts []rules.PodNodePort, synced chan<- struct{}) error {
	pt.tableLock.Lock()
	defer pt.tableLock.Unlock()
	for _, nplPort := range allNPLPorts {
		protocolData, err := openSocketsForPort(pt.LocalPortOpener, nplPort.NodePort, nplPort.Protocol)
		if err != nil {
			// This will be handled gracefully by the NPL controller: if there is an
			// annotation using this port, it will be removed and replaced with a new
			// one with a valid port mapping.
			klog.ErrorS(err, "Cannot bind to local port, skipping it", "port", nplPort.NodePort)
			continue
		}

		npData := &NodePortData{
			NodePort: nplPort.NodePort,
			PodPort:  nplPort.PodPort,
			PodIP:    nplPort.PodIP,
			Protocol: protocolData,
		}
		pt.addPortTableCache(npData)
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
