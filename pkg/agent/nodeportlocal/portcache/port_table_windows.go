//go:build windows
// +build windows

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

	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/nodeportlocal/rules"
)

const (
	// stateInUse means that the NPL rule has been installed.
	stateInUse protocolSocketState = 1
)

// podIPPortFormat formats the ip, port to string ip:port.
func podIPPortProtoFormat(ip string, port int, protocol string) string {
	return fmt.Sprintf("%s:%d:%s", ip, port, protocol)
}

func (pt *PortTable) getEntryByPodIPPortProto(ip string, port int, protocol string) *NodePortData {
	return pt.PodEndpointTable[podIPPortProtoFormat(ip, port, protocol)]
}

func (pt *PortTable) GetEntry(ip string, port int, protocol string) *NodePortData {
	pt.tableLock.RLock()
	defer pt.tableLock.RUnlock()
	// Return pointer to copy of data from the PodEndpointTable.
	if data := pt.getEntryByPodIPPortProto(ip, port, protocol); data != nil {
		dataCopy := *data
		return &dataCopy
	}
	return nil
}

func addRuleForPort(podPortRules rules.PodPortRules, port int, podIP string, podPort int, protocol string) ([]ProtocolSocketData, error) {
	// Only the protocol used here should be returned if NetNatStaticMapping rule
	// can be inserted to an unused protocol port.
	protocols := make([]ProtocolSocketData, 0, 1)
	err := podPortRules.AddRule(port, podIP, podPort, protocol)
	if err != nil {
		klog.ErrorS(err, "Local port cannot be opened", "port", port, "protocol", protocol)
		return nil, err
	}
	protocols = append(protocols, ProtocolSocketData{
		Protocol: protocol,
		State:    stateInUse,
		socket:   nil,
	})
	return protocols, nil
}

func (pt *PortTable) addRuleforFreePort(podIP string, podPort int, protocol string) (int, []ProtocolSocketData, error) {
	klog.V(2).InfoS("Looking for free Node port on Windows", "podIP", podIP, "podPort", podPort, "protocol", protocol)
	numPorts := pt.EndPort - pt.StartPort + 1
	for i := 0; i < numPorts; i++ {
		port := pt.PortSearchStart + i
		if port > pt.EndPort {
			// handle wrap around
			port = port - numPorts
		}
		if _, ok := pt.NodePortTable[NodePortProtoFormat(port, protocol)]; ok {
			// protocol port is already taken
			continue
		}

		protocols, err := addRuleForPort(pt.PodPortRules, port, podIP, podPort, protocol)
		if err != nil {
			klog.ErrorS(err, "Port cannot be reserved, moving on to the next one", "port", port)
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
	npData := pt.getEntryByPodIPPortProto(podIP, podPort, protocol)
	exists := (npData != nil)
	if !exists {
		nodePort, protocols, err := pt.addRuleforFreePort(podIP, podPort, protocol)
		//success means port, protocol available.
		if err != nil {
			return 0, err
		}
		npData = &NodePortData{
			NodePort:  nodePort,
			PodIP:     podIP,
			PodPort:   podPort,
			Protocols: protocols,
		}

		pt.NodePortTable[NodePortProtoFormat(nodePort, protocol)] = npData
		pt.PodEndpointTable[podIPPortProtoFormat(podIP, podPort, protocol)] = npData
	} else {
		// Only add rules for if the entry does not exist.
		return 0, fmt.Errorf("existed windows nodeport entry for %s:%d:%s", podIP, podPort, protocol)
	}
	return npData.NodePort, nil
}

// RestoreRules should be called at Antrea Agent startup to restore a set of NPL rules.
func (pt *PortTable) RestoreRules(allNPLPorts []rules.PodNodePort, synced chan<- struct{}) error {
	pt.tableLock.Lock()
	defer pt.tableLock.Unlock()
	for _, nplPort := range allNPLPorts {
		protocols, err := addRuleForPort(pt.PodPortRules, nplPort.NodePort, nplPort.PodIP, nplPort.PodPort, nplPort.Protocol)
		if err != nil {
			// This will be handled gracefully by the NPL controller: if there is an
			// annotation using this port, it will be removed and replaced with a new
			// one with a valid port mapping.
			klog.ErrorS(err, "Cannot bind to local port, skipping it", "port", nplPort.NodePort)
			continue
		}

		npData := &NodePortData{
			NodePort:  nplPort.NodePort,
			PodPort:   nplPort.PodPort,
			PodIP:     nplPort.PodIP,
			Protocols: protocols,
		}
		pt.PodEndpointTable[podIPPortProtoFormat(nplPort.PodIP, nplPort.PodPort, nplPort.Protocol)] = pt.NodePortTable[NodePortProtoFormat(nplPort.NodePort, nplPort.Protocol)]
		pt.NodePortTable[NodePortProtoFormat(nplPort.NodePort, nplPort.Protocol)] = npData
	}
	// No need to sync up again because addRuleForPort has updated all rules on Windows
	close(synced)
	return nil
}

func (pt *PortTable) DeleteRule(podIP string, podPort int, protocol string) error {
	pt.tableLock.Lock()
	defer pt.tableLock.Unlock()
	data := pt.getEntryByPodIPPortProto(podIP, podPort, protocol)
	if data == nil {
		// Delete not required when the PortTable entry does not exist
		return nil
	}
	var protocolSocketData *ProtocolSocketData
	protocolSocketData = &data.Protocols[0]
	if protocolSocketData != nil {
		if err := pt.PodPortRules.DeleteRule(data.NodePort, podIP, podPort, protocol); err != nil {
			return err
		}
	}
	delete(pt.NodePortTable, NodePortProtoFormat(data.NodePort, protocol))
	delete(pt.PodEndpointTable, podIPPortProtoFormat(podIP, podPort, protocol))
	return nil
}

func (pt *PortTable) DeleteRulesForPod(podIP string) error {
	pt.tableLock.Lock()
	defer pt.tableLock.Unlock()
	podEntries := pt.getDataForPodIP(podIP)
	for _, podEntry := range podEntries {
		if len(podEntry.Protocols) > 0 {
			protocolSocketData := podEntry.Protocols[0]
			if err := pt.PodPortRules.DeleteRule(podEntry.NodePort, podIP, podEntry.PodPort, protocolSocketData.Protocol); err != nil {
				return err
			}
			delete(pt.PodEndpointTable, podIPPortProtoFormat(podIP, podEntry.PodPort, protocolSocketData.Protocol))
			delete(pt.NodePortTable, NodePortProtoFormat(podEntry.NodePort, protocolSocketData.Protocol))
		}
	}
	return nil
}
