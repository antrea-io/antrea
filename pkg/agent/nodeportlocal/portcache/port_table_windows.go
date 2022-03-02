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

func addRuleForPort(podPortRules rules.PodPortRules, port int, podIP string, podPort int, protocol string) ([]ProtocolSocketData, error) {
	// port needs to be available for all supported protocols: all available protocols
	// should be returned if any NetNatStaticMapping rule can be inserted to an unused port.
	protocols := make([]ProtocolSocketData, 0, len(supportedProtocols))
	err := podPortRules.AddRule(port, podIP, podPort, protocol)
	if err != nil {
		klog.ErrorS(err, "Local port cannot be opened", "port", port, "protocol", protocol)
		return nil, err
	}
	for _, proto := range supportedProtocols {
		protocols = append(protocols, ProtocolSocketData{
			Protocol: proto,
			State:    stateOpen,
			socket:   nil,
		})
	}
	return protocols, nil
}

func updateCloseState(protocols []ProtocolSocketData) error {
	for idx := range protocols {
		protocolSocketData := &protocols[idx]
		if protocolSocketData.State != stateOpen {
			continue
		}
		protocolSocketData.State = stateClosed
	}
	return nil
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
		if _, ok := pt.NodePortTable[port]; ok {
			// port is already taken
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
	npData := pt.getEntryByPodIPPort(podIP, podPort)
	exists := (npData != nil)
	if !exists {
		nodePort, protocols, err := pt.addRuleforFreePort(podIP, podPort, protocol)
		//success means port, protocol available, state is open.
		if err != nil {
			return 0, err
		}
		npData = &NodePortData{
			NodePort:  nodePort,
			PodIP:     podIP,
			PodPort:   podPort,
			Protocols: protocols,
		}
		protocolSocketData := npData.FindProtocol(protocol)
		protocolSocketData.State = stateInUse

		pt.NodePortTable[nodePort] = npData
		pt.PodEndpointTable[podIPPortFormat(podIP, podPort)] = npData
	} else {
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
	}
	return npData.NodePort, nil
}

// syncRules ensures that contents of the port table matches the netnat rules present on the Node.
func (pt *PortTable) syncRules() error {
	pt.tableLock.Lock()
	defer pt.tableLock.Unlock()
	nplPorts := make([]rules.PodNodePort, 0, len(pt.NodePortTable))
	for _, npData := range pt.NodePortTable {
		protocols := make([]string, 0, len(supportedProtocols))
		for _, protocol := range npData.Protocols {
			if protocol.State == stateInUse {
				protocols = append(protocols, protocol.Protocol)
			}
		}
		nplPorts = append(nplPorts, rules.PodNodePort{
			NodePort:  npData.NodePort,
			PodPort:   npData.PodPort,
			PodIP:     npData.PodIP,
			Protocols: protocols,
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
		protocols, err := addRuleForPort(pt.PodPortRules, nplPort.NodePort, nplPort.PodIP, nplPort.PodPort, nplPort.Protocols[0])
		if err != nil {
			// This will be handled gracefully by the NPL controller: if there is an
			// annotation using this port, it will be removed and replaced with a new
			// one with a valid port mapping.
			klog.ErrorS(err, "Cannot bind to local port, skipping it", "port", nplPort.NodePort)
			updateCloseState(protocols)
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

	go func() {
		defer close(synced)
		if err := pt.syncRules(); err != nil {
			klog.ErrorS(err, "Failed to restore netnat rules")
		}
	}()
	return nil
}

func (d *NodePortData) UpdateCloseStates() error {
	for idx := range d.Protocols {
		protocolSocketData := &d.Protocols[idx]
		switch protocolSocketData.State {
		case stateClosed:
			// already closed
			continue
		case stateInUse:
			// should not happen
			return fmt.Errorf("protocol %s is still in use, cannot update status to closed", protocolSocketData.Protocol)
		case stateOpen:
			protocolSocketData.State = stateClosed
		default:
			return fmt.Errorf("invalid protocol state")
		}
	}
	return nil
}

func (pt *PortTable) DeleteRule(podIP string, podPort int, protocol string) error {
	pt.tableLock.Lock()
	defer pt.tableLock.Unlock()
	data := pt.getEntryByPodIPPort(podIP, podPort)
	if data == nil {
		// Delete not required when the PortTable entry does not exist
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
		// Node port is not needed anymore: status update
		if err := data.UpdateCloseStates(); err != nil {
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
			podEntry.Protocols = podEntry.Protocols[1:]
		}
		delete(pt.NodePortTable, podEntry.NodePort)
		delete(pt.PodEndpointTable, podIPPortFormat(podIP, podEntry.PodPort))
	}
	return nil
}
