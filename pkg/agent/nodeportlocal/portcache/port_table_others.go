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

func (pt *PortTable) AddRule(podKey string, podPort int, protocol string, podIP string) (int, error) {
	pt.tableLock.Lock()
	defer pt.tableLock.Unlock()
	npData := pt.getEntryByPodKeyPortProto(podKey, podPort, protocol)
	exists := (npData != nil)
	if !exists {
		nodePort, protocolData, err := pt.getFreePort(podIP, podPort, protocol)
		if err != nil {
			return 0, err
		}
		npData = &NodePortData{
			PodKey:   podKey,
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
		return 0, fmt.Errorf("existing Linux Nodeport entry for %s:%d:%s", podIP, podPort, protocol)
	}
	return npData.NodePort, nil
}

func (pt *PortTable) deleteRule(data *NodePortData) error {
	protocolSocketData := &data.Protocol
	protocol := protocolSocketData.Protocol

	// In theory, we should not be modifying a cache item in-place. However, the field we are
	// modifying (defunct) does NOT participate in indexing and the modification is thread-safe
	// because of pt.tableLock.
	// TODO: stop modifying cache items in-place.
	// We could set defunct after the call to DeleteRule, because a failed call to DeleteRule
	// should mean that the rule is still present and valid, but there is no harm in being more
	// conservative.
	data.defunct = true

	// Calling DeleteRule is idempotent.
	if err := pt.PodPortRules.DeleteRule(data.NodePort, data.PodIP, data.PodPort, protocol); err != nil {
		return err
	}
	if err := protocolSocketData.socket.Close(); err != nil {
		return fmt.Errorf("error when releasing local port %d with protocol %s: %w", data.NodePort, protocol, err)
	}
	// We don't need to delete cache from different indexes repeatedly because they map to the same entry.
	// Deletion errors are not possible because our Index functions cannot return errors.
	// See https://github.com/kubernetes/client-go/blob/3aa45779f2e5592d52edf68da66abfbd0805e413/tools/cache/store.go#L189-L196
	pt.deletePortTableCache(data)
	return nil
}

func (pt *PortTable) DeleteRule(podKey string, podPort int, protocol string) error {
	pt.tableLock.Lock()
	defer pt.tableLock.Unlock()
	data := pt.getEntryByPodKeyPortProto(podKey, podPort, protocol)
	if data == nil {
		// Delete not required when the PortTable entry does not exist
		return nil
	}
	return pt.deleteRule(data)
}

func (pt *PortTable) DeleteRulesForPod(podKey string) error {
	pt.tableLock.Lock()
	defer pt.tableLock.Unlock()
	podEntries := pt.getDataForPod(podKey)
	for _, podEntry := range podEntries {
		return pt.deleteRule(podEntry)
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
		nplPorts = append(nplPorts, rules.PodNodePort{
			PodKey:   npData.PodKey,
			NodePort: npData.NodePort,
			PodPort:  npData.PodPort,
			PodIP:    npData.PodIP,
			Protocol: npData.Protocol.Protocol,
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
			PodKey:   nplPort.PodKey,
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
