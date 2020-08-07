// Copyright 2020 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package connections

import (
	"fmt"
	"sync"
	"time"

	"k8s.io/klog/v2"

	"github.com/vmware-tanzu/antrea/pkg/agent/flowexporter"
	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
)

type ConnectionStore struct {
	connections  map[flowexporter.ConnectionKey]flowexporter.Connection
	connDumper   ConnTrackDumper
	ifaceStore   interfacestore.InterfaceStore
	pollInterval time.Duration
	mutex        sync.Mutex
}

func NewConnectionStore(connTrackDumper ConnTrackDumper, ifaceStore interfacestore.InterfaceStore, pollInterval time.Duration) *ConnectionStore {
	return &ConnectionStore{
		connections:  make(map[flowexporter.ConnectionKey]flowexporter.Connection),
		connDumper:   connTrackDumper,
		ifaceStore:   ifaceStore,
		pollInterval: pollInterval,
	}
}

// Run enables the periodical polling of conntrack connections, at the given flowPollInterval
func (cs *ConnectionStore) Run(stopCh <-chan struct{}, pollDone chan struct{}) {
	klog.Infof("Starting conntrack polling")

	pollTicker := time.NewTicker(cs.pollInterval)
	defer pollTicker.Stop()

	for {
		select {
		case <-stopCh:
			break
		case <-pollTicker.C:
			_, err := cs.Poll()
			if err != nil {
				// Not failing here as errors can be transient and could be resolved in future poll cycles.
				// TODO: Come up with a backoff/retry mechanism by increasing poll interval and adding retry timeout
				klog.Errorf("Error during conntrack poll cycle: %v", err)
			}
			// We need synchronization between ConnectionStore.Run and FlowExporter.Run go routines.
			// ConnectionStore.Run (connection poll) should be done to start FlowExporter.Run (connection export); pollDone signals helps enabling this.
			// FlowExporter.Run should be done to start ConnectionStore.Run; mutex on connection map object makes sure of this synchronization guarantee.
			pollDone <- struct{}{}

		}
	}
}

// addOrUpdateConn updates the connection if it is already present, i.e., update timestamp, counters etc.,
// or adds a new Connection by 5-tuple of the flow along with local Pod and PodNameSpace.
func (cs *ConnectionStore) addOrUpdateConn(conn *flowexporter.Connection) {
	connKey := flowexporter.NewConnectionKey(conn)

	existingConn, exists := cs.GetConnByKey(connKey)

	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	if exists {
		// Update the necessary fields that are used in generating flow records.
		// Can same 5-tuple flow get deleted and added to conntrack table? If so use ID.
		existingConn.StopTime = conn.StopTime
		existingConn.OriginalBytes = conn.OriginalBytes
		existingConn.OriginalPackets = conn.OriginalPackets
		existingConn.ReverseBytes = conn.ReverseBytes
		existingConn.ReversePackets = conn.ReversePackets
		existingConn.IsActive = true
		// Reassign the flow to update the map
		cs.connections[connKey] = *existingConn
		klog.V(4).Infof("Antrea flow updated: %v", existingConn)
	} else {
		var srcFound, dstFound bool
		sIface, srcFound := cs.ifaceStore.GetInterfaceByIP(conn.TupleOrig.SourceAddress.String())
		dIface, dstFound := cs.ifaceStore.GetInterfaceByIP(conn.TupleReply.SourceAddress.String())
		if !srcFound && !dstFound {
			klog.Warningf("Cannot map any of the IP %s or %s to a local Pod", conn.TupleOrig.SourceAddress.String(), conn.TupleReply.SourceAddress.String())
		}
		// sourceIP/destinationIP are mapped only to local pods and not remote pods.
		if srcFound && sIface.Type == interfacestore.ContainerInterface {
			conn.SourcePodName = sIface.ContainerInterfaceConfig.PodName
			conn.SourcePodNamespace = sIface.ContainerInterfaceConfig.PodNamespace
		}
		if dstFound && dIface.Type == interfacestore.ContainerInterface {
			conn.DestinationPodName = dIface.ContainerInterfaceConfig.PodName
			conn.DestinationPodNamespace = dIface.ContainerInterfaceConfig.PodNamespace
		}
		// Do not export flow records of connections whose destination is local pod and source is remote pod.
		// We export flow records only form "source node", where the connection is originated from. This is to avoid
		// 2 copies of flow records at flow collector. This restriction will be removed when flow records store network policy rule ID.
		// TODO: Remove this when network policy rule ID are added to flow records.
		if !srcFound && dstFound {
			conn.DoExport = false
		}
		klog.V(4).Infof("New Antrea flow added: %v", conn)
		// Add new antrea connection to connection store
		cs.connections[connKey] = *conn
	}
}

// GetConnByKey gets the connection in connection map given the connection key
func (cs *ConnectionStore) GetConnByKey(flowTuple flowexporter.ConnectionKey) (*flowexporter.Connection, bool) {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	conn, found := cs.connections[flowTuple]
	return &conn, found
}

// ForAllConnectionsDo execute the callback for each connection in connection map
func (cs *ConnectionStore) ForAllConnectionsDo(callback flowexporter.ConnectionMapCallBack) error {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	for k, v := range cs.connections {
		err := callback(k, v)
		if err != nil {
			klog.Errorf("Callback execution failed for flow with key: %v, conn: %v, k, v: %v", k, v, err)
			return err
		}
	}
	return nil
}

// Poll calls into conntrackDumper interface to dump conntrack flows
// TODO: As optimization, only poll invalid/closed connections during every poll, and poll the established connections right before the export.
func (cs *ConnectionStore) Poll() (int, error) {
	klog.V(2).Infof("Polling conntrack")

	// Reset isActive flag for all connections in connection map before dumping flows in conntrack module.
	// This is to specify that the connection and the flow record can be deleted after the next export.
	resetConn := func(key flowexporter.ConnectionKey, conn flowexporter.Connection) error {
		conn.IsActive = false
		cs.connections[key] = conn
		return nil
	}
	// We do not expect any error as resetConn is not returning any error
	cs.ForAllConnectionsDo(resetConn)

	filteredConns, err := cs.connDumper.DumpFlows(openflow.CtZone)
	if err != nil {
		return 0, err
	}
	// Update only the Connection store. IPFIX records are generated based on Connection store.
	for _, conn := range filteredConns {
		cs.addOrUpdateConn(conn)
	}
	connsLen := len(filteredConns)
	filteredConns = nil

	klog.V(2).Infof("Conntrack polling successful")

	return connsLen, nil
}

// DeleteConnectionByKey deletes the connection in connection map given the connection key
func (cs *ConnectionStore) DeleteConnectionByKey(connKey flowexporter.ConnectionKey) error {
	_, exists := cs.GetConnByKey(connKey)
	if !exists {
		return fmt.Errorf("connection with key %v doesn't exist in map", connKey)
	}
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	delete(cs.connections, connKey)

	return nil
}
