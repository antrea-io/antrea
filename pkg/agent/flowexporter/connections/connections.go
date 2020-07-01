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
	"sync"
	"time"

	"k8s.io/klog/v2"

	"github.com/vmware-tanzu/antrea/pkg/agent/flowexporter"
	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
)

var _ ConnectionStore = new(connectionStore)

type ConnectionStore interface {
	Run(stopCh <-chan struct{})
	IterateCxnMapWithCB(updateCallback flowexporter.FlowRecordUpdate) error
	FlushConnectionStore()
}

type connectionStore struct {
	connections  map[flowexporter.ConnectionKey]flowexporter.Connection // Add 5-tuple as string array
	connDumper   ConnTrackDumper
	ifaceStore   interfacestore.InterfaceStore
	pollInterval time.Duration
	mutex        sync.Mutex
}

func NewConnectionStore(ctDumper ConnTrackDumper, ifaceStore interfacestore.InterfaceStore, interval time.Duration) *connectionStore {
	return &connectionStore{
		connections:  make(map[flowexporter.ConnectionKey]flowexporter.Connection),
		connDumper:   ctDumper,
		ifaceStore:   ifaceStore,
		pollInterval: interval,
	}
}

// Run polls the connTrackDumper module periodically to get connections. These connections are used
// to build connection store.
func (cs *connectionStore) Run(stopCh <-chan struct{}) {
	klog.Infof("Starting conntrack polling")

	ticker := time.NewTicker(cs.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stopCh:
			break
		case <-ticker.C:
			_, err := cs.poll()
			if err != nil {
				// Not failing here as errors can be transient and could be resolved in future poll cycles.
				// TODO: Come up with a backoff/retry mechanism by increasing poll interval and adding retry timeout
				klog.Errorf("Error during conntrack poll cycle: %v", err)
			}
		}
	}
}

// addOrUpdateConn updates the connection if it is already present, i.e., update timestamp, counters etc.,
// or adds a new Connection by 5-tuple of the flow along with local Pod and PodNameSpace.
func (cs *connectionStore) addOrUpdateConn(conn *flowexporter.Connection) {
	connKey := flowexporter.NewConnectionKey(conn)

	existingConn, exists := cs.getConnByKey(connKey)

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
		klog.V(4).Infof("New Antrea flow added: %v", conn)
		// Add new antrea connection to connection store
		cs.connections[connKey] = *conn
	}
}

func (cs *connectionStore) getConnByKey(flowTuple flowexporter.ConnectionKey) (*flowexporter.Connection, bool) {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	conn, found := cs.connections[flowTuple]
	return &conn, found
}

func (cs *connectionStore) IterateCxnMapWithCB(updateCallback flowexporter.FlowRecordUpdate) error {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()

	for k, v := range cs.connections {
		cs.mutex.Unlock()
		// Releasing lock as there are no concurrent deletes. There can be concurrent add or modify. We may not consider the
		// newly added or modified field and send old connection data collected in last poll cycle.
		// This has to be changed when flushing of connection data logic changes.
		// Followed this go documentation (point#3 on iteration over map): https://golang.org/ref/spec#For_statements_with_range_clause
		err := updateCallback(k, v)
		if err != nil {
			klog.Errorf("Update callback failed for flow with key: %v, conn: %v, k, v: %v", k, v, err)
			return err
		}
		cs.mutex.Lock()
	}
	return nil
}

// poll returns number of filtered connections after poll cycle
// TODO: Optimize polling cycle--Only poll invalid/close connection during every poll. Poll established right before export
func (cs *connectionStore) poll() (int, error) {
	klog.V(2).Infof("Polling conntrack")

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

// FlushConnectionStore after each IPFIX export of flow records.
// Timed out conntrack connections will not be sent as IPFIX flow records.
func (cs *connectionStore) FlushConnectionStore() {
	klog.Infof("Flushing connection map")

	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	for conn := range cs.connections {
		delete(cs.connections, conn)
	}
}
