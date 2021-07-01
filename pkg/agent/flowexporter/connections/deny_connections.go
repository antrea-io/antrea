// Copyright 2021 Antrea Authors
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
	"time"

	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/flowexporter"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/metrics"
	"antrea.io/antrea/pkg/agent/proxy"
	"antrea.io/antrea/pkg/util/ip"
)

type DenyConnectionStore struct {
	connectionStore
}

func NewDenyConnectionStore(ifaceStore interfacestore.InterfaceStore,
	proxier proxy.Proxier) *DenyConnectionStore {
	return &DenyConnectionStore{
		connectionStore: NewConnectionStore(ifaceStore, proxier),
	}
}

// AddOrUpdateConn updates the connection if it is already present, i.e., update timestamp, counters etc.,
// or adds a new connection with the resolved K8s metadata.
func (ds *DenyConnectionStore) AddOrUpdateConn(conn *flowexporter.Connection, timeSeen time.Time, bytes uint64) {
	connKey := flowexporter.NewConnectionKey(conn)
	ds.mutex.Lock()
	defer ds.mutex.Unlock()
	if _, exist := ds.connections[connKey]; exist {
		conn.DeltaBytes += bytes
		conn.OriginalBytes += bytes
		conn.DeltaPackets += 1
		conn.OriginalPackets += 1
		conn.StopTime = timeSeen
		klog.V(2).Infof("Deny connection with flowKey %v has been updated.", connKey)
		return
	} else {
		conn.StartTime = timeSeen
		conn.StopTime = timeSeen
		conn.LastExportTime = timeSeen
		conn.DeltaBytes = bytes
		conn.OriginalBytes = bytes
		conn.DeltaPackets = uint64(1)
		conn.OriginalPackets = uint64(1)
		ds.fillPodInfo(conn)
		protocolStr := ip.IPProtocolNumberToString(conn.FlowKey.Protocol, "UnknownProtocol")
		serviceStr := fmt.Sprintf("%s:%d/%s", conn.DestinationServiceAddress, conn.DestinationServicePort, protocolStr)
		ds.fillServiceInfo(conn, serviceStr)
		metrics.TotalDenyConnections.Inc()
		ds.connections[connKey] = conn
	}
}

// ResetConnStatsWithoutLock resets DeltaBytes and DeltaPackets of connection
// after exporting without grabbing the lock. Caller is expected to grab lock.
func (ds *DenyConnectionStore) ResetConnStatsWithoutLock(connKey flowexporter.ConnectionKey) {
	conn, exist := ds.connections[connKey]
	if !exist {
		klog.Warningf("Connection with key %s does not exist in deny connection store.", connKey)
	} else {
		conn.DeltaBytes = 0
		conn.DeltaPackets = 0
		conn.LastExportTime = time.Now()
	}
}

// DeleteConnWithoutLock deletes the connection from the connection map given
// the connection key without grabbing the lock. Caller is expected to grab lock.
func (ds *DenyConnectionStore) DeleteConnWithoutLock(connKey flowexporter.ConnectionKey) error {
	_, exists := ds.connections[connKey]
	if !exists {
		return fmt.Errorf("connection with key %v doesn't exist in map", connKey)
	}
	delete(ds.connections, connKey)
	metrics.TotalDenyConnections.Dec()
	return nil
}
