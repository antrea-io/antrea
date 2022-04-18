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
	"container/heap"
	"fmt"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/flowexporter"
	"antrea.io/antrea/pkg/agent/flowexporter/priorityqueue"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/proxy"
)

const (
	periodicDeleteInterval = time.Minute
)

type connectionStore struct {
	connections            map[flowexporter.ConnectionKey]*flowexporter.Connection
	ifaceStore             interfacestore.InterfaceStore
	antreaProxier          proxy.Proxier
	expirePriorityQueue    *priorityqueue.ExpirePriorityQueue
	staleConnectionTimeout time.Duration
	mutex                  sync.Mutex
}

func NewConnectionStore(
	ifaceStore interfacestore.InterfaceStore,
	proxier proxy.Proxier,
	o *flowexporter.FlowExporterOptions) connectionStore {
	return connectionStore{
		connections:            make(map[flowexporter.ConnectionKey]*flowexporter.Connection),
		ifaceStore:             ifaceStore,
		antreaProxier:          proxier,
		expirePriorityQueue:    priorityqueue.NewExpirePriorityQueue(o.ActiveFlowTimeout, o.IdleFlowTimeout),
		staleConnectionTimeout: o.StaleConnectionTimeout,
	}
}

// GetConnByKey gets the connection in connection map given the connection key.
func (cs *connectionStore) GetConnByKey(connKey flowexporter.ConnectionKey) (*flowexporter.Connection, bool) {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	conn, found := cs.connections[connKey]
	return conn, found
}

// ForAllConnectionsDo execute the callback for each connection in connection map.
func (cs *connectionStore) ForAllConnectionsDo(callback flowexporter.ConnectionMapCallBack) error {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	for k, v := range cs.connections {
		err := callback(k, v)
		if err != nil {
			klog.ErrorS(err, "Callback execution failed for flow", "key", k, "conn", v)
			return err
		}
	}
	return nil
}

// ForAllConnectionsDoWithoutLock execute the callback for each connection in connection
// map, without grabbing the lock. Caller is expected to grab lock.
func (cs *connectionStore) ForAllConnectionsDoWithoutLock(callback flowexporter.ConnectionMapCallBack) error {
	for k, v := range cs.connections {
		err := callback(k, v)
		if err != nil {
			klog.ErrorS(err, "Callback execution failed for flow", "key", k, "conn", v)
			return err
		}
	}
	return nil
}

// AddConnToMap adds the connection to connections map given connection key.
// This is used only for unit tests.
func (cs *connectionStore) AddConnToMap(connKey *flowexporter.ConnectionKey, conn *flowexporter.Connection) {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	cs.connections[*connKey] = conn
}

func (cs *connectionStore) fillPodInfo(conn *flowexporter.Connection) {
	if cs.ifaceStore == nil {
		klog.V(4).Info("Interface store is not available to retrieve local Pods information.")
		return
	}
	// sourceIP/destinationIP are mapped only to local pods and not remote pods.
	srcIP := conn.FlowKey.SourceAddress.String()
	dstIP := conn.FlowKey.DestinationAddress.String()

	sIface, srcFound := cs.ifaceStore.GetInterfaceByIP(srcIP)
	dIface, dstFound := cs.ifaceStore.GetInterfaceByIP(dstIP)
	if !srcFound && !dstFound {
		klog.Warningf("Cannot map any of the IP %s or %s to a local Pod", srcIP, dstIP)
	}
	if srcFound && sIface.Type == interfacestore.ContainerInterface {
		conn.SourcePodName = sIface.ContainerInterfaceConfig.PodName
		conn.SourcePodNamespace = sIface.ContainerInterfaceConfig.PodNamespace
	}
	if dstFound && dIface.Type == interfacestore.ContainerInterface {
		conn.DestinationPodName = dIface.ContainerInterfaceConfig.PodName
		conn.DestinationPodNamespace = dIface.ContainerInterfaceConfig.PodNamespace
	}
}

func (cs *connectionStore) fillServiceInfo(conn *flowexporter.Connection, serviceStr string) {
	// resolve destination Service information
	if cs.antreaProxier != nil {
		servicePortName, exists := cs.antreaProxier.GetServiceByIP(serviceStr)
		if !exists {
			klog.Warningf("Could not retrieve the Service info from antrea-agent-proxier for the serviceStr: %s", serviceStr)
		} else {
			conn.DestinationServicePortName = servicePortName.String()
		}
	}
}

// LookupServiceProtocol returns the corresponding Service protocol string for a given protocol identifier
func lookupServiceProtocol(protoID uint8) (corev1.Protocol, error) {
	serviceProto, found := serviceProtocolMap[protoID]
	if !found {
		return "", fmt.Errorf("unknown protocol identifier: %d", protoID)
	}
	return serviceProto, nil
}

func (cs *connectionStore) addItemToQueue(connKey flowexporter.ConnectionKey, conn *flowexporter.Connection) {
	currTime := time.Now()
	pqItem := &flowexporter.ItemToExpire{
		Conn:             conn,
		ActiveExpireTime: currTime.Add(cs.expirePriorityQueue.ActiveFlowTimeout),
		IdleExpireTime:   currTime.Add(cs.expirePriorityQueue.IdleFlowTimeout),
	}
	heap.Push(cs.expirePriorityQueue, pqItem)
	cs.expirePriorityQueue.KeyToItem[connKey] = pqItem
}

func (cs *connectionStore) AcquireConnStoreLock() {
	cs.mutex.Lock()
}

func (cs *connectionStore) ReleaseConnStoreLock() {
	cs.mutex.Unlock()
}

// UpdateConnAndQueue deletes the inactive connection from keyToItem map,
// without adding it back to the PQ. In this way, we can avoid to reset the
// item's expire time every time we encounter it in the PQ. The method also
// updates active connection's stats fields and adds it back to the PQ.
func (cs *connectionStore) UpdateConnAndQueue(pqItem *flowexporter.ItemToExpire, currTime time.Time) {
	conn := pqItem.Conn
	conn.LastExportTime = currTime
	if conn.ReadyToDelete || !conn.IsActive {
		cs.expirePriorityQueue.RemoveItemFromMap(conn)
	} else {
		// For active connections, we update their "prev" stats fields,
		// reset active expire time and push back into the PQ.
		conn.PrevBytes = conn.OriginalBytes
		conn.PrevPackets = conn.OriginalPackets
		conn.PrevTCPState = conn.TCPState
		conn.PrevReverseBytes = conn.ReverseBytes
		conn.PrevReversePackets = conn.ReversePackets
		cs.expirePriorityQueue.ResetActiveExpireTimeAndPush(pqItem, currTime)
	}
}
