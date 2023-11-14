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
	"antrea.io/antrea/pkg/agent/flowexporter/priorityqueue"
	"antrea.io/antrea/pkg/agent/metrics"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/proxy"
	"antrea.io/antrea/pkg/util/ip"
	"antrea.io/antrea/pkg/util/podstore"
)

type DenyConnectionStore struct {
	connectionStore
}

func NewDenyConnectionStore(podStore podstore.Interface, proxier proxy.Proxier, o *flowexporter.FlowExporterOptions) *DenyConnectionStore {
	return &DenyConnectionStore{
		connectionStore: NewConnectionStore(podStore, proxier, o),
	}
}

func (ds *DenyConnectionStore) RunPeriodicDeletion(stopCh <-chan struct{}) {
	pollTicker := time.NewTicker(periodicDeleteInterval)
	defer pollTicker.Stop()

	for {
		select {
		case <-stopCh:
			break
		case <-pollTicker.C:
			deleteIfStaleConn := func(key flowexporter.ConnectionKey, conn *flowexporter.Connection) error {
				if conn.ReadyToDelete || time.Since(conn.LastExportTime) >= ds.staleConnectionTimeout {
					if removedItem := ds.expirePriorityQueue.Remove(key); removedItem != nil {
						// In case ReadyToDelete is true, item should already have been removed from pq
						klog.V(4).InfoS("Conn removed from ds pq due to stale timeout",
							"key", key, "conn", removedItem.Conn)
					}
					if err := ds.deleteConnWithoutLock(key); err != nil {
						return err
					}
				}
				return nil
			}
			ds.ForAllConnectionsDo(deleteIfStaleConn)
			klog.V(2).Infof("Stale connections in the Deny Connection Store are successfully deleted.")
		}
	}
}

// AddOrUpdateConn updates the connection if it is already present, i.e., update timestamp, counters etc.,
// or adds a new connection with the resolved K8s metadata.
func (ds *DenyConnectionStore) AddOrUpdateConn(conn *flowexporter.Connection, timeSeen time.Time, bytes uint64) {
	connKey := flowexporter.NewConnectionKey(conn)
	ds.mutex.Lock()
	defer ds.mutex.Unlock()

	if _, exist := ds.connections[connKey]; exist {
		if conn.ReadyToDelete {
			return
		}
		conn.OriginalBytes += bytes
		conn.OriginalPackets += 1
		conn.StopTime = timeSeen
		conn.IsActive = true
		existingItem, exists := ds.expirePriorityQueue.KeyToItem[connKey]
		if !exists {
			ds.expirePriorityQueue.WriteItemToQueue(connKey, conn)
		} else {
			ds.connectionStore.expirePriorityQueue.Update(existingItem, existingItem.ActiveExpireTime,
				time.Now().Add(ds.connectionStore.expirePriorityQueue.IdleFlowTimeout))
		}
		klog.V(4).InfoS("Deny connection has been updated", "connection", conn)
	} else {
		conn.StartTime = timeSeen
		conn.StopTime = timeSeen
		conn.LastExportTime = timeSeen
		conn.OriginalBytes = bytes
		conn.OriginalPackets = uint64(1)
		ds.fillPodInfo(conn)
		if conn.SourcePodName == "" && conn.DestinationPodName == "" {
			// We don't add connections to connection map or expirePriorityQueue if we can't find the pod
			// information for both srcPod and dstPod
			klog.V(5).InfoS("Skip this connection as we cannot map any of the connection IPs to a local Pod", "srcIP", conn.FlowKey.SourceAddress.String(), "dstIP", conn.FlowKey.DestinationAddress.String())
			return
		}
		protocolStr := ip.IPProtocolNumberToString(conn.FlowKey.Protocol, "UnknownProtocol")
		serviceStr := fmt.Sprintf("%s:%d/%s", conn.OriginalDestinationAddress, conn.OriginalDestinationPort, protocolStr)
		if conn.Mark&openflow.ServiceCTMark.GetRange().ToNXRange().ToUint32Mask() == openflow.ServiceCTMark.GetValue() {
			ds.fillServiceInfo(conn, serviceStr)
		}
		metrics.TotalDenyConnections.Inc()
		conn.IsActive = true
		ds.connections[connKey] = conn
		ds.expirePriorityQueue.WriteItemToQueue(connKey, conn)
		klog.V(4).InfoS("New deny connection added", "connection", conn)
	}
}

func (ds *DenyConnectionStore) GetExpiredConns(expiredConns []flowexporter.Connection, currTime time.Time, maxSize int) ([]flowexporter.Connection, time.Duration) {
	ds.AcquireConnStoreLock()
	defer ds.ReleaseConnStoreLock()
	for i := 0; i < maxSize; i++ {
		pqItem := ds.connectionStore.expirePriorityQueue.GetTopExpiredItem(currTime)
		if pqItem == nil {
			break
		}
		expiredConns = append(expiredConns, *pqItem.Conn)
		if pqItem.IdleExpireTime.Before(currTime) {
			// If a deny connection item is idle time out, we set the ReadyToDelete
			// flag to true to do the deletion later.
			pqItem.Conn.ReadyToDelete = true
		}
		if pqItem.Conn.OriginalPackets <= pqItem.Conn.PrevPackets {
			// If a deny connection doesn't have increase in packet count,
			// we consider the connection to be inactive.
			pqItem.Conn.IsActive = false
		}
		ds.UpdateConnAndQueue(pqItem, currTime)
	}
	return expiredConns, ds.connectionStore.expirePriorityQueue.GetExpiryFromExpirePriorityQueue()
}

// deleteConnWithoutLock deletes the connection from the connection map given
// the connection key without grabbing the lock. Caller is expected to grab lock.
func (ds *DenyConnectionStore) deleteConnWithoutLock(connKey flowexporter.ConnectionKey) error {
	_, exists := ds.connections[connKey]
	if !exists {
		return fmt.Errorf("connection with key %v doesn't exist in map", connKey)
	}
	delete(ds.connections, connKey)
	metrics.TotalDenyConnections.Dec()
	return nil
}

func (ds *DenyConnectionStore) GetPriorityQueue() *priorityqueue.ExpirePriorityQueue {
	return ds.connectionStore.expirePriorityQueue
}
