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
	"encoding/binary"
	"fmt"
	"time"

	"github.com/vmware/go-ipfix/pkg/registry"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/flowexporter"
	"antrea.io/antrea/pkg/agent/flowexporter/priorityqueue"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/metrics"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/proxy"
	"antrea.io/antrea/pkg/querier"
)

var serviceProtocolMap = map[uint8]corev1.Protocol{
	6:   corev1.ProtocolTCP,
	17:  corev1.ProtocolUDP,
	132: corev1.ProtocolSCTP,
}

type ConntrackConnectionStore struct {
	connDumper           ConnTrackDumper
	v4Enabled            bool
	v6Enabled            bool
	networkPolicyQuerier querier.AgentNetworkPolicyInfoQuerier
	pollInterval         time.Duration
	connectionStore
}

func NewConntrackConnectionStore(
	connTrackDumper ConnTrackDumper,
	v4Enabled bool,
	v6Enabled bool,
	npQuerier querier.AgentNetworkPolicyInfoQuerier,
	ifaceStore interfacestore.InterfaceStore,
	proxier proxy.Proxier,
	o *flowexporter.FlowExporterOptions,
) *ConntrackConnectionStore {
	return &ConntrackConnectionStore{
		connDumper:           connTrackDumper,
		v4Enabled:            v4Enabled,
		v6Enabled:            v6Enabled,
		networkPolicyQuerier: npQuerier,
		pollInterval:         o.PollInterval,
		connectionStore:      NewConnectionStore(ifaceStore, proxier, o),
	}
}

// Run enables the periodical polling of conntrack connections at a given flowPollInterval.
func (cs *ConntrackConnectionStore) Run(stopCh <-chan struct{}) {
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
		}
	}
}

// Poll calls into conntrackDumper interface to dump conntrack flows. It returns the number of connections for each
// address family, as a slice. In dual-stack clusters, the slice will contain 2 values (number of IPv4 connections first,
// then number of IPv6 connections).
// TODO: As optimization, only poll invalid/closed connections during every poll, and poll the established connections right before the export.
func (cs *ConntrackConnectionStore) Poll() ([]int, error) {
	klog.V(2).Infof("Polling conntrack")
	// Reset IsPresent flag for all connections in connection map before dumping
	// flows in conntrack module. If the connection does not exist in conntrack
	// table and has been exported, then we will delete it from connection map.
	// In addition, if the connection was not exported for a specific time period,
	// then we consider it to be stale and delete it.
	deleteIfStaleOrResetConn := func(key flowexporter.ConnectionKey, conn *flowexporter.Connection) error {
		if !conn.IsPresent {
			// Delete the connection if it is ready to delete or it was not exported
			// in the time period as specified by the stale connection timeout.
			if conn.ReadyToDelete || time.Since(conn.LastExportTime) >= cs.staleConnectionTimeout {
				if err := cs.deleteConnWithoutLock(key); err != nil {
					return err
				}
			}
		} else {
			conn.IsPresent = false
		}
		return nil
	}

	if err := cs.ForAllConnectionsDo(deleteIfStaleOrResetConn); err != nil {
		return []int{}, err
	}

	var zones []uint16
	var connsLens []int
	if cs.v4Enabled {
		zones = append(zones, openflow.CtZone)
	}
	if cs.v6Enabled {
		zones = append(zones, openflow.CtZoneV6)
	}
	var totalConns int
	for _, zone := range zones {
		filteredConnsList, totalConnsPerZone, err := cs.connDumper.DumpFlows(zone)
		if err != nil {
			return []int{}, err
		}
		totalConns += totalConnsPerZone
		// Update only the Connection store. IPFIX records are generated based on Connection store.
		for _, conn := range filteredConnsList {
			cs.AddOrUpdateConn(conn)
		}
		connsLens = append(connsLens, len(filteredConnsList))
	}
	metrics.TotalConnectionsInConnTrackTable.Set(float64(totalConns))
	maxConns, err := cs.connDumper.GetMaxConnections()
	if err != nil {
		return []int{}, err
	}
	metrics.MaxConnectionsInConnTrackTable.Set(float64(maxConns))
	klog.V(2).Infof("Conntrack polling successful")

	return connsLens, nil
}

func (cs *ConntrackConnectionStore) addNetworkPolicyMetadata(conn *flowexporter.Connection) {
	// Retrieve NetworkPolicy Name and Namespace by using the ingress and egress
	// IDs stored in the connection label.
	if len(conn.Labels) != 0 {
		klog.V(4).Infof("connection label: %x; label masks: %x", conn.Labels, conn.LabelsMask)
		ingressOfID := binary.LittleEndian.Uint32(conn.Labels[:4])
		egressOfID := binary.LittleEndian.Uint32(conn.Labels[4:8])
		if ingressOfID != 0 {
			policy := cs.networkPolicyQuerier.GetNetworkPolicyByRuleFlowID(ingressOfID)
			rule := cs.networkPolicyQuerier.GetRuleByFlowID(ingressOfID)
			if policy == nil || rule == nil {
				// This should not happen because the rule flow ID to rule mapping is
				// preserved for max(5s, flowPollInterval) even after the rule deletion.
				klog.Warningf("Cannot find NetworkPolicy or rule with ingressOfID %v", ingressOfID)
			} else {
				conn.IngressNetworkPolicyName = policy.Name
				conn.IngressNetworkPolicyNamespace = policy.Namespace
				conn.IngressNetworkPolicyType = flowexporter.PolicyTypeToUint8(policy.Type)
				conn.IngressNetworkPolicyRuleName = rule.Name
				conn.IngressNetworkPolicyRuleAction = registry.NetworkPolicyRuleActionAllow
			}
		}
		if egressOfID != 0 {
			policy := cs.networkPolicyQuerier.GetNetworkPolicyByRuleFlowID(egressOfID)
			rule := cs.networkPolicyQuerier.GetRuleByFlowID(egressOfID)
			if policy == nil || rule == nil {
				// This should not happen because the rule flow ID to rule mapping is
				// preserved for max(5s, flowPollInterval) even after the rule deletion.
				klog.Warningf("Cannot find NetworkPolicy or rule with egressOfID %v", egressOfID)
			} else {
				conn.EgressNetworkPolicyName = policy.Name
				conn.EgressNetworkPolicyNamespace = policy.Namespace
				conn.EgressNetworkPolicyType = flowexporter.PolicyTypeToUint8(policy.Type)
				conn.EgressNetworkPolicyRuleName = rule.Name
				conn.EgressNetworkPolicyRuleAction = registry.NetworkPolicyRuleActionAllow
			}
		}
	}
}

// AddOrUpdateConn updates the connection if it is already present, i.e., update timestamp, counters etc.,
// or adds a new connection with the resolved K8s metadata.
func (cs *ConntrackConnectionStore) AddOrUpdateConn(conn *flowexporter.Connection) {
	connKey := flowexporter.NewConnectionKey(conn)
	cs.mutex.Lock()
	defer cs.mutex.Unlock()

	existingConn, exists := cs.connections[connKey]
	if exists {
		existingConn.IsPresent = true
		if flowexporter.IsConnectionDying(existingConn) {
			return
		}
		// Update the necessary fields that are used in generating flow records.
		// Can same 5-tuple flow get deleted and added to conntrack table? If so use ID.
		existingConn.StopTime = conn.StopTime
		existingConn.OriginalBytes = conn.OriginalBytes
		existingConn.OriginalPackets = conn.OriginalPackets
		existingConn.ReverseBytes = conn.ReverseBytes
		existingConn.ReversePackets = conn.ReversePackets
		existingConn.TCPState = conn.TCPState
		existingConn.IsActive = flowexporter.CheckConntrackConnActive(existingConn)
		if existingConn.IsActive {
			existingItem, exists := cs.expirePriorityQueue.KeyToItem[connKey]
			if !exists {
				// If the connKey:pqItem pair does not exist in the map, it shows the
				// conn was inactive, and was removed from PQ and map. Since it becomes
				// active again now, we create a new pqItem and add it to PQ and map.
				cs.expirePriorityQueue.AddItemToQueue(connKey, existingConn)
			} else {
				cs.connectionStore.expirePriorityQueue.Update(existingItem, existingItem.ActiveExpireTime,
					time.Now().Add(cs.connectionStore.expirePriorityQueue.IdleFlowTimeout))
			}
		}
		klog.V(4).InfoS("Antrea flow updated", "connection", existingConn)
	} else {
		cs.fillPodInfo(conn)
		if conn.Mark&openflow.ServiceCTMark.GetRange().ToNXRange().ToUint32Mask() == openflow.ServiceCTMark.GetValue() {
			clusterIP := conn.DestinationServiceAddress.String()
			svcPort := conn.DestinationServicePort
			protocol, err := lookupServiceProtocol(conn.FlowKey.Protocol)
			if err != nil {
				klog.InfoS("Could not retrieve Service protocol", "error", err)
			} else {
				serviceStr := fmt.Sprintf("%s:%d/%s", clusterIP, svcPort, protocol)
				cs.fillServiceInfo(conn, serviceStr)
			}
		}
		cs.addNetworkPolicyMetadata(conn)
		if conn.StartTime.IsZero() {
			conn.StartTime = time.Now()
			conn.StopTime = time.Now()
		}
		metrics.TotalAntreaConnectionsInConnTrackTable.Inc()
		conn.IsActive = true
		// Add new antrea connection to connection store and PQ.
		cs.connections[connKey] = conn
		cs.expirePriorityQueue.AddItemToQueue(connKey, conn)
		klog.V(4).InfoS("New Antrea flow added", "connection", conn)
	}
}

func (cs *ConntrackConnectionStore) GetExpiredConns(expiredConns []flowexporter.Connection, currTime time.Time, maxSize int) ([]flowexporter.Connection, time.Duration) {
	cs.AcquireConnStoreLock()
	defer cs.ReleaseConnStoreLock()
	for i := 0; i < maxSize; i++ {
		pqItem := cs.connectionStore.expirePriorityQueue.GetTopExpiredItem(currTime)
		if pqItem == nil {
			break
		}
		expiredConns = append(expiredConns, *pqItem.Conn)
		if flowexporter.IsConnectionDying(pqItem.Conn) {
			// If a conntrack connection is in dying state or connection is not
			// in the conntrack table, we set the ReadyToDelete flag to true to
			// do the deletion later.
			pqItem.Conn.ReadyToDelete = true
		}
		if pqItem.IdleExpireTime.Before(currTime) {
			// No packets have been received during the idle timeout interval,
			// the connection is therefore considered inactive.
			pqItem.Conn.IsActive = false
		}
		cs.UpdateConnAndQueue(pqItem, currTime)
	}
	return expiredConns, cs.connectionStore.expirePriorityQueue.GetExpiryFromExpirePriorityQueue()
}

// deleteConnWithoutLock deletes the connection from the connection map given
// the connection key without grabbing the lock. Caller is expected to grab lock.
func (cs *ConntrackConnectionStore) deleteConnWithoutLock(connKey flowexporter.ConnectionKey) error {
	_, exists := cs.connections[connKey]
	if !exists {
		return fmt.Errorf("connection with key %v doesn't exist in map", connKey)
	}
	delete(cs.connections, connKey)
	metrics.TotalAntreaConnectionsInConnTrackTable.Dec()
	return nil
}

func (cs *ConntrackConnectionStore) GetPriorityQueue() *priorityqueue.ExpirePriorityQueue {
	return cs.connectionStore.expirePriorityQueue
}
