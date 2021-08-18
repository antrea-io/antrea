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
	"antrea.io/antrea/pkg/agent/flowexporter/flowrecords"
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
	flowRecords          *flowrecords.FlowRecords
	connDumper           ConnTrackDumper
	v4Enabled            bool
	v6Enabled            bool
	networkPolicyQuerier querier.AgentNetworkPolicyInfoQuerier
	pollInterval         time.Duration
	connectionStore
}

func NewConntrackConnectionStore(
	connTrackDumper ConnTrackDumper,
	flowRecords *flowrecords.FlowRecords,
	ifaceStore interfacestore.InterfaceStore,
	v4Enabled bool,
	v6Enabled bool,
	proxier proxy.Proxier,
	npQuerier querier.AgentNetworkPolicyInfoQuerier,
	pollInterval time.Duration,
	staleConnectionTimeout time.Duration,
) *ConntrackConnectionStore {
	return &ConntrackConnectionStore{
		flowRecords:          flowRecords,
		connDumper:           connTrackDumper,
		v4Enabled:            v4Enabled,
		v6Enabled:            v6Enabled,
		networkPolicyQuerier: npQuerier,
		pollInterval:         pollInterval,
		connectionStore:      NewConnectionStore(ifaceStore, proxier, staleConnectionTimeout),
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
			// AddOrUpdateFlowRecord method does not return any error, hence no error handling required.
			cs.ForAllConnectionsDo(cs.flowRecords.AddOrUpdateFlowRecord)
			klog.V(2).Infof("Flow records are successfully updated")
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
			if conn.DyingAndDoneExport {
				if err := cs.DeleteConnWithoutLock(key); err != nil {
					return err
				}
			} else {
				record, exists := cs.flowRecords.GetFlowRecordFromMap(&key)
				if exists {
					// Delete the connection if it was not exported for the time
					// period as specified by the stale connection timeout.
					if time.Since(record.LastExportTime) >= cs.staleConnectionTimeout {
						// Ignore error if flow record not found.
						cs.flowRecords.DeleteFlowRecordFromMap(&key)
						delete(cs.connections, key)
					}
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
		// avoid updating stats of the existing connection that is about to close
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
		klog.V(4).Infof("Antrea flow updated: %v", existingConn)
	} else {
		cs.fillPodInfo(conn)
		if conn.Mark == openflow.ServiceCTMark.GetValue() {
			clusterIP := conn.DestinationServiceAddress.String()
			svcPort := conn.DestinationServicePort
			protocol, err := lookupServiceProtocol(conn.FlowKey.Protocol)
			if err != nil {
				klog.Warningf("Could not retrieve Service protocol: %v", err)
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
		klog.V(4).Infof("New Antrea flow added: %v", conn)
		// Add new antrea connection to connection store
		cs.connections[connKey] = conn
	}
}

// DeleteConnWithoutLock deletes the connection from the connection map given
// the connection key without grabbing the lock. Caller is expected to grab lock.
func (cs *ConntrackConnectionStore) DeleteConnWithoutLock(connKey flowexporter.ConnectionKey) error {
	_, exists := cs.connections[connKey]
	if !exists {
		return fmt.Errorf("connection with key %v doesn't exist in map", connKey)
	}
	delete(cs.connections, connKey)
	metrics.TotalAntreaConnectionsInConnTrackTable.Dec()
	return nil
}
