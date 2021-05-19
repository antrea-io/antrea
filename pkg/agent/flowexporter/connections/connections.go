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
	"encoding/binary"
	"fmt"
	"sync"
	"time"

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

type ConnectionStore interface {
	// Run enables the periodical polling of conntrack connections at a given flowPollInterval.
	Run(stopCh <-chan struct{})
	// GetConnByKey gets the connection in connection map given the connection key.
	GetConnByKey(connKey flowexporter.ConnectionKey) (*flowexporter.Connection, bool)
	// SetExportDone sets DoneExport field of connection to true given the connection key.
	SetExportDone(connKey flowexporter.ConnectionKey) error
	// ForAllConnectionsDo execute the callback for each connection in connection map.
	ForAllConnectionsDo(callback flowexporter.ConnectionMapCallBack) error
}

type connectionStore struct {
	connections          map[flowexporter.ConnectionKey]*flowexporter.Connection
	flowRecords          *flowrecords.FlowRecords
	connDumper           ConnTrackDumper
	ifaceStore           interfacestore.InterfaceStore
	v4Enabled            bool
	v6Enabled            bool
	antreaProxier        proxy.Proxier
	networkPolicyQuerier querier.AgentNetworkPolicyInfoQuerier
	pollInterval         time.Duration
	mutex                sync.Mutex
}

func NewConnectionStore(
	connTrackDumper ConnTrackDumper,
	flowRecords *flowrecords.FlowRecords,
	ifaceStore interfacestore.InterfaceStore,
	v4Enabled bool,
	v6Enabled bool,
	proxier proxy.Proxier,
	npQuerier querier.AgentNetworkPolicyInfoQuerier,
	pollInterval time.Duration,
) *connectionStore {
	return &connectionStore{
		connections:          make(map[flowexporter.ConnectionKey]*flowexporter.Connection),
		flowRecords:          flowRecords,
		connDumper:           connTrackDumper,
		ifaceStore:           ifaceStore,
		v4Enabled:            v4Enabled,
		v6Enabled:            v6Enabled,
		antreaProxier:        proxier,
		networkPolicyQuerier: npQuerier,
		pollInterval:         pollInterval,
	}
}

// Run enables the periodical polling of conntrack connections at a given flowPollInterval.
func (cs *connectionStore) Run(stopCh <-chan struct{}) {
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

// addOrUpdateConn updates the connection if it is already present, i.e., update timestamp, counters etc.,
// or adds a new Connection by 5-tuple of the flow along with local Pod and PodNameSpace.
func (cs *connectionStore) addOrUpdateConn(conn *flowexporter.Connection) {
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
		// sourceIP/destinationIP are mapped only to local pods and not remote pods.
		sIface, srcFound := cs.ifaceStore.GetInterfaceByIP(conn.TupleOrig.SourceAddress.String())
		dIface, dstFound := cs.ifaceStore.GetInterfaceByIP(conn.TupleReply.SourceAddress.String())
		if !srcFound && !dstFound {
			klog.Warningf("Cannot map any of the IP %s or %s to a local Pod", conn.TupleOrig.SourceAddress.String(), conn.TupleReply.SourceAddress.String())
		}
		if srcFound && sIface.Type == interfacestore.ContainerInterface {
			conn.SourcePodName = sIface.ContainerInterfaceConfig.PodName
			conn.SourcePodNamespace = sIface.ContainerInterfaceConfig.PodNamespace
		}
		if dstFound && dIface.Type == interfacestore.ContainerInterface {
			conn.DestinationPodName = dIface.ContainerInterfaceConfig.PodName
			conn.DestinationPodNamespace = dIface.ContainerInterfaceConfig.PodNamespace
		}

		// Process Pod-to-Service flows when Antrea Proxy is enabled.
		if cs.antreaProxier != nil {
			if conn.Mark == openflow.ServiceCTMark {
				clusterIP := conn.TupleOrig.DestinationAddress.String()
				svcPort := conn.TupleOrig.DestinationPort
				protocol, err := lookupServiceProtocol(conn.TupleOrig.Protocol)
				if err != nil {
					klog.Warningf("Could not retrieve Service protocol: %v", err)
				} else {
					serviceStr := fmt.Sprintf("%s:%d/%s", clusterIP, svcPort, protocol)
					servicePortName, exists := cs.antreaProxier.GetServiceByIP(serviceStr)
					if !exists {
						klog.Warningf("Could not retrieve the Service info from antrea-agent-proxier for the serviceStr: %s", serviceStr)
					} else {
						conn.DestinationServicePortName = servicePortName.String()
					}
				}
			}
		}

		// Retrieve NetworkPolicy Name and Namespace by using the ingress and egress
		// IDs stored in the connection label.
		if len(conn.Labels) != 0 {
			klog.V(4).Infof("connection label: %x; label masks: %x", conn.Labels, conn.LabelsMask)
			// We always expect labels from conntrack dumper to be added in little-endian format right now
			// In kernel datapath, the labels uses the "native" endianness for the system, which are little-endian
			// on most of the modern CPUs based on x86 architecture like Intel, AMD, etc.
			ingressOfID := binary.LittleEndian.Uint32(conn.Labels[:4])
			egressOfID := binary.LittleEndian.Uint32(conn.Labels[4:8])
			if ingressOfID != 0 {
				policy := cs.networkPolicyQuerier.GetNetworkPolicyByRuleFlowID(ingressOfID)
				if policy == nil {
					// This should not happen because the rule flow ID to rule mapping is
					// preserved for max(5s, flowPollInterval) even after the rule deletion.
					klog.Warningf("Cannot find NetworkPolicy that has rule with ingressOfID %v", ingressOfID)
				} else {
					conn.IngressNetworkPolicyName = policy.Name
					conn.IngressNetworkPolicyNamespace = policy.Namespace
				}
			}
			if egressOfID != 0 {
				policy := cs.networkPolicyQuerier.GetNetworkPolicyByRuleFlowID(egressOfID)
				if policy == nil {
					// This should not happen because the rule flow ID to rule mapping is
					// preserved for max(5s, flowPollInterval) even after the rule deletion.
					klog.Warningf("Cannot find NetworkPolicy that has rule with egressOfID %v", egressOfID)
				} else {
					conn.EgressNetworkPolicyName = policy.Name
					conn.EgressNetworkPolicyNamespace = policy.Namespace
				}
			}
		}
		metrics.TotalAntreaConnectionsInConnTrackTable.Inc()
		klog.V(4).Infof("New Antrea flow added: %v", conn)
		// Add new antrea connection to connection store
		cs.connections[connKey] = conn
	}
}

// GetConnByKey gets the connection in connection map given the connection key.
func (cs *connectionStore) GetConnByKey(connKey flowexporter.ConnectionKey) (*flowexporter.Connection, bool) {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	conn, found := cs.connections[connKey]
	return conn, found
}

// SetExportDone sets DoneExport field of connection to true given the connection key.
func (cs *connectionStore) SetExportDone(connKey flowexporter.ConnectionKey) error {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	if conn, found := cs.connections[connKey]; !found {
		return fmt.Errorf("connection with key %v does not exist in connection map", connKey)
	} else {
		conn.DoneExport = true
		return nil
	}
}

// ForAllConnectionsDo execute the callback for each connection in connection map.
func (cs *connectionStore) ForAllConnectionsDo(callback flowexporter.ConnectionMapCallBack) error {
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

// Poll calls into conntrackDumper interface to dump conntrack flows. It returns the number of connections for each
// address family, as a slice. In dual-stack clusters, the slice will contain 2 values (number of IPv4 connections first,
// then number of IPv6 connections).
// TODO: As optimization, only poll invalid/closed connections during every poll, and poll the established connections right before the export.
func (cs *connectionStore) Poll() ([]int, error) {
	klog.V(2).Infof("Polling conntrack")
	// Reset IsPresent flag for all connections in connection map before dumping flows in conntrack module.
	// if the connection does not exist in conntrack table and has been exported, we will delete it from connection map.
	deleteIfStaleOrResetConn := func(key flowexporter.ConnectionKey, conn *flowexporter.Connection) error {
		if !conn.IsPresent && conn.DoneExport {
			if err := cs.deleteConnectionByKeyWithoutLock(key); err != nil {
				return err
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
			cs.addOrUpdateConn(conn)
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

// deleteConnectionByKeyWithoutLock deletes the connection in connection map given the
// connection key without grabbing the lock. Caller is expected to grab lock.
func (cs *connectionStore) deleteConnectionByKeyWithoutLock(connKey flowexporter.ConnectionKey) error {
	_, exists := cs.connections[connKey]
	if !exists {
		return fmt.Errorf("connection with key %v doesn't exist in map", connKey)
	}
	delete(cs.connections, connKey)
	metrics.TotalAntreaConnectionsInConnTrackTable.Dec()
	return nil
}

// LookupServiceProtocol returns the corresponding Service protocol string for a given protocol identifier
func lookupServiceProtocol(protoID uint8) (corev1.Protocol, error) {
	serviceProto, found := serviceProtocolMap[protoID]
	if !found {
		return "", fmt.Errorf("unknown protocol identifier: %d", protoID)
	}
	return serviceProto, nil
}
