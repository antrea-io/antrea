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

	"github.com/vmware-tanzu/antrea/pkg/agent/flowexporter"
	"github.com/vmware-tanzu/antrea/pkg/agent/flowexporter/flowrecords"
	"github.com/vmware-tanzu/antrea/pkg/agent/interfacestore"
	"github.com/vmware-tanzu/antrea/pkg/agent/metrics"
	"github.com/vmware-tanzu/antrea/pkg/agent/openflow"
	"github.com/vmware-tanzu/antrea/pkg/querier"
	"github.com/vmware-tanzu/antrea/third_party/proxy"
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
	GetConnByKey(flowTuple flowexporter.ConnectionKey) (*flowexporter.Connection, bool)
	// ForAllConnectionsDo execute the callback for each connection in connection map.
	ForAllConnectionsDo(callback flowexporter.ConnectionMapCallBack) error
	// DeleteConnectionByKey deletes the connection in connection map given the
	// connection key. This function is called from Flow Exporter once the connection
	// is deleted from conntrack module.
	DeleteConnectionByKey(connKey flowexporter.ConnectionKey) error
}

type connectionStore struct {
	connections          map[flowexporter.ConnectionKey]flowexporter.Connection
	flowRecords          *flowrecords.FlowRecords
	connDumper           ConnTrackDumper
	ifaceStore           interfacestore.InterfaceStore
	v4Enabled            bool
	v6Enabled            bool
	antreaProxier        proxy.Provider
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
	proxier proxy.Provider,
	npQuerier querier.AgentNetworkPolicyInfoQuerier,
	pollInterval time.Duration,
) *connectionStore {
	return &connectionStore{
		connections:          make(map[flowexporter.ConnectionKey]flowexporter.Connection),
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
		existingConn.IsPresent = true
		// Reassign the flow to update the map
		cs.connections[connKey] = *existingConn
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
		cs.connections[connKey] = *conn
	}
}

// GetConnByKey gets the connection in connection map given the connection key.
func (cs *connectionStore) GetConnByKey(flowTuple flowexporter.ConnectionKey) (*flowexporter.Connection, bool) {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	conn, found := cs.connections[flowTuple]
	return &conn, found
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
	// Reset isActive flag for all connections in connection map before dumping flows in conntrack module.
	// This is to specify that the connection and the flow record can be deleted after the next export.
	resetConn := func(key flowexporter.ConnectionKey, conn flowexporter.Connection) error {
		conn.IsPresent = false
		cs.connections[key] = conn
		return nil
	}
	// We do not expect any error as resetConn is not returning any error
	cs.ForAllConnectionsDo(resetConn)

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

// DeleteConnectionByKey deletes the connection in connection map given the connection key.
func (cs *connectionStore) DeleteConnectionByKey(connKey flowexporter.ConnectionKey) error {
	_, exists := cs.GetConnByKey(connKey)
	if !exists {
		return fmt.Errorf("connection with key %v doesn't exist in map", connKey)
	}
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
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
