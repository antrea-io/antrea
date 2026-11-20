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
	"net/netip"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"

	"antrea.io/antrea/v2/pkg/agent/flowexporter/connection"
	"antrea.io/antrea/v2/pkg/agent/flowexporter/priorityqueue"
	"antrea.io/antrea/v2/pkg/agent/flowexporter/utils"
	"antrea.io/antrea/v2/pkg/agent/proxy"
	"antrea.io/antrea/v2/pkg/agent/types"
	"antrea.io/antrea/v2/pkg/querier"
	"antrea.io/antrea/v2/pkg/util/objectstore"
)

const (
	periodicDeleteInterval = time.Minute
)

type ConnectionStoreConfig struct {
	ActiveFlowTimeout      time.Duration
	IdleFlowTimeout        time.Duration
	StaleConnectionTimeout time.Duration

	NetworkPolicyReadyTime time.Time
	AllowedProtocols       []string

	// RemotePodQuerier is used by the conntrack connection store to identify the Pods running on
	// other Nodes, so that it keeps the connections initiated by the host network stack of this
	// Node towards them (these connections are identified by the FromExternalCorrelator). It may
	// be nil, in which case these connections are ignored.
	RemotePodQuerier RemotePodQuerier
}

// RemotePodQuerier identifies the Pods running on other Nodes, towards which this Node reports the
// connections initiated by its host network, or by external clients that it forwards.
type RemotePodQuerier interface {
	// IsRemotePodIP returns whether ip is the IP of a Pod running on another Node which receives
	// the connections initiated by the host network of this Node with the gateway IP of this Node
	// as the source address, i.e., when the traffic to that Node is tunneled, or encrypted with
	// WireGuard. That Node then exports such a connection, with the same 5-tuple as this Node
	// after any SNAT applied by this Node, as an Inter-Node flow, which the FlowAggregator
	// correlates with the record exported by this Node. It returns false for the gateway IP of
	// another Node.
	IsRemotePodIP(ip netip.Addr) bool
	// IsRemotePodIPRoutedByHost returns whether ip is the IP of a Pod running on another Node, to
	// which the host network of this Node routes its traffic without going through OVS, i.e.,
	// through the uplink (noEncap mode, and hybrid mode for Nodes in the same subnet) or through
	// antrea-wg0 (WireGuard). It returns false for the gateway IP of another Node.
	IsRemotePodIPRoutedByHost(ip netip.Addr) bool
	// IsPodSubnetIP returns whether ip belongs to the Pod subnet of any Node, including this Node.
	IsPodSubnetIP(ip netip.Addr) bool
}

type connectionStore struct {
	connections            map[connection.ConnectionKey]*connection.Connection
	networkPolicyQuerier   querier.AgentNetworkPolicyInfoQuerier
	podStore               objectstore.PodStore
	antreaProxier          proxy.ProxyQuerier
	expirePriorityQueue    *priorityqueue.ExpirePriorityQueue
	staleConnectionTimeout time.Duration
	mutex                  sync.Mutex
}

func NewConnectionStore(
	npQuerier querier.AgentNetworkPolicyInfoQuerier,
	podStore objectstore.PodStore,
	proxier proxy.ProxyQuerier,
	cfg ConnectionStoreConfig) connectionStore {
	return connectionStore{
		connections:            make(map[connection.ConnectionKey]*connection.Connection),
		networkPolicyQuerier:   npQuerier,
		podStore:               podStore,
		antreaProxier:          proxier,
		expirePriorityQueue:    priorityqueue.NewExpirePriorityQueue(cfg.ActiveFlowTimeout, cfg.IdleFlowTimeout),
		staleConnectionTimeout: cfg.StaleConnectionTimeout,
	}
}

// GetConnByKey gets the connection in connection map given the connection key.
func (cs *connectionStore) GetConnByKey(connKey connection.ConnectionKey) (*connection.Connection, bool) {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	conn, found := cs.connections[connKey]
	return conn, found
}

func (cs *connectionStore) NumConnections() int {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	return len(cs.connections)
}

// ForAllConnectionsDo execute the callback for each connection in connection map.
func (cs *connectionStore) ForAllConnectionsDo(callback connection.ConnectionMapCallBack) error {
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
func (cs *connectionStore) ForAllConnectionsDoWithoutLock(callback connection.ConnectionMapCallBack) error {
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
func (cs *connectionStore) AddConnToMap(connKey *connection.ConnectionKey, conn *connection.Connection) {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	cs.connections[*connKey] = conn
}

func (cs *connectionStore) fillPodInfo(conn *connection.Connection) {
	if cs.podStore == nil {
		klog.V(4).Info("Pod store is not available to retrieve local Pods information.")
		return
	}
	// sourceIP/destinationIP are mapped only to local pods and not remote pods.
	srcIP := conn.FlowKey.SourceAddress.String()
	dstIP := conn.FlowKey.DestinationAddress.String()

	srcPod, srcFound := cs.podStore.GetPodByIPAndTime(srcIP, conn.StartTime)
	dstPod, dstFound := cs.podStore.GetPodByIPAndTime(dstIP, conn.StartTime)
	if srcFound {
		conn.SourcePodName = srcPod.Name
		conn.SourcePodNamespace = srcPod.Namespace
		conn.SourcePodUID = string(srcPod.UID)
	}
	if dstFound {
		conn.DestinationPodName = dstPod.Name
		conn.DestinationPodNamespace = dstPod.Namespace
		conn.DestinationPodUID = string(dstPod.UID)
	}
}

func (cs *connectionStore) fillServiceInfo(conn *connection.Connection, serviceStr string) {
	// resolve destination Service information
	if cs.antreaProxier != nil {
		servicePortName, exists := cs.antreaProxier.GetServiceByIP(serviceStr)
		if exists {
			conn.DestinationServicePortName = servicePortName.String()
		} else {
			klog.InfoS("Could not retrieve the Service info from antrea-agent-proxier", "serviceStr", serviceStr)
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

func (cs *connectionStore) getPolicyRuleMetadata(conn *connection.Connection, ruleID uint32, labelsStart, labelsEnd int) (*types.PolicyRule, uint8, bool) {
	var rule *types.PolicyRule
	var disposition uint8

	if ruleID != 0 {
		// deny connections have their ruleIDs set
		rule = cs.networkPolicyQuerier.GetRuleByFlowID(ruleID)
		disposition = utils.RuleActionToUint8(conn.Disposition)
	} else if len(conn.Labels) >= labelsEnd {
		// allow connections have their flowIDs set in the labels
		flowID := binary.BigEndian.Uint32(conn.Labels[labelsStart:labelsEnd])
		if flowID != 0 {
			rule = cs.networkPolicyQuerier.GetRuleByFlowID(flowID)
			disposition = utils.NetworkPolicyRuleActionAllow
		}
	} else {
		klog.V(4).InfoS("Failed to lookup policy rule for connection", "connectionLabels", conn.Labels)
	}

	if rule == nil {
		klog.V(4).InfoS("Cannot find NetworkPolicy rule", "ruleID", ruleID)
		return nil, 0, false
	}
	if rule.PolicyRef == nil {
		klog.V(4).InfoS("Found NetworkPolicy rule with nil PolicyRef", "ruleID", ruleID)
		return nil, 0, false
	}

	if klog.V(4).Enabled() {
		klog.InfoS("Found NetworkPolicy rule", "ruleID", ruleID, "policy", klog.KRef(rule.PolicyRef.Namespace, rule.PolicyRef.Name), "ruleName", rule.Name)
	}

	return rule, disposition, true
}
func (cs *connectionStore) addIngressNetworkPolicyMetadata(conn *connection.Connection) {
	rule, disposition, ok := cs.getPolicyRuleMetadata(conn, conn.IngressRuleID, 12, 16)
	if !ok {
		return
	}

	policy := rule.PolicyRef
	conn.IngressNetworkPolicyName = policy.Name
	conn.IngressNetworkPolicyNamespace = policy.Namespace
	conn.IngressNetworkPolicyUID = string(policy.UID)
	conn.IngressNetworkPolicyType = utils.PolicyTypeToUint8(policy.Type)
	conn.IngressNetworkPolicyRuleName = rule.Name
	conn.IngressNetworkPolicyRuleAction = disposition
}

func (cs *connectionStore) addEgressNetworkPolicyMetadata(conn *connection.Connection) {
	rule, disposition, ok := cs.getPolicyRuleMetadata(conn, conn.EgressRuleID, 8, 12)
	if !ok {
		return
	}

	policy := rule.PolicyRef
	conn.EgressNetworkPolicyName = policy.Name
	conn.EgressNetworkPolicyNamespace = policy.Namespace
	conn.EgressNetworkPolicyUID = string(policy.UID)
	conn.EgressNetworkPolicyType = utils.PolicyTypeToUint8(policy.Type)
	conn.EgressNetworkPolicyRuleName = rule.Name
	conn.EgressNetworkPolicyRuleAction = disposition
}

func (cs *connectionStore) addNetworkPolicyMetadata(conn *connection.Connection) {
	cs.addIngressNetworkPolicyMetadata(conn)
	cs.addEgressNetworkPolicyMetadata(conn)
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
// updates active connection's stats fields and adds it back to the PQ. Layer 7
// fields should be set to default to prevent from re-exporting same values.
func (cs *connectionStore) UpdateConnAndQueue(pqItem *priorityqueue.ItemToExpire, currTime time.Time) {
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
