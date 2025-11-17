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
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/vmware/go-ipfix/pkg/registry"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	"antrea.io/antrea/pkg/agent/flowexporter/priorityqueue"
	"antrea.io/antrea/pkg/agent/flowexporter/utils"
	"antrea.io/antrea/pkg/agent/proxy"
	"antrea.io/antrea/pkg/querier"
	"antrea.io/antrea/pkg/util/objectstore"
)

const (
	periodicDeleteInterval = time.Minute
)

type ConnectionStoreConfig struct {
	ActiveFlowTimeout      time.Duration
	IdleFlowTimeout        time.Duration
	StaleConnectionTimeout time.Duration

	AllowedProtocols []string
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

func (cs *connectionStore) addNetworkPolicyMetadata(conn *connection.Connection) {
	// Retrieve NetworkPolicy Name and Namespace by using the ingress and egress
	// IDs stored in the connection label.
	if len(conn.Labels) != 0 {
		if klog.V(4).Enabled() {
			klog.InfoS("Setting NetworkPolicy metadata from connection labels", "labels", hex.EncodeToString(conn.Labels))
		}
		ingressOfID := binary.BigEndian.Uint32(conn.Labels[12:16])
		egressOfID := binary.BigEndian.Uint32(conn.Labels[8:12])
		if ingressOfID != 0 {
			rule := cs.networkPolicyQuerier.GetRuleByFlowID(ingressOfID)
			if rule == nil {
				// This should not happen because the rule flow ID to rule mapping
				// is meant to be preserved for long enough (based on the poll
				// interval), even after the rule deletion.
				klog.InfoS("Cannot find ingress NetworkPolicy rule", "flowID", ingressOfID)
			} else if rule.PolicyRef == nil {
				// This should never be possible.
				klog.ErrorS(nil, "Found ingress NetworkPolicy rule with nil PolicyRef", "flowID", ingressOfID)
			} else {
				policy := rule.PolicyRef
				conn.IngressNetworkPolicyName = policy.Name
				conn.IngressNetworkPolicyNamespace = policy.Namespace
				conn.IngressNetworkPolicyUID = string(policy.UID)
				conn.IngressNetworkPolicyType = utils.PolicyTypeToUint8(policy.Type)
				conn.IngressNetworkPolicyRuleName = rule.Name
				conn.IngressNetworkPolicyRuleAction = registry.NetworkPolicyRuleActionAllow
				if klog.V(4).Enabled() {
					klog.InfoS("Found ingress NetworkPolicy rule", "flowID", ingressOfID, "policy", klog.KRef(policy.Namespace, policy.Name), "ruleName", rule.Name)
				}
			}
		}
		if egressOfID != 0 {
			rule := cs.networkPolicyQuerier.GetRuleByFlowID(egressOfID)
			if rule == nil {
				// This should not happen because the rule flow ID to rule mapping
				// is meant to be preserved for long enough (based on the poll
				// interval), even after the rule deletion.
				klog.InfoS("Cannot find egress NetworkPolicy rule", "flowID", egressOfID)
			} else if rule.PolicyRef == nil {
				// This should never be possible.
				klog.ErrorS(nil, "Found egress NetworkPolicy rule with nil PolicyRef", "flowID", egressOfID)
			} else {
				policy := rule.PolicyRef
				conn.EgressNetworkPolicyName = policy.Name
				conn.EgressNetworkPolicyNamespace = policy.Namespace
				conn.EgressNetworkPolicyUID = string(policy.UID)
				conn.EgressNetworkPolicyType = utils.PolicyTypeToUint8(policy.Type)
				conn.EgressNetworkPolicyRuleName = rule.Name
				conn.EgressNetworkPolicyRuleAction = registry.NetworkPolicyRuleActionAllow
				if klog.V(4).Enabled() {
					klog.InfoS("Found egress NetworkPolicy rule", "flowID", egressOfID, "policy", klog.KRef(policy.Namespace, policy.Name), "ruleName", rule.Name)
				}
			}
		}
	}
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
	conn.AppProtocolName = ""
	conn.HttpVals = ""
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
