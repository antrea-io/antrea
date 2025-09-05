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
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	"antrea.io/antrea/pkg/agent/flowexporter/options"
	"antrea.io/antrea/pkg/agent/flowexporter/priorityqueue"
	"antrea.io/antrea/pkg/agent/flowexporter/utils"
	"antrea.io/antrea/pkg/agent/metrics"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/proxy"
	"antrea.io/antrea/pkg/querier"
	"antrea.io/antrea/pkg/util/objectstore"
	utilwait "antrea.io/antrea/pkg/util/wait"
)

var serviceProtocolMap = map[uint8]corev1.Protocol{
	6:   corev1.ProtocolTCP,
	17:  corev1.ProtocolUDP,
	132: corev1.ProtocolSCTP,
}

type ConntrackConnectionStore struct {
	connDumper            ConnTrackDumper
	v4Enabled             bool
	v6Enabled             bool
	pollInterval          time.Duration
	connectUplinkToBridge bool
	// networkPolicyWait is used to determine when NetworkPolicy flows have been installed and
	// when the mapping from flow ID to NetworkPolicy rule is available. We will ignore
	// connections which started prior to that time to avoid reporting invalid NetworkPolicy
	// metadata in flow records. This is because the mapping is not "stable" and is expected to
	// change when the Agent restarts.
	networkPolicyWait *utilwait.Group
	// networkPolicyReadyTime is set to the current time when we are done waiting on networkPolicyWait.
	networkPolicyReadyTime time.Time
	connectionStore
	zoneZeroCache ZoneZeroCache
}

func NewConntrackConnectionStore(
	connTrackDumper ConnTrackDumper,
	v4Enabled bool,
	v6Enabled bool,
	npQuerier querier.AgentNetworkPolicyInfoQuerier,
	podStore objectstore.PodStore,
	proxier proxy.ProxyQuerier,
	networkPolicyWait *utilwait.Group,
	o *options.FlowExporterOptions,
) *ConntrackConnectionStore {
	return &ConntrackConnectionStore{
		connDumper:            connTrackDumper,
		v4Enabled:             v4Enabled,
		v6Enabled:             v6Enabled,
		pollInterval:          o.PollInterval,
		connectionStore:       NewConnectionStore(npQuerier, podStore, proxier, o),
		connectUplinkToBridge: o.ConnectUplinkToBridge,
		networkPolicyWait:     networkPolicyWait,
		zoneZeroCache:         NewZoneZeroCache(),
	}
}

// Run enables the periodical polling of conntrack connections at a given flowPollInterval.
func (cs *ConntrackConnectionStore) Run(stopCh <-chan struct{}) {
	if cs.networkPolicyWait != nil {
		klog.Info("Waiting for NetworkPolicies to become ready")
		if err := cs.networkPolicyWait.WaitUntil(stopCh); err != nil {
			klog.ErrorS(err, "Error while waiting for NetworkPolicies to become ready")
			return
		}
	} else {
		klog.Info("Skip waiting for NetworkPolicies to become ready")
	}
	cs.networkPolicyReadyTime = time.Now()

	klog.Info("Starting conntrack polling")

	pollTicker := time.NewTicker(cs.pollInterval)
	defer pollTicker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-pollTicker.C:
			if _, err := cs.Poll(); err != nil {
				// Not failing here as errors can be transient and could be resolved in future poll cycles.
				// TODO: Come up with a backoff/retry mechanism by increasing poll interval and adding retry timeout
				klog.ErrorS(err, "Error during conntrack poll cycle")
			}
		}
	}
}

// Poll calls into conntrackDumper interface to dump conntrack flows. It returns the number of connections for each
// address family, as a slice. In dual-stack clusters, the slice will contain 2 values (number of IPv4 connections first,
// then number of IPv6 connections).
// TODO: As optimization, only poll invalid/closed connections during every poll, and poll the established connections right before the export.
func (cs *ConntrackConnectionStore) Poll() ([]int, error) {
	klog.V(2).Info("Polling conntrack and updating connection store")
	startTime := time.Now()
	defer func() {
		duration := time.Since(startTime)
		metrics.ConntrackPollCycleDuration.Observe(duration.Seconds())
		klog.V(2).InfoS("Polled conntrack and updated connection store", "duration", duration)
	}()

	var connsLens []int
	var totalConns int
	var filteredConnsList []*connection.Connection
	zones := cs.getZones()
	for _, zone := range zones {
		filteredConnsListPerZone, totalConnsPerZone, err := cs.connDumper.DumpFlows(zone)
		if err != nil {
			return []int{}, err
		}
		totalConns += totalConnsPerZone
		filteredConnsList = append(filteredConnsList, filteredConnsListPerZone...)
		connsLens = append(connsLens, len(filteredConnsList))
	}

	// Reset IsPresent flag for all connections in connection map before updating
	// the dumped flows information in connection map. If the connection does not
	// exist in conntrack table and has been exported, then we will delete it from
	// connection map. In addition, if the connection was not exported for a specific
	// time period, then we consider it to be stale and delete it.
	deleteIfStaleOrResetConn := func(key connection.ConnectionKey, conn *connection.Connection) error {
		if !conn.IsPresent {
			// Delete the connection if it is ready to delete or it was not exported
			// in the time period as specified by the stale connection timeout.
			if conn.ReadyToDelete || time.Since(conn.LastExportTime) >= cs.staleConnectionTimeout {
				if removedItem := cs.expirePriorityQueue.Remove(key); removedItem != nil {
					// In case ReadyToDelete is true, item should already have been removed from pq
					klog.V(4).InfoS("Conn removed from cs pq due to stale timeout",
						"key", key, "conn", removedItem.Conn)
				}
				if err := cs.deleteConnWithoutLock(key); err != nil {
					return err
				}
				cs.zoneZeroCache.Delete(conn)
			}
		} else {
			conn.IsPresent = false
		}
		return nil
	}

	// Hold the lock until we verify whether the connection exist in conntrack table,
	// and finish updating the connection store.
	cs.AcquireConnStoreLock()

	if err := cs.ForAllConnectionsDoWithoutLock(deleteIfStaleOrResetConn); err != nil {
		cs.ReleaseConnStoreLock()
		return []int{}, err
	}

	// Update only the Connection store. IPFIX records are generated based on Connection store.
	for _, conn := range filteredConnsList {
		cs.AddOrUpdateConn(conn)
	}

	cs.ReleaseConnStoreLock()

	metrics.TotalConnectionsInConnTrackTable.Set(float64(totalConns))
	maxConns, err := cs.connDumper.GetMaxConnections()
	if err != nil {
		return []int{}, err
	}
	metrics.MaxConnectionsInConnTrackTable.Set(float64(maxConns))
	klog.V(2).Infof("Conntrack polling successful")

	return connsLens, nil
}

// AddOrUpdateConn updates the connection if it is already present, i.e., update timestamp, counters etc.,
// or adds a new connection with the resolved K8s metadata.
func (cs *ConntrackConnectionStore) AddOrUpdateConn(conn *connection.Connection) {
	conn.IsPresent = true

	if conn.Zone == 0 {
		cs.zoneZeroCache.Add(conn)
		return
	}

	if zoneZero := cs.zoneZeroCache.GetMatching(conn); zoneZero != nil {
		CorrelateExternal(zoneZero, conn)
	}

	connKey := connection.NewConnectionKey(conn)

	existingConn, exists := cs.connections[connKey]
	if exists {
		existingConn.IsPresent = conn.IsPresent
		if utils.IsConnectionDying(existingConn) {
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
		existingConn.IsActive = utils.CheckConntrackConnActive(existingConn)
		if existingConn.IsActive {
			existingItem, exists := cs.expirePriorityQueue.KeyToItem[connKey]
			if !exists {
				// If the connKey:pqItem pair does not exist in the map, it shows the
				// conn was inactive, and was removed from PQ and map. Since it becomes
				// active again now, we create a new pqItem and add it to PQ and map.
				cs.expirePriorityQueue.WriteItemToQueue(connKey, existingConn)
			} else {
				cs.connectionStore.expirePriorityQueue.Update(existingItem, existingItem.ActiveExpireTime,
					time.Now().Add(cs.connectionStore.expirePriorityQueue.IdleFlowTimeout))
			}
		}
		klog.V(4).InfoS("Antrea flow updated", "connection", existingConn)
	} else {
		cs.fillPodInfo(conn)
		if conn.Mark&openflow.ServiceCTMark.GetRange().ToNXRange().ToUint32Mask() == openflow.ServiceCTMark.GetValue() {
			clusterIP := conn.OriginalDestinationAddress.String()
			svcPort := conn.OriginalDestinationPort
			protocol, err := lookupServiceProtocol(conn.FlowKey.Protocol)
			if err != nil {
				klog.InfoS("Could not retrieve Service protocol", "error", err)
			} else {
				serviceStr := fmt.Sprintf("%s:%d/%s", clusterIP, svcPort, protocol)
				cs.fillServiceInfo(conn, serviceStr)
			}
		}
		// This should only happen if we failed to set net.netfilter.nf_conntrack_timestamp
		if conn.StartTime.IsZero() {
			conn.StartTime = time.Now()
			conn.StopTime = time.Now()
		}
		if conn.StartTime.Before(cs.networkPolicyReadyTime) {
			klog.V(1).InfoS("Skip adding NetworkPolicy metadata to connection to avoid reporting invalid information")
		} else {
			cs.addNetworkPolicyMetadata(conn)
		}
		conn.LastExportTime = conn.StartTime
		metrics.TotalAntreaConnectionsInConnTrackTable.Inc()
		conn.IsActive = true
		// Add new antrea connection to connection store and PQ.
		cs.connections[connKey] = conn
		cs.expirePriorityQueue.WriteItemToQueue(connKey, conn)
		klog.V(4).InfoS("New Antrea flow added", "connection", conn)
	}
}

func (cs *ConntrackConnectionStore) GetExpiredConns(expiredConns []connection.Connection, currTime time.Time, maxSize int) ([]connection.Connection, time.Duration) {
	cs.AcquireConnStoreLock()
	defer cs.ReleaseConnStoreLock()
	for i := 0; i < maxSize; i++ {
		pqItem := cs.connectionStore.expirePriorityQueue.GetTopExpiredItem(currTime)
		if pqItem == nil {
			break
		}
		expiredConns = append(expiredConns, *pqItem.Conn)
		if utils.IsConnectionDying(pqItem.Conn) {
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
func (cs *ConntrackConnectionStore) deleteConnWithoutLock(connKey connection.ConnectionKey) error {
	_, exists := cs.connections[connKey]
	if !exists {
		return fmt.Errorf("connection with key %v doesn't exist in map", connKey)
	}
	delete(cs.connections, connKey)
	metrics.TotalAntreaConnectionsInConnTrackTable.Dec()
	return nil
}

func (cs *ConntrackConnectionStore) DeleteAllConnections() int {
	cs.AcquireConnStoreLock()
	defer cs.ReleaseConnStoreLock()
	num := len(cs.connections)
	clear(cs.connections)
	return num
}

func (cs *ConntrackConnectionStore) GetPriorityQueue() *priorityqueue.ExpirePriorityQueue {
	return cs.connectionStore.expirePriorityQueue
}

func (cs *ConntrackConnectionStore) getZones() []uint16 {
	var zones []uint16
	zones = append(zones, 0)
	if cs.v4Enabled {
		if cs.connectUplinkToBridge {
			zones = append(zones, uint16(openflow.IPCtZoneTypeRegMark.GetValue()<<12))
		} else {
			zones = append(zones, openflow.CtZone)
		}
	}
	if cs.v6Enabled {
		if cs.connectUplinkToBridge {
			zones = append(zones, uint16(openflow.IPv6CtZoneTypeRegMark.GetValue()<<12))
		} else {
			zones = append(zones, openflow.CtZoneV6)
		}
	}
	return zones
}

func NewZoneZeroCache() ZoneZeroCache {
	return ZoneZeroCache{
		cache: map[string]*connection.Connection{},
	}
}

// A cache holding zone zero connections for correlating the zone zero and antrea flows that make up an external flow.
type ZoneZeroCache struct {
	cache map[string]*connection.Connection
}

// Given a conn, generate a key that is unique to this connection
// but can also be derived for the matching antrea ct_zone record.
func (c ZoneZeroCache) generateKey(conn *connection.Connection) string {
	destinationAddress := conn.FlowKey.DestinationAddress.String()
	replyDestinationPort := strconv.FormatUint(uint64(conn.ProxySnatPort), 10)
	return fmt.Sprintf("%s-%s", destinationAddress, replyDestinationPort)
}

// Add the given zone zero connection to the cache.
func (c ZoneZeroCache) Add(conn *connection.Connection) error {
	if conn.Zone != 0 {
		return fmt.Errorf("Cannot add connections to cache that are not zone zero. Connection has zone %v", conn.Zone)
	}
	key := c.generateKey(conn)
	c.cache[key] = conn
	return nil
}

// Return true if the given connection is in the cache.
func (c ZoneZeroCache) Contains(conn *connection.Connection) bool {
	key := c.generateKey(conn)
	_, ok := c.cache[key]
	return ok
}

// Given an antrea zone connection, generate a key that will equal the corresponding zone zero connection.
func (c ZoneZeroCache) generateKeyFromAntreaZone(conn *connection.Connection) string {
	destinationAddress := conn.FlowKey.DestinationAddress.String()
	zoneZeroReplyDestinationPort := strconv.FormatUint(uint64(conn.FlowKey.SourcePort), 10)
	return fmt.Sprintf("%s-%s", destinationAddress, zoneZeroReplyDestinationPort)
}

// Given an antrea ct zone connection, if there is a corresponding zone zero connection, return it. Otherwise return nil.
func (c ZoneZeroCache) GetMatching(conn *connection.Connection) *connection.Connection {
	key := c.generateKeyFromAntreaZone(conn)
	if match, ok := c.cache[key]; ok {
		return match
	}
	return nil
}

// Given a pair of matching connections, modify the antreaZone connection by
// filling in the fields needed from the zoneZero connection
func CorrelateExternal(zoneZero, antreaZone *connection.Connection) {
	antreaZone.FlowKey.SourcePort = zoneZero.FlowKey.SourcePort
	antreaZone.FlowKey.SourceAddress = zoneZero.FlowKey.SourceAddress
	antreaZone.ProxySnatIP = zoneZero.ProxySnatIP
	antreaZone.ProxySnatPort = zoneZero.ProxySnatPort
	antreaZone.OriginalDestinationAddress = zoneZero.OriginalDestinationAddress
}

// Given a connection key, delete it from the cache. Log an error
// if it didn't exist in the cache
func (c ZoneZeroCache) Delete(conn *connection.Connection) {
	destinationAddress := conn.FlowKey.DestinationAddress
	zoneZeroReplyDestinationPort := strconv.FormatUint(uint64(conn.ProxySnatPort), 10)

	key := fmt.Sprintf("%s-%s", destinationAddress, zoneZeroReplyDestinationPort)
	if _, ok := c.cache[key]; !ok {
		klog.V(5).InfoS("Delete connection from ZoneZeroCache failed. Did not exist.", "conn", conn)
	}
	delete(c.cache, key)
}
