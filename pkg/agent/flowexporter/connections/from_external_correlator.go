// Copyright 2026 Antrea Authors
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
	"sync"
	"time"

	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
	"antrea.io/antrea/pkg/agent/proxy"
)

// ttl threshold for expiring connections in the fromExternalCorrelator.
var ttl = time.Minute

// cleanUpInterval is the frequency in which we run the cleanup for expiring stale connections.
var cleanUpInterval = time.Second * 5

// FromExternalCorrelator handles correlating FromExternal connections
type fromExternalCorrelator struct {
	connections map[string]connectionItem
	stopCh      <-chan struct{}
	lock        sync.RWMutex
}

// connectionItem wraps a zone zero connection along with it's timestamp use for expiring connections.
type connectionItem struct {
	conn      *connection.Connection
	timestamp time.Time
}

// newFromExternalCorrelator returns an instance of the FromExternalCorrelator with it's internal map intialized and
// a go routine initiated to remove stale connections based on `ttl` at `cleanUpInterval`.
func newFromExternalCorrelator() *fromExternalCorrelator {
	stopCh := make(chan struct{})
	store := fromExternalCorrelator{
		connections: map[string]connectionItem{},
		stopCh:      stopCh,
	}
	go store.cleanUpLoop(stopCh, cleanUpInterval, ttl)
	return &store
}

// filterAndStoreExternalSource filters for connections that have external source information so correlation can be
// done on FromExternal flows. Returns true if the connection was zone zero.
func (c *fromExternalCorrelator) filterAndStoreExternalSource(conn *connection.Connection, antreaProxier proxy.ProxyQuerier) bool {
	if conn == nil {
		return false
	}

	if conn.Zone != 0 {
		return false
	}

	clusterIP := conn.OriginalDestinationAddress.String()
	svcPort := conn.OriginalDestinationPort
	protocol, err := lookupServiceProtocol(conn.FlowKey.Protocol)
	if err != nil {
		klog.InfoS("Could not retrieve Service protocol", "error", err, "conn", conn)
		return true
	}
	// When AntreaProxy is available, the store can selectively store zone zero connections with associated services
	if antreaProxier != nil {
		serviceStr := fmt.Sprintf("%s:%d/%s", clusterIP, svcPort, protocol)
		_, exists := antreaProxier.GetServiceByIP(serviceStr)
		if !exists {
			return true
		}
	}
	c.add(conn)
	return true
}

// correlateIfExternal correlates the connection to it's zone zero counterpart to preserve the SNAT'd source IP
func (c *fromExternalCorrelator) correlateIfExternal(conn *connection.Connection) {
	if conn == nil {
		return
	}

	zoneZero := c.popMatching(conn)
	if zoneZero != nil {
		CorrelateExternal(zoneZero, conn)
	}
}

// cleanUpLoop runs in an infinite loop and cleans up the store at the given interval.
func (c *fromExternalCorrelator) cleanUpLoop(stopCh <-chan struct{}, interval, ttl time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			c.cleanup(ttl)
		}
	}
}

// cleanup loops through the entire store and deleting connections that exceed the ttl.
func (c *fromExternalCorrelator) cleanup(ttl time.Duration) {
	c.lock.Lock()
	defer c.lock.Unlock()
	now := time.Now()
	for key, record := range c.connections {
		if now.Sub(record.timestamp) > ttl {
			delete(c.connections, key)
		}
	}
}

// Given a conn, generate a key that is unique to this connection
// but can also be derived for the matching antrea ct_zone record.
func (c *fromExternalCorrelator) generateKey(conn *connection.Connection) string {
	destinationAddress := conn.FlowKey.DestinationAddress.String()
	replyDestinationPort := strconv.FormatUint(uint64(conn.ProxySnatPort), 10)
	return fmt.Sprintf("%s-%s", destinationAddress, replyDestinationPort)
}

// add the given zone zero connection to the store.
func (c *fromExternalCorrelator) add(conn *connection.Connection) {
	c.lock.Lock()
	defer c.lock.Unlock()
	key := c.generateKey(conn)
	c.connections[key] = connectionItem{
		conn:      conn,
		timestamp: time.Now(),
	}
}

// Given an antrea zone connection, generate a key that will equal the corresponding zone zero connection.
func (c *fromExternalCorrelator) generateKeyFromAntreaZone(conn *connection.Connection) string {
	destinationAddress := conn.FlowKey.DestinationAddress.String()
	zoneZeroReplyDestinationPort := strconv.FormatUint(uint64(conn.FlowKey.SourcePort), 10)
	return fmt.Sprintf("%s-%s", destinationAddress, zoneZeroReplyDestinationPort)
}

// Given an antrea ct zone connection, if there is a corresponding zone zero connection remove it from the store and
// return it. Otherwise return nil.
func (c *fromExternalCorrelator) popMatching(conn *connection.Connection) *connection.Connection {
	c.lock.Lock()
	defer c.lock.Unlock()
	key := c.generateKeyFromAntreaZone(conn)
	record, exists := c.connections[key]
	if !exists {
		return nil
	}
	delete(c.connections, key)
	return record.conn
}

// Given a connection key, remove it from the store. Log an error
// if it didn't exist in the store.
func (c *fromExternalCorrelator) remove(conn *connection.Connection) {
	c.lock.Lock()
	defer c.lock.Unlock()
	destinationAddress := conn.FlowKey.DestinationAddress
	zoneZeroReplyDestinationPort := strconv.FormatUint(uint64(conn.ProxySnatPort), 10)

	key := fmt.Sprintf("%s-%s", destinationAddress, zoneZeroReplyDestinationPort)
	delete(c.connections, key)
}
