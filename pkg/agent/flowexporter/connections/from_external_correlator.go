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

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
)

// ttl threshold for expiring connections in the zoneZeroStore.
var ttl = time.Minute

// cleanUpInterval is the frequency in which we run the cleanup for expiring stale connections.
var cleanUpInterval = time.Second * 5

// FromExternalCorrelator handles correlating FromExternal connections
type zoneZeroStore struct {
	connections map[string]zoneZeroItem
	stopCh      <-chan struct{}
	lock        sync.RWMutex
}

// zoneZeroItem wraps a zone zero connection along with it's timestamp use for expiring connections.
type zoneZeroItem struct {
	conn      *connection.Connection
	timestamp time.Time
}

// newFromExternalCorrelator returns an instance of the FromExternalCorrelator with it's internal map intialized and
// a go routine initiated to remove stale connections based on `ttl` at `cleanUpInterval`.
func newFromExternalCorrelator() *zoneZeroStore {
	stopCh := make(chan struct{})
	store := zoneZeroStore{
		connections: map[string]zoneZeroItem{},
		stopCh:      stopCh,
	}
	go store.cleanUpLoop(stopCh, cleanUpInterval, ttl)
	return &store
}

// cleanUpLoop runs in an infinite loop and cleans up the store at the given interval.
func (c *zoneZeroStore) cleanUpLoop(stopCh <-chan struct{}, interval, ttl time.Duration) {
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
func (c *zoneZeroStore) cleanup(ttl time.Duration) {
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
func (c *zoneZeroStore) generateKey(conn *connection.Connection) string {
	destinationAddress := conn.FlowKey.DestinationAddress.String()
	replyDestinationPort := strconv.FormatUint(uint64(conn.ProxySnatPort), 10)
	return fmt.Sprintf("%s-%s", destinationAddress, replyDestinationPort)
}

// add the given zone zero connection to the store.
func (c *zoneZeroStore) add(conn *connection.Connection) error {
	c.lock.Lock()
	defer c.lock.Unlock()
	if conn.Zone != 0 {
		return fmt.Errorf("Cannot add connections to store that are not zone zero. Connection has zone %v", conn.Zone)
	}
	key := c.generateKey(conn)
	c.connections[key] = zoneZeroItem{
		conn:      conn,
		timestamp: time.Now(),
	}
	return nil
}

// Given an antrea zone connection, generate a key that will equal the corresponding zone zero connection.
func (c *zoneZeroStore) generateKeyFromAntreaZone(conn *connection.Connection) string {
	destinationAddress := conn.FlowKey.DestinationAddress.String()
	zoneZeroReplyDestinationPort := strconv.FormatUint(uint64(conn.FlowKey.SourcePort), 10)
	return fmt.Sprintf("%s-%s", destinationAddress, zoneZeroReplyDestinationPort)
}

// Given an antrea ct zone connection, if there is a corresponding zone zero connection remove it from the store and
// return it. Otherwise return nil.
func (c *zoneZeroStore) popMatching(conn *connection.Connection) *connection.Connection {
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
func (c *zoneZeroStore) remove(conn *connection.Connection) {
	c.lock.Lock()
	defer c.lock.Unlock()
	destinationAddress := conn.FlowKey.DestinationAddress
	zoneZeroReplyDestinationPort := strconv.FormatUint(uint64(conn.ProxySnatPort), 10)

	key := fmt.Sprintf("%s-%s", destinationAddress, zoneZeroReplyDestinationPort)
	delete(c.connections, key)
}
