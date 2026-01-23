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
	"time"

	"antrea.io/antrea/pkg/agent/flowexporter/connection"
)

// A cache holding zone zero connections for correlating the zone zero and antrea flows that make up an external flow.
type zoneZeroCache struct {
	cache  map[string]zoneZeroRecord
	stopCh <-chan struct{}
}

type zoneZeroRecord struct {
	conn      *connection.Connection
	timestamp time.Time
}

func newZoneZeroCache() *zoneZeroCache {
	stopCh := make(chan struct{})
	cache := zoneZeroCache{
		cache:  map[string]zoneZeroRecord{},
		stopCh: stopCh,
	}
	go cache.CleanupLoop(stopCh, 5*time.Second, time.Minute)
	return &cache
}

func (c *zoneZeroCache) CleanupLoop(stopCh <-chan struct{}, cleanupInterval, ttl time.Duration) {
	ticker := time.NewTicker(cleanupInterval)
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

func (c *zoneZeroCache) cleanup(ttl time.Duration) {
	now := time.Now()
	for key, record := range c.cache {
		if now.Sub(record.timestamp) > ttl {
			delete(c.cache, key)
		}
	}
}

// Given a conn, generate a key that is unique to this connection
// but can also be derived for the matching antrea ct_zone record.
func (c *zoneZeroCache) generateKey(conn *connection.Connection) string {
	destinationAddress := conn.FlowKey.DestinationAddress.String()
	replyDestinationPort := strconv.FormatUint(uint64(conn.ProxySnatPort), 10)
	return fmt.Sprintf("%s-%s", destinationAddress, replyDestinationPort)
}

// Add the given zone zero connection to the cache.
func (c *zoneZeroCache) Add(conn *connection.Connection) error {
	if conn.Zone != 0 {
		return fmt.Errorf("Cannot add connections to cache that are not zone zero. Connection has zone %v", conn.Zone)
	}
	key := c.generateKey(conn)
	c.cache[key] = zoneZeroRecord{
		conn:      conn,
		timestamp: time.Now(),
	}
	return nil
}

// Given an antrea zone connection, generate a key that will equal the corresponding zone zero connection.
func (c *zoneZeroCache) generateKeyFromAntreaZone(conn *connection.Connection) string {
	destinationAddress := conn.FlowKey.DestinationAddress.String()
	zoneZeroReplyDestinationPort := strconv.FormatUint(uint64(conn.FlowKey.SourcePort), 10)
	return fmt.Sprintf("%s-%s", destinationAddress, zoneZeroReplyDestinationPort)
}

// Given an antrea ct zone connection, if there is a corresponding zone zero connection, return it. Otherwise return nil.
func (c *zoneZeroCache) GetMatching(conn *connection.Connection) *connection.Connection {
	key := c.generateKeyFromAntreaZone(conn)
	record, exists := c.cache[key]
	if !exists {
		return nil
	}
	delete(c.cache, key)
	return record.conn
}

// Given a connection key, delete it from the cache. Log an error
// if it didn't exist in the cache
func (c *zoneZeroCache) Delete(conn *connection.Connection) {
	destinationAddress := conn.FlowKey.DestinationAddress
	zoneZeroReplyDestinationPort := strconv.FormatUint(uint64(conn.ProxySnatPort), 10)

	key := fmt.Sprintf("%s-%s", destinationAddress, zoneZeroReplyDestinationPort)
	delete(c.cache, key)
}
