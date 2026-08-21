// Copyright 2021 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// The idea is borrowed from https://github.com/golang/groupcache/blob/master/consistenthash/consistenthash.go with the following modifications:
// - Store the replicas in a 2-3-4 btree so that we can add/remove keys in O(log N) without rebuilding the whole cache.
// - Add a function GetWithFilters() to allow filtering keys with desired filters.

// Package consistenthash provides an implementation of a ring hash.
package consistenthash

import (
	"hash/crc32"
	"strconv"

	"github.com/google/btree"
)

type Hash func(data []byte) uint32

type Map struct {
	hash     Hash
	replicas int
	keys     map[string]struct{}
	tree     *btree.BTree
}

type replica struct {
	key  string
	hash uint32
}

func (v *replica) Less(than btree.Item) bool {
	return v.hash < than.(*replica).hash
}

var _ btree.Item = (*replica)(nil)

func New(replicas int, fn Hash) *Map {
	m := &Map{
		replicas: replicas,
		hash:     fn,
		keys:     make(map[string]struct{}),
		tree:     btree.New(2),
	}
	if m.hash == nil {
		m.hash = crc32.ChecksumIEEE
	}
	return m
}

// IsEmpty returns true if there are no items available.
func (m *Map) IsEmpty() bool {
	return len(m.keys) == 0
}

// Add adds some keys to the hash.
func (m *Map) Add(keys ...string) {
	for _, key := range keys {
		if _, exist := m.keys[key]; exist {
			continue
		}
		for i := 0; i < m.replicas; i++ {
			hash := m.hash([]byte(strconv.Itoa(i) + key))
			r := &replica{
				key:  key,
				hash: hash,
			}
			m.tree.ReplaceOrInsert(r)
		}
		m.keys[key] = struct{}{}
	}
}

// Remove removes keys from existing hash ring.
func (m *Map) Remove(keys ...string) {
	for _, key := range keys {
		_, exist := m.keys[key]
		if !exist {
			continue
		}
		for i := 0; i < m.replicas; i++ {
			hash := m.hash([]byte(strconv.Itoa(i) + key))
			replica := &replica{
				key:  key,
				hash: hash,
			}
			m.tree.Delete(replica)
		}
		delete(m.keys, key)
	}
}

// Get gets the closest item in the hash to the provided key.
func (m *Map) Get(key string) string {
	return m.GetWithFilters(key)
}

// GetWithFilters gets the closest item in the hash to which passes all filters.
func (m *Map) GetWithFilters(key string, filters ...func(string) bool) string {
	results := m.GetNWithFilters(key, 1, filters...)
	if len(results) == 0 {
		return ""
	}
	return results[0]
}

// GetNWithFilters gets up to n distinct items which pass all filters, ordered by their distance to
// the provided key on the ring: the first returned item is the one GetWithFilters would return, the
// second one is the item which would be returned if the first one were removed from the ring, and
// so on. Fewer than n items are returned if fewer pass the filters. A non-positive n returns all the
// items which pass the filters.
//
// The returned order only depends on the key and on the items present in the ring, so all the
// Antrea Agents which have the same view of the cluster compute the same order.
func (m *Map) GetNWithFilters(key string, n int, filters ...func(string) bool) []string {
	if m.IsEmpty() {
		return nil
	}
	if n <= 0 || n > len(m.keys) {
		n = len(m.keys)
	}
	hash := m.hash([]byte(key))
	pivot := &replica{
		key:  key,
		hash: hash,
	}
	results := make([]string, 0, n)
	visited := make(map[string]struct{}, len(m.keys))
	iterator := func(item btree.Item) bool {
		// all keys visited
		if len(visited) == len(m.keys) {
			return false
		}
		r := item.(*replica)
		if _, exists := visited[r.key]; exists {
			return true
		}
		visited[r.key] = struct{}{}
		for _, f := range filters {
			if !f(r.key) {
				return true
			}
		}
		results = append(results, r.key)
		// stop iterating once enough keys have been collected
		return len(results) < n
	}
	// search in [pivot, last]
	m.tree.AscendGreaterOrEqual(pivot, iterator)
	if len(results) < n {
		// search in [first, pivot)
		m.tree.AscendLessThan(pivot, iterator)
	}
	return results
}
