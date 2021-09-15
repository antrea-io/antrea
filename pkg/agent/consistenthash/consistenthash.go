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
			replica := &replica{
				key:  key,
				hash: hash,
			}
			m.tree.ReplaceOrInsert(replica)
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

// Get gets the closest item in the hash to the provided key with filters.
func (m *Map) GetWithFilters(key string, filters ...func(string) bool) string {
	if m.IsEmpty() {
		return ""
	}
	hash := m.hash([]byte(key))
	pivot := &replica{
		hash: hash,
	}
	var result *replica
	visited := make(map[string]struct{})
	iterator := func(item btree.Item) bool {
		replica := item.(*replica)
		if _, exists := visited[replica.key]; exists {
			return true
		}
		// all key visited
		if len(visited) == len(m.keys) {
			return false
		}
		for _, f := range filters {
			if !f(replica.key) {
				visited[replica.key] = struct{}{}
				return true
			}
		}
		// stop iterating
		result = replica
		return false
	}
	// search in [pivot, last]
	m.tree.AscendGreaterOrEqual(pivot, iterator)
	if result == nil {
		// search in [first, pivot)
		m.tree.AscendLessThan(pivot, iterator)
	}
	// no key passes all filters
	if result == nil {
		return ""
	}
	return result.key
}
