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

package consistenthash

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/google/btree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// simpleHashFn is a simple hash function for testing. It will return the integer value of the
// input key. The key must be the chars of decimal representation of an integer.
func simpleHashFn(key []byte) uint32 {
	i, err := strconv.Atoi(string(key))
	if err != nil {
		panic(err)
	}
	return uint32(i)
}

func TestMapGet(t *testing.T) {
	hash := New(3, simpleHashFn)

	// Given the above hash function, this will give replicas with "hashes":
	// 2, 4, 6, 12, 14, 16, 22, 24, 26
	hash.Add("6", "4", "2")
	testCases := map[string]string{
		"2":  "2",
		"11": "2",
		"23": "4",
		"27": "2",
	}
	for k, v := range testCases {
		assert.Equal(t, v, hash.Get(k))
	}

	// Adds 8, 18, 28
	hash.Add("8")
	// 27 should now map to 8.
	testCases["27"] = "8"
	for k, v := range testCases {
		assert.Equal(t, v, hash.Get(k))
	}

}

func TestConsistency(t *testing.T) {
	hash1 := New(1, nil)
	hash2 := New(1, nil)

	hash1.Add("Bill", "Bob", "Bonny")
	hash2.Add("Bob", "Bonny", "Bill")

	if hash1.Get("Ben") != hash2.Get("Ben") {
		t.Errorf("Fetching 'Ben' from both hashes should be the same")
	}
}

func TestGetWithFilter(t *testing.T) {
	testCases := []struct {
		name         string
		keys         []string
		testKey      string
		expectedHash string
		filter       []func(string) bool
	}{
		{
			"without filters",
			[]string{"1", "2", "3"},
			"2",
			"2",
			nil,
		},
		{
			"with one filter to exclude one key",
			[]string{"1", "2", "3"},
			"2",
			"3",
			[]func(s string) bool{
				func(s string) bool {
					return s != "2"
				},
			},
		},
		{
			"with one filter to match only one key",
			[]string{"1", "2", "3"},
			"2",
			"1",
			[]func(s string) bool{
				func(s string) bool {
					return s == "1"
				},
			},
		},
		{
			"with two filters",
			[]string{"1", "2", "3"},
			"2",
			"1",
			[]func(s string) bool{
				func(s string) bool {
					return s != "2"
				},
				func(s string) bool {
					return s != "3"
				},
			},
		},
		{
			"no valid value",
			[]string{"1", "2", "3"},
			"2",
			"",
			[]func(s string) bool{
				func(s string) bool {
					return s == "0"
				},
			},
		},
		{
			"filters should check exactly once for each key",
			[]string{"1", "2", "3"},
			"2",
			"",
			[]func(s string) bool{
				func(m map[string]struct{}) func(s string) bool {
					return func(s string) bool {
						if _, ok := m[s]; ok {
							t.Errorf("duplicate key passed to filters")
						}
						m[s] = struct{}{}
						return false
					}
				}(make(map[string]struct{})),
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			hash := New(3, simpleHashFn)
			hash.Add(tt.keys...)
			v := hash.GetWithFilters(tt.testKey, tt.filter...)
			assert.Equal(t, tt.expectedHash, v)
		})
	}
}

func TestRemove(t *testing.T) {
	testCases := []struct {
		name             string
		keys             []string
		toRemove         []string
		expectedHashRing []replica
	}{
		{
			"delete one key",
			[]string{"1", "2", "3"},
			[]string{"2"},
			[]replica{
				{"1", 1},
				{"3", 3},
				{"1", 11},
				{"3", 13},
			},
		},
		{
			"delete two keys",
			[]string{"1", "2", "3"},
			[]string{"2", "3"},
			[]replica{
				{"1", 1},
				{"1", 11},
			},
		}, {
			"delete all keys",
			[]string{"1", "2", "3"},
			[]string{"1", "2", "3"},
			nil,
		},
		{
			"delete non-existing key",
			[]string{"1", "2", "3"},
			[]string{"4"},
			[]replica{
				{"1", 1},
				{"2", 2},
				{"3", 3},
				{"1", 11},
				{"2", 12},
				{"3", 13},
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			hash := New(2, simpleHashFn)
			hash.Add(tt.keys...)
			hash.Remove(tt.toRemove...)
			var actualHashRing []replica
			iterator := func(item btree.Item) bool {
				replica, ok := item.(*replica)
				require.True(t, ok)
				actualHashRing = append(actualHashRing, *replica)
				return true
			}
			hash.tree.Ascend(iterator)
			assert.Equal(t, tt.expectedHashRing, actualHashRing)
			for _, r := range tt.toRemove {
				if _, ok := hash.keys[r]; ok {
					t.Errorf("key %s not deleted", r)
				}
			}
		})
	}
}

func BenchmarkGet8(b *testing.B)    { benchmarkGet(b, 8) }
func BenchmarkGet32(b *testing.B)   { benchmarkGet(b, 32) }
func BenchmarkGet128(b *testing.B)  { benchmarkGet(b, 128) }
func BenchmarkGet512(b *testing.B)  { benchmarkGet(b, 512) }
func BenchmarkGet1024(b *testing.B) { benchmarkGet(b, 1024) }

func benchmarkGet(b *testing.B, shards int) {
	b.SetBytes(1)
	hash := New(50, nil)

	var buckets []string
	for i := 0; i < shards; i++ {
		buckets = append(buckets, fmt.Sprintf("shard-%d", i))
	}

	hash.Add(buckets...)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hash.Get(buckets[i&(shards-1)])
	}
}
