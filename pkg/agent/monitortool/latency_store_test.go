// Copyright 2024 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package monitortool

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var (
	entry = &NodeIPLatencyEntry{
		LastSendTime:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		LastRecvTime:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		LastMeasuredRTT: 1 * time.Second,
	}
	entry2 = &NodeIPLatencyEntry{
		LastSendTime:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		LastRecvTime:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		LastMeasuredRTT: 2 * time.Second,
	}
	nodeIPLatencyMap = map[string]*NodeIPLatencyEntry{
		"10.244.2.1": entry,
	}
	nodeTargetIPsMap = map[string][]net.IP{
		"node1": {net.ParseIP("10.244.2.1")},
	}
)

func TestLatencyStore_GetConnByKey(t *testing.T) {
	latencyStore := &LatencyStore{
		isNetworkPolicyOnly: false,
		nodeIPLatencyMap:    nodeIPLatencyMap,
		nodeTargetIPsMap:    nodeTargetIPsMap,
	}
	tests := []struct {
		key           string
		expectedEntry *NodeIPLatencyEntry
	}{
		{
			key:           "10.244.2.1",
			expectedEntry: entry,
		},
		{
			key:           "10.244.2.2",
			expectedEntry: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			entry, _ := latencyStore.getNodeIPLatencyEntry(tt.key)
			assert.Equal(t, tt.expectedEntry, entry)
		})
	}
}

func TestLatencyStore_DeleteConnByKey(t *testing.T) {
	latencyStore := &LatencyStore{
		isNetworkPolicyOnly: false,
		nodeIPLatencyMap:    nodeIPLatencyMap,
		nodeTargetIPsMap:    nodeTargetIPsMap,
	}
	tests := []struct {
		key               string
		prevExpectedEntry *NodeIPLatencyEntry
		expectedEntry     *NodeIPLatencyEntry
	}{
		{
			key:               "10.244.2.1",
			prevExpectedEntry: entry,
			expectedEntry:     nil,
		},
		{
			key:               "10.244.2.2",
			prevExpectedEntry: nil,
			expectedEntry:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			entry, _ := latencyStore.getNodeIPLatencyEntry(tt.key)
			assert.Equal(t, tt.prevExpectedEntry, entry)
			latencyStore.DeleteNodeIPLatencyEntry(tt.key)
			entry, ok := latencyStore.getNodeIPLatencyEntry(tt.key)
			assert.Equal(t, entry, tt.expectedEntry)
			assert.False(t, ok)
		})
	}
}

func TestLatencyStore_SetNodeIPLatencyEntry(t *testing.T) {
	latencyStore := &LatencyStore{
		isNetworkPolicyOnly: false,
		nodeIPLatencyMap:    nodeIPLatencyMap,
		nodeTargetIPsMap:    nodeTargetIPsMap,
	}
	tests := []struct {
		key           string
		updatedEntry  *NodeIPLatencyEntry
		expectedEntry *NodeIPLatencyEntry
	}{
		{
			key:           "10.244.2.1",
			updatedEntry:  entry,
			expectedEntry: entry,
		},
		{
			key:           "10.244.2.1",
			updatedEntry:  entry2,
			expectedEntry: entry2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			mutator := func(entry *NodeIPLatencyEntry) {
				entry.LastSendTime = tt.updatedEntry.LastSendTime
				entry.LastRecvTime = tt.updatedEntry.LastRecvTime
				entry.LastMeasuredRTT = tt.updatedEntry.LastMeasuredRTT
			}
			latencyStore.SetNodeIPLatencyEntry(tt.key, mutator)
			entry, ok := latencyStore.getNodeIPLatencyEntry(tt.key)
			assert.Equal(t, tt.expectedEntry, entry)
			assert.True(t, ok)
		})
	}
}

func TestLatencyStore_ListLatencies(t *testing.T) {
	latencyStore := &LatencyStore{
		isNetworkPolicyOnly: false,
		nodeIPLatencyMap:    nodeIPLatencyMap,
		nodeTargetIPsMap:    nodeTargetIPsMap,
	}

	latencyMaps := latencyStore.ListLatencies()
	assert.Equal(t, nodeIPLatencyMap, latencyMaps)
}

func TestLatencyStore_ListNodeIPs(t *testing.T) {
	latencyStore := &LatencyStore{
		isNetworkPolicyOnly: false,
		nodeIPLatencyMap:    nodeIPLatencyMap,
		nodeTargetIPsMap:    nodeTargetIPsMap,
	}

	nodeIPs := latencyStore.ListNodeIPs()
	assert.Equal(t, nodeTargetIPsMap, nodeIPs)
}
