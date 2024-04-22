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
		SeqID:           1,
		LastSendTime:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		LastRecvTime:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		LastMeasuredRTT: 1 * time.Second,
	}
	entry2 = &NodeIPLatencyEntry{
		SeqID:           2,
		LastSendTime:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		LastRecvTime:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		LastMeasuredRTT: 2 * time.Second,
	}
	nodeIPLatencyMap = map[string]*NodeIPLatencyEntry{
		"10.244.2.1": entry,
	}
	nodeGatewayMap = map[string][]net.IP{
		"node1": {net.ParseIP("10.244.2.1")},
	}
)

func TestLatencyStore_GetConnByKey(t *testing.T) {
	latencyStore := &LatencyStore{
		isNetworkPolicyOnly: false,
		nodeIPLatencyMap:    nodeIPLatencyMap,
		nodeGatewayMap:      nodeGatewayMap,
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
			entry := latencyStore.GetNodeIPLatencyEntryByKey(tt.key)
			assert.Equal(t, tt.expectedEntry, entry)
		})
	}
}

func TestLatencyStore_DeleteConnByKey(t *testing.T) {
	latencyStore := &LatencyStore{
		isNetworkPolicyOnly: false,
		nodeIPLatencyMap:    nodeIPLatencyMap,
		nodeGatewayMap:      nodeGatewayMap,
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
			latencyStore.DeleteNodeIPLatencyEntryByKey(tt.key)
			entry := latencyStore.GetNodeIPLatencyEntryByKey(tt.key)
			assert.Nil(t, entry)
		})
	}
}

func TestLatencyStore_UpdateConnByKey(t *testing.T) {
	latencyStore := &LatencyStore{
		isNetworkPolicyOnly: false,
		nodeIPLatencyMap:    nodeIPLatencyMap,
		nodeGatewayMap:      nodeGatewayMap,
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
			latencyStore.UpdateNodeIPLatencyEntryByKey(tt.key, tt.updatedEntry)
			entry := latencyStore.GetNodeIPLatencyEntryByKey(tt.key)
			assert.Equal(t, tt.expectedEntry, entry)
		})
	}
}

func TestLatencyStore_ListLatencies(t *testing.T) {
	latencyStore := &LatencyStore{
		isNetworkPolicyOnly: false,
		nodeIPLatencyMap:    nodeIPLatencyMap,
		nodeGatewayMap:      nodeGatewayMap,
	}

	latencyMaps := latencyStore.ListLatencies()
	assert.Equal(t, nodeIPLatencyMap, latencyMaps)
}

func TestLatencyStore_ListNodeIPs(t *testing.T) {
	latencyStore := &LatencyStore{
		isNetworkPolicyOnly: false,
		nodeIPLatencyMap:    nodeIPLatencyMap,
		nodeGatewayMap:      nodeGatewayMap,
	}

	nodeIPs := latencyStore.ListNodeIPs()
	assert.Equal(t, nodeGatewayMap, nodeIPs)
}
