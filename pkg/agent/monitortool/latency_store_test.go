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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	entry = NodeIPLatencyEntry{
		LastSendTime:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		LastRecvTime:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		LastMeasuredRTT: 1 * time.Second,
	}
	entry2 = NodeIPLatencyEntry{
		LastSendTime:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		LastRecvTime:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		LastMeasuredRTT: 2 * time.Second,
	}
)

func TestLatencyStore_getNodeIPLatencyEntry(t *testing.T) {
	tests := []struct {
		key           string
		expectedEntry NodeIPLatencyEntry
	}{
		{
			key:           "10.244.2.1",
			expectedEntry: entry,
		},
		{
			key:           "10.244.2.2",
			expectedEntry: NodeIPLatencyEntry{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			latencyStore := &LatencyStore{
				isNetworkPolicyOnly: false,
				nodeIPLatencyMap: map[string]*NodeIPLatencyEntry{
					"10.244.2.1": &entry,
				},
				nodeTargetIPsMap: map[string][]net.IP{
					"Node1": {net.ParseIP("10.244.2.1")},
				},
			}

			entry, _ := latencyStore.getNodeIPLatencyEntry(tt.key)
			assert.Equal(t, tt.expectedEntry.LastMeasuredRTT, entry.LastMeasuredRTT)
			assert.Equal(t, tt.expectedEntry.LastSendTime, entry.LastSendTime)
			assert.Equal(t, tt.expectedEntry.LastRecvTime, entry.LastRecvTime)
		})
	}
}

func TestLatencyStore_SetNodeIPLatencyEntry(t *testing.T) {
	tests := []struct {
		key           string
		updatedEntry  NodeIPLatencyEntry
		expectedEntry NodeIPLatencyEntry
	}{
		{
			key:           "10.244.2.1",
			updatedEntry:  entry,
			expectedEntry: entry,
		},
		{
			key:           "10.244.2.2",
			updatedEntry:  entry2,
			expectedEntry: entry2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			latencyStore := &LatencyStore{
				isNetworkPolicyOnly: false,
				nodeIPLatencyMap: map[string]*NodeIPLatencyEntry{
					"10.244.2.1": &entry,
				},
				nodeTargetIPsMap: map[string][]net.IP{
					"Node1": {net.ParseIP("10.244.2.1")},
				},
			}

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

func TestLatencyStore_DeleteStaleNodeIPs(t *testing.T) {
	testKey := "10.244.2.1"

	latencyStore := &LatencyStore{
		isNetworkPolicyOnly: false,
		nodeIPLatencyMap: map[string]*NodeIPLatencyEntry{
			testKey: &entry,
		},
		nodeTargetIPsMap: map[string][]net.IP{
			"Node1": {net.ParseIP(testKey)},
		},
	}

	// Remove Node
	latencyStore.deleteNode(&corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "Node1",
		},
	})

	// Check that the entry is still present
	_, ok := latencyStore.getNodeIPLatencyEntry(testKey)
	assert.True(t, ok)

	// Check if that the entry has been deleted
	latencyStore.DeleteStaleNodeIPs()
	_, ok = latencyStore.getNodeIPLatencyEntry(testKey)
	assert.False(t, ok)
}

func TestLatencyStore_ListNodeIPs(t *testing.T) {
	tests := []struct {
		latentStore  *LatencyStore
		expectedList []net.IP
	}{
		{
			latentStore: &LatencyStore{
				isNetworkPolicyOnly: false,
				nodeIPLatencyMap: map[string]*NodeIPLatencyEntry{
					"10.244.2.1": &entry,
				},
				nodeTargetIPsMap: map[string][]net.IP{
					"Node1": {net.ParseIP("10.244.2.1")},
				},
			},
			expectedList: []net.IP{
				net.ParseIP("10.244.2.1"),
			},
		},
	}

	for _, tt := range tests {
		t.Run("List Node IPs", func(t *testing.T) {
			nodeIPs := tt.latentStore.ListNodeIPs()
			assert.Equal(t, tt.expectedList, nodeIPs)
		})
	}
}
