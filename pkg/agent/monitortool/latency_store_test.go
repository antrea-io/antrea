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
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
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

func TestNewLatencyStore(t *testing.T) {
	k8sClient := fake.NewSimpleClientset()
	informerFactory := informers.NewSharedInformerFactory(k8sClient, 0)
	latencyStore := NewLatencyStore(false)

	stopCh := make(chan struct{})
	defer close(stopCh)

	informerFactory.Start(stopCh)
	informerFactory.WaitForCacheSync(stopCh)

	nodeName := "node1"
	nodeCIDR := "1.1.1.1/24"
	nodeInternalIP := "2.2.2.2"
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: nodeName},
		Spec: corev1.NodeSpec{
			PodCIDRs: []string{nodeCIDR},
		},
		Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
			{Type: corev1.NodeInternalIP, Address: nodeInternalIP},
		}},
	}

	k8sClient.CoreV1().Nodes().Create(context.TODO(), node, metav1.CreateOptions{})
	assert.EventuallyWithT(t, func(c *assert.CollectT) {}, 2*time.Second, 10*time.Millisecond)

	updateNodeCIDR := "1.1.2.1/24"
	updatedNodeInternalIP := "1.1.2.2"
	updatedNode := node.DeepCopy()
	updatedNode.Spec.PodCIDRs = []string{updateNodeCIDR}
	updatedNode.Status.Addresses[0].Address = updatedNodeInternalIP
	k8sClient.CoreV1().Nodes().Update(context.TODO(), updatedNode, metav1.UpdateOptions{})
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		_, ok := latencyStore.nodeGatewayMap[nodeName]
		assert.True(c, ok)
	}, 2*time.Second, 10*time.Millisecond)

	k8sClient.CoreV1().Nodes().Delete(context.TODO(), node.Name, metav1.DeleteOptions{})
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		_, ok := latencyStore.nodeGatewayMap[nodeName]
		assert.False(c, ok)
	}, 2*time.Second, 10*time.Millisecond)
}

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
			entry, found := latencyStore.GetNodeIPLatencyEntryByKey(tt.key)
			assert.Equal(t, tt.expectedEntry, entry)
			if tt.expectedEntry == nil {
				assert.False(t, found)
			} else {
				assert.True(t, found)
			}
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
			entry, found := latencyStore.GetNodeIPLatencyEntryByKey(tt.key)
			assert.Nil(t, entry)
			assert.False(t, found)
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
			entry, found := latencyStore.GetNodeIPLatencyEntryByKey(tt.key)
			assert.Equal(t, tt.expectedEntry, entry)
			assert.True(t, found)
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
