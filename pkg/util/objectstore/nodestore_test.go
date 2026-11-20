// Copyright 2025 Antrea Authors
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

package objectstore

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	"antrea.io/antrea/v2/pkg/agent/types"
)

func TestNodeStore(t *testing.T) {
	ctx := context.Background()
	stopCh := make(chan struct{})
	defer close(stopCh)
	k8sClient := fake.NewSimpleClientset()
	nodeInformer := coreinformers.NewNodeInformer(k8sClient, 0, cache.Indexers{})
	nodeStore := NewNodeStore(nodeInformer)
	go nodeInformer.Run(stopCh)
	cache.WaitForCacheSync(stopCh, nodeInformer.HasSynced)

	node1 := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "node1",
			UID:               "node1",
			CreationTimestamp: metav1.Time{Time: refTime2},
		},
	}
	_, err := k8sClient.CoreV1().Nodes().Create(ctx, node1, metav1.CreateOptions{})
	require.NoError(t, err)

	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		node, ok := nodeStore.GetNodeByNameAndTime(node1.Name, refTime.Add(-time.Minute))
		if assert.True(t, ok) {
			assert.Equal(t, node1.UID, node.UID)
		}
	}, 1*time.Second, 10*time.Millisecond)

	require.NoError(t, k8sClient.CoreV1().Nodes().Delete(ctx, node1.Name, metav1.DeleteOptions{}))
	node1New := node1.DeepCopy()
	node1New.UID = "node1_new"
	node1New.CreationTimestamp = metav1.Time{Time: refTime}
	_, err = k8sClient.CoreV1().Nodes().Create(ctx, node1New, metav1.CreateOptions{})
	require.NoError(t, err)

	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		node, ok := nodeStore.GetNodeByNameAndTime(node1.Name, refTime.Add(time.Minute))
		if assert.True(t, ok) {
			assert.Equal(t, node1New.UID, node.UID)
		}
		node, ok = nodeStore.GetNodeByNameAndTime(node1.Name, refTime.Add(-time.Minute))
		if assert.True(t, ok) {
			assert.Equal(t, node1.UID, node.UID)
		}
	}, 1*time.Second, 10*time.Millisecond)
}

func TestNodeStore_GetNodeByIPAndTime(t *testing.T) {
	ctx := context.Background()
	stopCh := make(chan struct{})
	defer close(stopCh)
	k8sClient := fake.NewSimpleClientset()
	nodeInformer := coreinformers.NewNodeInformer(k8sClient, 0, cache.Indexers{})
	nodeStore := NewNodeStore(nodeInformer)
	go nodeInformer.Run(stopCh)
	cache.WaitForCacheSync(stopCh, nodeInformer.HasSynced)

	node1 := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "node1",
			UID:               "node1",
			CreationTimestamp: metav1.Time{Time: refTime2},
			Annotations: map[string]string{
				types.NodeTransportAddressAnnotationKey: "192.168.77.2,fd77::2",
			},
		},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeHostName, Address: "node1"},
				{Type: corev1.NodeInternalIP, Address: "172.18.0.2"},
				// Not in canonical form.
				{Type: corev1.NodeInternalIP, Address: "fd00:0:0:0::2"},
				{Type: corev1.NodeExternalIP, Address: "1.2.3.4"},
			},
		},
	}
	// A Node with an invalid annotation is still indexed by its other IPs.
	node2 := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "node2",
			UID:               "node2",
			CreationTimestamp: metav1.Time{Time: refTime2},
			Annotations: map[string]string{
				types.NodeTransportAddressAnnotationKey: "invalid",
			},
		},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "172.18.0.3"}},
		},
	}
	for _, node := range []*corev1.Node{node1, node2} {
		_, err := k8sClient.CoreV1().Nodes().Create(ctx, node, metav1.CreateOptions{})
		require.NoError(t, err)
	}

	tests := []struct {
		ip           string
		expectedNode string
	}{
		{ip: "172.18.0.2", expectedNode: "node1"},
		{ip: "fd00::2", expectedNode: "node1"},
		{ip: "1.2.3.4", expectedNode: "node1"},
		{ip: "192.168.77.2", expectedNode: "node1"},
		{ip: "fd77::2", expectedNode: "node1"},
		{ip: "172.18.0.3", expectedNode: "node2"},
		{ip: "node1", expectedNode: ""},
		{ip: "172.18.0.4", expectedNode: ""},
	}
	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		for _, tc := range tests {
			node, ok := nodeStore.GetNodeByIPAndTime(tc.ip, refTime)
			if tc.expectedNode == "" {
				assert.False(t, ok, "No Node should have IP %s", tc.ip)
				continue
			}
			if assert.True(t, ok, "Node %s should have IP %s", tc.expectedNode, tc.ip) {
				assert.Equal(t, tc.expectedNode, node.Name)
			}
		}
	}, 1*time.Second, 10*time.Millisecond)
}
