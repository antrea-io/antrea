// // Copyright 2024 Antrea Authors
// //
// // Licensed under the Apache License, Version 2.0 (the "License");
// // you may not use this file except in compliance with the License.
// // You may obtain a copy of the License at
// //
// //	http://www.apache.org/licenses/LICENSE-2.0
// //
// // Unless required by applicable law or agreed to in writing, software
// // distributed under the License is distributed on an "AS IS" BASIS,
// // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// // See the License for the specific language governing permissions and
// // limitations under the License.

package monitortool

// import (
// 	"context"
// 	"net"
// 	"testing"
// 	"time"

// 	"github.com/stretchr/testify/assert"
// 	corev1 "k8s.io/api/core/v1"
// 	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// 	"k8s.io/client-go/informers"
// 	"k8s.io/client-go/kubernetes/fake"
// )

// var (
// 	entry = &NodeIPLatencyEntry{
// 		SeqID:           1,
// 		LastSendTime:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
// 		LastRecvTime:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
// 		LastMeasuredRTT: 1 * time.Second,
// 	}
// 	entry2 = &NodeIPLatencyEntry{
// 		SeqID:           2,
// 		LastSendTime:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
// 		LastRecvTime:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
// 		LastMeasuredRTT: 2 * time.Second,
// 	}
// 	nodeLatency = map[string]*NodeIPLatencyEntry{
// 		"10.244.2.1": entry,
// 	}
// 	nodeGatewayMap = map[string][]net.IP{
// 		"node1": {net.ParseIP("10.244.2.1")},
// 	}
// )

// func TestNewLatencyStore(t *testing.T) {
// 	k8sClient := fake.NewSimpleClientset()
// 	informerFactory := informers.NewSharedInformerFactory(k8sClient, 0)
// 	nodeInformer := informerFactory.Core().V1().Nodes()
// 	_ = NewLatencyStore(nodeInformer, false)

// 	stopCh := make(chan struct{})
// 	defer close(stopCh)

// 	informerFactory.Start(stopCh)
// 	informerFactory.WaitForCacheSync(stopCh)

// 	nodeInternalIP := "1.1.1.1"
// 	nodeExternalIP := "2.2.2.2"
// 	node := &corev1.Node{
// 		ObjectMeta: metav1.ObjectMeta{Name: "node1"},
// 		Spec:       corev1.NodeSpec{},
// 		Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
// 			{Type: corev1.NodeInternalIP, Address: nodeInternalIP},
// 			{Type: corev1.NodeExternalIP, Address: nodeExternalIP},
// 		}},
// 	}

// 	k8sClient.CoreV1().Nodes().Create(context.TODO(), node, metav1.CreateOptions{})
// 	assert.EventuallyWithT(t, func(c *assert.CollectT) {}, 2*time.Second, 10*time.Millisecond)

// 	updatedNodeInternalIP := "1.1.1.2"
// 	updatedNode := node.DeepCopy()
// 	updatedNode.Status.Addresses[0].Address = updatedNodeInternalIP
// 	k8sClient.CoreV1().Nodes().Update(context.TODO(), updatedNode, metav1.UpdateOptions{})
// 	assert.EventuallyWithT(t, func(c *assert.CollectT) {}, 2*time.Second, 10*time.Millisecond)

// 	k8sClient.CoreV1().Nodes().Delete(context.TODO(), node.Name, metav1.DeleteOptions{})
// 	assert.EventuallyWithT(t, func(c *assert.CollectT) {}, 2*time.Second, 10*time.Millisecond)
// }

// func TestLatencyStore_GetConnByKey(t *testing.T) {
// 	latencyStore := &LatencyStore{
// 		connectionMap: connectionMap,
// 		nodeGW0Map:    nodeGW0Map,
// 	}
// 	tests := []struct {
// 		key          string
// 		expectedConn []*Connection
// 	}{
// 		{
// 			key:          "node1",
// 			expectedConn: []*Connection{conn},
// 		},
// 		{
// 			key:          "node2",
// 			expectedConn: nil,
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.key, func(t *testing.T) {
// 			conns, found := latencyStore.GetConnsByKey(tt.key)
// 			assert.Equal(t, tt.expectedConn, conns)
// 			if tt.expectedConn == nil {
// 				assert.False(t, found)
// 			} else {
// 				assert.True(t, found)
// 			}
// 		})
// 	}
// }

// func TestLatencyStore_DeleteConnByKey(t *testing.T) {
// 	latencyStore := &LatencyStore{
// 		connectionMap: connectionMap,
// 		nodeGW0Map:    nodeGW0Map,
// 	}
// 	tests := []struct {
// 		key          string
// 		expectedConn *Connection
// 	}{
// 		{
// 			key:          "node1",
// 			expectedConn: conn,
// 		},
// 		{
// 			key:          "node2",
// 			expectedConn: nil,
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.key, func(t *testing.T) {
// 			latencyStore.DeleteConnsByKey(tt.key)
// 			conn, found := latencyStore.GetConnsByKey(tt.key)
// 			assert.Nil(t, conn)
// 			assert.False(t, found)
// 		})
// 	}
// }

// func TestLatencyStore_UpdateConnByKey(t *testing.T) {
// 	latencyStore := &LatencyStore{
// 		connectionMap: connectionMap,
// 		nodeGW0Map:    nodeGW0Map,
// 	}
// 	tests := []struct {
// 		key          string
// 		updatedConn  *Connection
// 		expectedConn []*Connection
// 	}{
// 		{
// 			key:          "node1",
// 			updatedConn:  conn2,
// 			expectedConn: []*Connection{conn2},
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.key, func(t *testing.T) {
// 			latencyStore.UpdateConnByKey(tt.key, tt.updatedConn)
// 			conns, found := latencyStore.GetConnsByKey(tt.key)
// 			assert.Equal(t, tt.expectedConn, conns)
// 			assert.True(t, found)
// 		})
// 	}
// }

// func TestLatencyStore_ListConns(t *testing.T) {
// 	latencyStore := &LatencyStore{
// 		connectionMap: connectionMap,
// 		nodeGW0Map:    nodeGW0Map,
// 	}

// 	conns := latencyStore.ListConns()
// 	assert.Equal(t, connectionMap, conns)
// }

// func TestLatencyStore_ListNodeIPs(t *testing.T) {
// 	latencyStore := &LatencyStore{
// 		connectionMap: connectionMap,
// 		nodeGW0Map:    nodeGW0Map,
// 	}

// 	nodeIPs := latencyStore.ListNodeIPs()
// 	assert.Equal(t, nodeGW0Map, nodeIPs)
// }
