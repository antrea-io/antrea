// Copyright 2023 Antrea Authors
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

package nodeip

import (
	"testing"
	"testing/synctest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
)

func TestNewTracker(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		k8sClient := fake.NewSimpleClientset()
		informerFactory := informers.NewSharedInformerFactory(k8sClient, 0)
		nodeInformer := informerFactory.Core().V1().Nodes()
		tracker := NewTracker(nodeInformer)

		assert.False(t, tracker.HasSynced())

		stopCh := make(chan struct{})
		defer close(stopCh)
		informerFactory.Start(stopCh)
		informerFactory.WaitForCacheSync(stopCh)

		assert.True(t, tracker.HasSynced())

		nodeInternalIP := "1.1.1.1"
		nodeExternalIP := "2.2.2.2"
		node := &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "node1"},
			Spec:       corev1.NodeSpec{},
			Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: nodeInternalIP},
				{Type: corev1.NodeExternalIP, Address: nodeExternalIP},
			}},
		}
		assert.False(t, tracker.IsNodeIP(nodeInternalIP))
		assert.False(t, tracker.IsNodeIP(nodeExternalIP))

		_, err := k8sClient.CoreV1().Nodes().Create(t.Context(), node, metav1.CreateOptions{})
		require.NoError(t, err)
		synctest.Wait()
		assert.True(t, tracker.IsNodeIP(nodeInternalIP))
		assert.True(t, tracker.IsNodeIP(nodeExternalIP))

		updatedNodeInternalIP := "1.1.1.2"
		updatedNode := node.DeepCopy()
		updatedNode.Status.Addresses[0].Address = updatedNodeInternalIP
		_, err = k8sClient.CoreV1().Nodes().Update(t.Context(), updatedNode, metav1.UpdateOptions{})
		require.NoError(t, err)
		synctest.Wait()
		assert.False(t, tracker.IsNodeIP(nodeInternalIP))
		assert.True(t, tracker.IsNodeIP(updatedNodeInternalIP))
		assert.True(t, tracker.IsNodeIP(nodeExternalIP))

		err = k8sClient.CoreV1().Nodes().Delete(t.Context(), node.Name, metav1.DeleteOptions{})
		require.NoError(t, err)
		synctest.Wait()
		assert.False(t, tracker.IsNodeIP(nodeInternalIP))
		assert.False(t, tracker.IsNodeIP(updatedNodeInternalIP))
		assert.False(t, tracker.IsNodeIP(nodeExternalIP))
	})
}

func TestOnNodeDelete_Tombstone(t *testing.T) {
	k8sClient := fake.NewSimpleClientset()
	informerFactory := informers.NewSharedInformerFactory(k8sClient, 0)
	nodeInformer := informerFactory.Core().V1().Nodes()
	tracker := NewTracker(nodeInformer)

	nodeIP := "3.3.3.3"
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node2"},
		Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
			{Type: corev1.NodeInternalIP, Address: nodeIP},
		}},
	}

	// Seed the tracker directly.
	tracker.OnNodeAdd(node)
	assert.True(t, tracker.IsNodeIP(nodeIP))

	// Deliver the delete as a tombstone, as the informer does after a watch reconnect.
	tracker.OnNodeDelete(cache.DeletedFinalStateUnknown{Key: "node2", Obj: node})
	assert.False(t, tracker.IsNodeIP(nodeIP))
}
