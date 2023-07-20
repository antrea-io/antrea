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
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
)

func TestNewTracker(t *testing.T) {
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

	k8sClient.CoreV1().Nodes().Create(context.TODO(), node, metav1.CreateOptions{})
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.True(c, tracker.IsNodeIP(nodeInternalIP))
		assert.True(c, tracker.IsNodeIP(nodeExternalIP))
	}, 2*time.Second, 10*time.Millisecond)

	updatedNodeInternalIP := "1.1.1.2"
	updatedNode := node.DeepCopy()
	updatedNode.Status.Addresses[0].Address = updatedNodeInternalIP
	k8sClient.CoreV1().Nodes().Update(context.TODO(), updatedNode, metav1.UpdateOptions{})
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.False(c, tracker.IsNodeIP(nodeInternalIP))
		assert.True(c, tracker.IsNodeIP(updatedNodeInternalIP))
		assert.True(c, tracker.IsNodeIP(nodeExternalIP))
	}, 2*time.Second, 10*time.Millisecond)

	k8sClient.CoreV1().Nodes().Delete(context.TODO(), node.Name, metav1.DeleteOptions{})
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.False(c, tracker.IsNodeIP(nodeInternalIP))
		assert.False(c, tracker.IsNodeIP(updatedNodeInternalIP))
		assert.False(c, tracker.IsNodeIP(nodeExternalIP))
	}, 2*time.Second, 10*time.Millisecond)
}
