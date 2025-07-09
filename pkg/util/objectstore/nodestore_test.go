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
