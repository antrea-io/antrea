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

	"antrea.io/antrea/v2/pkg/util/k8s"
)

func TestServiceStore(t *testing.T) {
	ctx := context.Background()
	stopCh := make(chan struct{})
	defer close(stopCh)
	k8sClient := fake.NewSimpleClientset()
	serviceInformer := coreinformers.NewServiceInformer(k8sClient, metav1.NamespaceAll, 0, cache.Indexers{})
	serviceStore := NewServiceStore(serviceInformer)
	go serviceInformer.Run(stopCh)
	cache.WaitForCacheSync(stopCh, serviceInformer.HasSynced)

	svc1 := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         "default",
			Name:              "svc1",
			UID:               "svc1",
			CreationTimestamp: metav1.Time{Time: refTime2},
		},
	}
	_, err := k8sClient.CoreV1().Services(svc1.Namespace).Create(ctx, svc1, metav1.CreateOptions{})
	require.NoError(t, err)

	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		svc, ok := serviceStore.GetServiceByNamespacedNameAndTime(k8s.NamespacedName(svc1.Namespace, svc1.Name), refTime.Add(-time.Minute))
		if assert.True(t, ok) {
			assert.Equal(t, svc1.UID, svc.UID)
		}
	}, 1*time.Second, 10*time.Millisecond)

	require.NoError(t, k8sClient.CoreV1().Services(svc1.Namespace).Delete(ctx, svc1.Name, metav1.DeleteOptions{}))
	svc1New := svc1.DeepCopy()
	svc1New.UID = "svc1_new"
	svc1New.CreationTimestamp = metav1.Time{Time: refTime}
	_, err = k8sClient.CoreV1().Services(svc1New.Namespace).Create(ctx, svc1New, metav1.CreateOptions{})
	require.NoError(t, err)

	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		svc, ok := serviceStore.GetServiceByNamespacedNameAndTime(k8s.NamespacedName(svc1.Namespace, svc1.Name), refTime.Add(time.Minute))
		if assert.True(t, ok) {
			assert.Equal(t, svc1New.UID, svc.UID)
		}
		svc, ok = serviceStore.GetServiceByNamespacedNameAndTime(k8s.NamespacedName(svc1.Namespace, svc1.Name), refTime.Add(-time.Minute))
		if assert.True(t, ok) {
			assert.Equal(t, svc1.UID, svc.UID)
		}
	}, 1*time.Second, 10*time.Millisecond)
}
