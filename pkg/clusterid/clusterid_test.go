// Copyright 2021 Antrea Authors
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

package clusterid

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

const (
	antreaNamespace = "kube-system"
	runTimeout      = 2 * time.Second
)

var (
	clusterUUID = uuid.New()
	clusterName = "my-favorite-cluster"

	uuidConfigMap = &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: antreaNamespace,
			Name:      DefaultClusterIDConfigMapName,
		},
		Data: map[string]string{
			uuidConfigMapKey: clusterUUID.String(),
			nameConfigMapKey: clusterName,
		},
	}

	uuidConfigMapEmpty = &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: antreaNamespace,
			Name:      DefaultClusterIDConfigMapName,
		},
		Data: map[string]string{},
	}
)

func TestClusterIDAllocatorNew(t *testing.T) {
	client := fake.NewSimpleClientset(uuidConfigMapEmpty)
	allocator, err := NewClusterIDAllocator(antreaNamespace, DefaultClusterIDConfigMapName, client, "", "")
	require.NoError(t, err)
	require.NoError(t, allocator.updateConfigMapIfNeeded())

	provider := NewClusterIDProvider(antreaNamespace, DefaultClusterIDConfigMapName, client)
	actualUUID, actualName, err := provider.Get()
	require.NoError(t, err, "Error when retrieving cluster identity")
	assert.NotEqual(t, uuid.Nil, actualUUID)
	assert.Equal(t, actualUUID.String(), actualName, "Cluster name should match cluster UUID")
}

func TestClusterIDAllocatorExisting(t *testing.T) {
	client := fake.NewSimpleClientset(uuidConfigMap)
	allocator, err := NewClusterIDAllocator(antreaNamespace, DefaultClusterIDConfigMapName, client, "", "")
	require.NoError(t, err)
	require.NoError(t, allocator.updateConfigMapIfNeeded())

	provider := NewClusterIDProvider(antreaNamespace, DefaultClusterIDConfigMapName, client)
	actualUUID, actualName, err := provider.Get()
	require.NoError(t, err, "Error when retrieving cluster identity")
	assert.Equal(t, clusterUUID, actualUUID)
	assert.Equal(t, clusterName, actualName)
}

// TestClusterIDAllocatorMismatch tests the case where the user provides a cluster UUID which does
// not match the current one stored in the ConfigMap.
func TestClusterIDAllocatorMismatch(t *testing.T) {
	client := fake.NewSimpleClientset(uuidConfigMap)
	userProvidedUUID := uuid.New().String()
	allocator, err := NewClusterIDAllocator(antreaNamespace, DefaultClusterIDConfigMapName, client, "", userProvidedUUID)
	require.NoError(t, err)
	assert.Error(t, allocator.updateConfigMapIfNeeded())
}

func TestClusterIDProviderMissingConfigMap(t *testing.T) {
	client := fake.NewSimpleClientset()
	provider := NewClusterIDProvider(antreaNamespace, DefaultClusterIDConfigMapName, client)
	_, _, err := provider.Get()
	assert.Error(t, err, "Cluster identity should not be available")
}

func runWrapper(ctx context.Context, allocator *ClusterIDAllocator) error {
	stopCh := make(chan struct{})
	doneCh := make(chan struct{})
	defer close(stopCh)
	go func() {
		allocator.Run(stopCh)
		close(doneCh)
	}()
	select {
	case <-doneCh: // success
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestClusterIDAllocatorRun(t *testing.T) {
	client := fake.NewSimpleClientset(uuidConfigMapEmpty)
	allocator, err := NewClusterIDAllocator(antreaNamespace, DefaultClusterIDConfigMapName, client, "", "")
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
	defer cancel()
	require.NoError(t, runWrapper(ctx, allocator), "Cluster identity could not be updated")

	provider := NewClusterIDProvider(antreaNamespace, DefaultClusterIDConfigMapName, client)
	actualUUID, actualName, err := provider.Get()
	require.NoError(t, err, "Error when retrieving cluster identity")
	assert.NotEqual(t, uuid.Nil, actualUUID)
	assert.Equal(t, actualUUID.String(), actualName, "Cluster name should match cluster UUID")
}
