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

package clusteruuid

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

	uuidConfigMap = &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: antreaNamespace,
			Name:      DefaultUUIDConfigMapName,
		},
		Data: map[string]string{
			uuidConfigMapKey: clusterUUID.String(),
		},
	}

	uuidConfigMapEmpty = &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: antreaNamespace,
			Name:      DefaultUUIDConfigMapName,
		},
		Data: map[string]string{},
	}
)

func runWrapper(ctx context.Context, allocator ClusterUUIDAllocator) error {
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

func TestClusterUUIDNew(t *testing.T) {
	client := fake.NewSimpleClientset(uuidConfigMapEmpty)
	allocator := NewClusterUUIDAllocator(antreaNamespace, DefaultUUIDConfigMapName, client)
	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
	defer cancel()
	require.NoError(t, runWrapper(ctx, allocator), "Cluster UUID could not be allocated")

	provider := NewClusterUUIDProvider(antreaNamespace, DefaultUUIDConfigMapName, client)
	_, err := provider.Get()
	assert.NoError(t, err, "Error when retrieving cluster UUID")
}

func TestClusterUUIDExisting(t *testing.T) {
	client := fake.NewSimpleClientset(uuidConfigMap)
	allocator := NewClusterUUIDAllocator(antreaNamespace, DefaultUUIDConfigMapName, client)
	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
	defer cancel()
	require.NoError(t, runWrapper(ctx, allocator), "Cluster UUID could not be allocated")

	provider := NewClusterUUIDProvider(antreaNamespace, DefaultUUIDConfigMapName, client)
	uuid, err := provider.Get()
	require.NoError(t, err, "Error when retrieving cluster UUID")
	require.NotNil(t, uuid)
	assert.Equal(t, clusterUUID, *uuid)
}

func TestClusterUUIDProviderMissingConfigMap(t *testing.T) {
	client := fake.NewSimpleClientset()
	provider := NewClusterUUIDProvider(antreaNamespace, DefaultUUIDConfigMapName, client)
	uuid, err := provider.Get()
	assert.Error(t, err, "Cluster UUID should not be available")
	assert.Nil(t, uuid)
}
