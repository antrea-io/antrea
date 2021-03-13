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

package clusteridentity

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

	// First release of Antrea (v0.1.0) at KubeCon NA 2019 (San Diego) :)
	sanDiegoLocation, _        = time.LoadLocation("America/Los_Angeles")
	configMapCreationTimestamp = metav1.Date(2019, time.November, 18, 11, 26, 2, 0, sanDiegoLocation)

	idConfigMap = &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         antreaNamespace,
			Name:              DefaultClusterIdentityConfigMapName,
			CreationTimestamp: configMapCreationTimestamp,
		},
		Data: map[string]string{
			uuidConfigMapKey: clusterUUID.String(),
		},
	}

	idConfigMapEmpty = &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         antreaNamespace,
			Name:              DefaultClusterIdentityConfigMapName,
			CreationTimestamp: configMapCreationTimestamp,
		},
		Data: map[string]string{},
	}
)

func TestClusterIdentityAllocatorNew(t *testing.T) {
	client := fake.NewSimpleClientset(idConfigMapEmpty)
	allocator := NewClusterIdentityAllocator(antreaNamespace, DefaultClusterIdentityConfigMapName, client)
	require.NoError(t, allocator.updateConfigMapIfNeeded())

	provider := NewClusterIdentityProvider(antreaNamespace, DefaultClusterIdentityConfigMapName, client)
	identity, creationTime, err := provider.Get()
	require.NoError(t, err, "Error when retrieving cluster identity")
	assert.NotEqual(t, uuid.Nil, identity.UUID)
	// comparing timestamps directly does not work because of different location pointers

	assert.True(t, creationTime.Equal(configMapCreationTimestamp.Time))
}

func TestClusterIdentityAllocatorExisting(t *testing.T) {
	client := fake.NewSimpleClientset(idConfigMap)
	allocator := NewClusterIdentityAllocator(antreaNamespace, DefaultClusterIdentityConfigMapName, client)
	require.NoError(t, allocator.updateConfigMapIfNeeded())

	provider := NewClusterIdentityProvider(antreaNamespace, DefaultClusterIdentityConfigMapName, client)
	identity, creationTime, err := provider.Get()
	require.NoError(t, err, "Error when retrieving cluster identity")
	assert.Equal(t, clusterUUID, identity.UUID)

	assert.True(t, creationTime.Equal(configMapCreationTimestamp.Time))
}

func TestClusterIdentityProviderMissingConfigMap(t *testing.T) {
	client := fake.NewSimpleClientset()
	provider := NewClusterIdentityProvider(antreaNamespace, DefaultClusterIdentityConfigMapName, client)
	_, _, err := provider.Get()
	assert.Error(t, err, "Cluster identity should not be available")
}

func runWrapper(ctx context.Context, allocator *ClusterIdentityAllocator) error {
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

func TestClusterIdentityAllocatorRun(t *testing.T) {
	client := fake.NewSimpleClientset(idConfigMapEmpty)
	allocator := NewClusterIdentityAllocator(antreaNamespace, DefaultClusterIdentityConfigMapName, client)
	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
	defer cancel()
	require.NoError(t, runWrapper(ctx, allocator), "Cluster identity could not be updated")

	provider := NewClusterIdentityProvider(antreaNamespace, DefaultClusterIdentityConfigMapName, client)
	identity, creationTime, err := provider.Get()
	require.NoError(t, err, "Error when retrieving cluster identity")
	assert.NotEqual(t, uuid.Nil, identity.UUID)

	assert.True(t, creationTime.Equal(configMapCreationTimestamp.Time))
}
