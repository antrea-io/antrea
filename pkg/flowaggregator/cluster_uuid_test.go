// Copyright 2024 Antrea Authors
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

package flowaggregator

import (
	"testing"
	"testing/synctest"
	"uuid"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"antrea.io/antrea/v2/pkg/clusteridentity"
)

func TestGetClusterUUID(t *testing.T) {
	t.Setenv(antreaNamespaceEnvKey, "")
	synctest.Test(t, func(t *testing.T) {
		client := fake.NewSimpleClientset()
		clusterIdentityAllocator := clusteridentity.NewClusterIdentityAllocator(
			"kube-system",
			clusteridentity.DefaultClusterIdentityConfigMapName,
			client,
		)
		stopCh := make(chan struct{})
		defer close(stopCh)
		go clusterIdentityAllocator.Run(stopCh)

		// Wait for the allocator goroutine to create the ConfigMap before
		// polling, so GetClusterUUID succeeds on the first attempt.
		synctest.Wait()

		_, err := GetClusterUUID(t.Context(), client)
		require.NoError(t, err, "cluster UUID not available")
	})
}

func TestGetClusterUUIDCustomNamespace(t *testing.T) {
	const namespace = "antrea-system"
	t.Setenv(antreaNamespaceEnvKey, namespace)

	expectedUUID := uuid.NewV4()
	client := fake.NewSimpleClientset(
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      clusteridentity.DefaultClusterIdentityConfigMapName,
				Namespace: metav1.NamespaceSystem,
			},
			Data: map[string]string{"uuid": uuid.NewV4().String()},
		},
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      clusteridentity.DefaultClusterIdentityConfigMapName,
				Namespace: namespace,
			},
			Data: map[string]string{"uuid": expectedUUID.String()},
		},
	)

	synctest.Test(t, func(t *testing.T) {
		clusterUUID, err := GetClusterUUID(t.Context(), client)
		require.NoError(t, err)
		require.Equal(t, expectedUUID, clusterUUID)
	})
}
