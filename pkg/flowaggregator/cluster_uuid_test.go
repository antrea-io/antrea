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
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes/fake"

	"antrea.io/antrea/pkg/clusteridentity"
)

func TestGetClusterUUID(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset()
	clusterIdentityAllocator := clusteridentity.NewClusterIdentityAllocator(
		"kube-system",
		clusteridentity.DefaultClusterIdentityConfigMapName,
		client,
	)
	stopCh := make(chan struct{})
	defer close(stopCh)
	go clusterIdentityAllocator.Run(stopCh)

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, err := GetClusterUUID(ctx, client)
	require.NoError(t, err, "cluster UUID not available")
}
