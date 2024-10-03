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
	"fmt"
	"time"

	"github.com/google/uuid"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"

	"antrea.io/antrea/pkg/clusteridentity"
)

// GetClusterUUID retrieves the cluster UUID (if available, with a timeout of 10s).
// Otherwise, it returns an empty cluster UUID and error. The cluster UUID should
// be available if Antrea is deployed to the cluster ahead of the flow aggregator,
// which is the expectation since when deploying flow aggregator as a Pod,
// networking needs to be configured by the CNI plugin.
func GetClusterUUID(ctx context.Context, k8sClient kubernetes.Interface) (uuid.UUID, error) {
	const retryInterval = time.Second
	const timeout = 10 * time.Second
	const defaultAntreaNamespace = "kube-system"

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	clusterIdentityProvider := clusteridentity.NewClusterIdentityProvider(
		defaultAntreaNamespace,
		clusteridentity.DefaultClusterIdentityConfigMapName,
		k8sClient,
	)
	var clusterUUID uuid.UUID
	if err := wait.PollUntilContextCancel(ctx, retryInterval, true, func(ctx context.Context) (bool, error) {
		clusterIdentity, _, err := clusterIdentityProvider.Get()
		if err != nil {
			return false, nil
		}
		clusterUUID = clusterIdentity.UUID
		return true, nil
	}); err != nil {
		return clusterUUID, fmt.Errorf("unable to retrieve cluster UUID from ConfigMap '%s/%s': %w", defaultAntreaNamespace, clusteridentity.DefaultClusterIdentityConfigMapName, err)
	}
	return clusterUUID, nil
}
