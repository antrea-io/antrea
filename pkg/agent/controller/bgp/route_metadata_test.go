// Copyright 2026 Antrea Authors
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

package bgp

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"antrea.io/antrea/v2/pkg/agent/bgp"
	"antrea.io/antrea/v2/pkg/agent/types"
)

func TestAddRoutesSharedPrefix(t *testing.T) {
	prefix := ipStrToPrefix(externalIPv4s[0])
	svcA := RouteMetadata{Type: ServiceExternalIP, K8sObjRef: getServiceName("svc-a")}
	svcB := RouteMetadata{Type: ServiceExternalIP, K8sObjRef: getServiceName("svc-b")}
	tests := []struct {
		name string
		// objects are the objects sharing the prefix, in the order in which they are listed.
		objects  []RouteMetadata
		expected RouteMetadata
	}{
		{
			name:     "object that sorts first is listed first",
			objects:  []RouteMetadata{svcA, svcB},
			expected: svcA,
		},
		{
			name:     "object that sorts first is listed last",
			objects:  []RouteMetadata{svcB, svcA},
			expected: svcA,
		},
		{
			name: "same object uses the prefix for two IP types",
			objects: []RouteMetadata{
				{Type: ServiceExternalIP, K8sObjRef: getServiceName("svc-a")},
				{Type: ServiceLoadBalancerIP, K8sObjRef: getServiceName("svc-a")},
			},
			expected: svcA,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			routes := make(map[bgp.Route]RouteMetadata)
			for _, obj := range tt.objects {
				addRoutes(routes, prefix, obj.K8sObjRef, obj.Type)
			}
			assert.Equal(t, map[bgp.Route]RouteMetadata{{Prefix: prefix}: tt.expected}, routes)
		})
	}
}

func TestRouteMetadataRefresh(t *testing.T) {
	policy := generateBGPPolicy(bgpPolicyName1, creationTimestamp, nodeLabels1, 179, 65000,
		false, true, false, false, false, nil, nil)
	sharedIP := externalIPv4s[0]
	sharedRoute := bgp.Route{Prefix: ipStrToPrefix(sharedIP)}
	svcA := generateService("svc-a", corev1.ServiceTypeClusterIP, clusterIPv4s[0], sharedIP, "", false, false)
	svcB := generateService("svc-b", corev1.ServiceTypeClusterIP, clusterIPv4s[1], sharedIP, "", false, false)

	tests := []struct {
		name             string
		services         []runtime.Object
		existingMetadata RouteMetadata
		expectedMetadata RouteMetadata
	}{
		{
			name:             "Service that the prefix was advertised for is deleted",
			services:         []runtime.Object{svcB},
			existingMetadata: RouteMetadata{Type: ServiceExternalIP, K8sObjRef: getServiceName("svc-a")},
			expectedMetadata: RouteMetadata{Type: ServiceExternalIP, K8sObjRef: getServiceName("svc-b")},
		},
		{
			name:             "Service that sorts first starts using the prefix",
			services:         []runtime.Object{svcA, svcB},
			existingMetadata: RouteMetadata{Type: ServiceExternalIP, K8sObjRef: getServiceName("svc-b")},
			expectedMetadata: RouteMetadata{Type: ServiceExternalIP, K8sObjRef: getServiceName("svc-a")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			c := newFakeController(t, nil, nil, true, false)
			populateListers(t, c, append([]runtime.Object{node, policy}, tt.services...)...)
			c.bgpPolicyState = generateBGPPolicyState(bgpPolicyName1, 179, 65000,
				nodeAnnotations1[types.NodeBGPRouterIDAnnotationKey], nil, nil, nil)
			c.bgpPolicyState.bgpServer = c.mockBGPServer
			c.bgpPolicyState.routes[sharedRoute] = tt.existingMetadata

			// The prefix stays advertised, so the mock BGP server, which expects no call, is not called.
			require.NoError(t, c.syncBGPPolicy(ctx))
			routes, err := c.GetBGPRoutes(ctx)
			require.NoError(t, err)
			assert.Equal(t, map[bgp.Route]RouteMetadata{sharedRoute: tt.expectedMetadata}, routes)
		})
	}
}
