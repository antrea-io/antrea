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

package e2e

import (
	"fmt"
	"net"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

// TestClusterIP tests traffic from Nodes and Pods to ClusterIP Service.
func TestClusterIP(t *testing.T) {
	// TODO: Support for dual-stack and IPv6-only clusters
	skipIfIPv6Cluster(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	svcName := "nginx"
	serverPodNode := nodeName(0)
	svc, cleanup := data.createClusterIPServiceAndBackendPods(t, svcName, serverPodNode)
	defer cleanup()
	t.Logf("%s Service is ready", svcName)

	testFromPod := func(podName, nodeName string, hostNetwork bool) {
		require.NoError(t, data.createPodOnNode(podName, nodeName, busyboxImage, []string{"sleep", strconv.Itoa(3600)}, nil, nil, nil, hostNetwork, nil))
		defer data.deletePodAndWait(defaultTimeout, podName)
		require.NoError(t, data.podWaitForRunning(defaultTimeout, podName, testNamespace))
		err := data.runNetcatCommandFromTestPod(podName, svc.Spec.ClusterIP, 80)
		require.NoError(t, err, "Pod %s should be able to connect %s, but was not able to connect", podName, net.JoinHostPort(svc.Spec.ClusterIP, fmt.Sprint(80)))
	}

	t.Run("ClusterIP", func(t *testing.T) {
		t.Run("Same Linux Node can access the Service", func(t *testing.T) {
			t.Parallel()
			testFromPod("hostnetwork-client-on-same-node", serverPodNode, true)
		})
		t.Run("Different Linux Node can access the Service", func(t *testing.T) {
			t.Parallel()
			skipIfNumNodesLessThan(t, 2)
			testFromPod("hostnetwork-client-on-different-node", nodeName(1), true)
		})
		t.Run("Linux Pod on same Node can access the Service", func(t *testing.T) {
			t.Parallel()
			testFromPod("client-on-same-node", serverPodNode, false)
		})
		t.Run("Linux Pod on different Node can access the Service", func(t *testing.T) {
			t.Parallel()
			skipIfNumNodesLessThan(t, 2)
			testFromPod("client-on-different-node", nodeName(1), false)
		})
	})
}

func (data *TestData) createClusterIPServiceAndBackendPods(t *testing.T, name string, node string) (*corev1.Service, func()) {
	ipv4Protocol := corev1.IPv4Protocol
	require.NoError(t, data.createNginxPod(name, node))
	_, err := data.podWaitForIPs(defaultTimeout, name, testNamespace)
	require.NoError(t, err)
	require.NoError(t, data.podWaitForRunning(defaultTimeout, name, testNamespace))
	svc, err := data.createNginxClusterIPService(name, false, &ipv4Protocol)
	require.NoError(t, err)

	cleanup := func() {
		data.deletePodAndWait(defaultTimeout, name)
		data.deleteServiceAndWait(defaultTimeout, name)
	}

	return svc, cleanup
}
