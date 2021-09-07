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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

func TestCluster(t *testing.T) {
	skipIfNumNodesLessThan(t, 2)
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	nodes := []string{nodeName(0), nodeName(1)}
	var busyboxes []string
	var cleanups []func()
	for idx, node := range nodes {
		podName, _, cleanup := createAndWaitForPod(t, data, data.createBusyboxPodOnNode, fmt.Sprintf("busybox-%d-", idx), node, testNamespace, false)
		busyboxes = append(busyboxes, podName)
		cleanups = append(cleanups, cleanup)
	}
	defer func() {
		for _, cleanup := range cleanups {
			cleanup()
		}
	}()

	t.Run("ClusterIP", func(t *testing.T) {
		t.Run("IPv4", func(t *testing.T) {
			t.Parallel()
			skipIfNotIPv4Cluster(t)
			testClusterIP(t, data, corev1.IPv4Protocol, nodes, busyboxes)
		})
		t.Run("IPv6", func(t *testing.T) {
			t.Parallel()
			skipIfNotIPv6Cluster(t)
			testClusterIP(t, data, corev1.IPv6Protocol, nodes, busyboxes)
		})
	})
}

func testClusterIP(t *testing.T, data *TestData, ipProtocol corev1.IPFamily, nodes []string, busyboxes []string) {
	nginx := fmt.Sprintf("nginx-%v", ipProtocol)
	hostNginx := fmt.Sprintf("nginx-host-%v", ipProtocol)
	nginxSvcName := fmt.Sprintf("nginx-%v", ipProtocol)

	clusterIPSvc, err := data.createNginxClusterIPService(nginxSvcName, true, &ipProtocol)
	defer func() {
		require.NoError(t, data.deleteServiceAndWait(defaultTimeout, nginxSvcName))
	}()
	require.NoError(t, err)
	require.NotEqual(t, "", clusterIPSvc.Spec.ClusterIP, "ClusterIP should not be empty")
	url := net.JoinHostPort(clusterIPSvc.Spec.ClusterIP, "80")

	createAndWaitForPod(t, data, data.createNginxPodOnNode, nginx, nodeName(0), testNamespace, false)
	t.Run("Non-HostNetwork Endpoints", func(t *testing.T) {
		testClusterIPCases(t, data, url, nodes, busyboxes)
	})
	require.NoError(t, data.deletePod(testNamespace, nginx))

	_, _, cleanupHostNginx := createAndWaitForPod(t, data, data.createNginxPodOnNode, hostNginx, nodeName(0), testNamespace, true)
	defer cleanupHostNginx()
	t.Run("HostNetwork Endpoints", func(t *testing.T) {
		testClusterIPCases(t, data, url, nodes, busyboxes)
	})
}

func testClusterIPCases(t *testing.T, data *TestData, url string, nodes, pods []string) {
	t.Run("All Nodes can access Service ClusterIP", func(t *testing.T) {
		skipIfProxyAllDisabled(t, data)
		skipIfKubeProxyEnabled(t, data)
		for _, node := range nodes {
			testClusterIPFromNode(t, url, node)
		}
	})
	t.Run("Pods from all Nodes can access Service ClusterIP", func(t *testing.T) {
		for _, pod := range pods {
			testClusterIPFromPod(t, data, url, pod)
		}
	})
}

func testClusterIPFromPod(t *testing.T, data *TestData, url, podName string) {
	_, _, err := data.runCommandFromPod(testNamespace, podName, busyboxContainerName, []string{"wget", "-O", "-", url, "-T", "1"})
	require.NoError(t, err, "Service ClusterIP should be able to be connected from Pod")
}

func testClusterIPFromNode(t *testing.T, url, nodeName string) {
	_, _, _, err := RunCommandOnNode(nodeName, strings.Join([]string{"wget", "-O", "-", url, "-T", "1"}, " "))
	require.NoError(t, err, "Service ClusterIP should be able to be connected from Node")
}
