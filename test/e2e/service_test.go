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

func TestClusterIPv4(t *testing.T) {
	skipIfNotIPv4Cluster(t)
	testClusterIP(t, false)
}

func TestClusterIPv6(t *testing.T) {
	skipIfNotIPv6Cluster(t)
	testClusterIP(t, true)
}

func testClusterIP(t *testing.T, isIPv6 bool) {
	skipIfNumNodesLessThan(t, 2)
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	nodes := []string{nodeName(0), nodeName(1)}
	var busyboxes []string
	for idx, node := range nodes {
		podName, _, _ := createAndWaitForPod(t, data, data.createBusyboxPodOnNode, fmt.Sprintf("busybox-%d-", idx), node, testNamespace, false)
		busyboxes = append(busyboxes, podName)
	}

	nginx := fmt.Sprintf("nginx-%v", isIPv6)
	hostNginx := fmt.Sprintf("nginx-host-%v", isIPv6)
	ipProtocol := corev1.IPv4Protocol
	if isIPv6 {
		ipProtocol = corev1.IPv6Protocol
	}
	clusterIPSvc, err := data.createNginxClusterIPService(fmt.Sprintf("nginx-%v", isIPv6), true, &ipProtocol)
	require.NoError(t, err)
	require.NotEqual(t, "", clusterIPSvc.Spec.ClusterIP, "ClusterIP should not be empty")
	url := net.JoinHostPort(clusterIPSvc.Spec.ClusterIP, "80")

	createAndWaitForPod(t, data, data.createNginxPodOnNode, nginx, nodeName(0), testNamespace, false)
	t.Run("Non-HostNetwork Endpoints", func(t *testing.T) {
		testClusterIPCases(t, data, url, nodes, busyboxes)
	})

	require.NoError(t, data.deletePod(testNamespace, nginx))
	createAndWaitForPod(t, data, data.createNginxPodOnNode, hostNginx, nodeName(0), testNamespace, true)
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

// TestNodePortWindows tests NodePort Service on Windows Node. It is a temporary test to replace upstream Kubernetes one:
// https://github.com/kubernetes/kubernetes/blob/ea0764452222146c47ec826977f49d7001b0ea8c/test/e2e/windows/service.go#L42
// Issue: https://github.com/antrea-io/antrea/issues/2289
func TestNodePortWindows(t *testing.T) {
	skipIfNoWindowsNodes(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	svcName := "agnhost"
	svcNode := nodeName(clusterInfo.windowsNodes[0])
	svc, cleanup := data.createAgnhostServiceAndBackendPods(t, svcName, svcNode, corev1.ServiceTypeNodePort)
	defer cleanup()
	t.Logf("%s Service is ready", svcName)

	// Unlike upstream Kubernetes Conformance, here the client is on a Linux Node (nodeName(0)).
	// It doesn't need to be the control-plane for e2e test and other Linux workers will work as well. However, in this
	// e2e framework, nodeName(0)/Control-plane Node is guaranteed to be a Linux one.
	clientName := "agnhost-client"
	require.NoError(t, data.createAgnhostPodOnNode(clientName, testNamespace, nodeName(0)))
	defer data.deletePodAndWait(defaultTimeout, clientName, testNamespace)
	_, err = data.podWaitForIPs(defaultTimeout, clientName, testNamespace)
	require.NoError(t, err)

	nodeIP := clusterInfo.nodes[0].ip()
	nodePort := int(svc.Spec.Ports[0].NodePort)
	addr := fmt.Sprintf("http://%s:%d", nodeIP, nodePort)

	cmd := append([]string{"curl", "--connect-timeout", "1", "--retry", "5", "--retry-connrefused"}, addr)
	stdout, stderr, err := data.runCommandFromPod(testNamespace, clientName, agnhostContainerName, cmd)
	if err != nil {
		t.Errorf("Error when running command '%s' from Pod '%s', stdout: %s, stderr: %s, error: %v",
			strings.Join(cmd, " "), clientName, stdout, stderr, err)
	} else {
		t.Logf("curl from Pod '%s' to '%s' succeeded", clientName, addr)
	}
}

func (data *TestData) createAgnhostServiceAndBackendPods(t *testing.T, name string, node string, svcType corev1.ServiceType) (*corev1.Service, func()) {
	ipv4Protocol := corev1.IPv4Protocol
	args := []string{"netexec", "--http-port=80", "--udp-port=80"}
	require.NoError(t, data.createPodOnNode(name, testNamespace, node, agnhostImage, []string{}, args, nil, []corev1.ContainerPort{
		{
			Name:          "http",
			ContainerPort: 80,
			Protocol:      corev1.ProtocolTCP,
		},
	}, false, nil))
	_, err := data.podWaitForIPs(defaultTimeout, name, testNamespace)
	require.NoError(t, err)
	require.NoError(t, data.podWaitForRunning(defaultTimeout, name, testNamespace))
	svc, err := data.createService(name, 80, 80, map[string]string{"app": "agnhost"}, false, false, svcType, &ipv4Protocol)
	require.NoError(t, err)

	cleanup := func() {
		data.deletePodAndWait(defaultTimeout, name, testNamespace)
		data.deleteServiceAndWait(defaultTimeout, name)
	}

	return svc, cleanup
}
