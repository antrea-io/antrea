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
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

func TestIPv4ClusterIP(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	skipIfNumNodesLessThan(t, 2)
	skipIfNotIPv4Cluster(t)

	clientPodCp := "busybox-cp"
	clientPodWk := "busybox-wk"
	createTestClientPods(t, data, clientPodCp, clientPodWk)
	testClusterIPHelper(t, data, false, clientPodCp, clientPodWk)
}

func TestIPv6ClusterIP(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	skipIfNumNodesLessThan(t, 2)
	skipIfNotIPv6Cluster(t)

	clientPodCp := "busybox-cp"
	clientPodWk := "busybox-wk"
	createTestClientPods(t, data, clientPodCp, clientPodWk)
	testClusterIPHelper(t, data, true, clientPodCp, clientPodWk)
}

func testClusterIPHelper(t *testing.T, data *TestData, isIPv6 bool, clientPodCp, clientPodWk string) {
	testPodName := fmt.Sprintf("nginx-%v", isIPv6)
	createTestNginxPod(t, data, testPodName, false)
	clusterIP := createClusterIPService(t, data, isIPv6)
	time.Sleep(2 * time.Second)
	url := "http://" + net.JoinHostPort(clusterIP, "80")
	t.Run("Pod CIDR Endpoints", func(t *testing.T) {
		testClusterIPCases(t, data, url, testPodName, clientPodCp, clientPodWk)
	})
	deleteTestNginxPod(t, data, testPodName)

	testPodHostNetworkName := fmt.Sprintf("echoserver-cp-h-%v", isIPv6)
	createTestNginxPod(t, data, testPodHostNetworkName, true)
	time.Sleep(2 * time.Second)
	t.Run("Host Network Endpoints", func(t *testing.T) {
		testClusterIPCases(t, data, url, nodeName(0), clientPodCp, clientPodWk)
	})
	deleteTestNginxPod(t, data, testPodHostNetworkName)
}

func testClusterIPCases(t *testing.T, data *TestData, url, hostname, clientPodCp, clientPodWk string) {
	t.Run("Host on different Node can access the Service", func(t *testing.T) {
		t.Parallel()
		skipIfKubeProxyEnabledOnLinux(t, data, nodeName(1))
		skipIfProxyFullDisabled(t)
		testClusterIPFromNode(t, url, nodeName(1))
	})
	t.Run("Host on the same Node can access the Service", func(t *testing.T) {
		t.Parallel()
		skipIfKubeProxyEnabledOnLinux(t, data, nodeName(0))
		skipIfProxyFullDisabled(t)
		testClusterIPFromNode(t, url, nodeName(0))
	})
	t.Run("Pod on same Node can access the Service", func(t *testing.T) {
		t.Parallel()
		testClusterIPFromPod(t, data, url, clientPodCp)
	})
	t.Run("Pod on different Node can access the Service", func(t *testing.T) {
		t.Parallel()
		testClusterIPFromPod(t, data, url, clientPodWk)
	})
}

func testClusterIPFromPod(t *testing.T, data *TestData, url, podName string) {
	errMsg := "Server ClusterIP should be able to be connected from pod"
	_, _, err := data.runCommandFromPod(testNamespace, podName, busyboxContainerName, []string{"wget", "-O", "-", url, "-T", "1"})
	require.NoError(t, err, errMsg)
}

func testClusterIPFromNode(t *testing.T, url, nodeName string) {
	errMsg := "Server ClusterIP should be able to be connected from node on the same k8s node"
	_, _, _, err := RunCommandOnNode(nodeName, strings.Join([]string{"wget", "-O", "-", url, "-T", "1"}, " "))
	require.NoError(t, err, errMsg)
}

func createClusterIPService(t *testing.T, data *TestData, isIPv6 bool) string {
	ipProctol := corev1.IPv4Protocol
	if isIPv6 {
		ipProctol = corev1.IPv6Protocol
	}
	clusterIP, err := data.createNginxClusterIPService(fmt.Sprintf("echoserver-%v", isIPv6), false, &ipProctol)
	require.NoError(t, err)
	return clusterIP.Spec.ClusterIP
}

func createTestNginxPod(t *testing.T, data *TestData, testPodName string, hostNetwork bool) {
	require.NoError(t, data.createNginxPodOnNodeV2(testPodName, nodeName(0), false))
	_, err := data.podWaitForIPs(defaultTimeout, testPodName, testNamespace)
	require.NoError(t, err)
	require.NoError(t, data.podWaitForRunning(defaultTimeout, testPodName, testNamespace))
}

func deleteTestNginxPod(t *testing.T, data *TestData, testPodName string) {
	err := data.deletePod(testNamespace, testPodName)
	require.NoError(t, err)
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

	nodeIP := clusterInfo.nodes[0].ip
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
