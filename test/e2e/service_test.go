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

	testFromNode := func(node string) {
		// Retry is needed for rules to be installed by kube-proxy/antrea-proxy.
		cmd := fmt.Sprintf("curl --connect-timeout 1 --retry 5 --retry-connrefused %s:80", svc.Spec.ClusterIP)
		rc, stdout, stderr, err := RunCommandOnNode(node, cmd)
		if rc != 0 || err != nil {
			t.Errorf("Error when running command '%s' on Node '%s', rc: %d, stdout: %s, stderr: %s, error: %v",
				cmd, node, rc, stdout, stderr, err)
		}
	}

	testFromPod := func(podName, nodeName string) {
		require.NoError(t, data.createBusyboxPodOnNode(podName, nodeName))
		defer data.deletePodAndWait(defaultTimeout, podName)
		require.NoError(t, data.podWaitForRunning(defaultTimeout, podName, testNamespace))
		err := data.runNetcatCommandFromTestPod(podName, svc.Spec.ClusterIP, 80)
		require.NoError(t, err, "Pod %s should be able to connect %s, but was not able to connect", podName, net.JoinHostPort(svc.Spec.ClusterIP, fmt.Sprint(80)))
	}

	t.Run("ClusterIP", func(t *testing.T) {
		t.Run("Same Linux Node can access the Service", func(t *testing.T) {
			t.Parallel()
			testFromNode(serverPodNode)
		})
		t.Run("Different Linux Node can access the Service", func(t *testing.T) {
			t.Parallel()
			skipIfNumNodesLessThan(t, 2)
			testFromNode(nodeName(1))
		})
		t.Run("Windows host can access the Service", func(t *testing.T) {
			t.Parallel()
			skipIfNoWindowsNodes(t)
			idx := clusterInfo.windowsNodes[0]
			winNode := clusterInfo.nodes[idx].name
			testFromNode(winNode)
		})
		t.Run("Linux Pod on same Node can access the Service", func(t *testing.T) {
			t.Parallel()
			testFromPod("client-on-same-node", serverPodNode)
		})
		t.Run("Linux Pod on different Node can access the Service", func(t *testing.T) {
			t.Parallel()
			skipIfNumNodesLessThan(t, 2)
			testFromPod("client-on-different-node", nodeName(1))
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
	require.NoError(t, data.createAgnhostPodOnNode(clientName, nodeName(0)))
	defer data.deletePodAndWait(defaultTimeout, clientName)
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
	require.NoError(t, data.createPodOnNode(name, node, agnhostImage, []string{}, args, nil, []corev1.ContainerPort{
		{
			Name:          "http",
			ContainerPort: 80,
			Protocol:      corev1.ProtocolTCP,
		},
	}, false, nil))
	_, err := data.podWaitForIPs(defaultTimeout, name, testNamespace)
	require.NoError(t, err)
	require.NoError(t, data.podWaitForRunning(defaultTimeout, name, testNamespace))
	svc, err := data.createService(name, 80, 80, map[string]string{"app": "agnhost"}, false, svcType, &ipv4Protocol)
	require.NoError(t, err)

	cleanup := func() {
		data.deletePodAndWait(defaultTimeout, name)
		data.deleteServiceAndWait(defaultTimeout, name)
	}

	return svc, cleanup
}
