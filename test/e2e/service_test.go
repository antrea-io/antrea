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
	"testing"
	"time"

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

	data.testClusterIP(t, isIPv6, data.testNamespace, data.testNamespace)
}

func (data *TestData) testClusterIP(t *testing.T, isIPv6 bool, clientNamespace, serverNamespace string) {
	nodes := []string{nodeName(0), nodeName(1)}
	clients := make(map[string]string)
	for idx, node := range nodes {
		podName, _, cleanupFunc := createAndWaitForPod(t, data, data.createAgnhostPodOnNode, fmt.Sprintf("client-%d-", idx), node, clientNamespace, false)
		clients[node] = podName
		defer cleanupFunc()
	}
	hostNetworkClients := make(map[string]string)
	for idx, node := range nodes {
		podName, _, cleanupFunc := createAndWaitForPod(t, data, data.createAgnhostPodOnNode, fmt.Sprintf("hostnet-client-%d-", idx), node, clientNamespace, true)
		hostNetworkClients[node] = podName
		defer cleanupFunc()
	}

	nginx := fmt.Sprintf("nginx-%v-", isIPv6)
	hostNginx := fmt.Sprintf("nginx-host-%v", isIPv6)
	ipProtocol := corev1.IPv4Protocol
	if isIPv6 {
		ipProtocol = corev1.IPv6Protocol
	}
	clusterIPSvc, err := data.createNginxClusterIPService(fmt.Sprintf("nginx-%v", isIPv6), serverNamespace, true, &ipProtocol)
	require.NoError(t, err)
	defer data.deleteService(clusterIPSvc.Namespace, clusterIPSvc.Name)
	require.NotEqual(t, "", clusterIPSvc.Spec.ClusterIP, "ClusterIP should not be empty")
	url := net.JoinHostPort(clusterIPSvc.Spec.ClusterIP, "80")

	t.Run("No Endpoint", func(t *testing.T) {
		skipIfNamespaceIsNotEqual(t, serverNamespace, data.testNamespace)
		testClusterIPCases(t, data, url, clients, hostNetworkClients, clientNamespace, Rejected)
	})

	t.Run("Non-HostNetwork Endpoints", func(t *testing.T) {
		_, _, cleanupFunc := createAndWaitForPod(t, data, data.createNginxPodOnNode, nginx, nodeName(0), serverNamespace, false)
		defer cleanupFunc()
		// Wait for complete synchronization of the test Service after updating the Endpoints.
		time.Sleep(time.Second)
		testClusterIPCases(t, data, url, clients, hostNetworkClients, clientNamespace, Connected)
	})

	t.Run("HostNetwork Endpoints", func(t *testing.T) {
		_, _, cleanupFunc := createAndWaitForPod(t, data, data.createNginxPodOnNode, hostNginx, nodeName(0), serverNamespace, true)
		defer cleanupFunc()
		skipIfNamespaceIsNotEqual(t, serverNamespace, data.testNamespace)
		// Wait for complete synchronization of the test Service after updating the Endpoints.
		time.Sleep(time.Second)
		testClusterIPCases(t, data, url, clients, hostNetworkClients, clientNamespace, Connected)
	})
}

func testClusterIPCases(t *testing.T, data *TestData, url string, clients, hostNetworkClients map[string]string, namespace string, expectedConnectivity PodConnectivityMark) {
	t.Run("Connect to Service ClusterIP from Node", func(t *testing.T) {
		skipIfProxyAllDisabled(t, data)
		skipIfKubeProxyEnabled(t, data)
		skipIfNamespaceIsNotEqual(t, namespace, data.testNamespace)
		for node, pod := range hostNetworkClients {
			testClusterIPFromPod(t, data, url, node, pod, true, namespace, expectedConnectivity)
		}
	})
	t.Run("Connect to Service ClusterIP from Pod", func(t *testing.T) {
		for node, pod := range clients {
			testClusterIPFromPod(t, data, url, node, pod, false, namespace, expectedConnectivity)
		}
	})
}

func testClusterIPFromPod(t *testing.T, data *TestData, url, nodeName, podName string, hostNetwork bool, namespace string, expectedConnectivity PodConnectivityMark) {
	cmd := ProbeCommand(url, "tcp", "")
	stdout, stderr, err := data.RunCommandFromPod(namespace, podName, agnhostContainerName, cmd)
	connectivity := Connected
	if err != nil || stderr != "" {
		// If err != nil and stderr == "", then it means this probe failed because of the command instead of connectivity.
		// For example, container name doesn't exist.
		if stderr == "" {
			connectivity = Error
		}
		connectivity = DecideProbeResult(stderr, 3)
	}
	require.Equal(t, expectedConnectivity, connectivity, "Accessing ClusterIP from Pod got unexpected result", "Pod", podName, "hostNetwork", hostNetwork, "Node", nodeName, "url", url, "stdout", stdout, "stderr", stderr, "err", err)
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

	data.testNodePort(t, true, data.testNamespace, data.testNamespace)
}

func (data *TestData) testNodePort(t *testing.T, isWindows bool, clientNamespace, serverNamespace string) {
	svcName := "agnhost"
	svcNode := ""
	if isWindows {
		svcNode = nodeName(clusterInfo.windowsNodes[0])
	} else {
		svcNode = nodeName(1)
	}
	svc, cleanup := data.createAgnhostServiceAndBackendPods(t, svcName, serverNamespace, svcNode, corev1.ServiceTypeNodePort)
	defer cleanup()
	t.Logf("%s Service is ready", svcName)

	// Unlike upstream Kubernetes Conformance, here the client is on a Linux Node (nodeName(0)).
	// It doesn't need to be the control-plane for e2e test and other Linux workers will work as well. However, in this
	// e2e framework, nodeName(0)/Control-plane Node is guaranteed to be a Linux one.
	clientName := "toolbox-client"
	require.NoError(t, data.createToolboxPodOnNode(clientName, clientNamespace, nodeName(0), false))
	defer data.DeletePodAndWait(defaultTimeout, clientName, clientNamespace)
	podIPs, err := data.podWaitForIPs(defaultTimeout, clientName, clientNamespace)
	require.NoError(t, err)
	t.Logf("Created client Pod IPs %v", podIPs.IPStrings)

	url := getHTTPURLFromIPPort(clusterInfo.nodes[0].ip(), svc.Spec.Ports[0].NodePort)

	stdout, stderr, err := data.runWgetCommandOnToolboxWithRetry(clientName, clientNamespace, url, 5)
	if err != nil {
		t.Errorf("Error when running 'wget -O - %s' from Pod '%s', stdout: %s, stderr: %s, error: %v",
			url, clientName, stdout, stderr, err)
	} else {
		t.Logf("wget from Pod '%s' to '%s' succeeded", clientName, url)
	}
}

func (data *TestData) createAgnhostServiceAndBackendPods(t *testing.T, name, namespace string, node string, svcType corev1.ServiceType) (*corev1.Service, func()) {
	ipProtocol := corev1.IPv4Protocol
	args := []string{"netexec", "--http-port=80", "--udp-port=80"}
	require.NoError(t, NewPodBuilder(name, namespace, agnhostImage).OnNode(node).WithArgs(args).WithPorts([]corev1.ContainerPort{
		{
			Name:          "http",
			ContainerPort: 80,
			Protocol:      corev1.ProtocolTCP,
		},
	}).Create(data))
	podIPs, err := data.podWaitForIPs(defaultTimeout, name, namespace)
	require.NoError(t, err)
	t.Logf("Created service Pod IPs %v", podIPs.IPStrings)
	if podIPs.IPv4 == nil {
		// "IPv4" is invalid in IPv6 only cluster with K8s>=1.21
		// error: Service "s1" is invalid: spec.ipFamilies[0]: Invalid value: "IPv4": not configured on this cluster
		ipProtocol = corev1.IPv6Protocol
	}
	require.NoError(t, data.podWaitForRunning(defaultTimeout, name, namespace))
	svc, err := data.CreateService(name, namespace, 80, 80, map[string]string{"app": "agnhost", "antrea-e2e": name}, false, false, svcType, &ipProtocol)
	require.NoError(t, err)
	t.Logf("Created service Cluster IP %v", svc.Spec.ClusterIP)

	cleanup := func() {
		data.DeletePodAndWait(defaultTimeout, name, namespace)
		data.deleteServiceAndWait(defaultTimeout, name, namespace)
	}

	return svc, cleanup
}
