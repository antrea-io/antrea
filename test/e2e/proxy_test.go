// Copyright 2020 Antrea Authors
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
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"antrea.io/antrea/pkg/features"
)

type expectTableFlows struct {
	tableID int
	flows   []string
}

// TestProxy is the top-level test which contains all subtests for
// Proxy related test cases so they can share setup, teardown.
func TestProxy(t *testing.T) {
	skipIfHasWindowsNodes(t)
	skipIfProxyDisabled(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	t.Run("testProxyServiceSessionAffinityCase", func(t *testing.T) {
		skipIfProviderIs(t, "kind", "#881 Does not work in Kind, needs to be investigated.")
		testProxyServiceSessionAffinityCase(t, data)
	})
	t.Run("testProxyHairpinCase", func(t *testing.T) {
		testProxyHairpinCase(t, data)
	})
	t.Run("testProxyEndpointLifeCycleCase", func(t *testing.T) {
		testProxyEndpointLifeCycleCase(t, data)
	})
	t.Run("testProxyServiceLifeCycleCase", func(t *testing.T) {
		testProxyServiceLifeCycleCase(t, data)
	})
}

func skipIfProxyDisabled(t *testing.T) {
	skipIfFeatureDisabled(t, features.AntreaProxy, true /* checkAgent */, false /* checkController */)
}

func testProxyServiceSessionAffinityCase(t *testing.T, data *TestData) {
	if len(clusterInfo.podV4NetworkCIDR) != 0 {
		ipFamily := corev1.IPv4Protocol
		testProxyServiceSessionAffinity(&ipFamily, []string{"169.254.169.253", "169.254.169.254"}, data, t)
	}
	if len(clusterInfo.podV6NetworkCIDR) != 0 {
		ipFamily := corev1.IPv6Protocol
		testProxyServiceSessionAffinity(&ipFamily, []string{"fd75::aabb:ccdd:ef00", "fd75::aabb:ccdd:ef01"}, data, t)
	}
}

func skipIfProxyFullDisabled(t *testing.T, data *TestData) {
	isProxyFull, err := data.IsProxyFull()
	if err != nil {
		t.Fatalf("Error getting option antreaProxyFull value")
	}
	if !isProxyFull {
		t.Skipf("Skipping test because option antreaProxyFull is not enabled")
	}
}

func skipIfKubeProxyEnabledOnLinux(t *testing.T, data *TestData, nodeName string) {
	pods, err := data.clientset.CoreV1().Pods(antreaNamespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("Error fetching pods: %v", err)
	}
	for _, pod := range pods.Items {
		if strings.Contains(pod.Name, "kube-proxy") && pod.Spec.NodeName == nodeName {
			t.Skipf("Skipping test because kube-proxy is running")
		}
	}
}

func TestProxyLoadBalancerService(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	skipIfProxyDisabled(t)
	skipIfProxyFullDisabled(t, data)
	skipIfHasWindowsNodes(t)
	skipIfNumNodesLessThan(t, 2)

	testPodNameCp := "echoserver-cp"
	testPodNameWk := "echoserver-wk"
	clientPodCp := "busybox-cp"
	clientPodWk := "busybox-wk"
	clusterIngressIP := []string{"169.254.169.1"}
	localIngressIP := []string{"169.254.169.2"}
	port := "8080"

	clientCpIP, clientWkIP := createTestClientPods(t, data, clientPodCp, clientPodWk)
	createTestEchoServerPods(t, data, testPodNameCp, testPodNameWk, false)
	createLoadBalancerServices(t, data, clusterIngressIP, localIngressIP)
	clusterUrl := net.JoinHostPort(clusterIngressIP[0], port)
	localUrl := net.JoinHostPort(localIngressIP[0], port)

	t.Run("Pod CIDR Endpoints", func(t *testing.T) {
		loadBalancerTestCases(t, data, clusterUrl, localUrl, clientPodCp, clientPodWk, clientCpIP, clientWkIP, testPodNameCp, testPodNameWk)
	})

	testPodHostNetworkNameCp := "echoserver-cp-h"
	testPodHostNetworkNameWk := "echoserver-wk-h"
	nodeNameCp := controlPlaneNodeName()
	nodeNameWk := workerNodeName(1)
	deleteTestEchoServerPods(t, data, testPodNameCp, testPodNameWk)
	createTestEchoServerPods(t, data, testPodHostNetworkNameCp, testPodHostNetworkNameWk, true)
	t.Run("Host Network Endpoints", func(t *testing.T) {
		loadBalancerTestCases(t, data, clusterUrl, localUrl, clientPodCp, clientPodWk, clientCpIP, clientWkIP, nodeNameCp, nodeNameWk)
	})
}

func loadBalancerTestCases(t *testing.T, data *TestData, clusterUrl, localUrl, clientCp, clientWk, clientCpIP, clientWkIP,
	testPodHostnameCp, testPodHostnameWk string) {
	t.Run("Case=ExternalTrafficPolicy:Cluster Client:Local", func(t *testing.T) {
		testLoadBalancerClusterFromLocal(t, data, clusterUrl)
	})
	t.Run("Case=ExternalTrafficPolicy:Cluster Client:Pod", func(t *testing.T) {
		testLoadBalancerClusterFromPod(t, data, clusterUrl, clientCp, clientWk)
	})
	t.Run("Case=ExternalTrafficPolicy:Local Client:Local", func(t *testing.T) {
		testLoadBalancerLocalFromLocal(t, data, localUrl, testPodHostnameCp, testPodHostnameWk)
	})
	t.Run("Case=ExternalTrafficPolicy:Local Client:Pod", func(t *testing.T) {
		testLoadBalancerLocalFromPod(t, data, localUrl, clientCp, clientWk, clientCpIP, clientWkIP, testPodHostnameCp, testPodHostnameWk)
	})
}

func createLoadBalancerServices(t *testing.T, data *TestData, ingressIPCluster, ingressIPLocal []string) {
	ipProctol := corev1.IPv4Protocol
	_, err := data.createEchoServerLoadBalancerService("echoserver-cluster", true, false, ingressIPCluster, &ipProctol)
	require.NoError(t, err)
	_, err = data.createEchoServerLoadBalancerService("echoserver-local", true, true, ingressIPLocal, &ipProctol)
	require.NoError(t, err)
}

func testLoadBalancerClusterFromLocal(t *testing.T, data *TestData, url string) {
	errMsg := "Server LoadBalancer whose externalTrafficPolicy is Cluster should be able to be connected from local"

	nodeCp := controlPlaneNodeName()
	skipIfKubeProxyEnabledOnLinux(t, data, nodeCp)
	_, _, _, err := RunCommandOnNode(nodeCp, strings.Join([]string{"wget", "-O", "-", url, "-T", "1"}, " "))
	require.NoError(t, err, errMsg)

	nodeWk := workerNodeName(1)
	skipIfKubeProxyEnabledOnLinux(t, data, nodeWk)
	_, _, _, err = RunCommandOnNode(nodeWk, strings.Join([]string{"wget", "-O", "-", url, "-T", "1"}, " "))
	require.NoError(t, err, errMsg)
}

func testLoadBalancerClusterFromPod(t *testing.T, data *TestData, url, clientCp, clientWk string) {
	errMsg := "Server LoadBalancer whose externalTrafficPolicy is Cluster should be able to be connected from pod"
	_, _, err := data.runCommandFromPod(testNamespace, clientCp, busyboxContainerName, []string{"wget", "-O", "-", url, "-T", "1"})
	require.NoError(t, err, errMsg)
	_, _, err = data.runCommandFromPod(testNamespace, clientWk, busyboxContainerName, []string{"wget", "-O", "-", url, "-T", "1"})
	require.NoError(t, err, errMsg)
}

func testLoadBalancerLocalFromLocal(t *testing.T, data *TestData, url, nodeHostnameCp, nodeHostnameWk string) {
	errMsg := "Server LoadBalancer whose externalTrafficPolicy is Local should be able to be connected from local"

	nodeCp := controlPlaneNodeName()
	skipIfKubeProxyEnabledOnLinux(t, data, nodeCp)
	_, output, _, err := RunCommandOnNode(nodeCp, strings.Join([]string{"wget", "-O", "-", url, "-T", "1"}, " "))
	require.NoError(t, err, errMsg)
	require.Contains(t, output, fmt.Sprintf("Hostname: %s", nodeHostnameCp), fmt.Sprintf("hostname should be %s", nodeHostnameCp))

	nodeWk := workerNodeName(1)
	skipIfKubeProxyEnabledOnLinux(t, data, nodeWk)
	_, output, _, err = RunCommandOnNode(nodeWk, strings.Join([]string{"wget", "-O", "-", url, "-T", "1"}, " "))
	require.NoError(t, err, errMsg)
	require.Contains(t, output, fmt.Sprintf("Hostname: %s", nodeHostnameWk), fmt.Sprintf("hostname should be %s", nodeHostnameWk))
}

func testLoadBalancerLocalFromPod(t *testing.T, data *TestData, url, clientCp, clientWk, clientCpIP, clientWkIP, testPodHostnameCp, testPodHostnameWk string) {
	errMsg := "Server NodePort whose externalTrafficPolicy is Local should be able to be connected from pod "
	output, _, err := data.runCommandFromPod(testNamespace, clientCp, busyboxContainerName, []string{"wget", "-O", "-", url, "-T", "1"})
	require.NoError(t, err, errMsg)
	require.Contains(t, output, fmt.Sprintf("Hostname: %s", testPodHostnameCp), fmt.Sprintf("hostname should be %s", testPodHostnameCp))
	require.Contains(t, output, fmt.Sprintf("client_address=%s", clientCpIP), fmt.Sprintf("client IP should be %s", clientCpIP))

	output, _, err = data.runCommandFromPod(testNamespace, clientWk, busyboxContainerName, []string{"wget", "-O", "-", url, "-T", "1"})
	require.NoError(t, err, errMsg)
	require.Contains(t, output, fmt.Sprintf("Hostname: %s", testPodHostnameWk), fmt.Sprintf("hostname should be %s", testPodHostnameWk))
	require.Contains(t, output, fmt.Sprintf("client_address=%s", clientWkIP), fmt.Sprintf("client IP should be %s", clientWkIP))
}

func TestProxyNodePortService(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	skipIfProxyDisabled(t)
	skipIfProxyFullDisabled(t, data)
	skipIfHasWindowsNodes(t)
	skipIfNumNodesLessThan(t, 2)

	testPodNameCp := "echoserver-cp"
	testPodNameWk := "echoserver-wk"
	clientPodCp := "busybox-cp"
	clientPodWk := "busybox-wk"

	podClientCpIP, podClientWkIP := createTestClientPods(t, data, clientPodCp, clientPodWk)
	createTestEchoServerPods(t, data, testPodNameCp, testPodNameWk, false)
	portCluster, portLocal := createNodePortServices(t, data)
	nodeCpIP := controlPlaneNodeIP()
	nodeWkIP := workerNodeIP(1)
	clusterUrlCp := net.JoinHostPort(nodeCpIP, portCluster)
	clusterUrlWk := net.JoinHostPort(nodeWkIP, portCluster)
	clusterUrlLo := net.JoinHostPort("127.0.0.1", portCluster)
	localUrlCp := net.JoinHostPort(nodeCpIP, portLocal)
	localUrlWk := net.JoinHostPort(nodeWkIP, portLocal)
	localUrlLo := net.JoinHostPort("127.0.0.1", portLocal)

	t.Run("Pod CIDR Endpoints", func(t *testing.T) {
		nodePortTestCases(t, data, clusterUrlCp, clusterUrlWk, clusterUrlLo, localUrlCp, localUrlWk, localUrlLo,
			nodeCpIP, nodeWkIP, podClientCpIP, podClientWkIP, testPodNameCp, testPodNameWk, clientPodCp, clientPodWk, false)
	})

	testPodHostNetworkNameCp := "echoserver-cp-h"
	testPodHostNetworkNameWk := "echoserver-wk-h"
	nodeNameCp := controlPlaneNodeName()
	nodeNameWk := workerNodeName(1)
	deleteTestEchoServerPods(t, data, testPodNameCp, testPodNameWk)
	createTestEchoServerPods(t, data, testPodHostNetworkNameCp, testPodHostNetworkNameWk, true)
	t.Run("Host Network Endpoints", func(t *testing.T) {
		nodePortTestCases(t, data, clusterUrlCp, clusterUrlWk, clusterUrlLo, localUrlCp, localUrlWk, localUrlLo,
			nodeCpIP, nodeWkIP, podClientCpIP, podClientWkIP, nodeNameCp, nodeNameWk, clientPodCp, clientPodWk, true)
	})
}

func nodePortTestCases(t *testing.T, data *TestData, clusterUrlCp, clusterUrlWk, clusterUrlLo, localUrlCp, localUrlWk, localUrlLo string,
	nodeCpIP, nodeWkIP, podClientCpIP, podClientWkIP, testPodHostnameCp, testPodHostnameWk, clientPodCp, clientPodWk string, hostNetwork bool) {
	t.Run("Case=ExternalTrafficPolicy:Cluster Client:Remote", func(t *testing.T) {
		testNodePortClusterFromRemote(t, clusterUrlCp, clusterUrlCp)
	})
	t.Run("Case=ExternalTrafficPolicy:Cluster Client:Local", func(t *testing.T) {
		testNodePortClusterFromLocal(t, data, clusterUrlCp, clusterUrlWk, clusterUrlLo)
	})
	t.Run("Case=ExternalTrafficPolicy:Cluster Client:Pod", func(t *testing.T) {
		testNodePortClusterFromPod(t, data, clusterUrlCp, clusterUrlCp, clientPodCp, clientPodWk)
	})
	t.Run("Case=ExternalTrafficPolicy:Local Client:Remote", func(t *testing.T) {
		if hostNetwork {
			t.Skipf("Skip this test if Endpoint is on host network")
		}
		testNodePortLocalFromRemote(t, localUrlCp, localUrlWk, nodeCpIP, nodeWkIP, testPodHostnameCp, testPodHostnameWk)
	})
	t.Run("Case=ExternalTrafficPolicy:Local Client:Local", func(t *testing.T) {
		testNodePortLocalFromLocal(t, data, localUrlCp, localUrlWk, localUrlLo, nodeCpIP, nodeWkIP, testPodHostnameCp, testPodHostnameWk)
	})
	t.Run("Case=ExternalTrafficPolicy:Local Client:Pod", func(t *testing.T) {
		testNodePortLocalFromPod(t, data, localUrlCp, localUrlWk, clientPodCp, clientPodWk, podClientCpIP, podClientWkIP, testPodHostnameCp, testPodHostnameWk)
	})
}

func createTestEchoServerPods(t *testing.T, data *TestData, echoServerCp, echoServerWk string, hostNetwork bool) {
	// Create test echoserver pod on each node.
	if echoServerCp != "" {
		require.NoError(t, data.createEchoServerPodOnNode(echoServerCp, nodeName(0), hostNetwork))
		_, err := data.podWaitForIPs(defaultTimeout, echoServerCp, testNamespace)
		require.NoError(t, err)
		require.NoError(t, data.podWaitForRunning(defaultTimeout, echoServerCp, testNamespace))
	}
	if echoServerWk != "" {
		require.NoError(t, data.createEchoServerPodOnNode(echoServerWk, nodeName(1), hostNetwork))
		_, err := data.podWaitForIPs(defaultTimeout, echoServerWk, testNamespace)
		require.NoError(t, err)
		require.NoError(t, data.podWaitForRunning(defaultTimeout, echoServerWk, testNamespace))
	}
}

func createTestClientPods(t *testing.T, data *TestData, clientCp, clientWk string) (string, string) {
	// Create a busybox Pod on each node which is used as test client.
	require.NoError(t, data.createBusyboxPodOnNode(clientCp, testNamespace, nodeName(0)))
	require.NoError(t, data.podWaitForRunning(defaultTimeout, clientCp, testNamespace))
	busyboxCpPod, err := data.podWaitFor(defaultTimeout, clientCp, testNamespace, func(pod *corev1.Pod) (bool, error) {
		return pod.Status.Phase == corev1.PodRunning, nil
	})
	require.NoError(t, err)
	require.NotNil(t, busyboxCpPod.Status)
	require.NoError(t, data.createBusyboxPodOnNode(clientWk, testNamespace, nodeName(1)))
	require.NoError(t, data.podWaitForRunning(defaultTimeout, clientWk, testNamespace))
	busyboxWkPod, err := data.podWaitFor(defaultTimeout, clientWk, testNamespace, func(pod *corev1.Pod) (bool, error) {
		return pod.Status.Phase == corev1.PodRunning, nil
	})
	require.NoError(t, err)
	require.NotNil(t, busyboxWkPod.Status)
	return busyboxCpPod.Status.PodIP, busyboxWkPod.Status.PodIP
}

func deleteTestEchoServerPods(t *testing.T, data *TestData, echoServerCp, echoServerWk string) {
	if echoServerCp != "" {
		require.NoError(t, data.deletePod(testNamespace, echoServerCp))
	}
	if echoServerWk != "" {
		require.NoError(t, data.deletePod(testNamespace, echoServerWk))
	}
}

func createNodePortServices(t *testing.T, data *TestData) (string, string) {
	ipProctol := corev1.IPv4Protocol
	nodePortCluster, err := data.createEchoServerNodePortService("echoserver-cluster", false, false, &ipProctol)
	require.NoError(t, err)
	nodePortLocal, err := data.createEchoServerNodePortService("echoserver-local", false, true, &ipProctol)
	require.NoError(t, err)
	var portCluster, portLocal string
	for _, port := range nodePortCluster.Spec.Ports {
		if port.NodePort != 0 {
			portCluster = fmt.Sprint(port.NodePort)
			break
		}
	}
	for _, port := range nodePortLocal.Spec.Ports {
		if port.NodePort != 0 {
			portLocal = fmt.Sprint(port.NodePort)
			break
		}
	}
	return portCluster, portLocal
}

func testNodePortClusterFromRemote(t *testing.T, urlCp, urlWk string) {
	errMsg := "Server NodePort whose externalTrafficPolicy is Cluster should be able to be connected from remote"
	_, _, _, err := RunCommandOnNode(controlPlaneNodeName(), strings.Join([]string{"wget", "-O", "-", urlWk, "-T", "1"}, " "))
	require.NoError(t, err, errMsg)
	_, _, _, err = RunCommandOnNode(workerNodeName(1), strings.Join([]string{"wget", "-O", "-", urlCp, "-T", "1"}, " "))
	require.NoError(t, err, errMsg)
}

func testNodePortClusterFromLocal(t *testing.T, data *TestData, urlCp, urlWk, urlLo string) {
	errMsg := "Server NodePort whose externalTrafficPolicy is Cluster should be able to be connected from localhost"

	nodeCp := controlPlaneNodeName()
	skipIfKubeProxyEnabledOnLinux(t, data, nodeCp)
	_, _, _, err := RunCommandOnNode(nodeCp, strings.Join([]string{"wget", "-O", "-", urlCp, "-T", "1"}, " "))
	require.NoError(t, err, errMsg)
	_, _, _, err = RunCommandOnNode(nodeCp, strings.Join([]string{"wget", "-O", "-", urlLo, "-T", "1"}, " "))
	require.NoError(t, err, errMsg)

	nodeWk := workerNodeName(1)
	skipIfKubeProxyEnabledOnLinux(t, data, nodeWk)
	_, _, _, err = RunCommandOnNode(nodeWk, strings.Join([]string{"wget", "-O", "-", urlWk, "-T", "1"}, " "))
	require.NoError(t, err, errMsg)
	_, _, _, err = RunCommandOnNode(nodeWk, strings.Join([]string{"wget", "-O", "-", urlLo, "-T", "1"}, " "))
	require.NoError(t, err, errMsg)
}

func testNodePortClusterFromPod(t *testing.T, data *TestData, urlCp, urlWk, clientCp, clientWk string) {
	errMsg := "Server NodePort whose externalTrafficPolicy is Cluster should be able to be connected from pod"
	_, _, err := data.runCommandFromPod(testNamespace, clientCp, busyboxContainerName, []string{"wget", "-O", "-", urlCp, "-T", "1"})
	require.NoError(t, err, errMsg)
	_, _, err = data.runCommandFromPod(testNamespace, clientCp, busyboxContainerName, []string{"wget", "-O", "-", urlWk, "-T", "1"})
	require.NoError(t, err, errMsg)
	_, _, err = data.runCommandFromPod(testNamespace, clientWk, busyboxContainerName, []string{"wget", "-O", "-", urlCp, "-T", "1"})
	require.NoError(t, err, errMsg)
	_, _, err = data.runCommandFromPod(testNamespace, clientWk, busyboxContainerName, []string{"wget", "-O", "-", urlWk, "-T", "1"})
	require.NoError(t, err, errMsg)
}

func testNodePortLocalFromRemote(t *testing.T, urlCp, urlWk, nodeIPCp, nodeIPWk, nodeHostnameCp, nodeHostnameWk string) {
	errMsg := "Server NodePort whose externalTrafficPolicy is Local should be able to be connected from remote"
	_, output, _, err := RunCommandOnNode(controlPlaneNodeName(), strings.Join([]string{"wget", "-O", "-", urlWk, "-T", "1"}, " "))
	require.NoError(t, err, errMsg)
	require.Contains(t, output, fmt.Sprintf("Hostname: %s", nodeHostnameWk), fmt.Sprintf("hostname should be %s", nodeHostnameWk))
	require.Contains(t, output, fmt.Sprintf("client_address=%s", nodeIPCp), fmt.Sprintf("client IP should be %s", nodeIPCp))
	_, output, _, err = RunCommandOnNode(workerNodeName(1), strings.Join([]string{"wget", "-O", "-", urlCp, "-T", "1"}, " "))
	require.NoError(t, err, errMsg)
	require.Contains(t, output, fmt.Sprintf("Hostname: %s", nodeHostnameCp), fmt.Sprintf("hostname should be %s", nodeHostnameCp))
	require.Contains(t, output, fmt.Sprintf("client_address=%s", nodeIPWk), fmt.Sprintf("client IP should be %s", nodeIPWk))
}

func testNodePortLocalFromLocal(t *testing.T, data *TestData, urlCp, urlWk, urlLo, nodeIPCp, nodeIPWk, nodeHostnameCp, nodeHostnameWk string) {
	errMsg := "Server NodePort whose externalTrafficPolicy is Local should be able to be connected from local"

	nodeCp := controlPlaneNodeName()
	skipIfKubeProxyEnabledOnLinux(t, data, nodeCp)
	_, output, _, err := RunCommandOnNode(nodeCp, strings.Join([]string{"wget", "-O", "-", urlCp, "-T", "1"}, " "))
	require.NoError(t, err, errMsg)
	require.Contains(t, output, fmt.Sprintf("Hostname: %s", nodeHostnameCp), fmt.Sprintf("hostname should be %s", nodeHostnameCp))
	require.NotContains(t, output, fmt.Sprintf("client_address=%s", nodeIPCp), fmt.Sprintf("client IP should not be %s", nodeIPCp))
	_, output, _, err = RunCommandOnNode(nodeCp, strings.Join([]string{"wget", "-O", "-", urlLo, "-T", "1"}, " "))
	require.NoError(t, err, errMsg)
	require.Contains(t, output, fmt.Sprintf("Hostname: %s", nodeHostnameCp), fmt.Sprintf("hostname should be %s", nodeHostnameCp))
	require.NotContains(t, output, fmt.Sprintf("client_address=%s", nodeIPCp), fmt.Sprintf("client IP should not be %s", nodeIPCp))

	nodeWk := nodeName(1)
	skipIfKubeProxyEnabledOnLinux(t, data, nodeWk)
	_, output, _, err = RunCommandOnNode(nodeWk, strings.Join([]string{"wget", "-O", "-", urlWk, "-T", "1"}, " "))
	require.NoError(t, err, errMsg)
	require.Contains(t, output, fmt.Sprintf("Hostname: %s", nodeHostnameWk), fmt.Sprintf("hostname should be %s", nodeHostnameWk))
	require.NotContains(t, output, fmt.Sprintf("client_address=%s", nodeIPWk), fmt.Sprintf("client IP should not be %s", nodeIPWk))
	_, output, _, err = RunCommandOnNode(nodeWk, strings.Join([]string{"wget", "-O", "-", urlLo, "-T", "1"}, " "))
	require.NoError(t, err, errMsg)
	require.Contains(t, output, fmt.Sprintf("Hostname: %s", nodeHostnameWk), fmt.Sprintf("hostname should be %s", nodeHostnameWk))
	require.NotContains(t, output, fmt.Sprintf("client_address=%s", nodeIPWk), fmt.Sprintf("client IP should not be %s", nodeIPWk))
}

func testNodePortLocalFromPod(t *testing.T, data *TestData, urlCp, urlWk, clientCp, clientWk, clientIPCp, clientIPWk, nodeHostnameCp, nodeHostnameWk string) {
	errMsg := "Server NodePort whose externalTrafficPolicy is Local should be able to be connected from pod "
	output, _, err := data.runCommandFromPod(testNamespace, clientCp, busyboxContainerName, []string{"wget", "-O", "-", urlCp, "-T", "1"})
	require.NoError(t, err, errMsg)
	require.Contains(t, output, fmt.Sprintf("Hostname: %s", nodeHostnameCp), fmt.Sprintf("hostname should be %s", nodeHostnameCp))
	require.Contains(t, output, fmt.Sprintf("client_address=%s", clientIPCp), fmt.Sprintf("client IP should be %s", clientIPCp))

	output, _, err = data.runCommandFromPod(testNamespace, clientWk, busyboxContainerName, []string{"wget", "-O", "-", urlWk, "-T", "1"})
	require.NoError(t, err, errMsg)
	require.Contains(t, output, fmt.Sprintf("Hostname: %s", nodeHostnameWk), fmt.Sprintf("hostname should be %s", nodeHostnameWk))
	require.Contains(t, output, fmt.Sprintf("client_address=%s", clientIPWk), fmt.Sprintf("client IP should be %s", clientIPWk))
}

func TestProxyServiceSessionAffinity(t *testing.T) {
	skipIfProviderIs(t, "kind", "#881 Does not work in Kind, needs to be investigated.")
	skipIfHasWindowsNodes(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	skipIfProxyDisabled(t)

	if len(clusterInfo.podV4NetworkCIDR) != 0 {
		ipFamily := corev1.IPv4Protocol
		testProxyServiceSessionAffinity(&ipFamily, []string{"169.254.169.1", "169.254.169.2"}, data, t)
	}
	if len(clusterInfo.podV6NetworkCIDR) != 0 {
		ipFamily := corev1.IPv6Protocol
		testProxyServiceSessionAffinity(&ipFamily, []string{"fd75::aabb:ccdd:ef00", "fd75::aabb:ccdd:ef01"}, data, t)
	}
}

func testProxyServiceSessionAffinity(ipFamily *corev1.IPFamily, ingressIPs []string, data *TestData, t *testing.T) {
	nodeName := nodeName(1)
	nginx := randName("nginx-")
	isProxyFull, err := data.IsProxyFull()
	if err != nil {
		t.Fatalf("Error getting option antreaProxyFull value")
	}

	require.NoError(t, data.createNginxPodOnNode(nginx, testNamespace, nodeName))
	nginxIP, err := data.podWaitForIPs(defaultTimeout, nginx, testNamespace)
	defer data.deletePodAndWait(defaultTimeout, nginx, testNamespace)
	require.NoError(t, err)
	require.NoError(t, data.podWaitForRunning(defaultTimeout, nginx, testNamespace))
	svc, err := data.createNginxClusterIPService(nginx, true, ipFamily)
	defer data.deleteServiceAndWait(defaultTimeout, nginx)
	require.NoError(t, err)
	_, err = data.createNginxLoadBalancerService(true, ingressIPs, ipFamily)
	defer data.deleteServiceAndWait(defaultTimeout, nginxLBService)
	require.NoError(t, err)

	busyboxPod := randName("busybox-")
	require.NoError(t, data.createBusyboxPodOnNode(busyboxPod, testNamespace, nodeName))
	defer data.deletePodAndWait(defaultTimeout, busyboxPod, testNamespace)
	require.NoError(t, data.podWaitForRunning(defaultTimeout, busyboxPod, testNamespace))
	stdout, stderr, err := data.runCommandFromPod(testNamespace, busyboxPod, busyboxContainerName, []string{"wget", "-O", "-", svc.Spec.ClusterIP, "-T", "1"})
	require.NoError(t, err, fmt.Sprintf("ipFamily: %v\nstdout: %s\nstderr: %s\n", *ipFamily, stdout, stderr))
	for _, ingressIP := range ingressIPs {
		stdout, stderr, err := data.runCommandFromPod(testNamespace, busyboxPod, busyboxContainerName, []string{"wget", "-O", "-", ingressIP, "-T", "1"})
		require.NoError(t, err, fmt.Sprintf("ipFamily: %v\nstdout: %s\nstderr: %s\n", *ipFamily, stdout, stderr))
	}

	// Hold on to make sure that the Service is realized.
	time.Sleep(3 * time.Second)

	agentName, err := data.getAntreaPodOnNode(nodeName)
	require.NoError(t, err)
	table40Output, _, err := data.runCommandFromPod(metav1.NamespaceSystem, agentName, "antrea-agent", []string{"ovs-ofctl", "dump-flows", defaultBridgeName, "table=40"})
	require.NoError(t, err)
	if *ipFamily == corev1.IPv4Protocol {
		require.Contains(t, table40Output, fmt.Sprintf("nw_dst=%s,tp_dst=80", svc.Spec.ClusterIP))
		require.Contains(t, table40Output, fmt.Sprintf("load:0x%s->NXM_NX_REG3[]", strings.TrimLeft(hex.EncodeToString(nginxIP.ipv4.To4()), "0")))
		if isProxyFull {
			for _, ingressIP := range ingressIPs {
				require.Contains(t, table40Output, fmt.Sprintf("nw_dst=%s,tp_dst=80", ingressIP))
			}
		}
	} else {
		require.Contains(t, table40Output, fmt.Sprintf("ipv6_dst=%s,tp_dst=80", svc.Spec.ClusterIP))
		require.Contains(t, table40Output, fmt.Sprintf("load:0x%s->NXM_NX_XXREG3[0..63]", strings.TrimLeft(hex.EncodeToString([]byte(*nginxIP.ipv6)[8:16]), "0")))
		require.Contains(t, table40Output, fmt.Sprintf("load:0x%s->NXM_NX_XXREG3[64..127]", strings.TrimLeft(hex.EncodeToString([]byte(*nginxIP.ipv6)[0:8]), "0")))
		if isProxyFull {
			for _, ingressIP := range ingressIPs {
				require.Contains(t, table40Output, fmt.Sprintf("ipv6_dst=%s,tp_dst=80", ingressIP))
			}
		}
	}
}
func testProxyHairpinCase(t *testing.T, data *TestData) {
	if len(clusterInfo.podV4NetworkCIDR) != 0 {
		ipFamily := corev1.IPv4Protocol
		testProxyHairpin(&ipFamily, data, t)
	}
	if len(clusterInfo.podV6NetworkCIDR) != 0 {
		ipFamily := corev1.IPv6Protocol
		testProxyHairpin(&ipFamily, data, t)
	}
}

func TestProxyHairpin(t *testing.T) {
	skipIfHasWindowsNodes(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	skipIfProxyDisabled(t)

	if len(clusterInfo.podV4NetworkCIDR) != 0 {
		ipFamily := corev1.IPv4Protocol
		testProxyHairpin(&ipFamily, data, t)
	}
	if len(clusterInfo.podV6NetworkCIDR) != 0 {
		ipFamily := corev1.IPv6Protocol
		testProxyHairpin(&ipFamily, data, t)
	}
}

func testProxyHairpin(ipFamily *corev1.IPFamily, data *TestData, t *testing.T) {
	busybox := randName("busybox-")
	nodeName := nodeName(1)
	err := data.createPodOnNode(busybox, testNamespace, nodeName, busyboxImage, []string{"nc", "-lk", "-p", "80"}, nil, nil, []corev1.ContainerPort{{ContainerPort: 80, Protocol: corev1.ProtocolTCP}}, false, nil)
	defer data.deletePodAndWait(defaultTimeout, busybox, testNamespace)
	require.NoError(t, err)
	require.NoError(t, data.podWaitForRunning(defaultTimeout, busybox, testNamespace))
	svc, err := data.createService(busybox, 80, 80, map[string]string{"antrea-e2e": busybox}, false, false, corev1.ServiceTypeClusterIP, ipFamily)
	defer data.deleteServiceAndWait(defaultTimeout, busybox)
	require.NoError(t, err)

	// Hold on to make sure that the Service is realized.
	time.Sleep(3 * time.Second)

	stdout, stderr, err := data.runCommandFromPod(testNamespace, busybox, busyboxContainerName, []string{"nc", svc.Spec.ClusterIP, "80", "-w", "1", "-e", "ls", "/"})
	require.NoError(t, err, fmt.Sprintf("ipFamily: %v\nstdout: %s\nstderr: %s\n", *ipFamily, stdout, stderr))
}

func testProxyEndpointLifeCycleCase(t *testing.T, data *TestData) {
	if len(clusterInfo.podV4NetworkCIDR) != 0 {
		ipFamily := corev1.IPv4Protocol
		testProxyEndpointLifeCycle(&ipFamily, data, t)
	}
	if len(clusterInfo.podV6NetworkCIDR) != 0 {
		ipFamily := corev1.IPv6Protocol
		testProxyEndpointLifeCycle(&ipFamily, data, t)
	}
}

func TestProxyEndpointLifeCycle(t *testing.T) {
	skipIfHasWindowsNodes(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	skipIfProxyDisabled(t)

	if len(clusterInfo.podV4NetworkCIDR) != 0 {
		ipFamily := corev1.IPv4Protocol
		testProxyEndpointLifeCycle(&ipFamily, data, t)
	}
	if len(clusterInfo.podV6NetworkCIDR) != 0 {
		ipFamily := corev1.IPv6Protocol
		testProxyEndpointLifeCycle(&ipFamily, data, t)
	}
}

func testProxyEndpointLifeCycle(ipFamily *corev1.IPFamily, data *TestData, t *testing.T) {
	nodeName := nodeName(1)
	nginx := randName("nginx-")
	require.NoError(t, data.createNginxPodOnNode(nginx, testNamespace, nodeName))
	nginxIPs, err := data.podWaitForIPs(defaultTimeout, nginx, testNamespace)
	require.NoError(t, err)
	_, err = data.createNginxClusterIPService(nginx, false, ipFamily)
	defer data.deleteServiceAndWait(defaultTimeout, nginx)
	require.NoError(t, err)

	// Hold on to make sure that the Service is realized.
	time.Sleep(3 * time.Second)

	agentName, err := data.getAntreaPodOnNode(nodeName)
	require.NoError(t, err)
	var nginxIP string
	if *ipFamily == corev1.IPv6Protocol {
		nginxIP = nginxIPs.ipv6.String()
	} else {
		nginxIP = nginxIPs.ipv4.String()
	}

	keywords := make(map[int]string)
	keywords[42] = fmt.Sprintf("nat(dst=%s)", net.JoinHostPort(nginxIP, "80")) // endpointNATTable

	var groupKeywords []string
	if *ipFamily == corev1.IPv6Protocol {
		groupKeywords = append(groupKeywords, fmt.Sprintf("set_field:0x%s->xxreg3", strings.TrimPrefix(hex.EncodeToString(*nginxIPs.ipv6), "0")))
	} else {
		groupKeywords = append(groupKeywords, fmt.Sprintf("0x%s->NXM_NX_REG3[]", strings.TrimPrefix(hex.EncodeToString(nginxIPs.ipv4.To4()), "0")))
	}

	for tableID, keyword := range keywords {
		tableOutput, _, err := data.runCommandFromPod(metav1.NamespaceSystem, agentName, "antrea-agent", []string{"ovs-ofctl", "dump-flows", defaultBridgeName, fmt.Sprintf("table=%d", tableID)})
		require.NoError(t, err)
		require.Contains(t, tableOutput, keyword)
	}

	groupOutput, _, err := data.runCommandFromPod(metav1.NamespaceSystem, agentName, "antrea-agent", []string{"ovs-ofctl", "dump-groups", defaultBridgeName})
	require.NoError(t, err)
	for _, k := range groupKeywords {
		require.Contains(t, groupOutput, k)
	}

	require.NoError(t, data.deletePodAndWait(defaultTimeout, nginx, testNamespace))

	// Wait for one second to make sure the pipeline to be updated.
	time.Sleep(time.Second)

	for tableID, keyword := range keywords {
		tableOutput, _, err := data.runCommandFromPod(metav1.NamespaceSystem, agentName, "antrea-agent", []string{"ovs-ofctl", "dump-flows", defaultBridgeName, fmt.Sprintf("table=%d", tableID)})
		require.NoError(t, err)
		require.NotContains(t, tableOutput, keyword)
	}

	groupOutput, _, err = data.runCommandFromPod(metav1.NamespaceSystem, agentName, "antrea-agent", []string{"ovs-ofctl", "dump-groups", defaultBridgeName})
	require.NoError(t, err)
	for _, k := range groupKeywords {
		require.NotContains(t, groupOutput, k)
	}
}

func testProxyServiceLifeCycleCase(t *testing.T, data *TestData) {
	if len(clusterInfo.podV4NetworkCIDR) != 0 {
		ipFamily := corev1.IPv4Protocol
		testProxyServiceLifeCycle(&ipFamily, []string{"169.254.169.253", "169.254.169.254"}, data, t)
	}
	if len(clusterInfo.podV6NetworkCIDR) != 0 {
		ipFamily := corev1.IPv6Protocol
		testProxyServiceLifeCycle(&ipFamily, []string{"fd75::aabb:ccdd:ef00", "fd75::aabb:ccdd:ef01"}, data, t)
	}
}

func TestProxyServiceLifeCycle(t *testing.T) {
	skipIfHasWindowsNodes(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	skipIfProxyDisabled(t)

	if len(clusterInfo.podV4NetworkCIDR) != 0 {
		ipFamily := corev1.IPv4Protocol
		testProxyServiceLifeCycle(&ipFamily, []string{"169.254.169.1", "169.254.169.2"}, data, t)
	}
	if len(clusterInfo.podV6NetworkCIDR) != 0 {
		ipFamily := corev1.IPv6Protocol
		testProxyServiceLifeCycle(&ipFamily, []string{"fd75::aabb:ccdd:ef00", "fd75::aabb:ccdd:ef01"}, data, t)
	}
}

func testProxyServiceLifeCycle(ipFamily *corev1.IPFamily, ingressIPs []string, data *TestData, t *testing.T) {
	nodeName := nodeName(1)
	nginx := randName("nginx-")
	isProxyFull, err := data.IsProxyFull()
	if err != nil {
		t.Fatalf("Error getting option antreaProxyFull value")
	}

	require.NoError(t, data.createNginxPodOnNode(nginx, testNamespace, nodeName))
	defer data.deletePodAndWait(defaultTimeout, nginx, testNamespace)
	nginxIPs, err := data.podWaitForIPs(defaultTimeout, nginx, testNamespace)
	require.NoError(t, err)
	var nginxIP string
	if *ipFamily == corev1.IPv6Protocol {
		nginxIP = nginxIPs.ipv6.String()
	} else {
		nginxIP = nginxIPs.ipv4.String()
	}
	svc, err := data.createNginxClusterIPService(nginx, false, ipFamily)
	defer data.deleteServiceAndWait(defaultTimeout, nginx)
	require.NoError(t, err)
	_, err = data.createNginxLoadBalancerService(false, ingressIPs, ipFamily)
	defer data.deleteServiceAndWait(defaultTimeout, nginxLBService)
	require.NoError(t, err)
	agentName, err := data.getAntreaPodOnNode(nodeName)
	require.NoError(t, err)

	// Hold on to make sure that the Service is realized.
	time.Sleep(3 * time.Second)

	var svcLBflows []string
	if *ipFamily == corev1.IPv6Protocol {
		svcLBflows = append(svcLBflows, fmt.Sprintf("ipv6_dst=%s,tp_dst=80", svc.Spec.ClusterIP))
		if isProxyFull {
			for _, ingressIP := range ingressIPs {
				svcLBflows = append(svcLBflows, fmt.Sprintf("ipv6_dst=%s,tp_dst=80", ingressIP))
			}
		}
	} else {
		svcLBflows = append(svcLBflows, fmt.Sprintf("nw_dst=%s,tp_dst=80", svc.Spec.ClusterIP))
		if isProxyFull {
			for _, ingressIP := range ingressIPs {
				svcLBflows = append(svcLBflows, fmt.Sprintf("nw_dst=%s,tp_dst=80", ingressIP))
			}
		}
	}

	table42Format := "nat(dst=%s:80)"
	if *ipFamily == corev1.IPv6Protocol {
		table42Format = "nat(dst=[%s]:80)"
	}
	expectedFlows := []expectTableFlows{
		{
			41, // serviceLBTable
			svcLBflows,
		},
		{
			42,
			[]string{fmt.Sprintf(table42Format, nginxIP)}, // endpointNATTable
		},
	}

	var groupKeyword string
	if *ipFamily == corev1.IPv6Protocol {
		groupKeyword = fmt.Sprintf("set_field:0x%s->xxreg3,load:0x%x->NXM_NX_REG4[0..15]", strings.TrimLeft(hex.EncodeToString(nginxIPs.ipv6.To16()), "0"), 80)
	} else {
		groupKeyword = fmt.Sprintf("load:0x%s->NXM_NX_REG3[],load:0x%x->NXM_NX_REG4[0..15]", strings.TrimLeft(hex.EncodeToString(nginxIPs.ipv4.To4()), "0"), 80)
	}
	groupOutput, _, err := data.runCommandFromPod(metav1.NamespaceSystem, agentName, "antrea-agent", []string{"ovs-ofctl", "dump-groups", defaultBridgeName})
	require.NoError(t, err)
	require.Contains(t, groupOutput, groupKeyword)
	for _, expectedTable := range expectedFlows {
		tableOutput, _, err := data.runCommandFromPod(metav1.NamespaceSystem, agentName, "antrea-agent", []string{"ovs-ofctl", "dump-flows", defaultBridgeName, fmt.Sprintf("table=%d", expectedTable.tableID)})
		require.NoError(t, err)
		for _, expectedFlow := range expectedTable.flows {
			require.Contains(t, tableOutput, expectedFlow)
		}
	}

	require.NoError(t, data.deleteService(nginx))
	require.NoError(t, data.deleteService(nginxLBService))

	// Hold on to make sure that the Service is realized.
	time.Sleep(3 * time.Second)

	groupOutput, _, err = data.runCommandFromPod(metav1.NamespaceSystem, agentName, "antrea-agent", []string{"ovs-ofctl", "dump-groups", defaultBridgeName})
	require.NoError(t, err)
	require.NotContains(t, groupOutput, groupKeyword)
	for _, expectedTable := range expectedFlows {
		tableOutput, _, err := data.runCommandFromPod(metav1.NamespaceSystem, agentName, "antrea-agent", []string{"ovs-ofctl", "dump-flows", defaultBridgeName, fmt.Sprintf("table=%d", expectedTable.tableID)})
		require.NoError(t, err)
		for _, expectedFlow := range expectedTable.flows {
			require.NotContains(t, tableOutput, expectedFlow)
		}
	}
}
