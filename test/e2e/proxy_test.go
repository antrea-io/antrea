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
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/features"
)

type expectTableFlows struct {
	tableName string
	flows     []string
}

// TestProxy is the top-level test which contains all subtests for
// Proxy related test cases so they can share setup, teardown.
func TestProxy(t *testing.T) {
	skipIfHasWindowsNodes(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
	skipIfProxyDisabled(t, data)

	t.Run("testProxyServiceSessionAffinityCase", func(t *testing.T) {
		testProxyServiceSessionAffinityCase(t, data)
	})
	t.Run("testProxyEndpointLifeCycleCase", func(t *testing.T) {
		testProxyEndpointLifeCycleCase(t, data)
	})
	t.Run("testProxyServiceLifeCycleCase", func(t *testing.T) {
		testProxyServiceLifeCycleCase(t, data)
	})
}

func testProxyServiceSessionAffinityCase(t *testing.T, data *TestData) {
	if len(clusterInfo.podV4NetworkCIDR) != 0 {
		ipFamily := corev1.IPv4Protocol
		testProxyServiceSessionAffinity(&ipFamily, []string{"169.254.169.1", "169.254.169.2"}, data, t)
	}
	if len(clusterInfo.podV6NetworkCIDR) != 0 {
		ipFamily := corev1.IPv6Protocol
		testProxyServiceSessionAffinity(&ipFamily, []string{"fd75::aabb:ccdd:ef00", "fd75::aabb:ccdd:ef01"}, data, t)
	}
}

func skipIfKubeProxyEnabled(t *testing.T, data *TestData) {
	_, err := data.clientset.AppsV1().DaemonSets(kubeNamespace).Get(context.TODO(), "kube-proxy", metav1.GetOptions{})
	if err == nil {
		t.Skipf("Skipping test because kube-proxy is running")
	}
}

func probeFromNode(node string, url string, data *TestData) error {
	_, _, _, err := data.RunCommandOnNode(node, fmt.Sprintf("curl --connect-timeout 1 --retry 5 --retry-connrefused %s", url))
	return err
}

func probeHealthFromNode(node string, baseUrl string, data *TestData) (string, string, error) {
	url := fmt.Sprintf("%s/%s", baseUrl, "healthz")
	_, stdout, stderr, err := data.RunCommandOnNode(node, fmt.Sprintf("curl --connect-timeout 1 --retry 5 --retry-connrefused %s", url))
	return stdout, stderr, err
}

func probeHostnameFromNode(node string, baseUrl string, data *TestData) (string, error) {
	url := fmt.Sprintf("%s/%s", baseUrl, "hostname")
	_, hostname, _, err := data.RunCommandOnNode(node, fmt.Sprintf("curl --connect-timeout 1 --retry 5 --retry-connrefused %s", url))
	return hostname, err
}

func probeClientIPFromNode(node string, baseUrl string, data *TestData) (string, error) {
	url := fmt.Sprintf("%s/%s", baseUrl, "clientip")
	_, hostPort, _, err := data.RunCommandOnNode(node, fmt.Sprintf("curl --connect-timeout 1 --retry 5 --retry-connrefused %s", url))
	if err != nil {
		return "", err
	}
	host, _, err := net.SplitHostPort(hostPort)
	return host, err
}

func probeFromPod(data *TestData, pod, container string, url string) error {
	_, _, err := data.runWgetCommandFromTestPodWithRetry(pod, data.testNamespace, container, url, 5)
	return err
}

func probeHostnameFromPod(data *TestData, pod, container string, baseUrl string) (string, error) {
	url := fmt.Sprintf("%s/%s", baseUrl, "hostname")
	hostname, _, err := data.runWgetCommandFromTestPodWithRetry(pod, data.testNamespace, container, url, 5)
	return hostname, err
}

func probeClientIPFromPod(data *TestData, pod, container string, baseUrl string) (string, error) {
	url := fmt.Sprintf("%s/%s", baseUrl, "clientip")
	hostPort, _, err := data.runWgetCommandFromTestPodWithRetry(pod, data.testNamespace, container, url, 5)
	if err != nil {
		return "", err
	}
	host, _, err := net.SplitHostPort(hostPort)
	return host, err
}

func reverseStrs(strs []string) []string {
	var res []string
	for i := len(strs) - 1; i >= 0; i-- {
		res = append(res, strs[i])
	}
	return res
}

func TestProxyLoadBalancerServiceIPv4(t *testing.T) {
	skipIfNotIPv4Cluster(t)
	testProxyLoadBalancerService(t, false)
}

func TestProxyLoadBalancerServiceIPv6(t *testing.T) {
	skipIfNotIPv6Cluster(t)
	testProxyLoadBalancerService(t, true)
}

func testProxyLoadBalancerService(t *testing.T, isIPv6 bool) {
	skipIfHasWindowsNodes(t)
	skipIfNumNodesLessThan(t, 2)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
	skipIfProxyDisabled(t, data)
	skipIfProxyAllDisabled(t, data)

	// Create a busybox Pod on every Node. The busybox Pod is used as a client.
	nodes := []string{nodeName(0), nodeName(1)}
	var busyboxes, busyboxIPs []string
	for idx, node := range nodes {
		podName, ips, _ := createAndWaitForPod(t, data, data.createBusyboxPodOnNode, fmt.Sprintf("busybox-%d-", idx), node, data.testNamespace, false)
		busyboxes = append(busyboxes, podName)
		if !isIPv6 {
			busyboxIPs = append(busyboxIPs, ips.IPv4.String())
		} else {
			busyboxIPs = append(busyboxIPs, ips.IPv6.String())
		}
	}

	clusterIngressIP := []string{"169.254.169.1"}
	localIngressIP := []string{"169.254.169.2"}
	ipProtocol := corev1.IPv4Protocol
	if isIPv6 {
		ipProtocol = corev1.IPv6Protocol
		clusterIngressIP = []string{"fd75::aabb:ccdd:ef00"}
		localIngressIP = []string{"fd75::aabb:ccdd:ef01"}
	}

	// Create two LoadBalancer Services. The externalTrafficPolicy of one Service is Cluster, and the externalTrafficPolicy
	// of another one is Local.
	_, err = data.createAgnhostLoadBalancerService("agnhost-cluster", true, false, clusterIngressIP, &ipProtocol, nil)
	require.NoError(t, err)
	svc, err := data.createAgnhostLoadBalancerService("agnhost-local", true, true, localIngressIP, &ipProtocol, nil)
	require.NoError(t, err)

	// For the 'Local' externalTrafficPolicy, setup the health checks.
	healthPort := fmt.Sprint(svc.Spec.HealthCheckNodePort)
	require.NotEqual(t, "", healthPort, "HealthCheckNodePort port number should not be empty")
	nodeIPs := []string{controlPlaneNodeIPv4(), workerNodeIPv4(1)}
	var healthUrls []string
	for _, nodeIP := range nodeIPs {
		healthUrls = append(healthUrls, net.JoinHostPort(nodeIP, healthPort))
	}
	healthOutputTmpl := `{
	"service": {
		"namespace": "%s",
		"name": "agnhost-local"
	},
	"localEndpoints": 1
}`
	healthExpected := fmt.Sprintf(healthOutputTmpl, data.testNamespace)

	port := "8080"
	clusterUrl := net.JoinHostPort(clusterIngressIP[0], port)
	localUrl := net.JoinHostPort(localIngressIP[0], port)

	// Create agnhost Pods which are not on host network.
	agnhosts := []string{"agnhost-0", "agnhost-1"}
	for idx, node := range nodes {
		createAgnhostPod(t, data, agnhosts[idx], node, false)
	}
	t.Run("Non-HostNetwork Endpoints", func(t *testing.T) {
		loadBalancerTestCases(t, data, clusterUrl, localUrl, healthExpected, nodes, healthUrls, busyboxes, busyboxIPs, agnhosts)
	})

	// Delete agnhost Pods which are not on host network and create new agnhost Pods which are on host network.
	hostAgnhosts := []string{"agnhost-host-0", "agnhost-host-1"}
	for idx, node := range nodes {
		require.NoError(t, data.DeletePod(data.testNamespace, agnhosts[idx]))
		createAgnhostPod(t, data, hostAgnhosts[idx], node, true)
	}
	t.Run("HostNetwork Endpoints", func(t *testing.T) {
		loadBalancerTestCases(t, data, clusterUrl, localUrl, healthExpected, nodes, healthUrls, busyboxes, busyboxIPs, nodes)
	})
}

func loadBalancerTestCases(t *testing.T, data *TestData, clusterUrl, localUrl, healthExpected string, nodes, healthUrls, pods, podIPs, hostnames []string) {
	t.Run("ExternalTrafficPolicy:Cluster/Client:Node", func(t *testing.T) {
		testLoadBalancerClusterFromNode(t, data, nodes, clusterUrl)
	})
	t.Run("ExternalTrafficPolicy:Cluster/Client:Pod", func(t *testing.T) {
		testLoadBalancerClusterFromPod(t, data, pods, clusterUrl)
	})
	t.Run("ExternalTrafficPolicy:Local/Client:Node", func(t *testing.T) {
		testLoadBalancerLocalFromNode(t, data, nodes, healthUrls, healthExpected, localUrl)
	})
	t.Run("ExternalTrafficPolicy:Local/Client:Pod", func(t *testing.T) {
		testLoadBalancerLocalFromPod(t, data, pods, localUrl)
	})
}

func testLoadBalancerClusterFromNode(t *testing.T, data *TestData, nodes []string, url string) {
	skipIfKubeProxyEnabled(t, data)
	for _, node := range nodes {
		require.NoError(t, probeFromNode(node, url, data), "Service LoadBalancer whose externalTrafficPolicy is Cluster should be able to be connected from Node")
	}
}

func testLoadBalancerClusterFromPod(t *testing.T, data *TestData, pods []string, url string) {
	for _, pod := range pods {
		require.NoError(t, probeFromPod(data, pod, busyboxContainerName, url), "Service LoadBalancer whose externalTrafficPolicy is Cluster should be able to be connected from Pod")
	}
}

func testLoadBalancerLocalFromNode(t *testing.T, data *TestData, nodes, healthUrls []string, healthExpected, url string) {
	skipIfKubeProxyEnabled(t, data)
	for _, node := range nodes {
		require.NoError(t, probeFromNode(node, url, data), "Service LoadBalancer whose externalTrafficPolicy is Local should be able to be connected from Node")

		for _, healthUrl := range healthUrls {
			healthOutput, _, err := probeHealthFromNode(node, healthUrl, data)
			require.NoError(t, err, "Service LoadBalancer whose externalTrafficPolicy is Local should have a response for healthcheck")
			require.Equal(t, healthOutput, healthExpected)
		}
	}
}

func testLoadBalancerLocalFromPod(t *testing.T, data *TestData, pods []string, url string) {
	errMsg := "Service NodePort whose externalTrafficPolicy is Local should be able to be connected from Pod"
	for _, pod := range pods {
		require.NoError(t, probeFromPod(data, pod, busyboxContainerName, url), errMsg)
	}
}

func TestProxyNodePortServiceIPv4(t *testing.T) {
	skipIfNotIPv4Cluster(t)
	testProxyNodePortService(t, false)
}

func TestProxyNodePortServiceIPv6(t *testing.T) {
	skipIfNotIPv6Cluster(t)
	testProxyNodePortService(t, true)
}

func testProxyNodePortService(t *testing.T, isIPv6 bool) {
	skipIfHasWindowsNodes(t)
	skipIfNumNodesLessThan(t, 2)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
	skipIfProxyDisabled(t, data)
	skipIfProxyAllDisabled(t, data)

	nodes := []string{nodeName(0), nodeName(1)}
	nodeIPs := []string{controlPlaneNodeIPv4(), workerNodeIPv4(1)}
	ipProtocol := corev1.IPv4Protocol
	if isIPv6 {
		nodeIPs = []string{controlPlaneNodeIPv6(), workerNodeIPv6(1)}
		ipProtocol = corev1.IPv6Protocol
	}

	// Create a busybox Pod on every Node. The busybox Pod is used as a client.
	var busyboxes, busyboxIPs []string
	for idx, node := range nodes {
		podName, ips, _ := createAndWaitForPod(t, data, data.createBusyboxPodOnNode, fmt.Sprintf("busybox-%d-", idx), node, data.testNamespace, false)
		busyboxes = append(busyboxes, podName)
		if !isIPv6 {
			busyboxIPs = append(busyboxIPs, ips.IPv4.String())
		} else {
			busyboxIPs = append(busyboxIPs, ips.IPv6.String())
		}
	}

	// Create two NodePort Services. The externalTrafficPolicy of one Service is Cluster, and the externalTrafficPolicy
	// of another one is Local.
	var portCluster, portLocal string
	nodePortSvc, err := data.createAgnhostNodePortService("agnhost-cluster", true, false, &ipProtocol)
	require.NoError(t, err)
	for _, port := range nodePortSvc.Spec.Ports {
		if port.NodePort != 0 {
			portCluster = fmt.Sprint(port.NodePort)
			break
		}
	}
	require.NotEqual(t, "", portCluster, "NodePort port number should not be empty")
	nodePortSvc, err = data.createAgnhostNodePortService("agnhost-local", true, true, &ipProtocol)
	require.NoError(t, err)
	for _, port := range nodePortSvc.Spec.Ports {
		if port.NodePort != 0 {
			portLocal = fmt.Sprint(port.NodePort)
			break
		}
	}
	require.NotEqual(t, "", portLocal, "NodePort port number should not be empty")

	// Create agnhost Pods which are not on host network.
	agnhosts := []string{"agnhost-0", "agnhost-1"}
	for idx, node := range nodes {
		createAgnhostPod(t, data, agnhosts[idx], node, false)
	}
	t.Run("Non-HostNetwork Endpoints", func(t *testing.T) {
		nodePortTestCases(t, data, portCluster, portLocal, nodes, nodeIPs, busyboxes, busyboxIPs, agnhosts, false)
	})

	// Delete agnhost Pods which are not on host network and create new agnhost Pods which are on host network.
	hostAgnhosts := []string{"agnhost-host-0", "agnhost-host-1"}
	for idx, node := range nodes {
		require.NoError(t, data.DeletePod(data.testNamespace, agnhosts[idx]))
		createAgnhostPod(t, data, hostAgnhosts[idx], node, true)
	}
	t.Run("HostNetwork Endpoints", func(t *testing.T) {
		nodePortTestCases(t, data, portCluster, portLocal, nodes, nodeIPs, busyboxes, busyboxIPs, nodes, true)
	})
}

func nodePortTestCases(t *testing.T, data *TestData, portStrCluster, portStrLocal string, nodes, nodeIPs, pods, podIPs, hostnames []string, hostNetwork bool) {
	var clusterUrls, localUrls []string
	for _, nodeIP := range nodeIPs {
		clusterUrls = append(clusterUrls, net.JoinHostPort(nodeIP, portStrCluster))
		localUrls = append(localUrls, net.JoinHostPort(nodeIP, portStrLocal))
	}

	t.Run("ExternalTrafficPolicy:Cluster/Client:Remote", func(t *testing.T) {
		testNodePortClusterFromRemote(t, data, nodes, reverseStrs(clusterUrls))
	})
	t.Run("ExternalTrafficPolicy:Cluster/Client:Node", func(t *testing.T) {
		testNodePortClusterFromNode(t, data, nodes, clusterUrls)
	})
	t.Run("ExternalTrafficPolicy:Cluster/Client:Pod", func(t *testing.T) {
		testNodePortClusterFromPod(t, data, pods, clusterUrls)
	})
	t.Run("ExternalTrafficPolicy:Local/Client:Remote", func(t *testing.T) {
		if hostNetwork {
			t.Skipf("Skip this test as Endpoint is on host network")
		}
		testNodePortLocalFromRemote(t, data, nodes, reverseStrs(localUrls), nodeIPs, reverseStrs(hostnames))
	})
	t.Run("ExternalTrafficPolicy:Local/Client:Node", func(t *testing.T) {
		testNodePortLocalFromNode(t, data, nodes, localUrls)
	})
	t.Run("ExternalTrafficPolicy:Local/Client:Pod", func(t *testing.T) {
		testNodePortLocalFromPod(t, data, pods, localUrls)
	})
}

func TestNodePortAndEgressWithTheSameBackendPod(t *testing.T) {
	skipIfHasWindowsNodes(t)
	skipIfNotIPv4Cluster(t)
	skipIfNumNodesLessThan(t, 2)
	skipIfAntreaIPAMTest(t)
	skipIfEgressDisabled(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
	skipIfProxyDisabled(t, data)
	skipIfProxyAllDisabled(t, data)
	skipIfEncapModeIsNot(t, data, config.TrafficEncapModeEncap) // Egress works for encap mode only.

	// Create a NodePort Service.
	nodePortIP := controlPlaneNodeIPv4()
	ipProtocol := corev1.IPv4Protocol
	var portStr string
	nodePortSvc, err := data.createNginxNodePortService("test-nodeport-svc", data.testNamespace, true, false, &ipProtocol)
	require.NoError(t, err)
	for _, port := range nodePortSvc.Spec.Ports {
		if port.NodePort != 0 {
			portStr = fmt.Sprint(port.NodePort)
			break
		}
	}
	testNodePortURL := net.JoinHostPort(nodePortIP, portStr)

	// Create an Egress whose external IP is on worker Node.
	egressNodeIP := workerNodeIPv4(1)
	egress := data.createEgress(t, "test-egress", nil, map[string]string{"app": "nginx"}, "", egressNodeIP, nil)
	defer data.crdClient.CrdV1beta1().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{})

	// Create the backend Pod on control plane Node.
	backendPodName := "test-nodeport-egress-backend-pod"
	require.NoError(t, data.createNginxPodOnNode(backendPodName, data.testNamespace, controlPlaneNodeName(), false))
	defer deletePodWrapper(t, data, data.testNamespace, backendPodName)
	if err := data.podWaitForRunning(defaultTimeout, backendPodName, data.testNamespace); err != nil {
		t.Fatalf("Error when waiting for Pod '%s' to be in the Running state", backendPodName)
	}

	// Create another netns to fake an external network on the host network Pod.
	testPod := "test-client"
	cmd, testNetns := getCommandInFakeExternalNetwork("sleep 3600", 24, "1.1.1.1", "1.1.1.254")
	if err := NewPodBuilder(testPod, data.testNamespace, agnhostImage).OnNode(controlPlaneNodeName()).WithCommand([]string{"sh", "-c", cmd}).InHostNetwork().Privileged().Create(data); err != nil {
		t.Fatalf("Failed to create client Pod: %v", err)
	}
	defer deletePodWrapper(t, data, data.testNamespace, testPod)
	if err := data.podWaitForRunning(defaultTimeout, testPod, data.testNamespace); err != nil {
		t.Fatalf("Error when waiting for Pod '%s' to be in the Running state", testPod)
	}
	// Connect to NodePort on control plane Node in the fake external network.
	cmd = fmt.Sprintf("ip netns exec %s curl --connect-timeout 1 --retry 5 --retry-connrefused %s", testNetns, testNodePortURL)
	_, _, err = data.RunCommandFromPod(data.testNamespace, testPod, agnhostContainerName, []string{"sh", "-c", cmd})
	require.NoError(t, err, "Service NodePort should be able to be connected from external network when Egress is enabled")
}

func createAgnhostPod(t *testing.T, data *TestData, podName string, node string, hostNetwork bool) {
	args := []string{"netexec", "--http-port=8080"}
	ports := []corev1.ContainerPort{
		{
			Name:          "http",
			ContainerPort: 8080,
			Protocol:      corev1.ProtocolTCP,
		},
	}

	require.NoError(t, NewPodBuilder(podName, data.testNamespace, agnhostImage).OnNode(node).WithArgs(args).WithPorts(ports).WithHostNetwork(hostNetwork).Create(data))
	_, err := data.podWaitForIPs(defaultTimeout, podName, data.testNamespace)
	require.NoError(t, err)
	require.NoError(t, data.podWaitForRunning(defaultTimeout, podName, data.testNamespace))
}

func testNodePortClusterFromRemote(t *testing.T, data *TestData, nodes, urls []string) {
	skipIfKubeProxyEnabled(t, data)
	for idx, node := range nodes {
		require.NoError(t, probeFromNode(node, urls[idx], data), "Service NodePort whose externalTrafficPolicy is Cluster should be able to be connected from remote Node")
	}
}

func testNodePortClusterFromNode(t *testing.T, data *TestData, nodes, urls []string) {
	skipIfKubeProxyEnabled(t, data)
	for idx, node := range nodes {
		require.NoError(t, probeFromNode(node, urls[idx], data), "Service NodePort whose externalTrafficPolicy is Cluster should be able to be connected from Node")
	}
}

func testNodePortClusterFromPod(t *testing.T, data *TestData, pods, urls []string) {
	for _, url := range urls {
		for _, pod := range pods {
			require.NoError(t, probeFromPod(data, pod, busyboxContainerName, url), "Service NodePort whose externalTrafficPolicy is Cluster should be able to be connected from Pod")
		}
	}
}

func testNodePortLocalFromRemote(t *testing.T, data *TestData, nodes, urls, expectedClientIPs, expectedHostnames []string) {
	skipIfKubeProxyEnabled(t, data)
	errMsg := "Service NodePort whose externalTrafficPolicy is Local should be able to be connected from remote Node"
	for idx, node := range nodes {
		hostname, err := probeHostnameFromNode(node, urls[idx], data)
		require.NoError(t, err, errMsg)
		require.Equal(t, expectedHostnames[idx], hostname)

		clientIP, err := probeClientIPFromNode(node, urls[idx], data)
		require.NoError(t, err, errMsg)
		require.Equal(t, expectedClientIPs[idx], clientIP)
	}
}

func testNodePortLocalFromNode(t *testing.T, data *TestData, nodes, urls []string) {
	skipIfKubeProxyEnabled(t, data)
	for idx, node := range nodes {
		require.NoError(t, probeFromNode(node, urls[idx], data), "Service NodePort whose externalTrafficPolicy is Local should be able to be connected from Node")
	}
}

func testNodePortLocalFromPod(t *testing.T, data *TestData, pods, urls []string) {
	for idx, pod := range pods {
		require.NoError(t, probeFromPod(data, pod, busyboxContainerName, urls[idx]), "There should be no errors when accessing to Service NodePort whose externalTrafficPolicy is Local from Pod")
	}
}

func TestProxyServiceSessionAffinity(t *testing.T) {
	skipIfHasWindowsNodes(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
	skipIfProxyDisabled(t, data)

	if len(clusterInfo.podV4NetworkCIDR) != 0 {
		ipFamily := corev1.IPv4Protocol
		testProxyServiceSessionAffinity(&ipFamily, []string{"169.254.169.1", "169.254.169.2"}, data, t)
	}
	if len(clusterInfo.podV6NetworkCIDR) != 0 {
		ipFamily := corev1.IPv6Protocol
		testProxyServiceSessionAffinity(&ipFamily, []string{"fd75::aabb:ccdd:ef00", "fd75::aabb:ccdd:ef01"}, data, t)
	}
}

func TestProxyExternalTrafficPolicyIPv4(t *testing.T) {
	skipIfNotIPv4Cluster(t)
	testProxyExternalTrafficPolicy(t, false)
}

func TestProxyExternalTrafficPolicyIPv6(t *testing.T) {
	skipIfNotIPv6Cluster(t)
	testProxyExternalTrafficPolicy(t, true)
}

func testProxyExternalTrafficPolicy(t *testing.T, isIPv6 bool) {
	skipIfHasWindowsNodes(t)
	skipIfNumNodesLessThan(t, 2)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
	skipIfProxyDisabled(t, data)
	skipIfProxyAllDisabled(t, data)

	svcName := fmt.Sprintf("nodeport-external-traffic-policy-test-ipv6-%v", isIPv6)
	nodes := []string{nodeName(0), nodeName(1)}
	nodeIPs := []string{controlPlaneNodeIPv4(), workerNodeIPv4(1)}
	ipProtocol := corev1.IPv4Protocol
	if isIPv6 {
		nodeIPs = []string{controlPlaneNodeIPv6(), workerNodeIPv6(1)}
		ipProtocol = corev1.IPv6Protocol
	}

	// Create agnhost Pods which are not on host network.
	var podNames []string
	for idx, node := range nodes {
		podName := fmt.Sprintf("agnhost-%d-ipv6-%v", idx, isIPv6)
		createAgnhostPod(t, data, podName, node, false)
		podNames = append(podNames, podName)
	}

	// Create a NodePort Service whose externalTrafficPolicy is Cluster and backend Pods are created above.
	var portStr string
	nodePortSvc, err := data.createAgnhostNodePortService(svcName, false, false, &ipProtocol)
	require.NoError(t, err)
	for _, port := range nodePortSvc.Spec.Ports {
		if port.NodePort != 0 {
			portStr = fmt.Sprint(port.NodePort)
			break
		}
	}
	require.NotEqual(t, "", portStr, "NodePort port number should not be empty")

	// Get test NodePort URLs.
	var urls []string
	for _, nodeIP := range nodeIPs {
		urls = append(urls, net.JoinHostPort(nodeIP, portStr))
	}

	// Hold on to make sure that the Service is realized, then test the NodePort on each Node.
	time.Sleep(2 * time.Second)
	testNodePortClusterFromRemote(t, data, nodes, reverseStrs(urls))

	// Update the NodePort Service's externalTrafficPolicy from Cluster to Local.
	_, err = data.updateServiceExternalTrafficPolicy(svcName, true)
	require.NoError(t, err)

	// Hold on to make sure that the update of Service is realized, then test the NodePort on each Node.
	time.Sleep(2 * time.Second)
	testNodePortLocalFromRemote(t, data, nodes, reverseStrs(urls), nodeIPs, reverseStrs(podNames))
}

func testProxyServiceSessionAffinity(ipFamily *corev1.IPFamily, ingressIPs []string, data *TestData, t *testing.T) {
	nodeName := nodeName(1)
	nginx := randName("nginx-")

	require.NoError(t, data.createNginxPodOnNode(nginx, data.testNamespace, nodeName, false))
	nginxIP, err := data.podWaitForIPs(defaultTimeout, nginx, data.testNamespace)
	defer data.DeletePodAndWait(defaultTimeout, nginx, data.testNamespace)
	require.NoError(t, err)
	require.NoError(t, data.podWaitForRunning(defaultTimeout, nginx, data.testNamespace))
	svc, err := data.createNginxClusterIPService(nginx, data.testNamespace, true, ipFamily)
	defer data.deleteServiceAndWait(defaultTimeout, nginx, data.testNamespace)
	require.NoError(t, err)
	_, err = data.createNginxLoadBalancerService(true, ingressIPs, ipFamily)
	defer data.deleteServiceAndWait(defaultTimeout, nginxLBService, data.testNamespace)
	require.NoError(t, err)

	busyboxPod := randName("busybox-")
	require.NoError(t, data.createBusyboxPodOnNode(busyboxPod, data.testNamespace, nodeName, false))
	defer data.DeletePodAndWait(defaultTimeout, busyboxPod, data.testNamespace)
	require.NoError(t, data.podWaitForRunning(defaultTimeout, busyboxPod, data.testNamespace))
	stdout, stderr, err := data.runWgetCommandOnBusyboxWithRetry(busyboxPod, data.testNamespace, svc.Spec.ClusterIP, 5)
	require.NoError(t, err, fmt.Sprintf("ipFamily: %v\nstdout: %s\nstderr: %s\n", *ipFamily, stdout, stderr))
	for _, ingressIP := range ingressIPs {
		stdout, stderr, err := data.runWgetCommandOnBusyboxWithRetry(busyboxPod, data.testNamespace, ingressIP, 5)
		require.NoError(t, err, fmt.Sprintf("ipFamily: %v\nstdout: %s\nstderr: %s\n", *ipFamily, stdout, stderr))
	}

	// Hold on to make sure that the Service is realized.
	time.Sleep(3 * time.Second)

	agentName, err := data.getAntreaPodOnNode(nodeName)
	require.NoError(t, err)
	tableSessionAffinityName := "SessionAffinity"
	tableSessionAffinityOutput, _, err := data.RunCommandFromPod(metav1.NamespaceSystem, agentName, "antrea-agent", []string{"ovs-ofctl", "dump-flows", defaultBridgeName, fmt.Sprintf("table=%s", tableSessionAffinityName)})
	require.NoError(t, err)
	if *ipFamily == corev1.IPv4Protocol {
		require.Contains(t, tableSessionAffinityOutput, fmt.Sprintf("nw_dst=%s,tp_dst=80", svc.Spec.ClusterIP))
		require.Contains(t, tableSessionAffinityOutput, fmt.Sprintf("load:0x%s->NXM_NX_REG3[]", strings.TrimLeft(hex.EncodeToString(nginxIP.IPv4.To4()), "0")))
		for _, ingressIP := range ingressIPs {
			require.Contains(t, tableSessionAffinityOutput, fmt.Sprintf("nw_dst=%s,tp_dst=80", ingressIP))
		}
	} else {
		require.Contains(t, tableSessionAffinityOutput, fmt.Sprintf("ipv6_dst=%s,tp_dst=80", svc.Spec.ClusterIP))
		require.Contains(t, tableSessionAffinityOutput, fmt.Sprintf("load:0x%s->NXM_NX_XXREG3[0..63]", strings.TrimLeft(hex.EncodeToString([]byte(*nginxIP.IPv6)[8:16]), "0")))
		require.Contains(t, tableSessionAffinityOutput, fmt.Sprintf("load:0x%s->NXM_NX_XXREG3[64..127]", strings.TrimLeft(hex.EncodeToString([]byte(*nginxIP.IPv6)[0:8]), "0")))
		for _, ingressIP := range ingressIPs {
			require.Contains(t, tableSessionAffinityOutput, fmt.Sprintf("ipv6_dst=%s,tp_dst=80", ingressIP))
		}
	}
}

func TestProxyHairpinIPv4(t *testing.T) {
	skipIfHasWindowsNodes(t)
	skipIfNotIPv4Cluster(t)
	testProxyHairpin(t, false)
}

func TestProxyHairpinIPv6(t *testing.T) {
	skipIfHasWindowsNodes(t)
	skipIfNotIPv6Cluster(t)
	testProxyHairpin(t, true)
}

func testProxyHairpin(t *testing.T, isIPv6 bool) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
	skipIfProxyDisabled(t, data)

	node := nodeName(1)
	workerNodeIP := workerNodeIPv4(1)
	controllerNodeIP := controlPlaneNodeIPv4()
	ipProtocol := corev1.IPv4Protocol
	lbClusterIngressIP := []string{"192.168.240.1"}
	lbLocalIngressIP := []string{"192.168.240.2"}
	if isIPv6 {
		workerNodeIP = workerNodeIPv6(1)
		controllerNodeIP = controlPlaneNodeIPv6()
		ipProtocol = corev1.IPv6Protocol
		lbClusterIngressIP = []string{"fd75::aabb:ccdd:ef00"}
		lbLocalIngressIP = []string{"fd75::aabb:ccdd:ef01"}
	}

	// Create a ClusterIP Service.
	serviceClusterIP := fmt.Sprintf("clusterip-%v", isIPv6)
	clusterIPSvc, err := data.createAgnhostClusterIPService(serviceClusterIP, true, &ipProtocol)
	defer data.deleteServiceAndWait(defaultTimeout, serviceClusterIP, data.testNamespace)
	require.NoError(t, err)

	// Create two NodePort Services. The externalTrafficPolicy of one Service is Cluster, and the externalTrafficPolicy
	// of another one is Local.
	var nodePortCluster, nodePortLocal string
	serviceNodePortCluster := fmt.Sprintf("nodeport-cluster-%v", isIPv6)
	serviceNodePortLocal := fmt.Sprintf("nodeport-local-%v", isIPv6)
	nodePortSvc, err := data.createAgnhostNodePortService(serviceNodePortCluster, true, false, &ipProtocol)
	defer data.deleteServiceAndWait(defaultTimeout, serviceNodePortCluster, data.testNamespace)
	require.NoError(t, err)
	for _, port := range nodePortSvc.Spec.Ports {
		if port.NodePort != 0 {
			nodePortCluster = fmt.Sprint(port.NodePort)
			break
		}
	}
	require.NotEqual(t, "", nodePortCluster, "NodePort port number should not be empty")
	nodePortSvc, err = data.createAgnhostNodePortService(serviceNodePortLocal, true, true, &ipProtocol)
	require.NoError(t, err)
	defer data.deleteServiceAndWait(defaultTimeout, serviceNodePortLocal, data.testNamespace)
	for _, port := range nodePortSvc.Spec.Ports {
		if port.NodePort != 0 {
			nodePortLocal = fmt.Sprint(port.NodePort)
			break
		}
	}
	require.NotEqual(t, "", nodePortLocal, "NodePort port number should not be empty")

	// Create two LoadBalancer Services. The externalTrafficPolicy of one Service is Cluster, and the externalTrafficPolicy
	// of another one is Local.
	serviceLBCluster := fmt.Sprintf("lb-cluster-%v", isIPv6)
	serviceLBLocal := fmt.Sprintf("lb-local-%v", isIPv6)
	_, err = data.createAgnhostLoadBalancerService(serviceLBCluster, true, false, lbClusterIngressIP, &ipProtocol, nil)
	require.NoError(t, err)
	_, err = data.createAgnhostLoadBalancerService(serviceLBLocal, true, true, lbLocalIngressIP, &ipProtocol, nil)
	require.NoError(t, err)

	// These are test urls.
	port := "8080"
	clusterIPUrl := net.JoinHostPort(clusterIPSvc.Spec.ClusterIP, port)
	workerNodePortClusterUrl := net.JoinHostPort(workerNodeIP, nodePortCluster)
	workerNodePortLocalUrl := net.JoinHostPort(workerNodeIP, nodePortLocal)
	controllerNodePortClusterUrl := net.JoinHostPort(controllerNodeIP, nodePortCluster)
	lbClusterUrl := net.JoinHostPort(lbClusterIngressIP[0], port)
	lbLocalUrl := net.JoinHostPort(lbLocalIngressIP[0], port)

	// These are expected client IP.
	expectedGatewayIP, _ := nodeGatewayIPs(1)
	expectedVirtualIP := config.VirtualServiceIPv4.String()
	expectedControllerIP := controllerNodeIP
	if isIPv6 {
		_, expectedGatewayIP = nodeGatewayIPs(1)
		expectedVirtualIP = config.VirtualServiceIPv6.String()
	}

	agnhost := fmt.Sprintf("agnhost-%v", isIPv6)
	createAgnhostPod(t, data, agnhost, node, false)
	t.Run("Non-HostNetwork Endpoints", func(t *testing.T) {
		testProxyIntraNodeHairpinCases(data, t, expectedGatewayIP, agnhost, clusterIPUrl, workerNodePortClusterUrl, workerNodePortLocalUrl, lbClusterUrl, lbLocalUrl)
		testProxyInterNodeHairpinCases(data, t, false, expectedControllerIP, nodeName(0), clusterIPUrl, controllerNodePortClusterUrl, lbClusterUrl)
	})
	require.NoError(t, data.DeletePod(data.testNamespace, agnhost))

	agnhostHost := fmt.Sprintf("agnhost-host-%v", isIPv6)
	createAgnhostPod(t, data, agnhostHost, node, true)
	t.Run("HostNetwork Endpoints", func(t *testing.T) {
		skipIfProxyAllDisabled(t, data)
		testProxyIntraNodeHairpinCases(data, t, expectedVirtualIP, agnhostHost, clusterIPUrl, workerNodePortClusterUrl, workerNodePortLocalUrl, lbClusterUrl, lbLocalUrl)
		testProxyInterNodeHairpinCases(data, t, true, expectedControllerIP, nodeName(0), clusterIPUrl, controllerNodePortClusterUrl, lbClusterUrl)
	})
}

// If a Pod is not on host network, when it accesses a ClusterIP/NodePort/LoadBalancer Service whose Endpoint is on itself,
// that means a hairpin connection. Antrea gateway IP is used to SNAT the connection. The IP changes of the connection are:
// - Pod :     Pod IP            -> Service IP
// - OVS DNAT: Pod IP            -> Pod IP
// - OVS SNAT: Antrea gateway IP -> Pod IP
// - Pod :     Antrea gateway IP -> Pod IP
//
// If a Pod is on host network, when it accesses a ClusterIP/NodePort/LoadBalancer Service whose Endpoint is on itself
// (this is equivalent to that a Node accesses a Cluster/NodePort/LoadBalancer whose Endpoint is host network and the
// Endpoint is on this Node), that means a hairpin connection. A virtual IP is used to SNAT the connection to ensure
// that the packet can be routed via Antrea gateway. The IP changes of the connection are:
// - Antrea gateway: Antrea gateway IP  -> Service IP
// - OVS DNAT:       Antrea gateway IP  -> Node IP
// - OVS SNAT:       virtual IP         -> Node IP
// - Antrea gateway: virtual IP         -> Node IP
func testProxyIntraNodeHairpinCases(data *TestData, t *testing.T, expectedClientIP, pod, clusterIPUrl, nodePortClusterUrl, nodePortLocalUrl, lbClusterUrl, lbLocalUrl string) {
	t.Run("IntraNode/ClusterIP", func(t *testing.T) {
		clientIP, err := probeClientIPFromPod(data, pod, agnhostContainerName, clusterIPUrl)
		require.NoError(t, err, "ClusterIP hairpin should be able to be connected")
		require.Equal(t, expectedClientIP, clientIP)
	})
	t.Run("IntraNode/NodePort/ExternalTrafficPolicy:Cluster", func(t *testing.T) {
		skipIfProxyAllDisabled(t, data)
		clientIP, err := probeClientIPFromPod(data, pod, agnhostContainerName, nodePortClusterUrl)
		require.NoError(t, err, "NodePort whose externalTrafficPolicy is Cluster hairpin should be able to be connected")
		require.Equal(t, expectedClientIP, clientIP)
	})
	t.Run("IntraNode/NodePort/ExternalTrafficPolicy:Local", func(t *testing.T) {
		skipIfProxyAllDisabled(t, data)
		clientIP, err := probeClientIPFromPod(data, pod, agnhostContainerName, nodePortLocalUrl)
		require.NoError(t, err, "NodePort whose externalTrafficPolicy is Local hairpin should be able to be connected")
		require.Equal(t, expectedClientIP, clientIP)
	})
	t.Run("IntraNode/LoadBalancer/ExternalTrafficPolicy:Cluster", func(t *testing.T) {
		clientIP, err := probeClientIPFromPod(data, pod, agnhostContainerName, lbClusterUrl)
		require.NoError(t, err, "LoadBalancer whose externalTrafficPolicy is Cluster hairpin should be able to be connected")
		require.Equal(t, expectedClientIP, clientIP)
	})
	t.Run("IntraNode/LoadBalancer/ExternalTrafficPolicy:Local", func(t *testing.T) {
		clientIP, err := probeClientIPFromPod(data, pod, agnhostContainerName, lbLocalUrl)
		require.NoError(t, err, "LoadBalancer whose externalTrafficPolicy is Local hairpin should be able to be connected")
		require.Equal(t, expectedClientIP, clientIP)
	})
}

// If client is Node A, when it accesses a ClusterIP/NodePort/LoadBalancer Service whose Endpoint is on Node B, below
// cases are hairpin (assumed that feature AntreaIPAM is not enabled):
// - Traffic mode: encap,    Endpoint network: host network,     OS: Linux/Windows
// - Traffic mode: noEncap,  Endpoint network: not host network, OS: Linux (packets are routed via uplink interface)
// - Traffic mode: noEncap,  Endpoint network: host network,     OS: Linux/Windows
// The IP changes of the hairpin connections are:
// - Node A Antrea gateway: Antrea gateway IP  -> Service IP
// - OVS DNAT:              Antrea gateway IP  -> Endpoint IP
// - OVS SNAT:              virtual IP         -> Endpoint IP
// - Node A Antrea gateway: virtual IP         -> Endpoint IP
// - Node A output:         Node A IP          -> Endpoint IP (another SNAT for virtual IP, otherwise reply packets can't be routed back).
// - Node B:                Node A IP          -> Endpoint IP
func testProxyInterNodeHairpinCases(data *TestData, t *testing.T, hostNetwork bool, expectedClientIP, node, clusterIPUrl, nodePortClusterUrl, lbClusterUrl string) {
	skipIfAntreaIPAMTest(t)
	currentEncapMode, err := data.GetEncapMode()
	if err != nil {
		t.Fatalf("Failed to get encap mode: %v", err)
	}
	if !hostNetwork {
		if testOptions.providerName == "kind" && (currentEncapMode == config.TrafficEncapModeEncap || currentEncapMode == config.TrafficEncapModeHybrid) {
			t.Skipf("Skipping test because inter-Node Pod traffic is encapsulated when testbed is Kind and traffic mode is encap/hybrid")
		} else if currentEncapMode == config.TrafficEncapModeEncap {
			t.Skipf("Skipping test because inter-Node Pod traffic is encapsulated when testbed is not Kind and traffic mode encap")
		}
	}

	t.Run("InterNode/ClusterIP", func(t *testing.T) {
		clientIP, err := probeClientIPFromNode(node, clusterIPUrl, data)
		require.NoError(t, err, "ClusterIP hairpin should be able to be connected")
		require.Equal(t, expectedClientIP, clientIP)
	})
	t.Run("InterNode/NodePort/ExternalTrafficPolicy:Cluster", func(t *testing.T) {
		skipIfProxyAllDisabled(t, data)
		if !hostNetwork && currentEncapMode == config.TrafficEncapModeNoEncap {
			skipIfHasWindowsNodes(t)
		}
		clientIP, err := probeClientIPFromNode(node, nodePortClusterUrl, data)
		require.NoError(t, err, "NodePort whose externalTrafficPolicy is Cluster hairpin should be able to be connected")
		require.Equal(t, expectedClientIP, clientIP)
	})
	t.Run("InterNode/LoadBalancer/ExternalTrafficPolicy:Cluster", func(t *testing.T) {
		skipIfProxyAllDisabled(t, data)
		if !hostNetwork && currentEncapMode == config.TrafficEncapModeNoEncap {
			skipIfHasWindowsNodes(t)
		}
		clientIP, err := probeClientIPFromNode(node, lbClusterUrl, data)
		require.NoError(t, err, "LoadBalancer whose externalTrafficPolicy is Cluster hairpin should be able to be connected")
		require.Equal(t, expectedClientIP, clientIP)
	})
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
	skipIfProxyDisabled(t, data)

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
	require.NoError(t, data.createNginxPodOnNode(nginx, data.testNamespace, nodeName, false))
	nginxIPs, err := data.podWaitForIPs(defaultTimeout, nginx, data.testNamespace)
	require.NoError(t, err)
	_, err = data.createNginxClusterIPService(nginx, data.testNamespace, false, ipFamily)
	defer data.deleteServiceAndWait(defaultTimeout, nginx, data.testNamespace)
	require.NoError(t, err)

	// Hold on to make sure that the Service is realized.
	time.Sleep(3 * time.Second)

	agentName, err := data.getAntreaPodOnNode(nodeName)
	require.NoError(t, err)
	var nginxIP string
	if *ipFamily == corev1.IPv6Protocol {
		nginxIP = nginxIPs.IPv6.String()
	} else {
		nginxIP = nginxIPs.IPv4.String()
	}

	keywords := make(map[string]string)
	keywords["EndpointDNAT"] = fmt.Sprintf("nat(dst=%s)", net.JoinHostPort(nginxIP, "80")) // endpointNATTable

	var groupKeywords []string
	if *ipFamily == corev1.IPv6Protocol {
		groupKeywords = append(groupKeywords,
			fmt.Sprintf("load:0x%s->NXM_NX_XXREG3[0..63],load:0x%s->NXM_NX_XXREG3[64..127]", strings.TrimLeft(hex.EncodeToString((*nginxIPs.IPv6)[8:16]), "0"), strings.TrimLeft(hex.EncodeToString((*nginxIPs.IPv6)[:8]), "0")))
	} else {
		groupKeywords = append(groupKeywords, fmt.Sprintf("0x%s->NXM_NX_REG3[]", strings.TrimLeft(hex.EncodeToString(nginxIPs.IPv4.To4()), "0")))
	}

	for tableName, keyword := range keywords {
		tableOutput, _, err := data.RunCommandFromPod(metav1.NamespaceSystem, agentName, "antrea-agent", []string{"ovs-ofctl", "dump-flows", defaultBridgeName, fmt.Sprintf("table=%s", tableName)})
		require.NoError(t, err)
		require.Contains(t, tableOutput, keyword)
	}

	groupOutput, _, err := data.RunCommandFromPod(metav1.NamespaceSystem, agentName, "antrea-agent", []string{"ovs-ofctl", "dump-groups", defaultBridgeName})
	require.NoError(t, err)
	for _, k := range groupKeywords {
		require.Contains(t, groupOutput, k)
	}

	require.NoError(t, data.DeletePodAndWait(defaultTimeout, nginx, data.testNamespace))

	// Wait for one second to make sure the pipeline to be updated.
	time.Sleep(time.Second)

	for tableName, keyword := range keywords {
		tableOutput, _, err := data.RunCommandFromPod(metav1.NamespaceSystem, agentName, "antrea-agent", []string{"ovs-ofctl", "dump-flows", defaultBridgeName, fmt.Sprintf("table=%s", tableName)})
		require.NoError(t, err)
		require.NotContains(t, tableOutput, keyword)
	}

	groupOutput, _, err = data.RunCommandFromPod(metav1.NamespaceSystem, agentName, "antrea-agent", []string{"ovs-ofctl", "dump-groups", defaultBridgeName})
	require.NoError(t, err)
	for _, k := range groupKeywords {
		require.NotContains(t, groupOutput, k)
	}
}

func testProxyServiceLifeCycleCase(t *testing.T, data *TestData) {
	if len(clusterInfo.podV4NetworkCIDR) != 0 {
		ipFamily := corev1.IPv4Protocol
		testProxyServiceLifeCycle(&ipFamily, []string{"169.254.169.1", "169.254.169.2"}, data, t)
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
	skipIfProxyDisabled(t, data)

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

	require.NoError(t, data.createNginxPodOnNode(nginx, data.testNamespace, nodeName, false))
	defer data.DeletePodAndWait(defaultTimeout, nginx, data.testNamespace)
	nginxIPs, err := data.podWaitForIPs(defaultTimeout, nginx, data.testNamespace)
	require.NoError(t, err)
	var nginxIP string
	if *ipFamily == corev1.IPv6Protocol {
		nginxIP = nginxIPs.IPv6.String()
	} else {
		nginxIP = nginxIPs.IPv4.String()
	}
	svc, err := data.createNginxClusterIPService(nginx, data.testNamespace, false, ipFamily)
	defer data.deleteServiceAndWait(defaultTimeout, nginx, data.testNamespace)
	require.NoError(t, err)
	_, err = data.createNginxLoadBalancerService(false, ingressIPs, ipFamily)
	defer data.deleteServiceAndWait(defaultTimeout, nginxLBService, data.testNamespace)
	require.NoError(t, err)
	agentName, err := data.getAntreaPodOnNode(nodeName)
	require.NoError(t, err)

	// Hold on to make sure that the Service is realized.
	time.Sleep(3 * time.Second)

	var svcLBflows []string
	if *ipFamily == corev1.IPv6Protocol {
		svcLBflows = append(svcLBflows, fmt.Sprintf("ipv6_dst=%s,tp_dst=80", svc.Spec.ClusterIP))
		for _, ingressIP := range ingressIPs {
			svcLBflows = append(svcLBflows, fmt.Sprintf("ipv6_dst=%s,tp_dst=80", ingressIP))
		}
	} else {
		svcLBflows = append(svcLBflows, fmt.Sprintf("nw_dst=%s,tp_dst=80", svc.Spec.ClusterIP))
		for _, ingressIP := range ingressIPs {
			svcLBflows = append(svcLBflows, fmt.Sprintf("nw_dst=%s,tp_dst=80", ingressIP))
		}
	}

	tableEndpointDNATFlowFormat := "nat(dst=%s:80)"
	if *ipFamily == corev1.IPv6Protocol {
		tableEndpointDNATFlowFormat = "nat(dst=[%s]:80)"
	}
	expectedFlows := []expectTableFlows{
		{
			"ServiceLB", // serviceLBTable
			svcLBflows,
		},
		{
			"EndpointDNAT",
			[]string{fmt.Sprintf(tableEndpointDNATFlowFormat, nginxIP)}, // endpointNATTable
		},
	}

	var groupKeyword string
	if *ipFamily == corev1.IPv6Protocol {
		groupKeyword = fmt.Sprintf("load:0x%s->NXM_NX_XXREG3[0..63],load:0x%s->NXM_NX_XXREG3[64..127],load:0x%x->NXM_NX_REG4[0..15]",
			strings.TrimLeft(hex.EncodeToString(nginxIPs.IPv6.To16()[8:16]), "0"),
			strings.TrimLeft(hex.EncodeToString(nginxIPs.IPv6.To16()[:8]), "0"),
			80)
	} else {
		groupKeyword = fmt.Sprintf("load:0x%s->NXM_NX_REG3[],load:0x%x->NXM_NX_REG4[0..15]", strings.TrimLeft(hex.EncodeToString(nginxIPs.IPv4.To4()), "0"), 80)
	}
	groupOutput, _, err := data.RunCommandFromPod(metav1.NamespaceSystem, agentName, "antrea-agent", []string{"ovs-ofctl", "dump-groups", defaultBridgeName})
	require.NoError(t, err)
	require.Contains(t, groupOutput, groupKeyword)
	for _, expectedTable := range expectedFlows {
		tableOutput, _, err := data.RunCommandFromPod(metav1.NamespaceSystem, agentName, "antrea-agent", []string{"ovs-ofctl", "dump-flows", defaultBridgeName, fmt.Sprintf("table=%s", expectedTable.tableName)})
		require.NoError(t, err)
		for _, expectedFlow := range expectedTable.flows {
			require.Contains(t, tableOutput, expectedFlow)
		}
	}

	require.NoError(t, data.deleteService(data.testNamespace, nginx))
	require.NoError(t, data.deleteService(data.testNamespace, nginxLBService))

	// Hold on to make sure that the Service is realized.
	time.Sleep(3 * time.Second)

	groupOutput, _, err = data.RunCommandFromPod(metav1.NamespaceSystem, agentName, "antrea-agent", []string{"ovs-ofctl", "dump-groups", defaultBridgeName})
	require.NoError(t, err)
	require.NotContains(t, groupOutput, groupKeyword)
	for _, expectedTable := range expectedFlows {
		tableOutput, _, err := data.RunCommandFromPod(metav1.NamespaceSystem, agentName, "antrea-agent", []string{"ovs-ofctl", "dump-flows", defaultBridgeName, fmt.Sprintf("table=%s", expectedTable.tableName)})
		require.NoError(t, err)
		for _, expectedFlow := range expectedTable.flows {
			require.NotContains(t, tableOutput, expectedFlow)
		}
	}
}

// TestProxyLoadBalancerModeDSR creates a LoadBalancer Service and verifies both external and internal clients accessing
// its LoadBalancer IPs work as expected.
// Client IP should always be preserved regardless of whether the traffic is externally or internally originated.
// Session affinity should take effect when it's enabled.
func TestProxyLoadBalancerModeDSR(t *testing.T) {
	skipIfFeatureDisabled(t, features.LoadBalancerModeDSR, true, false)
	skipIfHasWindowsNodes(t)
	skipIfNumNodesLessThan(t, 3)
	skipIfAntreaIPAMTest(t)

	data, err := setupTest(t)
	require.NoError(t, err, "Error when setting up test")
	defer teardownTest(t, data)
	skipIfProxyDisabled(t, data)
	skipIfProxyAllDisabled(t, data)
	skipIfEncapModeIsNot(t, data, config.TrafficEncapModeEncap)

	ingressNode := controlPlaneNodeName()
	backendNode1 := workerNodeName(1)
	backendNode2 := workerNodeName(2)

	internalClient := "internal-client"
	err = NewPodBuilder(internalClient, data.testNamespace, ToolboxImage).OnNode(ingressNode).Create(data)
	require.NoError(t, err, "Failed to create internal client")
	defer deletePodWrapper(t, data, data.testNamespace, internalClient)
	internalClientIPs, err := data.podWaitForIPs(defaultTimeout, internalClient, data.testNamespace)
	require.NoError(t, err, "Error when waiting for Pod '%s' to be in the Running state", internalClient)

	// Create 4 backend Nodes on 2 backend Nodes different from the ingress Node.
	var wg sync.WaitGroup
	for i, node := range []string{backendNode1, backendNode1, backendNode2, backendNode2} {
		wg.Add(1)
		go func(index int, node string) {
			defer wg.Done()
			createAgnhostPod(t, data, fmt.Sprintf("agnhost-%d", index), node, false)
		}(i, node)
	}
	wg.Wait()

	testCases := []struct {
		name                string
		withSessionAffinity bool
	}{
		{
			name:                "IPv4,withSessionAffinity",
			withSessionAffinity: true,
		},
		{
			name:                "IPv4,withoutSessionAffinity",
			withSessionAffinity: false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			skipIfNotIPv4Cluster(t)
			ingressNodeIP := controlPlaneNodeIPv4()
			ipProtocol := corev1.IPv4Protocol
			lbIP := "1.1.2.1"
			internalClientIP := internalClientIPs.IPv4.String()
			externalClientIP := "1.1.1.1"
			externalClientGateway := "1.1.1.254"
			externalIPPrefix := 24

			// Create another netns to fake an external network on the host network Pod.
			externalClient := randName("external-client-")
			cmd, externalNetns := getCommandInFakeExternalNetwork("sleep infinity", externalIPPrefix, externalClientIP, externalClientGateway)
			err := NewPodBuilder(externalClient, data.testNamespace, ToolboxImage).OnNode(ingressNode).WithCommand([]string{"sh", "-c", cmd}).InHostNetwork().Privileged().Create(data)
			require.NoError(t, err, "Failed to create external client")
			defer deletePodWrapper(t, data, data.testNamespace, externalClient)
			err = data.podWaitForRunning(defaultTimeout, externalClient, data.testNamespace)
			require.NoError(t, err, "Error when waiting for Pod '%s' to be in the Running state", externalClient)

			// Since the "external client" runs in a netns on ingress Node, we install a route on backend Node to route reply
			// traffic to ingress Node.
			addRouteToClientIPCmd := []string{"ip", "route", "replace", externalClientIP, "via", ingressNodeIP}
			stdout, stderr, err := data.RunCommandFromAntreaPodOnNode(backendNode1, addRouteToClientIPCmd)
			require.NoError(t, err, "Failed to add route to client IP on Node %s, stdout: %s, stderr: %s", backendNode1, stdout, stderr)
			stdout, stderr, err = data.RunCommandFromAntreaPodOnNode(backendNode2, addRouteToClientIPCmd)
			require.NoError(t, err, "Failed to add route to client IP on Node %s, stdout: %s, stderr: %s", backendNode2, stdout, stderr)
			defer func() {
				delRouteToClientIPCmd := []string{"ip", "route", "del", externalClientIP, "via", ingressNodeIP}
				stdout, stderr, err := data.RunCommandFromAntreaPodOnNode(backendNode1, delRouteToClientIPCmd)
				assert.NoError(t, err, "Failed to delete route to client IP on Node %s, stdout: %s, stderr: %s", backendNode1, stdout, stderr)
				stdout, stderr, err = data.RunCommandFromAntreaPodOnNode(backendNode2, delRouteToClientIPCmd)
				assert.NoError(t, err, "Failed to delete route to client IP on Node %s, stdout: %s, stderr: %s", backendNode2, stdout, stderr)
			}()

			serviceName := fmt.Sprintf("svc-dsr")
			annotations := map[string]string{
				types.ServiceLoadBalancerModeAnnotationKey: "dsr",
			}
			service, err := data.createAgnhostLoadBalancerService(serviceName, tc.withSessionAffinity, false, []string{lbIP}, &ipProtocol, annotations)
			require.NoError(t, err)
			defer data.deleteServiceAndWait(defaultTimeout, serviceName, data.testNamespace)

			curlServiceWithPath := func(clientPod, clientNetns, path string) string {
				testURL := fmt.Sprintf("http://%s:%d/%s", lbIP, service.Spec.Ports[0].Port, path)
				cmd = fmt.Sprintf("curl --connect-timeout 1 --retry 5 --retry-connrefused %s", testURL)
				if clientNetns != "" {
					cmd = fmt.Sprintf("ip netns exec %s %s", clientNetns, cmd)
				}
				stdout, stderr, err = data.RunCommandFromPod(data.testNamespace, clientPod, "toolbox", []string{"sh", "-c", cmd})
				require.NoError(t, err, "Failed to access ExternalIP of Service %s from Pod %s, stdout: %s, stderr: %s", service.Name, clientPod, stdout, stderr)
				return stdout
			}

			checkClientIPAndSessionAffinity := func(clientPod, clientNetns, clientIP string) {
				clientIPResponse := curlServiceWithPath(clientPod, clientNetns, "clientip")
				gotClientIP, _, err := net.SplitHostPort(clientIPResponse)
				require.NoError(t, err, "Failed to got client IP from stdout: %s", clientIPResponse)
				assert.Equal(t, clientIP, gotClientIP, "Client IP should be preserved with DSR mode")

				hostNames := sets.New[string]()
				for i := 0; i < 10; i++ {
					hostName := curlServiceWithPath(clientPod, clientNetns, "hostname")
					t.Logf("Request #%d from %s got hostname: %s", i, clientPod, hostName)
					hostNames.Insert(hostName)
					// Session affinity can only be guaranteed after the learned flow is realized in the datapath, which
					// currently has a delay of 200ms, as set by start_ovs via other_config:max-revalidator.
					// To avoid test flake, we wait enough time before sending more requests after the first one.
					if i == 0 {
						time.Sleep(200 * time.Millisecond)
					}
				}
				if tc.withSessionAffinity {
					assert.Len(t, hostNames, 1, "Hostnames should be the same when session affinity is enabled")
				} else {
					// There is 1/262144 (1/4^9) chance that all requests are forwarded to the same backend when session affinity is disabled.
					assert.Greater(t, len(hostNames), 1, "Hostnames should not be the same when session affinity is disabled")
				}
			}
			checkClientIPAndSessionAffinity(externalClient, externalNetns, externalClientIP)
			checkClientIPAndSessionAffinity(internalClient, "", internalClientIP)

			// Update the Service's LoadBalancerMode to NAT by updating its annotation, verify the operation takes effect.
			_, err = data.updateService(serviceName, func(service *corev1.Service) {
				if service.Annotations == nil {
					service.Annotations = map[string]string{}
				}
				service.Annotations[types.ServiceLoadBalancerModeAnnotationKey] = "nat"
			})
			require.NoError(t, err)
			clientIPResponse := curlServiceWithPath(externalClient, externalNetns, "clientip")
			gotClientIP, _, err := net.SplitHostPort(clientIPResponse)
			require.NoError(t, err, "Failed to got client IP from stdout: %s", clientIPResponse)
			assert.NotEqual(t, externalClientIP, gotClientIP, "Client IP should not be preserved with NAT mode")
		})
	}
}
