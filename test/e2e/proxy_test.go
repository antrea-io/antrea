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

	"antrea.io/antrea/pkg/agent/config"
	agentconfig "antrea.io/antrea/pkg/config/agent"
	controllerconfig "antrea.io/antrea/pkg/config/controller"
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

func skipIfProxyAllDisabled(t *testing.T, data *TestData) {
	isProxyAll, err := data.isProxyAll()
	if err != nil {
		t.Fatalf("Error getting option antreaProxy.proxyAll value")
	}
	if !isProxyAll {
		t.Skipf("Skipping test because option antreaProxy.proxyAll is not enabled")
	}
}

func skipIfKubeProxyEnabled(t *testing.T, data *TestData) {
	_, err := data.clientset.AppsV1().DaemonSets(kubeNamespace).Get(context.TODO(), "kube-proxy", metav1.GetOptions{})
	if err == nil {
		t.Skipf("Skipping test because kube-proxy is running")
	}
}

func probeFromNode(node string, url string) error {
	_, _, _, err := RunCommandOnNode(node, fmt.Sprintf("curl --connect-timeout 1 --retry 5 --retry-connrefused %s", url))
	return err
}

func probeHostnameFromNode(node string, baseUrl string) (string, error) {
	url := fmt.Sprintf("%s/%s", baseUrl, "hostname")
	_, hostname, _, err := RunCommandOnNode(node, fmt.Sprintf("curl --connect-timeout 1 --retry 5 --retry-connrefused %s", url))
	return hostname, err
}

func probeClientIPFromNode(node string, baseUrl string) (string, error) {
	url := fmt.Sprintf("%s/%s", baseUrl, "clientip")
	_, hostPort, _, err := RunCommandOnNode(node, fmt.Sprintf("curl --connect-timeout 1 --retry 5 --retry-connrefused %s", url))
	if err != nil {
		return "", err
	}
	host, _, err := net.SplitHostPort(hostPort)
	return host, err
}

func probeFromPod(data *TestData, pod string, url string) error {
	_, _, err := data.runCommandFromPod(testNamespace, pod, busyboxContainerName, []string{"wget", "-O", "-", url, "-T", "1", "-t", "5"})
	return err
}

func probeHostnameFromPod(data *TestData, pod string, baseUrl string) (string, error) {
	url := fmt.Sprintf("%s/%s", baseUrl, "hostname")
	hostname, _, err := data.runCommandFromPod(testNamespace, pod, busyboxContainerName, []string{"wget", "-O", "-", url, "-T", "1", "-t", "5"})
	return hostname, err
}

func probeClientIPFromPod(data *TestData, pod string, baseUrl string) (string, error) {
	url := fmt.Sprintf("%s/%s", baseUrl, "clientip")
	hostPort, _, err := data.runCommandFromPod(testNamespace, pod, busyboxContainerName, []string{"wget", "-O", "-", url, "-T", "1", "-t", "5"})
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
	skipIfProxyDisabled(t)
	skipIfHasWindowsNodes(t)
	skipIfNumNodesLessThan(t, 2)
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
	skipIfProxyAllDisabled(t, data)

	// Create a busybox Pod on every Node. The busybox Pod is used as a client.
	nodes := []string{nodeName(0), nodeName(1)}
	var busyboxes, busyboxIPs []string
	for idx, node := range nodes {
		podName, ips, _ := createAndWaitForPod(t, data, data.createBusyboxPodOnNode, fmt.Sprintf("busybox-%d-", idx), node, testNamespace, false)
		busyboxes = append(busyboxes, podName)
		if !isIPv6 {
			busyboxIPs = append(busyboxIPs, ips.ipv4.String())
		} else {
			busyboxIPs = append(busyboxIPs, ips.ipv6.String())
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
	_, err = data.createAgnhostLoadBalancerService("agnhost-cluster", true, false, clusterIngressIP, &ipProtocol)
	require.NoError(t, err)
	_, err = data.createAgnhostLoadBalancerService("agnhost-local", true, true, localIngressIP, &ipProtocol)
	require.NoError(t, err)

	port := "8080"
	clusterUrl := net.JoinHostPort(clusterIngressIP[0], port)
	localUrl := net.JoinHostPort(localIngressIP[0], port)

	// Create agnhost Pods which are not on host network.
	agnhosts := []string{"agnhost-0", "agnhost-1"}
	for idx, node := range nodes {
		createAgnhostPod(t, data, agnhosts[idx], node, false)
	}
	t.Run("Non-HostNetwork Endpoints", func(t *testing.T) {
		loadBalancerTestCases(t, data, clusterUrl, localUrl, nodes, busyboxes, busyboxIPs, agnhosts)
	})

	// Delete agnhost Pods which are not on host network and create new agnhost Pods which are on host network.
	hostAgnhosts := []string{"agnhost-host-0", "agnhost-host-1"}
	for idx, node := range nodes {
		require.NoError(t, data.deletePod(testNamespace, agnhosts[idx]))
		createAgnhostPod(t, data, hostAgnhosts[idx], node, true)
	}
	t.Run("HostNetwork Endpoints", func(t *testing.T) {
		loadBalancerTestCases(t, data, clusterUrl, localUrl, nodes, busyboxes, busyboxIPs, nodes)
	})
}

func loadBalancerTestCases(t *testing.T, data *TestData, clusterUrl, localUrl string, nodes, pods, podIPs, hostnames []string) {
	t.Run("ExternalTrafficPolicy:Cluster/Client:Node", func(t *testing.T) {
		testLoadBalancerClusterFromNode(t, data, nodes, clusterUrl)
	})
	t.Run("ExternalTrafficPolicy:Cluster/Client:Pod", func(t *testing.T) {
		testLoadBalancerClusterFromPod(t, data, pods, clusterUrl)
	})
	t.Run("ExternalTrafficPolicy:Local/Client:Node", func(t *testing.T) {
		testLoadBalancerLocalFromNode(t, data, nodes, localUrl, hostnames)
	})
	t.Run("ExternalTrafficPolicy:Local/Client:Pod", func(t *testing.T) {
		testLoadBalancerLocalFromPod(t, data, pods, localUrl, podIPs, hostnames)
	})
}

func testLoadBalancerClusterFromNode(t *testing.T, data *TestData, nodes []string, url string) {
	skipIfKubeProxyEnabled(t, data)
	for _, node := range nodes {
		require.NoError(t, probeFromNode(node, url), "Service LoadBalancer whose externalTrafficPolicy is Cluster should be able to be connected from Node")
	}
}

func testLoadBalancerClusterFromPod(t *testing.T, data *TestData, pods []string, url string) {
	for _, pod := range pods {
		require.NoError(t, probeFromPod(data, pod, url), "Service LoadBalancer whose externalTrafficPolicy is Cluster should be able to be connected from Pod")
	}
}

func testLoadBalancerLocalFromNode(t *testing.T, data *TestData, nodes []string, url string, expectedHostnames []string) {
	skipIfKubeProxyEnabled(t, data)
	for idx, node := range nodes {
		hostname, err := probeHostnameFromNode(node, url)
		require.NoError(t, err, "Service LoadBalancer whose externalTrafficPolicy is Local should be able to be connected from Node")
		require.Equal(t, hostname, expectedHostnames[idx])
	}
}

func testLoadBalancerLocalFromPod(t *testing.T, data *TestData, pods []string, url string, expectedClientIPs, expectedHostnames []string) {
	errMsg := "Service NodePort whose externalTrafficPolicy is Local should be able to be connected from Pod"
	for idx, pod := range pods {
		hostname, err := probeHostnameFromPod(data, pod, url)
		require.NoError(t, err, errMsg)
		require.Equal(t, hostname, expectedHostnames[idx])

		clientIP, err := probeClientIPFromPod(data, pod, url)
		require.NoError(t, err, errMsg)
		require.Equal(t, clientIP, expectedClientIPs[idx])
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
	skipIfProxyDisabled(t)
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
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
		podName, ips, _ := createAndWaitForPod(t, data, data.createBusyboxPodOnNode, fmt.Sprintf("busybox-%d-", idx), node, testNamespace, false)
		busyboxes = append(busyboxes, podName)
		if !isIPv6 {
			busyboxIPs = append(busyboxIPs, ips.ipv4.String())
		} else {
			busyboxIPs = append(busyboxIPs, ips.ipv6.String())
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
		require.NoError(t, data.deletePod(testNamespace, agnhosts[idx]))
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
		testNodePortLocalFromNode(t, data, nodes, localUrls, hostnames)
	})
	t.Run("ExternalTrafficPolicy:Local/Client:Pod", func(t *testing.T) {
		testNodePortLocalFromPod(t, data, pods, localUrls, podIPs, hostnames)
	})
}

func TestNodePortAndEgressWithTheSameBackendPod(t *testing.T) {
	skipIfHasWindowsNodes(t)
	skipIfNotIPv4Cluster(t)
	skipIfNumNodesLessThan(t, 2)
	skipIfProxyDisabled(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
	skipIfProxyAllDisabled(t, data)
	skipIfEncapModeIsNot(t, data, config.TrafficEncapModeEncap) // Egress works for encap mode only.

	cc := func(config *controllerconfig.ControllerConfig) {
		config.FeatureGates["Egress"] = true
	}
	ac := func(config *agentconfig.AgentConfig) {
		config.FeatureGates["Egress"] = true
	}

	if err := data.mutateAntreaConfigMap(cc, ac, true, true); err != nil {
		t.Fatalf("Failed to enable Egress feature: %v", err)
	}

	// Create a NodePort Service.
	nodePortIP := controlPlaneNodeIPv4()
	ipProtocol := corev1.IPv4Protocol
	var portStr string
	nodePortSvc, err := data.createNginxNodePortService("test-nodeport-svc", true, false, &ipProtocol)
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
	egress := data.createEgress(t, "test-egress", nil, map[string]string{"app": "nginx"}, "", egressNodeIP)
	defer data.crdClient.CrdV1alpha2().Egresses().Delete(context.TODO(), egress.Name, metav1.DeleteOptions{})

	// Create the backend Pod on control plane Node.
	backendPodName := "test-nodeport-egress-backend-pod"
	require.NoError(t, data.createNginxPodOnNode(backendPodName, testNamespace, controlPlaneNodeName(), false))
	defer deletePodWrapper(t, data, testNamespace, backendPodName)
	if err := data.podWaitForRunning(defaultTimeout, backendPodName, testNamespace); err != nil {
		t.Fatalf("Error when waiting for Pod '%s' to be in the Running state", backendPodName)
	}

	// Create another netns to fake an external network on the host network Pod.
	testPod := "test-client"
	testNetns := "test-ns"
	cmd := fmt.Sprintf(`ip netns add %[1]s && \
ip link add dev %[1]s-a type veth peer name %[1]s-b && \
ip link set dev %[1]s-a netns %[1]s && \
ip addr add %[3]s/%[4]d dev %[1]s-b && \
ip link set dev %[1]s-b up && \
ip netns exec %[1]s ip addr add %[2]s/%[4]d dev %[1]s-a && \
ip netns exec %[1]s ip link set dev %[1]s-a up && \
ip netns exec %[1]s ip route replace default via %[3]s && \
sleep 3600
`, testNetns, "1.1.1.1", "1.1.1.254", 24)
	if err := data.createPodOnNode(testPod, testNamespace, controlPlaneNodeName(), agnhostImage, []string{"sh", "-c", cmd}, nil, nil, nil, true, func(pod *corev1.Pod) {
		privileged := true
		pod.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{Privileged: &privileged}
	}); err != nil {
		t.Fatalf("Failed to create client Pod: %v", err)
	}
	defer deletePodWrapper(t, data, testNamespace, testPod)
	if err := data.podWaitForRunning(defaultTimeout, testPod, testNamespace); err != nil {
		t.Fatalf("Error when waiting for Pod '%s' to be in the Running state", testPod)
	}
	// Connect to NodePort on control plane Node in the fake external network.
	cmd = fmt.Sprintf("ip netns exec %s curl --connect-timeout 1 --retry 5 --retry-connrefused %s", testNetns, testNodePortURL)
	_, _, err = data.runCommandFromPod(testNamespace, testPod, agnhostContainerName, []string{"sh", "-c", cmd})
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

	require.NoError(t, data.createPodOnNode(podName, testNamespace, node, agnhostImage, []string{}, args, nil, ports, hostNetwork, nil))
	_, err := data.podWaitForIPs(defaultTimeout, podName, testNamespace)
	require.NoError(t, err)
	require.NoError(t, data.podWaitForRunning(defaultTimeout, podName, testNamespace))
}

func testNodePortClusterFromRemote(t *testing.T, data *TestData, nodes, urls []string) {
	skipIfKubeProxyEnabled(t, data)
	for idx, node := range nodes {
		require.NoError(t, probeFromNode(node, urls[idx]), "Service NodePort whose externalTrafficPolicy is Cluster should be able to be connected from remote Node")
	}
}

func testNodePortClusterFromNode(t *testing.T, data *TestData, nodes, urls []string) {
	skipIfKubeProxyEnabled(t, data)
	for idx, node := range nodes {
		require.NoError(t, probeFromNode(node, urls[idx]), "Service NodePort whose externalTrafficPolicy is Cluster should be able to be connected from Node")
	}
}

func testNodePortClusterFromPod(t *testing.T, data *TestData, pods, urls []string) {
	for _, url := range urls {
		for _, pod := range pods {
			require.NoError(t, probeFromPod(data, pod, url), "Service NodePort whose externalTrafficPolicy is Cluster should be able to be connected from Pod")
		}
	}
}

func testNodePortLocalFromRemote(t *testing.T, data *TestData, nodes, urls, expectedClientIPs, expectedHostnames []string) {
	skipIfKubeProxyEnabled(t, data)
	errMsg := "Service NodePort whose externalTrafficPolicy is Local should be able to be connected from remote Node"
	for idx, node := range nodes {
		hostname, err := probeHostnameFromNode(node, urls[idx])
		require.NoError(t, err, errMsg)
		require.Equal(t, expectedHostnames[idx], hostname)

		clientIP, err := probeClientIPFromNode(node, urls[idx])
		require.NoError(t, err, errMsg)
		require.Equal(t, expectedClientIPs[idx], clientIP)
	}
}

func testNodePortLocalFromNode(t *testing.T, data *TestData, nodes, urls, expectedHostnames []string) {
	skipIfKubeProxyEnabled(t, data)
	for idx, node := range nodes {
		hostname, err := probeHostnameFromNode(node, urls[idx])
		require.NoError(t, err, "Service NodePort whose externalTrafficPolicy is Local should be able to be connected rom Node")
		require.Equal(t, expectedHostnames[idx], hostname)
	}
}

func testNodePortLocalFromPod(t *testing.T, data *TestData, pods, urls, expectedClientIPs, expectedHostnames []string) {
	errMsg := "There should be no errors when accessing to Service NodePort whose externalTrafficPolicy is Local from Pod"
	for idx, pod := range pods {
		hostname, err := probeHostnameFromPod(data, pod, urls[idx])
		require.NoError(t, err, errMsg)
		require.Equal(t, expectedHostnames[idx], hostname)

		clientIP, err := probeClientIPFromPod(data, pod, urls[idx])
		require.NoError(t, err, errMsg)
		require.Equal(t, expectedClientIPs[idx], clientIP)
	}
}

func TestProxyServiceSessionAffinity(t *testing.T) {
	skipIfHasWindowsNodes(t)
	skipIfProxyDisabled(t)
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

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
	skipIfProxyDisabled(t)
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
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

	require.NoError(t, data.createNginxPodOnNode(nginx, testNamespace, nodeName, false))
	nginxIP, err := data.podWaitForIPs(defaultTimeout, nginx, testNamespace)
	defer data.deletePodAndWait(defaultTimeout, nginx, testNamespace)
	require.NoError(t, err)
	require.NoError(t, data.podWaitForRunning(defaultTimeout, nginx, testNamespace))
	svc, err := data.createNginxClusterIPService(nginx, testNamespace, true, ipFamily)
	defer data.deleteServiceAndWait(defaultTimeout, nginx)
	require.NoError(t, err)
	_, err = data.createNginxLoadBalancerService(true, ingressIPs, ipFamily)
	defer data.deleteServiceAndWait(defaultTimeout, nginxLBService)
	require.NoError(t, err)

	busyboxPod := randName("busybox-")
	require.NoError(t, data.createBusyboxPodOnNode(busyboxPod, testNamespace, nodeName, false))
	defer data.deletePodAndWait(defaultTimeout, busyboxPod, testNamespace)
	require.NoError(t, data.podWaitForRunning(defaultTimeout, busyboxPod, testNamespace))
	stdout, stderr, err := data.runCommandFromPod(testNamespace, busyboxPod, busyboxContainerName, []string{"wget", "-O", "-", svc.Spec.ClusterIP, "-T", "1", "-t", "5"})
	require.NoError(t, err, fmt.Sprintf("ipFamily: %v\nstdout: %s\nstderr: %s\n", *ipFamily, stdout, stderr))
	for _, ingressIP := range ingressIPs {
		stdout, stderr, err := data.runCommandFromPod(testNamespace, busyboxPod, busyboxContainerName, []string{"wget", "-O", "-", ingressIP, "-T", "1", "-t", "5"})
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
		for _, ingressIP := range ingressIPs {
			require.Contains(t, table40Output, fmt.Sprintf("nw_dst=%s,tp_dst=80", ingressIP))
		}
	} else {
		require.Contains(t, table40Output, fmt.Sprintf("ipv6_dst=%s,tp_dst=80", svc.Spec.ClusterIP))
		require.Contains(t, table40Output, fmt.Sprintf("load:0x%s->NXM_NX_XXREG3[0..63]", strings.TrimLeft(hex.EncodeToString([]byte(*nginxIP.ipv6)[8:16]), "0")))
		require.Contains(t, table40Output, fmt.Sprintf("load:0x%s->NXM_NX_XXREG3[64..127]", strings.TrimLeft(hex.EncodeToString([]byte(*nginxIP.ipv6)[0:8]), "0")))
		for _, ingressIP := range ingressIPs {
			require.Contains(t, table40Output, fmt.Sprintf("ipv6_dst=%s,tp_dst=80", ingressIP))
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
	skipIfProxyDisabled(t)
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

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
	svc, err := data.createService(busybox, testNamespace, 80, 80, map[string]string{"antrea-e2e": busybox}, false, false, corev1.ServiceTypeClusterIP, ipFamily)
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
	skipIfProxyDisabled(t)
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

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
	require.NoError(t, data.createNginxPodOnNode(nginx, testNamespace, nodeName, false))
	nginxIPs, err := data.podWaitForIPs(defaultTimeout, nginx, testNamespace)
	require.NoError(t, err)
	_, err = data.createNginxClusterIPService(nginx, testNamespace, false, ipFamily)
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
		testProxyServiceLifeCycle(&ipFamily, []string{"169.254.169.1", "169.254.169.2"}, data, t)
	}
	if len(clusterInfo.podV6NetworkCIDR) != 0 {
		ipFamily := corev1.IPv6Protocol
		testProxyServiceLifeCycle(&ipFamily, []string{"fd75::aabb:ccdd:ef00", "fd75::aabb:ccdd:ef01"}, data, t)
	}
}

func TestProxyServiceLifeCycle(t *testing.T) {
	skipIfHasWindowsNodes(t)
	skipIfProxyDisabled(t)
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

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

	require.NoError(t, data.createNginxPodOnNode(nginx, testNamespace, nodeName, false))
	defer data.deletePodAndWait(defaultTimeout, nginx, testNamespace)
	nginxIPs, err := data.podWaitForIPs(defaultTimeout, nginx, testNamespace)
	require.NoError(t, err)
	var nginxIP string
	if *ipFamily == corev1.IPv6Protocol {
		nginxIP = nginxIPs.ipv6.String()
	} else {
		nginxIP = nginxIPs.ipv4.String()
	}
	svc, err := data.createNginxClusterIPService(nginx, testNamespace, false, ipFamily)
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
		for _, ingressIP := range ingressIPs {
			svcLBflows = append(svcLBflows, fmt.Sprintf("ipv6_dst=%s,tp_dst=80", ingressIP))
		}
	} else {
		svcLBflows = append(svcLBflows, fmt.Sprintf("nw_dst=%s,tp_dst=80", svc.Spec.ClusterIP))
		for _, ingressIP := range ingressIPs {
			svcLBflows = append(svcLBflows, fmt.Sprintf("nw_dst=%s,tp_dst=80", ingressIP))
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
