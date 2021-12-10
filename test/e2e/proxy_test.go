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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"antrea.io/antrea/pkg/features"
)

type agnhostEndpoint string

const (
	emptyEndpoint       agnhostEndpoint = ""
	clientIPEndpoint    agnhostEndpoint = "clientip"
	hostNetworkEndpoint agnhostEndpoint = "shell?cmd=echo+$hostnetwork"
	nodeNameEndpoint agnhostEndpoint = "shell?cmd=echo+$nodeName"

	expectedNonHostNetworkResult = "{\"output\":\"false\\n\"}"
	expectedHostNetworkResult    = "{\"output\":\"true\\n\"}"
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
	_, err := probeEndpointFromNode(node, url, emptyEndpoint)
	return err
}

func probeClientIPEndpointFromNode(node string, url string) (string, error) {
	stdout, err := probeEndpointFromNode(node, url, clientIPEndpoint)
	if err != nil {
		return "", err
	}
	host, _, err := net.SplitHostPort(stdout)
	return host, err
}

func probeNodeNameEndpointFromNode(node string, url string) (string, error) {
	stdout, err := probeEndpointFromNode(node, url, nodeNameEndpoint)
	if err != nil {
		return "", err
	}
	host, _, err := net.SplitHostPort(stdout)
	return host, err
}

func probeEndpointFromNode(node string, baseURL string, endpoint agnhostEndpoint) (string, error) {
	url := fmt.Sprintf("%s/%s", baseURL, endpoint)
	rc, stdout, stderr, err := RunCommandOnNode(node, fmt.Sprintf("curl --connect-timeout 5 --retry 5 --retry-connrefused '%s'", url))
	if err != nil {
		return "", fmt.Errorf("rc: %d, stdout: %s, stderr: %s, err: %v", rc, stdout, stderr, err)
	}
	return stdout, nil
}

func probeFromPod(data *TestData, pod string, os string, url string) error {
	_, err := probeEndpointFromPod(data, pod, os, url, emptyEndpoint)
	return err
}

func probeClientIPEndpointFromPod(data *TestData, pod string, os string, url string) (string, error) {
	stdout, err := probeEndpointFromPod(data, pod, os, url, clientIPEndpoint)
	if err != nil {
		return "", err
	}
	host, _, err := net.SplitHostPort(stdout)
	return host, err
}

func probeNodeNameEndpointFromPod(data *TestData, pod string, os string, url string) (string, error) {
	stdout, err := probeEndpointFromPod(data, pod, os, url, nodeNameEndpoint)
	if err != nil {
		return "", err
	}
	host, _, err := net.SplitHostPort(stdout)
	return host, err
}

func probeEndpointFromPod(data *TestData, pod string, os string, baseUrl string, endpoint agnhostEndpoint) (string, error) {
	url := fmt.Sprintf("%s/%s", baseUrl, endpoint)
	cmd := []string{"curl", "--connect-timeout", "5", "--retry", "5", url}
	stdout, stderr, err := data.runCommandFromPod(testNamespace, pod, agnhostContainerName, cmd)
	if err != nil {
		return "", fmt.Errorf("stdout: %s, stderr: %s, err: %v", stdout, stderr, err)
	}
	return stdout, nil
}

func pickNodes(isIPv6 bool) ([]string, []string) {
	nodes := []string{nodeName(0)}
	nodeIPs := []string{controlPlaneNodeIPv4()}
	if isIPv6 {
		nodeIPs = []string{controlPlaneNodeIPv6()}
	}
	if len(clusterInfo.windowsNodes) > 0 {
		// For a Windows cluster, ensure a Windows Node is included.
		// Node 0 is always Linux Node, control-plane Node.
		winNode := clusterInfo.windowsNodes[0]
		nodes = append(nodes, nodeName(winNode))
		if isIPv6 {
			nodeIPs = append(nodeIPs, workerNodeIPv6(winNode))
		} else {
			nodeIPs = append(nodeIPs, workerNodeIPv4(winNode))
		}
	} else {
		nodes = append(nodes, nodeName(1))
		if isIPv6 {
			nodeIPs = append(nodeIPs, workerNodeIPv6(1))
		} else {
			nodeIPs = append(nodeIPs, workerNodeIPv4(1))
		}
	}
	return nodes, nodeIPs
}

func TestProxyLoadBalancerServiceIPv4(t *testing.T) {
	skipIfNotIPv4Cluster(t)
	testProxyLoadBalancerService(t, false)
}

func TestProxyLoadBalancerServiceIPv6(t *testing.T) {
	skipIfNotIPv6Cluster(t)
	testProxyLoadBalancerService(t, true)
}

func loadBalancerClusterTestCases(t *testing.T, data *TestData, clusterUrl string, nodes, pods, podOSes []string) {
	t.Run("Client:Node", func(t *testing.T) {
		testLoadBalancerClusterFromNode(t, data, nodes, clusterUrl)
	})
	t.Run("Client:Pod", func(t *testing.T) {
		testLoadBalancerClusterFromPod(t, data, pods, podOSes, clusterUrl)
	})
}

func loadBalancerLocalTestCases(t *testing.T, data *TestData, localUrl string, nodes, nodeIPs, pods, podIPs, podOSes []string, hostNetwork bool) {
	expectedClientIPs := make([]string, len(podIPs))
	copy(expectedClientIPs, podIPs)
	hostNetworkStr := expectedNonHostNetworkResult
	if hostNetwork {
		hostNetworkStr = expectedHostNetworkResult
		for idx := range podOSes {
			if podOSes[idx] == "windows" {
				// There's a NetNat on Windows host doing SNAT. So if endpoint is a hostNetwork Pod
				// request packet will be SNATed to Node IP.
				expectedClientIPs[idx] = nodeIPs[idx]
			}
		}
	}

	t.Run("Client:Node", func(t *testing.T) {
		testLoadBalancerLocalFromNode(t, data, nodes, localUrl, hostNetworkStr, nodes)
	})
	t.Run("Client:Pod", func(t *testing.T) {
		testLoadBalancerLocalFromPod(t, data, pods, podOSes, localUrl, expectedClientIPs, hostNetworkStr, nodes)
	})
}

func testProxyLoadBalancerService(t *testing.T, isIPv6 bool) {
	skipIfProxyDisabled(t)
	skipIfNumNodesLessThan(t, 2)
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
	skipIfProxyAllDisabled(t, data)

	nodes, nodeIPs := pickNodes(isIPv6)

	var clients, clientIPs, clientOSes []string
	for idx, node := range nodes {
		os := nodeOS(node)
		clientOSes = append(clientOSes, os)
		podName, ips, _ := createAndWaitForPod(t, data, data.createAgnhostPodOnNode, fmt.Sprintf("client-%d-%s-", idx, os), node, testNamespace, false)
		clients = append(clients, podName)
		if !isIPv6 {
			clientIPs = append(clientIPs, ips.ipv4.String())
		} else {
			clientIPs = append(clientIPs, ips.ipv6.String())
		}
	}

	clusterIngressIP := []string{"192.0.2.100"}
	localIngressIP := []string{"192.0.2.101"}
	ipProtocol := corev1.IPv4Protocol
	if isIPv6 {
		ipProtocol = corev1.IPv6Protocol
		clusterIngressIP = []string{"fd75::aabb:ccdd:ef00"}
		localIngressIP = []string{"fd75::aabb:ccdd:ef01"}
	}

	// Create two LoadBalancer Services. The externalTrafficPolicy of one Service is Cluster, and the externalTrafficPolicy
	// of another one is Local.
	_, err = data.createAgnhostLoadBalancerService("agnhost-cluster", agnhostLBClusterServiceLabel, 8080, true, false, clusterIngressIP, &ipProtocol)
	require.NoError(t, err)
	_, err = data.createAgnhostLoadBalancerService("agnhost-local", agnhostLBLocalServiceLabel, 8081, true, true, localIngressIP, &ipProtocol)
	require.NoError(t, err)

	t.Run("HostNetwork-Non Endpoints", func(t *testing.T) {
		t.Run("ExternalTrafficPolicy:Cluster", func(t *testing.T) {
			t.Parallel()
			port := "8080"
			clusterUrl := net.JoinHostPort(clusterIngressIP[0], port)
			agnhostsCluster := []string{"endpoint-lb-nonhost-cluster-0", "endpoint-lb-nonhost-cluster-1"}
			for idx, node := range nodes {
				endpoint := agnhostsCluster[idx]
				createAgnhostPod(t, data, endpoint, node, false, agnhostLBClusterServiceLabel)
				defer func(pod string) {
					require.NoError(t, data.deletePod(testNamespace, pod))
				}(endpoint)
			}
			loadBalancerClusterTestCases(t, data, clusterUrl, nodes, clients, clientOSes)
		})
		t.Run("ExternalTrafficPolicy:Local", func(t *testing.T) {
			t.Parallel()
			port := "8081"
			localUrl := net.JoinHostPort(localIngressIP[0], port)
			agnhostsLocal := []string{"endpoint-lb-nonhost-local-0", "endpoint-lb-nonhost-local-1"}
			for idx, node := range nodes {
				endpoint := agnhostsLocal[idx]
				createAgnhostPod(t, data, endpoint, node, false, agnhostLBLocalServiceLabel)
				defer func(pod string) {
					require.NoError(t, data.deletePod(testNamespace, pod))
				}(endpoint)
			}
			loadBalancerLocalTestCases(t, data, localUrl, nodes, nodeIPs, clients, clientIPs, clientOSes, false)
		})
	})
	t.Run("HostNetwork Endpoints", func(t *testing.T) {
		t.Run("ExternalTrafficPolicy:Cluster", func(t *testing.T) {
			t.Parallel()
			port := "8080"
			clusterUrl := net.JoinHostPort(clusterIngressIP[0], port)
			hostAgnhostsCluster := []string{"endpoint-lb-host-cluster-0", "endpoint-lb-host-cluster-1"}
			for idx, node := range nodes {
				endpoint := hostAgnhostsCluster[idx]
				createAgnhostPod(t, data, endpoint, node, true, agnhostLBClusterServiceLabel)
				defer func(pod string) {
					require.NoError(t, data.deletePod(testNamespace, pod))
				}(endpoint)
			}
			loadBalancerClusterTestCases(t, data, clusterUrl, nodes, clients, clientOSes)
		})
		t.Run("ExternalTrafficPolicy:Local", func(t *testing.T) {
			t.Parallel()
			port := "8081"
			localUrl := net.JoinHostPort(localIngressIP[0], port)
			hostAgnhostsCluster := []string{"endpoint-lb-host-local-0", "endpoint-lb-host-local-1"}
			for idx, node := range nodes {
				endpoint := hostAgnhostsCluster[idx]
				createAgnhostPod(t, data, endpoint, node, true, agnhostLBLocalServiceLabel)
				defer func(pod string) {
					require.NoError(t, data.deletePod(testNamespace, pod))
				}(endpoint)
			}
			loadBalancerLocalTestCases(t, data, localUrl, nodes, nodeIPs, clients, clientIPs, clientOSes, true)
		})
	})
}

func testLoadBalancerClusterFromNode(t *testing.T, data *TestData, nodes []string, url string) {
	skipIfKubeProxyEnabled(t, data)
	for _, node := range nodes {
		require.NoError(t, probeFromNode(node, url),
			"Service LoadBalancer should be able to be connected from Node '%s' with URL '%s'", node, url)
	}
}

func testLoadBalancerClusterFromPod(t *testing.T, data *TestData, pods, podOSes []string, url string) {
	for idx, pod := range pods {
		require.NoError(t, probeFromPod(data, pod, podOSes[idx], url),
			"Service LoadBalancer should be able to be connected from Pod '%s' with url '%s'", pod, url)
	}
}

func testLoadBalancerLocalFromNode(t *testing.T, data *TestData, nodes []string, url string, expectedHostNetwork string, expectedHostnames []string) {
	skipIfKubeProxyEnabled(t, data)
	for idx, node := range nodes {
		nodeNameMsg := fmt.Sprintf("Service LoadBalancer should be able to be connected from Node '%s' with url '%s/%s'", node, url, nodeNameEndpoint)
		nodeName, err := probeNodeNameEndpointFromNode(node, url)
		require.NoError(t, err, nodeNameMsg)
		require.Equal(t, expectedHostnames[idx], nodeName, nodeNameMsg)

		hostNetworkMsg := fmt.Sprintf("Service LoadBalancer should be able to be connected from Node '%s' with url '%s/%s'", node, url, hostNetworkEndpoint)
		hostNetwork, err := probeEndpointFromNode(node, url, hostNetworkEndpoint)
		require.NoError(t, err, hostNetworkMsg)
		assert.Equal(t, expectedHostNetwork, hostNetwork, hostNetworkMsg)
	}
}

func testLoadBalancerLocalFromPod(t *testing.T, data *TestData, pods []string, podOSes []string, url string, expectedClientIPs []string, expectedHostNetwork string, expectedHostnames []string) {
	for idx, pod := range pods {
		nodeNameErrMsg := fmt.Sprintf("Service NodePort should be able to be connected from Pod '%s' with url '%s/%s'", pod, url, nodeNameEndpoint)
		hostname, err := probeNodeNameEndpointFromPod(data, pod, podOSes[idx], url)
		require.NoError(t, err, nodeNameErrMsg)
		require.Equal(t, hostname, expectedHostnames[idx])

		hostNetworkErrMsg := fmt.Sprintf("Service NodePort should be able to be connected from Pod '%s' with url '%s/%s'", pod, url, hostNetworkEndpoint)
		hostNetwork, err := probeEndpointFromPod(data, pod, podOSes[idx], url, hostNetworkEndpoint)
		require.NoError(t, err, hostNetworkErrMsg)
		assert.Equal(t, expectedHostNetwork, hostNetwork, hostNetworkErrMsg)

		clientIPErrMsg := fmt.Sprintf("Service NodePort should be able to be connected from Pod '%s' with url '%s/%s'", pod, url, clientIPEndpoint)
		clientIP, err := probeClientIPEndpointFromPod(data, pod, podOSes[idx], url)
		require.NoError(t, err, clientIPErrMsg)
		assert.Equal(t, expectedClientIPs[idx], clientIP, clientIPErrMsg)
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
	skipIfNumNodesLessThan(t, 2)
	skipIfProxyDisabled(t)
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
	skipIfProxyAllDisabled(t, data)

	nodes, nodeIPs := pickNodes(isIPv6)
	ipProtocol := corev1.IPv4Protocol
	if isIPv6 {
		ipProtocol = corev1.IPv6Protocol
	}

	// Create an agnhost Pod as client on every Node.
	var clients, clientIPs, clientOSes []string
	for idx, node := range nodes {
		os := nodeOS(node)
		clientOSes = append(clientOSes, os)
		podName, ips, _ := createAndWaitForPod(t, data, data.createAgnhostPodOnNode, fmt.Sprintf("client-%d-%s-", idx, os), node, testNamespace, false)
		clients = append(clients, podName)
		if !isIPv6 {
			clientIPs = append(clientIPs, ips.ipv4.String())
		} else {
			clientIPs = append(clientIPs, ips.ipv6.String())
		}
	}

	// Create two NodePort Services. The externalTrafficPolicy of one Service is Cluster, and the externalTrafficPolicy
	// of another one is Local.
	var portCluster, portLocal string
	nodePortSvc, err := data.createAgnhostNodePortService("server-cluster", agnhostNodePortClusterServiceLabel, 8080, true, false, &ipProtocol)
	require.NoError(t, err)
	for _, port := range nodePortSvc.Spec.Ports {
		if port.NodePort != 0 {
			portCluster = fmt.Sprint(port.NodePort)
			break
		}
	}
	require.NotEqual(t, "", portCluster, "NodePort port number should not be empty")
	nodePortSvc, err = data.createAgnhostNodePortService("server-local", agnhostNodePortLocalServiceLabel, 8081, true, true, &ipProtocol)
	require.NoError(t, err)
	for _, port := range nodePortSvc.Spec.Ports {
		if port.NodePort != 0 {
			portLocal = fmt.Sprint(port.NodePort)
			break
		}
	}
	require.NotEqual(t, "", portLocal, "NodePort port number should not be empty")

	t.Run("HostNetwork-Non Endpoints", func(t *testing.T) {
		t.Run("ExternalTrafficPolicy:Cluster", func(t *testing.T) {
			t.Parallel()
			agnhostsCluster := []string{"endpoint-nodeport-nonhost-cluster-0", "endpoint-nodeport-nonhost-cluster-1"}
			for idx, node := range nodes {
				endpoint := agnhostsCluster[idx]
				createAgnhostPod(t, data, endpoint, node, false, agnhostNodePortClusterServiceLabel)
				defer func(pod string) {
					require.NoError(t, data.deletePod(testNamespace, pod))
				}(endpoint)
			}
			nodePortClusterTestCases(t, data, portCluster, nodes, nodeIPs, clients, clientOSes)
		})
		t.Run("ExternalTrafficPolicy:Local", func(t *testing.T) {
			t.Parallel()
			agnhostsLocal := []string{"endpoint-nodeport-nonhost-local-0", "endpoint-nodeport-nonhost-local-1"}
			for idx, node := range nodes {
				endpoint := agnhostsLocal[idx]
				createAgnhostPod(t, data, endpoint, node, false, agnhostNodePortLocalServiceLabel)
				defer func(pod string) {
					require.NoError(t, data.deletePod(testNamespace, endpoint))
				}(endpoint)
			}
			nodePortLocalTestCases(t, data, portLocal, nodes, nodeIPs, clients, clientIPs, clientOSes, false)
		})
	})
	t.Run("HostNetwork Endpoints", func(t *testing.T) {
		t.Run("ExternalTrafficPolicy:Cluster", func(t *testing.T) {
			t.Parallel()
			agnhostsCluster := []string{"endpoint-nodeport-host-cluster-0", "endpoint-nodeport-host-cluster-1"}
			for idx, node := range nodes {
				endpoint := agnhostsCluster[idx]
				createAgnhostPod(t, data, endpoint, node, true, agnhostNodePortClusterServiceLabel)
				defer func(pod string) {
					require.NoError(t, data.deletePod(testNamespace, pod))
				}(endpoint)
			}
			nodePortClusterTestCases(t, data, portCluster, nodes, nodeIPs, clients, clientOSes)
		})
		t.Run("ExternalTrafficPolicy:Local", func(t *testing.T) {
			t.Parallel()
			agnhostsLocal := []string{"endpoint-nodeport-host-local-0", "endpoint-nodeport-host-local-1"}
			for idx, node := range nodes {
				endpoint := agnhostsLocal[idx]
				createAgnhostPod(t, data, endpoint, node, true, agnhostNodePortLocalServiceLabel)
				defer func(pod string) {
					require.NoError(t, data.deletePod(testNamespace, pod))
				}(endpoint)
			}
			nodePortLocalTestCases(t, data, portLocal, nodes, nodeIPs, clients, clientIPs, clientOSes, true)
		})
	})
}

func nodePortClusterTestCases(t *testing.T, data *TestData, portStrCluster string, nodes, nodeIPs, pods, podOSes []string) {
	var clusterUrls []string
	for _, nodeIP := range nodeIPs {
		clusterUrls = append(clusterUrls, net.JoinHostPort(nodeIP, portStrCluster))
	}
	reverseStrs := func(strs []string) []string {
		var res []string
		for i := len(strs) - 1; i >= 0; i-- {
			res = append(res, strs[i])
		}
		return res
	}

	t.Run("Client:Remote", func(t *testing.T) {
		testNodePortClusterFromRemote(t, data, nodes, reverseStrs(clusterUrls))
	})
	t.Run("Client:Node", func(t *testing.T) {
		testNodePortClusterFromNode(t, data, nodes, clusterUrls)
	})
	t.Run("Client:Pod", func(t *testing.T) {
		testNodePortClusterFromPod(t, data, pods, podOSes, clusterUrls)
	})
}

func nodePortLocalTestCases(t *testing.T, data *TestData, portStrLocal string, nodes, nodeIPs, pods, podIPs, podOSes []string, hostNetwork bool) {
	var localUrls []string
	for _, nodeIP := range nodeIPs {
		localUrls = append(localUrls, net.JoinHostPort(nodeIP, portStrLocal))
	}
	reverseStrs := func(strs []string) []string {
		var res []string
		for i := len(strs) - 1; i >= 0; i-- {
			res = append(res, strs[i])
		}
		return res
	}

	expectedClientIPs := make([]string, len(podIPs))
	copy(expectedClientIPs, podIPs)
	if hostNetwork {
		for idx := range podOSes {
			if podOSes[idx] == "windows" {
				// There's a NetNat on Windows host doing SNAT. So if endpoint is a hostNetwork Pod
				// request packet will be SNATed to Node IP.
				expectedClientIPs[idx] = nodeIPs[idx]
			}
		}
	}
	hostNetworkStr := expectedNonHostNetworkResult
	if hostNetwork {
		hostNetworkStr = expectedHostNetworkResult
	}

	t.Run("Client:Remote", func(t *testing.T) {
		if hostNetwork {
			t.Skipf("Skip this test as Endpoint is on host network")
		}
		testNodePortLocalFromRemote(t, data, nodes, reverseStrs(localUrls), nodeIPs, hostNetworkStr)
	})
	t.Run("Client:Node", func(t *testing.T) {
		testNodePortLocalFromNode(t, data, nodes, localUrls, hostNetworkStr)
	})
	t.Run("Client:Pod", func(t *testing.T) {
		testNodePortLocalFromPod(t, data, pods, podOSes, localUrls, expectedClientIPs, hostNetworkStr)
	})
}

func createAgnhostPod(t *testing.T, data *TestData, podName string, node string, hostNetwork bool, label string) {
	args := []string{"netexec", "--http-port=8080"}
	ports := []corev1.ContainerPort{
		{
			Name:          "http",
			ContainerPort: 8080,
			Protocol:      corev1.ProtocolTCP,
		},
	}

	envVars := []corev1.EnvVar{
		{Name: "nodeName", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"}}},
	}
	if hostNetwork {
		envVars = append(envVars, corev1.EnvVar{Name: "hostnetwork", Value: "true"})
	} else {
		envVars = append(envVars, corev1.EnvVar{Name: "hostnetwork", Value: "false"})
	}
	require.NoError(t, data.createPodOnNode(podName, testNamespace, node, agnhostImage, []string{}, args, envVars, ports, hostNetwork, func(pod *corev1.Pod) {
		pod.Labels["app"] = label
	}))
	_, err := data.podWaitForIPs(defaultTimeout, podName, testNamespace)
	require.NoError(t, err)
	require.NoError(t, data.podWaitForRunning(defaultTimeout, podName, testNamespace))
}

func testNodePortClusterFromRemote(t *testing.T, data *TestData, nodes, urls []string) {
	skipIfKubeProxyEnabled(t, data)
	for idx, node := range nodes {
		require.NoErrorf(t, probeFromNode(node, urls[idx]),
			"Service NodePort should be able to be connected from remote Node %s with URL %s",
			node, urls[idx])
	}
}

func testNodePortClusterFromNode(t *testing.T, data *TestData, nodes, urls []string) {
	skipIfKubeProxyEnabled(t, data)
	for idx, node := range nodes {
		require.NoErrorf(t, probeFromNode(node, urls[idx]),
			"Service NodePort should be able to be connected from Node %s with URL %s",
			node, urls[idx])
	}
}

func testNodePortClusterFromPod(t *testing.T, data *TestData, pods, podOSes, urls []string) {
	for _, url := range urls {
		for idx, pod := range pods {
			require.NoErrorf(t, probeFromPod(data, pod, podOSes[idx], url),
				"Service NodePort should be able to be connected from Pod '%s' with URL '%s'", pod, url)
		}
	}
}

func testNodePortLocalFromRemote(t *testing.T, data *TestData, nodes, urls, expectedClientIPs []string, expectedHostNetwork string) {
	skipIfKubeProxyEnabled(t, data)
	errMsg := "Service NodePort should be able to be connected from remote Node"
	for idx, node := range nodes {
		// It hangs on Linux Pod/Node to execute <Windows-nodeIP>/shell?cmd=<some-command> while clientip/hostname endpoints work.
		if len(clusterInfo.windowsNodes) == 0 || nodeOS(node) != "linux" {
			hostNetwork, err := probeEndpointFromNode(node, urls[idx], hostNetworkEndpoint)
			require.NoError(t, err, errMsg)
			assert.Equal(t, expectedHostNetwork, hostNetwork,
				"unexpected hostNetwork on Node '%s' with URL '%s/%s'", node, urls[idx], hostNetworkEndpoint)
		}

		clientIP, err := probeClientIPEndpointFromNode(node, urls[idx])
		require.NoError(t, err, errMsg)
		assert.Equal(t, expectedClientIPs[idx], clientIP, "unexpected clientIP on Node '%s' with URL '%s/%s'",
			node, urls[idx], clientIPEndpoint)
	}
}

func testNodePortLocalFromNode(t *testing.T, data *TestData, nodes, urls []string, expectedHostNetwork string) {
	skipIfKubeProxyEnabled(t, data)
	for idx, node := range nodes {
		msg := fmt.Sprintf("Node '%s' should connect Service with URL '%s/%s'", node, urls[idx], hostNetworkEndpoint)
		hostNetwork, err := probeEndpointFromNode(node, urls[idx], hostNetworkEndpoint)
		require.NoError(t, err, msg)
		assert.Equal(t, expectedHostNetwork, hostNetwork, msg)
	}
}

func testNodePortLocalFromPod(t *testing.T, data *TestData, pods, podOSes, urls, expectedClientIPs []string, expectedHostNetwork string) {
	for idx, pod := range pods {
		hostNetworkErrMsg := fmt.Sprintf("Error when accessing Service NodePort from Pod '%s' with URL '%s/%s'", pod, urls[idx], hostNetworkEndpoint)
		hostNetwork, err := probeEndpointFromPod(data, pod, podOSes[idx], urls[idx], hostNetworkEndpoint)
		require.NoError(t, err, hostNetworkErrMsg)
		assert.Equal(t, expectedHostNetwork, hostNetwork, hostNetworkErrMsg)

		clientIPErrMsg := fmt.Sprintf("Error when accessing Service NodePort from Pod '%s' with URL '%s/%s'", pod, urls[idx], clientIPEndpoint)
		clientIP, err := probeClientIPEndpointFromPod(data, pod, podOSes[idx], urls[idx])
		require.NoError(t, err, clientIPErrMsg)
		assert.Equal(t, expectedClientIPs[idx], clientIP, clientIPErrMsg)
	}
}

func TestProxyServiceSessionAffinity(t *testing.T) {
	skipIfProviderIs(t, "kind", "#881 Does not work in Kind, needs to be investigated.")
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
