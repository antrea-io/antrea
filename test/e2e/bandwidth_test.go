// Copyright 2019 Antrea Authors
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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

const iperfPort = 5201

// TestBenchmarkBandwidth is the top-level test which contains all subtests for
// Bandwidth related test cases so they can share setup, teardown.
func TestBenchmarkBandwidth(t *testing.T) {
	skipIfNotRequired(t, "mode-irrelevant")

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	t.Run("Pod", func(t *testing.T) {
		skipIfHasWindowsNodes(t)
		t.Run("TrafficShaping", func(t *testing.T) {
			testPodTrafficShaping(t, data)
		})
		t.Run("IntraNode", func(t *testing.T) {
			skipIfNotIPv4Cluster(t)
			testBenchmarkBandwidthIntraNode(t, data)
		})
	})
	t.Run("ServicePodAccess", func(t *testing.T) {
		t.Run("ClusterIP", func(t *testing.T) {
			t.Run("Local", func(t *testing.T) {
				testServiceClusterIPPodLocalAccess(t, data)
			})
			t.Run("Remote", func(t *testing.T) {
				skipIfNumNodesLessThan(t, 2)
				testServiceClusterIPPodRemoteAccess(t, data)
			})
		})
		t.Run("NodePort", func(t *testing.T) {
			if len(clusterInfo.windowsNodes) == 0 {
				skipIfNumNodesLessThan(t, 2)
			}
			testServiceNodePortPodAccess(t, data)
		})
	})
	// For Windows testbeds, make sure iperf3.exe is in system PATH.
	t.Run("ServiceNodeAccess", func(t *testing.T) {
		t.Run("ClusterIP", func(t *testing.T) {
			t.Run("Local", func(t *testing.T) {
				testServiceClusterIPNodeLocalAccess(t, data)
			})
			t.Run("Remote", func(t *testing.T) {
				skipIfNumNodesLessThan(t, 2)
				testServiceClusterIPNodeRemoteAccess(t, data)
			})
		})
		t.Run("NodePort", func(t *testing.T) {
			if len(clusterInfo.windowsNodes) == 0 {
				skipIfNumNodesLessThan(t, 2)
			}
			testServiceNodePortNodeAccess(t, data)
		})
	})
}

// testBenchmarkBandwidthIntraNode runs the bandwidth benchmark between Pods on same node.
func testBenchmarkBandwidthIntraNode(t *testing.T, data *TestData) {
	if err := data.createPodOnNode("perftest-a", testNamespace, controlPlaneNodeName(), perftoolImage, nil, nil, nil, nil, false, nil); err != nil {
		t.Fatalf("Error when creating the perftest client Pod: %v", err)
	}
	if err := data.podWaitForRunning(defaultTimeout, "perftest-a", testNamespace); err != nil {
		t.Fatalf("Error when waiting for the perftest client Pod: %v", err)
	}
	if err := data.createPodOnNode("perftest-b", testNamespace, controlPlaneNodeName(), perftoolImage, nil, nil, nil, []v1.ContainerPort{{Protocol: v1.ProtocolTCP, ContainerPort: iperfPort}}, false, nil); err != nil {
		t.Fatalf("Error when creating the perftest server Pod: %v", err)
	}
	podBIPs, err := data.podWaitForIPs(defaultTimeout, "perftest-b", testNamespace)
	if err != nil {
		t.Fatalf("Error when getting the perftest server Pod's IP: %v", err)
	}
	podBIP := podBIPs.ipv4.String()
	stdout, _, err := data.runCommandFromPod(testNamespace, "perftest-a", "perftool", []string{"bash", "-c", fmt.Sprintf("iperf3 -c %s|grep sender|awk '{print $7,$8}'", podBIP)})
	if err != nil {
		t.Fatalf("Error when running iperf3 client: %v", err)
	}
	stdout = strings.TrimSpace(stdout)
	t.Logf("Bandwidth: %s", stdout)
}

func benchmarkBandwidthServicePodAccess(t *testing.T, data *TestData, endpointNode, clientNode string, access string) {
	perftoolImageUsed := perftoolImage
	if clusterInfo.nodesOS[endpointNode] == "windows" {
		perftoolImageUsed = perftoolWindowsImage
	}
	server := randName(fmt.Sprintf("perftest-server-%s-", access))
	svc, err := data.createService(server, testNamespace, []servicePorts{{port: iperfPort, targetPort: iperfPort}}, map[string]string{"antrea-e2e": server}, false, false, v1.ServiceTypeClusterIP, nil)
	require.NoErrorf(t, err, "Error when creating perftest service")
	defer data.deleteServiceAndWait(defaultTimeout, server)
	require.NoErrorf(t, data.createPodOnNode(server, testNamespace, endpointNode, perftoolImageUsed, nil, nil, nil, []v1.ContainerPort{{Protocol: v1.ProtocolTCP, ContainerPort: iperfPort}}, false, nil), "Error when creating the perftest server Pod")
	defer data.deletePodAndWait(defaultTimeout, server, testNamespace)
	require.NoErrorf(t, data.podWaitForRunning(defaultTimeout, server, testNamespace), "Error when getting the perftest server Pod's IP")

	client := randName(fmt.Sprintf("perftest-client-%s-", access))
	require.NoErrorf(t, data.createPodOnNode(client, testNamespace, clientNode, perftoolImageUsed, nil, nil, nil, nil, false, nil), "Error when creating the perftest client Pod")
	defer data.deletePodAndWait(defaultTimeout, client, testNamespace)
	require.NoErrorf(t, data.podWaitForRunning(defaultTimeout, client, testNamespace), "Error when waiting for the perftest client Pod")

	var cmd []string
	if clusterInfo.nodesOS[clientNode] == "windows" {
		cmd = []string{"powershell", fmt.Sprintf("iperf3 -c %s|findstr sender", svc.Spec.ClusterIP)}
	} else {
		cmd = []string{"bash", "-c", fmt.Sprintf("iperf3 -c %s|grep sender", svc.Spec.ClusterIP)}
	}
	stdout, stderr, err := data.runCommandFromPod(testNamespace, client, perftoolContainerName, cmd)
	require.NoErrorf(t, err, "Error when running iperf3 client '%s': cmd '%s', stdout: %s, stderr: %s", client, cmd, stdout, stderr)
	fields := strings.Fields(stdout)
	require.GreaterOrEqualf(t, len(fields), 7, "Error when getting stdout fields, stdout: %s", stdout)
	t.Logf("Bandwidth (%s): %s %s", access, fields[6], fields[7])
}

func benchmarkBandwidthServiceNodeAccess(t *testing.T, data *TestData, endpointNode, clientNode string, access string) {
	perftoolImageUsed := perftoolImage
	if clusterInfo.nodesOS[endpointNode] == "windows" {
		perftoolImageUsed = perftoolWindowsImage
	}
	server := randName(fmt.Sprintf("perftest-server-%s-", access))
	svc, err := data.createService(server, testNamespace, []servicePorts{{port: iperfPort, targetPort: iperfPort}}, map[string]string{"antrea-e2e": server}, false, false, v1.ServiceTypeClusterIP, nil)
	require.NoErrorf(t, err, "Error when creating perftest service")
	defer data.deleteServiceAndWait(defaultTimeout, server)
	require.NoErrorf(t, data.createPodOnNode(server, testNamespace, endpointNode, perftoolImageUsed, nil, nil, nil, []v1.ContainerPort{{Protocol: v1.ProtocolTCP, ContainerPort: iperfPort}}, false, nil), "Error when creating the perftest server Pod")
	defer data.deletePodAndWait(defaultTimeout, server, testNamespace)
	require.NoErrorf(t, data.podWaitForRunning(defaultTimeout, server, testNamespace), "Error when getting the perftest server Pod's IP")

	var cmd string
	if clusterInfo.nodesOS[clientNode] == "windows" {
		cmd = fmt.Sprintf("iperf3 -c %s|findstr sender", svc.Spec.ClusterIP)
	} else {
		cmd = fmt.Sprintf("iperf3 -c %s|grep sender", svc.Spec.ClusterIP)
	}
	checkConnectivityCmd := fmt.Sprintf("iperf3 -c %s -t 1s", svc.Spec.ClusterIP)
	var rc int
	var stdout, stderr string
	if err := wait.PollImmediate(time.Second*5, time.Second*30, func() (bool, error) {
		rc, stdout, stderr, err = RunCommandOnNode(clientNode, checkConnectivityCmd)
		if err != nil || rc != 0 || stderr != "" {
			return false, nil
		}
		return true, nil
	}); err == wait.ErrWaitTimeout {
		t.Fatalf("Error when running iperf3 on Node '%s': cmd '%s', rc: %d, stdout: %s, stderr: %s, err: %v", clientNode, cmd, rc, stdout, stderr, err)
	}
	rc, stdout, stderr, err = RunCommandOnNode(clientNode, cmd)
	if err != nil || rc != 0 || stderr != "" {
		t.Fatalf("Error when running iperf3 on Node '%s': cmd '%s', rc: %d, stdout: %s, stderr: %s, err: %v", clientNode, cmd, rc, stdout, stderr, err)
	}
	fields := strings.Fields(stdout)
	require.GreaterOrEqualf(t, len(fields), 7, fmt.Sprintf("Error when getting stdout fields, rc: %d, stdout: %s, stderr: %s, cmd: '%s', Node: '%s'", rc, stdout, stderr, cmd, clientNode))
	t.Logf("Bandwidth (%s): %s %s", access, fields[6], fields[7])
}

// testServiceClusterIPPodLocalAccess runs the bandwidth benchmark of service
// traffic between a Pod and an Endpoint on same Node.
func testServiceClusterIPPodLocalAccess(t *testing.T, data *TestData) {
	if len(clusterInfo.windowsNodes) != 0 {
		winNode := nodeName(clusterInfo.windowsNodes[0])
		benchmarkBandwidthServicePodAccess(t, data, winNode, winNode, "local")
	} else {
		controlPlaneNode := controlPlaneNodeName()
		benchmarkBandwidthServicePodAccess(t, data, controlPlaneNode, controlPlaneNode, "local")
	}
}

// testServiceClusterIPPodRemoteAccess runs the bandwidth benchmark of service
// traffic between a Pod and an Endpoint on different Nodes.
func testServiceClusterIPPodRemoteAccess(t *testing.T, data *TestData) {
	if len(clusterInfo.windowsNodes) != 0 {
		benchmarkBandwidthServicePodAccess(t, data, controlPlaneNodeName(), nodeName(clusterInfo.windowsNodes[0]), "remote")
	} else {
		benchmarkBandwidthServicePodAccess(t, data, controlPlaneNodeName(), workerNodeName(1), "remote")
	}
}

// testServiceClusterIPNodeLocalAccess runs the bandwidth benchmark of service
// traffic between a Node and an Endpoint on same Node.
func testServiceClusterIPNodeLocalAccess(t *testing.T, data *TestData) {
	if len(clusterInfo.windowsNodes) != 0 {
		winNode := nodeName(clusterInfo.windowsNodes[0])
		benchmarkBandwidthServiceNodeAccess(t, data, winNode, winNode, "local")
	} else {
		controlPlaneNode := controlPlaneNodeName()
		benchmarkBandwidthServiceNodeAccess(t, data, controlPlaneNode, controlPlaneNode, "local")
	}
}

// testServiceClusterIPNodeRemoteAccess runs the bandwidth benchmark of service
// traffic between a Node and an Endpoint on different Nodes.
func testServiceClusterIPNodeRemoteAccess(t *testing.T, data *TestData) {
	if len(clusterInfo.windowsNodes) != 0 {
		benchmarkBandwidthServiceNodeAccess(t, data, controlPlaneNodeName(), nodeName(clusterInfo.windowsNodes[0]), "remote")
	} else {
		benchmarkBandwidthServiceNodeAccess(t, data, controlPlaneNodeName(), workerNodeName(1), "remote")
	}
}

// testServiceNodePortPodAccess runs the bandwidth benchmark of NodePort Service in Pod.
// Client is a control plane Pod and Endpoint on the control plane Node. If in a Windows cluster, url will be <Windows-Node-IP>:<NodePort>.
// If not, url will be <second-Node-IP>:<NodePort>.
func testServiceNodePortPodAccess(t *testing.T, data *TestData) {
	endpointNode := controlPlaneNodeName()
	server := randName("perftest-server-nodeport-")
	svc, err := data.createService(server, testNamespace, []servicePorts{{port: iperfPort, targetPort: iperfPort}}, map[string]string{"antrea-e2e": server}, false, false, v1.ServiceTypeNodePort, nil)
	require.NoErrorf(t, err, "Error when creating perftest service")
	defer data.deleteServiceAndWait(defaultTimeout, server)
	require.NoErrorf(t, data.createPodOnNode(server, testNamespace, endpointNode, perftoolImage, nil, nil, nil, []v1.ContainerPort{{Protocol: v1.ProtocolTCP, ContainerPort: iperfPort}}, false, nil), "Error when creating the perftest server Pod")
	defer data.deletePodAndWait(defaultTimeout, server, testNamespace)
	require.NoErrorf(t, data.podWaitForRunning(defaultTimeout, server, testNamespace), "Error when getting the perftest server Pod's IP")
	var nodePort string
	for _, port := range svc.Spec.Ports {
		if port.NodePort != 0 {
			nodePort = fmt.Sprint(port.NodePort)
			break
		}
	}

	nodeIP := clusterInfo.nodes[1].ip()
	if len(clusterInfo.windowsNodes) != 0 {
		nodeIP = clusterInfo.nodes[clusterInfo.windowsNodes[0]].ip()
	}

	clientPod := controlPlaneNodeName()
	client := randName("perftest-client-nodeport-")
	require.NoErrorf(t, data.createPodOnNode(client, testNamespace, clientPod, perftoolImage, nil, nil, nil, nil, false, nil), "Error when creating the perftest client Pod")
	defer data.deletePodAndWait(defaultTimeout, client, testNamespace)
	require.NoErrorf(t, data.podWaitForRunning(defaultTimeout, client, testNamespace), "Error when waiting for the perftest client Pod")

	var stdout, stderr string
	checkConnectivityCmd := []string{"bash", "-c", fmt.Sprintf("iperf3 -c %s -p %s -t 1s", nodeIP, nodePort)}
	if err := wait.PollImmediate(time.Second*5, time.Second*30, func() (bool, error) {
		stdout, stderr, err = data.runCommandFromPod(testNamespace, client, perftoolContainerName, checkConnectivityCmd)
		if err != nil || stderr != "" {
			return false, nil
		}
		return true, nil
	}); err == wait.ErrWaitTimeout {
		t.Fatalf("Error when running iperf3 cmd '%s' on Pod '%s', stdout: %s, stderr: %s, err: %v", checkConnectivityCmd, client, stdout, stderr, err)
	}

	cmd := []string{"bash", "-c", fmt.Sprintf("iperf3 -c %s -p %s|grep sender", nodeIP, nodePort)}
	stdout, stderr, err = data.runCommandFromPod(testNamespace, client, perftoolContainerName, cmd)
	require.NoErrorf(t, err, "Error when running iperf3 client '%s': cmd: '%s', stdout: %s, stderr: %s", client, cmd, stdout, stderr)
	fields := strings.Fields(stdout)
	require.GreaterOrEqualf(t, len(fields), 7, "Error when getting stdout fields, stdout: %s", stdout)
	t.Logf("Bandwidth: %s %s", fields[6], fields[7])
}

// testServiceNodePortNodeAccess runs the bandwidth benchmark of NodePort Service on Node.
// Client is control plane Node and Endpoint is on the control plane Node. If in a Windows cluster, url will be
// <Windows-Node-IP>:<NodePort>. If not, url will be <second-Node-IP>:<NodePort>.
func testServiceNodePortNodeAccess(t *testing.T, data *TestData) {
	endpointNode := controlPlaneNodeName()
	server := randName("perftest-server-nodeport-")
	svc, err := data.createService(server, testNamespace, []servicePorts{{port: iperfPort, targetPort: iperfPort}}, map[string]string{"antrea-e2e": server}, false, false, v1.ServiceTypeNodePort, nil)
	require.NoErrorf(t, err, "Error when creating perftest service")
	defer data.deleteServiceAndWait(defaultTimeout, server)
	require.NoErrorf(t, data.createPodOnNode(server, testNamespace, endpointNode, perftoolImage, nil, nil, nil, []v1.ContainerPort{{Protocol: v1.ProtocolTCP, ContainerPort: iperfPort}}, false, nil), "Error when creating the perftest server Pod")
	defer data.deletePodAndWait(defaultTimeout, server, testNamespace)
	require.NoErrorf(t, data.podWaitForRunning(defaultTimeout, server, testNamespace), "Error when getting the perftest server Pod's IP")
	var nodePort string
	for _, port := range svc.Spec.Ports {
		if port.NodePort != 0 {
			nodePort = fmt.Sprint(port.NodePort)
			break
		}
	}

	nodeIP := clusterInfo.nodes[1].ip()
	if len(clusterInfo.windowsNodes) != 0 {
		nodeIP = clusterInfo.nodes[clusterInfo.windowsNodes[0]].ip()
	}

	cmd := fmt.Sprintf("iperf3 -c %s -p %s|grep sender", nodeIP, nodePort)
	checkConnectivityCmd := fmt.Sprintf("iperf3 -c %s -p %s -t 1s", nodeIP, nodePort)
	var rc int
	var stdout, stderr string
	clientNode := controlPlaneNodeName()
	if err := wait.PollImmediate(time.Second*5, time.Second*30, func() (bool, error) {
		rc, stdout, stderr, err = RunCommandOnNode(clientNode, checkConnectivityCmd)
		if err != nil || rc != 0 || stderr != "" {
			return false, nil
		}
		return true, nil
	}); err == wait.ErrWaitTimeout {
		t.Fatalf("Error when running iperf3 cmd '%s' on Node '%s': rc: %d, stdout: %s, stderr: %s, err: %v",
			checkConnectivityCmd, clientNode, rc, stdout, stderr, err)
	}
	rc, stdout, stderr, err = RunCommandOnNode(clientNode, cmd)
	if err != nil || rc != 0 || stderr != "" {
		t.Fatalf("Error when running iperf3 cmd '%s' on Node '%s': rc: %d, stdout: %s, stderr: %s, err: %v",
			cmd, clientNode, rc, stdout, stderr, err)
	}
	fields := strings.Fields(stdout)
	require.GreaterOrEqualf(t, len(fields), 7, fmt.Sprintf("Error when getting stdout fields, rc: %d, stdout: %s, stderr: %s, cmd: '%s', Node: '%s'",
		rc, stdout, stderr, cmd, clientNode))
	t.Logf("Bandwidth: %s %s", fields[6], fields[7])
}

func testPodTrafficShaping(t *testing.T, data *TestData) {
	// TODO: tc configuration succeeded, however it didn't take effect, need to understand the reason.
	skipIfProviderIs(t, "kind", "tc does not work with Kind")
	// Test is flaky on dual-stack clusters: https://github.com/antrea-io/antrea/issues/1543.
	// So we disable it except for IPv4 single-stack clusters for now.
	skipIfIPv6Cluster(t)
	nodeName := controlPlaneNodeName()
	skipIfMissingKernelModule(t, nodeName, []string{"ifb", "sch_tbf", "sch_ingress"})

	tests := []struct {
		name string
		// The bandwidths' unit is Mbits/sec.
		clientEgressBandwidth  int
		serverIngressBandwidth int
		expectedBandwidth      int
	}{
		{
			name:                   "limited by egress bandwidth",
			clientEgressBandwidth:  100,
			serverIngressBandwidth: 200,
			expectedBandwidth:      100,
		},
		{
			name:                   "limited by ingress bandwidth",
			clientEgressBandwidth:  300,
			serverIngressBandwidth: 200,
			expectedBandwidth:      200,
		},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientPodName := fmt.Sprintf("client-a-%d", i)
			serverPodName := fmt.Sprintf("server-a-%d", i)
			if err := data.createPodOnNode(clientPodName, testNamespace, nodeName, perftoolImage, nil, nil, nil, nil, false, func(pod *v1.Pod) {
				pod.Annotations = map[string]string{
					"kubernetes.io/egress-bandwidth": fmt.Sprintf("%dM", tt.clientEgressBandwidth),
				}
			}); err != nil {
				t.Fatalf("Error when creating the perftest client Pod: %v", err)
			}
			defer deletePodWrapper(t, data, testNamespace, clientPodName)
			if err := data.podWaitForRunning(defaultTimeout, clientPodName, testNamespace); err != nil {
				t.Fatalf("Error when waiting for the perftest client Pod: %v", err)
			}
			if err := data.createPodOnNode(serverPodName, testNamespace, nodeName, perftoolImage, nil, nil, nil, []v1.ContainerPort{{Protocol: v1.ProtocolTCP, ContainerPort: iperfPort}}, false, func(pod *v1.Pod) {
				pod.Annotations = map[string]string{
					"kubernetes.io/ingress-bandwidth": fmt.Sprintf("%dM", tt.serverIngressBandwidth),
				}
			}); err != nil {
				t.Fatalf("Error when creating the perftest server Pod: %v", err)
			}
			defer deletePodWrapper(t, data, testNamespace, serverPodName)
			podIPs, err := data.podWaitForIPs(defaultTimeout, serverPodName, testNamespace)
			if err != nil {
				t.Fatalf("Error when getting the perftest server Pod's IP: %v", err)
			}

			runIperf := func(cmd []string) {
				stdout, _, err := data.runCommandFromPod(testNamespace, clientPodName, "perftool", cmd)
				if err != nil {
					t.Fatalf("Error when running iperf3 client: %v", err)
				}
				stdout = strings.TrimSpace(stdout)
				actualBandwidth, _ := strconv.ParseFloat(strings.TrimSpace(stdout), 64)
				t.Logf("Actual bandwidth: %v Mbits/sec", actualBandwidth)
				// Allow a certain deviation.
				assert.InEpsilon(t, actualBandwidth, tt.expectedBandwidth, 0.1)
			}
			if podIPs.ipv4 != nil {
				runIperf([]string{"bash", "-c", fmt.Sprintf("iperf3 -c %s -f m -O 1|grep sender|awk '{print $7}'", podIPs.ipv4.String())})
			}
			if podIPs.ipv6 != nil {
				runIperf([]string{"bash", "-c", fmt.Sprintf("iperf3 -6 -c %s -f m -O 1|grep sender|awk '{print $7}'", podIPs.ipv6.String())})
			}
		})
	}
}
