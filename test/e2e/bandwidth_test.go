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

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
)

// TestBandwidth is the top-level test which contains all subtests for
// Bandwidth related test cases so they can share setup, teardown.
func TestBandwidth(t *testing.T) {
	skipIfHasWindowsNodes(t)
	skipIfNotRequired(t, "mode-irrelevant")

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	t.Run("testPodTrafficShaping", func(t *testing.T) { testPodTrafficShaping(t, data) })
}

// TestBenchmarkBandwidth is the top-level benchmark test which contains all subtests for
// Bandwidth related test cases so they can share setup, teardown.
func TestBenchmarkBandwidth(t *testing.T) {
	skipIfNotBenchmarkTest(t)
	skipIfHasWindowsNodes(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	t.Run("testBenchmarkBandwidthServiceLocalAccess", func(t *testing.T) {
		testBenchmarkBandwidthServiceLocalAccess(t, data)
	})
	t.Run("testBenchmarkBandwidthServiceRemoteAccess", func(t *testing.T) {
		skipIfNumNodesLessThan(t, 2)
		testBenchmarkBandwidthServiceRemoteAccess(t, data)
	})
	t.Run("testBenchmarkBandwidthIntraNode", func(t *testing.T) {
		skipIfNotIPv4Cluster(t)
		testBenchmarkBandwidthIntraNode(t, data)
	})
}

// testBenchmarkBandwidthIntraNode runs the bandwidth benchmark between Pods on same node.
func testBenchmarkBandwidthIntraNode(t *testing.T, data *TestData) {
	if err := NewPodBuilder("perftest-a", data.testNamespace, ToolboxImage).OnNode(controlPlaneNodeName()).Create(data); err != nil {
		t.Fatalf("Error when creating the perftest client Pod: %v", err)
	}
	if err := data.podWaitForRunning(defaultTimeout, "perftest-a", data.testNamespace); err != nil {
		t.Fatalf("Error when waiting for the perftest client Pod: %v", err)
	}
	cmd := []string{"iperf3", "-s"}
	if err := NewPodBuilder("perftest-b", data.testNamespace, ToolboxImage).WithCommand(cmd).OnNode(controlPlaneNodeName()).WithPorts([]v1.ContainerPort{{Protocol: v1.ProtocolTCP, ContainerPort: iperfPort}}).Create(data); err != nil {
		t.Fatalf("Error when creating the perftest server Pod: %v", err)
	}
	podBIPs, err := data.podWaitForIPs(defaultTimeout, "perftest-b", data.testNamespace)
	if err != nil {
		t.Fatalf("Error when getting the perftest server Pod's IP: %v", err)
	}
	podBIP := podBIPs.IPv4.String()
	stdout, _, err := data.RunCommandFromPod(data.testNamespace, "perftest-a", "toolbox", []string{"bash", "-c", fmt.Sprintf("iperf3 -c %s|grep sender|awk '{print $7,$8}'", podBIP)})
	if err != nil {
		t.Fatalf("Error when running iperf3 client: %v", err)
	}
	stdout = strings.TrimSpace(stdout)
	t.Logf("Bandwidth: %s", stdout)
}

func benchmarkBandwidthService(t *testing.T, endpointNode, clientNode string, data *TestData) {
	svc, err := data.CreateService("perftest-b", data.testNamespace, iperfPort, iperfPort, map[string]string{"antrea-e2e": "perftest-b"}, false, false, v1.ServiceTypeClusterIP, nil)
	if err != nil {
		t.Fatalf("Error when creating perftest service: %v", err)
	}
	if err := NewPodBuilder("perftest-a", data.testNamespace, ToolboxImage).OnNode(clientNode).Create(data); err != nil {
		t.Fatalf("Error when creating the perftest client Pod: %v", err)
	}
	if err := data.podWaitForRunning(defaultTimeout, "perftest-a", data.testNamespace); err != nil {
		t.Fatalf("Error when waiting for the perftest client Pod: %v", err)
	}
	cmd := []string{"iperf3", "-s"}
	if err := NewPodBuilder("perftest-b", data.testNamespace, ToolboxImage).WithCommand(cmd).OnNode(clientNode).WithPorts([]v1.ContainerPort{{Protocol: v1.ProtocolTCP, ContainerPort: iperfPort}}).Create(data); err != nil {
		t.Fatalf("Error when creating the perftest server Pod: %v", err)
	}
	if err := data.podWaitForRunning(defaultTimeout, "perftest-b", data.testNamespace); err != nil {
		t.Fatalf("Error when getting the perftest server Pod's IP: %v", err)
	}
	stdout, stderr, err := data.RunCommandFromPod(data.testNamespace, "perftest-a", "toolbox", []string{"bash", "-c", fmt.Sprintf("iperf3 -c %s|grep sender|awk '{print $7,$8}'", svc.Spec.ClusterIP)})
	if err != nil {
		t.Fatalf("Error when running iperf3 client: %v, stderr: %s", err, stderr)
	}
	stdout = strings.TrimSpace(stdout)
	t.Logf("Bandwidth: %s", stdout)
}

// testBenchmarkBandwidthServiceLocalAccess runs the bandwidth benchmark of service
// traffic between a Pod and an Endpoint on same Node.
func testBenchmarkBandwidthServiceLocalAccess(t *testing.T, data *TestData) {
	benchmarkBandwidthService(t, controlPlaneNodeName(), controlPlaneNodeName(), data)
}

// testBenchmarkBandwidthServiceRemoteAccess runs the bandwidth benchmark of service
// traffic between a Pod and an Endpoint on different Node.
func testBenchmarkBandwidthServiceRemoteAccess(t *testing.T, data *TestData) {
	benchmarkBandwidthService(t, controlPlaneNodeName(), workerNodeName(1), data)
}

func testPodTrafficShaping(t *testing.T, data *TestData) {
	// Test is flaky on dual-stack clusters: https://github.com/antrea-io/antrea/issues/1543.
	// So we disable it except for IPv4 single-stack clusters for now.
	skipIfIPv6Cluster(t)
	nodeName := controlPlaneNodeName()
	skipIfMissingKernelModule(t, data, nodeName, []string{"ifb", "sch_tbf", "sch_ingress"})

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
			if err := NewPodBuilder(clientPodName, data.testNamespace, ToolboxImage).OnNode(nodeName).WithAnnotations(
				map[string]string{
					"kubernetes.io/egress-bandwidth": fmt.Sprintf("%dM", tt.clientEgressBandwidth),
				},
			).Create(data); err != nil {
				t.Fatalf("Error when creating the perftest client Pod: %v", err)
			}
			defer deletePodWrapper(t, data, data.testNamespace, clientPodName)
			if err := data.podWaitForRunning(defaultTimeout, clientPodName, data.testNamespace); err != nil {
				t.Fatalf("Error when waiting for the perftest client Pod: %v", err)
			}
			cmd := []string{"iperf3", "-s"}
			if err := NewPodBuilder(serverPodName, data.testNamespace, ToolboxImage).WithCommand(cmd).OnNode(nodeName).WithPorts([]v1.ContainerPort{{Protocol: v1.ProtocolTCP, ContainerPort: iperfPort}}).WithAnnotations(
				map[string]string{
					"kubernetes.io/ingress-bandwidth": fmt.Sprintf("%dM", tt.serverIngressBandwidth),
				},
			).Create(data); err != nil {
				t.Fatalf("Error when creating the perftest server Pod: %v", err)
			}
			defer deletePodWrapper(t, data, data.testNamespace, serverPodName)
			podIPs, err := data.podWaitForIPs(defaultTimeout, serverPodName, data.testNamespace)
			if err != nil {
				t.Fatalf("Error when getting the perftest server Pod's IP: %v", err)
			}

			runIperf := func(cmd []string) {
				stdout, _, err := data.RunCommandFromPod(data.testNamespace, clientPodName, "toolbox", cmd)
				if err != nil {
					t.Fatalf("Error when running iperf3 client: %v", err)
				}
				stdout = strings.TrimSpace(stdout)
				actualBandwidth, _ := strconv.ParseFloat(strings.TrimSpace(stdout), 64)
				t.Logf("Actual bandwidth: %v Mbits/sec", actualBandwidth)
				// Allow a certain deviation.
				assert.InEpsilon(t, actualBandwidth, tt.expectedBandwidth, 0.1)
			}
			if podIPs.IPv4 != nil {
				runIperf([]string{"bash", "-c", fmt.Sprintf("iperf3 -c %s -f m -O 1|grep sender|awk '{print $7}'", podIPs.IPv4.String())})
			}
			if podIPs.IPv6 != nil {
				runIperf([]string{"bash", "-c", fmt.Sprintf("iperf3 -6 -c %s -f m -O 1|grep sender|awk '{print $7}'", podIPs.IPv6.String())})
			}
		})
	}
}
