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

const iperfPort = 5201

// TestBenchmarkBandwidthIntraNode runs the bandwidth benchmark between Pods on same node.
func TestBenchmarkBandwidthIntraNode(t *testing.T) {
	skipIfNotBenchmarkTest(t)
	skipIfNotIPv4Cluster(t)
	skipIfHasWindowsNodes(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
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

func benchmarkBandwidthService(t *testing.T, endpointNode, clientNode string) {
	skipIfHasWindowsNodes(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	svc, err := data.createService("perftest-b", iperfPort, iperfPort, map[string]string{"antrea-e2e": "perftest-b"}, false, v1.ServiceTypeClusterIP, nil)
	if err != nil {
		t.Fatalf("Error when creating perftest service: %v", err)
	}
	if err := data.createPodOnNode("perftest-a", testNamespace, clientNode, perftoolImage, nil, nil, nil, nil, false, nil); err != nil {
		t.Fatalf("Error when creating the perftest client Pod: %v", err)
	}
	if err := data.podWaitForRunning(defaultTimeout, "perftest-a", testNamespace); err != nil {
		t.Fatalf("Error when waiting for the perftest client Pod: %v", err)
	}
	if err := data.createPodOnNode("perftest-b", testNamespace, endpointNode, perftoolImage, nil, nil, nil, []v1.ContainerPort{{Protocol: v1.ProtocolTCP, ContainerPort: iperfPort}}, false, nil); err != nil {
		t.Fatalf("Error when creating the perftest server Pod: %v", err)
	}
	if err := data.podWaitForRunning(defaultTimeout, "perftest-b", testNamespace); err != nil {
		t.Fatalf("Error when getting the perftest server Pod's IP: %v", err)
	}
	stdout, stderr, err := data.runCommandFromPod(testNamespace, "perftest-a", perftoolContainerName, []string{"bash", "-c", fmt.Sprintf("iperf3 -c %s|grep sender|awk '{print $7,$8}'", svc.Spec.ClusterIP)})
	if err != nil {
		t.Fatalf("Error when running iperf3 client: %v, stderr: %s", err, stderr)
	}
	stdout = strings.TrimSpace(stdout)
	t.Logf("Bandwidth: %s", stdout)
}

// TestBenchmarkBandwidthServiceLocalAccess runs the bandwidth benchmark of service
// traffic between a Pod and an Endpoint on same Node.
func TestBenchmarkBandwidthServiceLocalAccess(t *testing.T) {
	skipIfNotBenchmarkTest(t)
	benchmarkBandwidthService(t, controlPlaneNodeName(), controlPlaneNodeName())
}

// TestBenchmarkBandwidthServiceRemoteAccess runs the bandwidth benchmark of service
// traffic between a Pod and an Endpoint on different Node.
func TestBenchmarkBandwidthServiceRemoteAccess(t *testing.T) {
	skipIfNotBenchmarkTest(t)
	skipIfNumNodesLessThan(t, 2)
	benchmarkBandwidthService(t, controlPlaneNodeName(), workerNodeName(1))
}

func TestPodTrafficShaping(t *testing.T) {
	// TODO: tc configuration succeeded, however it didn't take effect, need to understand the reason.
	skipIfProviderIs(t, "kind", "tc does not work with Kind")
	// Test is flaky on dual-stack clusters: https://github.com/antrea-io/antrea/issues/1543.
	// So we disable it except for IPv4 single-stack clusters for now.
	skipIfIPv6Cluster(t)
	nodeName := controlPlaneNodeName()
	skipIfMissingKernelModule(t, nodeName, []string{"ifb", "sch_tbf", "sch_ingress"})
	skipIfHasWindowsNodes(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
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
			defer deletePodWrapper(t, data, clientPodName)
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
			defer deletePodWrapper(t, data, serverPodName)
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
