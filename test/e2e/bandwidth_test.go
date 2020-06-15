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
	"strings"
	"testing"

	v1 "k8s.io/api/core/v1"
)

const iperfPort = 5201

// TestBenchmarkBandwidthIntraNode runs the bandwidth benchmark between Pods on same node.
func TestBenchmarkBandwidthIntraNode(t *testing.T) {
	skipIfNotBenchmarkTest(t)
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
	if err := data.createPodOnNode("perftest-a", masterNodeName(), perftoolImage, nil, nil, nil, nil); err != nil {
		t.Fatalf("Error when creating the perftest client Pod: %v", err)
	}
	if err := data.podWaitForRunning(defaultTimeout, "perftest-a", testNamespace); err != nil {
		t.Fatalf("Error when waiting for the perftest client Pod: %v", err)
	}
	if err := data.createPodOnNode("perftest-b", masterNodeName(), perftoolImage, nil, nil, nil, []v1.ContainerPort{{Protocol: v1.ProtocolTCP, ContainerPort: iperfPort}}); err != nil {
		t.Fatalf("Error when creating the perftest server Pod: %v", err)
	}
	podBIP, err := data.podWaitForIP(defaultTimeout, "perftest-b", testNamespace)
	if err != nil {
		t.Fatalf("Error when getting the perftest server Pod's IP: %v", err)
	}
	stdout, _, err := data.runCommandFromPod(testNamespace, "perftest-a", "perftool", []string{"bash", "-c", fmt.Sprintf("iperf3 -c %s|grep sender|awk '{print $7,$8}'", podBIP)})
	if err != nil {
		t.Fatalf("Error when running iperf3 client: %v", err)
	}
	stdout = strings.TrimSpace(stdout)
	t.Logf("Bandwidth: %s", stdout)
}

func benchmarkBandwidthService(t *testing.T, endpointNode, clientNode string) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	svc, err := data.createService("perftest-b", iperfPort, iperfPort, map[string]string{"antrea-e2e": "perftest-b"})
	if err != nil {
		t.Fatalf("Error when creating perftest service: %v", err)
	}
	if err := data.createPodOnNode("perftest-a", clientNode, perftoolImage, nil, nil, nil, nil); err != nil {
		t.Fatalf("Error when creating the perftest client Pod: %v", err)
	}
	if err := data.podWaitForRunning(defaultTimeout, "perftest-a", testNamespace); err != nil {
		t.Fatalf("Error when waiting for the perftest client Pod: %v", err)
	}
	if err := data.createPodOnNode("perftest-b", endpointNode, perftoolImage, nil, nil, nil, []v1.ContainerPort{{Protocol: v1.ProtocolTCP, ContainerPort: iperfPort}}); err != nil {
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
	benchmarkBandwidthService(t, masterNodeName(), masterNodeName())
}

// TestBenchmarkBandwidthServiceRemoteAccess runs the bandwidth benchmark of service
// traffic between a Pod and an Endpoint on different Node.
func TestBenchmarkBandwidthServiceRemoteAccess(t *testing.T) {
	skipIfNotBenchmarkTest(t)
	skipIfNumNodesLessThan(t, 2)
	benchmarkBandwidthService(t, masterNodeName(), workerNodeName(1))
}
