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
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
)

const (
	serviceNumber   = 50
	netperfCommPort = 30000
	netperfDataPort = 30001
)

func TestBenchmarkLatency(t *testing.T) {
	skipIfNotRequired(t, "mode-irrelevant")
	skipIfNotBenchmarkTest(t)
	skipIfNumNodesLessThan(t, 2)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	t.Run("ServiceRealization", func(t *testing.T) {
		t.Run("FromNode", func(t *testing.T) {
			t.Run("ClusterIP", func(t *testing.T) {
				endpointNode := controlPlaneNodeName()
				clientNode := clusterInfo.nodes[1].name
				if len(clusterInfo.windowsNodes) != 0 {
					clientNode = nodeName(clusterInfo.windowsNodes[0])
				}
				testClusterIPServiceRealizationLatency(t, data, endpointNode, clientNode, true)
			})
			t.Run("NodePort", func(t *testing.T) {
				testNodePortServiceRealizationLatency(t, data, controlPlaneNodeName(), controlPlaneNodeName(), true)
			})
		})
		t.Run("FromPod", func(t *testing.T) {
			t.Run("ClusterIP", func(t *testing.T) {
				endpointNode := controlPlaneNodeName()
				clientNode := clusterInfo.nodes[1].name
				if len(clusterInfo.windowsNodes) != 0 {
					clientNode = nodeName(clusterInfo.windowsNodes[0])
				}
				testClusterIPServiceRealizationLatency(t, data, endpointNode, clientNode, false)
			})
			t.Run("NodePort", func(t *testing.T) {
				testNodePortServiceRealizationLatency(t, data, controlPlaneNodeName(), controlPlaneNodeName(), false)
			})
		})
	})
	t.Run("ServiceNetpef", func(t *testing.T) {
		t.Run("ClusterIP", func(t *testing.T) {
			endpointNode := controlPlaneNodeName()
			clientNode := clusterInfo.nodes[1].name
			if len(clusterInfo.windowsNodes) != 0 {
				clientNode = nodeName(clusterInfo.windowsNodes[0])
			}
			server := randName(fmt.Sprintf("netperf-clusterip-server-"))
			svc, err := data.createService(server, testNamespace, []servicePorts{{netperfCommPort, netperfCommPort, netperfCommPort}, {netperfDataPort, netperfDataPort, netperfDataPort}},
				map[string]string{"antrea-e2e": server}, false, false, v1.ServiceTypeClusterIP, nil)
			require.NoErrorf(t, err, "Error when creating netperf service")
			defer data.deleteServiceAndWait(defaultTimeout, server)
			require.NoErrorf(t, data.createPodOnNode(server, testNamespace, endpointNode, netperf25LinuxImage, []string{"netserver", "-D", "-p", fmt.Sprintf("%d", netperfCommPort)},
				nil, nil, []v1.ContainerPort{{Protocol: v1.ProtocolTCP, ContainerPort: netperfCommPort}, {Protocol: v1.ProtocolTCP, ContainerPort: netperfDataPort}}, false, nil),
				"Error when creating the netperf ClusterIP server Pod")
			defer data.deletePodAndWait(defaultTimeout, server, testNamespace)
			require.NoErrorf(t, data.podWaitForRunning(defaultTimeout, server, testNamespace), "Error when getting the netperf ClusterIP server Pod's IP")
			time.Sleep(30 * time.Second)

			t.Run("FromNode", func(t *testing.T) {
				testNetperfLatency(t, data, clientNode, true, svc.Spec.ClusterIP, netperfCommPort, netperfDataPort, netperf25LinuxImage)
			})
			t.Run("FromPod", func(t *testing.T) {
				testNetperfLatency(t, data, clientNode, false, svc.Spec.ClusterIP, netperfCommPort, netperfDataPort, netperf25LinuxImage)
			})
		})
		t.Run("NodePort", func(t *testing.T) {
			endpointNode, clientNode := controlPlaneNodeName(), controlPlaneNodeName()
			server := randName(fmt.Sprintf("netperf-nodeport-server-"))
			svc, err := data.createService(server, testNamespace, []servicePorts{{netperfCommPort, netperfCommPort, netperfCommPort}, {netperfDataPort, netperfDataPort, netperfDataPort}},
				map[string]string{"antrea-e2e": server}, false, false, v1.ServiceTypeNodePort, nil)
			require.NoErrorf(t, err, "Error when creating netperf service")
			defer data.deleteServiceAndWait(defaultTimeout, server)
			require.NoErrorf(t, data.createPodOnNode(server, testNamespace, endpointNode, netperf27LinuxImage,
				[]string{"netserver", "-D", "-p", fmt.Sprintf("%d", netperfCommPort)}, nil, nil,
				[]v1.ContainerPort{{Protocol: v1.ProtocolTCP, ContainerPort: netperfCommPort}, {Protocol: v1.ProtocolTCP, ContainerPort: netperfDataPort}},
				false, nil), "Error when creating the netperf NodePort server Pod")
			defer data.deletePodAndWait(defaultTimeout, server, testNamespace)
			require.NoErrorf(t, data.podWaitForRunning(defaultTimeout, server, testNamespace), "Error when getting the netperf NodePort server Pod's IP")
			time.Sleep(10 * time.Second)

			nodeIP := clusterInfo.nodes[1].ip()
			if len(clusterInfo.windowsNodes) != 0 {
				nodeIP = clusterInfo.nodes[clusterInfo.windowsNodes[0]].ip()
			}
			var commPort, dataPort int32
			for _, port := range svc.Spec.Ports {
				if port.Name == fmt.Sprintf("%s-0", servicePortPrefix) {
					commPort = port.NodePort
				} else if port.Name == fmt.Sprintf("%s-1", servicePortPrefix) {
					dataPort = port.NodePort
				}
			}

			t.Run("FromNode", func(t *testing.T) {
				testNetperfLatency(t, data, clientNode, true, nodeIP, commPort, dataPort, netperf27LinuxImage)
			})
			t.Run("FromPod", func(t *testing.T) {
				testNetperfLatency(t, data, clientNode, false, nodeIP, commPort, dataPort, netperf27LinuxImage)
			})
		})
	})
}

func testClusterIPServiceRealizationLatency(t *testing.T, data *TestData, endpointNode, clientNode string, fromNode bool) {
	var client string
	if !fromNode {
		client = randName("latency-client-clusterip-")
		require.NoErrorf(t, data.createPodOnNode(client, testNamespace, clientNode, agnhostImage, nil, nil, nil, nil, false, nil), "Error when creating the agnhost client Pod")
		defer data.deletePodAndWait(defaultTimeout, client, testNamespace)
		require.NoErrorf(t, data.podWaitForRunning(defaultTimeout, client, testNamespace), "Error when waiting for the agnhost client Pod")
	}

	latencies := make([]time.Duration, serviceNumber)
	var wg sync.WaitGroup
	t.Logf("Start realizing %d ClusterIP Services in parallel", serviceNumber)
	totalStart := time.Now()
	for i := 0; i < serviceNumber; i++ {
		i := i
		wg.Add(1)
		go func() {
			start := time.Now()
			server := randName(fmt.Sprintf("latency-clusterip-server-%d-", i))
			svc, err := data.createService(server, testNamespace, []servicePorts{{port: 8080, targetPort: 8080}}, map[string]string{"antrea-e2e": server}, false, false, v1.ServiceTypeClusterIP, nil)
			require.NoErrorf(t, err, "Error when creating ClusterIP latency service")
			createAgnhostPod(t, data, server, endpointNode, false)
			url := net.JoinHostPort(svc.Spec.ClusterIP, "8080")

			if fromNode {
				_, _, _, err = RunCommandOnNode(clientNode, fmt.Sprintf("curl --connect-timeout 1 --retry 10 --retry-connrefused %s", url))
				if err != nil {
					t.Errorf("failed to curl %s on client %s: %v", url, clientNode, err)
				}
			} else {
				_, _, err = data.runCommandFromPod(testNamespace, client, agnhostContainerName, []string{"/bin/sh", "-c", fmt.Sprintf("curl --connect-timeout 1 --retry 10 --retry-connrefused %s", url)})
				if err != nil {
					t.Errorf("failed to curl %s on client %s: %v", url, clientNode, err)
				}
			}

			latencies[i] = time.Since(start)
			wg.Done()
		}()
	}
	wg.Wait()
	totalElapsed := time.Since(totalStart)
	t.Logf("Total latency: %s", totalElapsed)

	var avg float64
	for i := 0; i < serviceNumber; i++ {
		avg += latencies[i].Seconds()
	}
	avg /= float64(serviceNumber)
	t.Logf("Average latency: %vs", avg)
}

func testNodePortServiceRealizationLatency(t *testing.T, data *TestData, endpointNode, clientNode string, fromNode bool) {
	var client string
	if !fromNode {
		client = randName("latency-client-nodeport-")
		require.NoErrorf(t, data.createPodOnNode(client, testNamespace, clientNode, agnhostImage, nil, nil, nil, nil, false, nil), "Error when creating the agnhost client Pod")
		defer data.deletePodAndWait(defaultTimeout, client, testNamespace)
		require.NoErrorf(t, data.podWaitForRunning(defaultTimeout, client, testNamespace), "Error when waiting for the agnhost client Pod")
	}

	latencies := make([]time.Duration, serviceNumber)
	var wg sync.WaitGroup
	t.Logf("Start realizing %d NodePort Services in parallel", serviceNumber)
	totalStart := time.Now()
	for i := 0; i < serviceNumber; i++ {
		i := i
		wg.Add(1)
		go func() {
			start := time.Now()
			server := randName(fmt.Sprintf("latency-nodeport-server-%d-", i))
			svc, err := data.createService(server, testNamespace, []servicePorts{{port: 8080, targetPort: 8080}}, map[string]string{"antrea-e2e": server}, false, false, v1.ServiceTypeNodePort, nil)
			require.NoErrorf(t, err, "Error when creating NodePort latency service")
			createAgnhostPod(t, data, server, endpointNode, false)

			nodeIP := clusterInfo.nodes[1].ip()
			if len(clusterInfo.windowsNodes) != 0 {
				nodeIP = clusterInfo.nodes[clusterInfo.windowsNodes[0]].ip()
			}
			var nodePort string
			for _, port := range svc.Spec.Ports {
				if port.NodePort != 0 {
					nodePort = fmt.Sprint(port.NodePort)
					break
				}
			}
			url := net.JoinHostPort(nodeIP, nodePort)

			if fromNode {
				_, _, _, err = RunCommandOnNode(clientNode, fmt.Sprintf("curl --connect-timeout 1 --retry 10 --retry-connrefused %s", url))
				if err != nil {
					t.Errorf("failed to curl %s on client %s", url, clientNode)
				}
			} else {
				_, _, err = data.runCommandFromPod(testNamespace, client, agnhostContainerName, []string{"/bin/sh", "-c", fmt.Sprintf("curl --connect-timeout 1 --retry 10 --retry-connrefused %s", url)})
				if err != nil {
					t.Errorf("failed to curl %s on client %s", url, clientNode)
				}
			}

			latencies[i] = time.Since(start)
			wg.Done()
		}()
	}
	wg.Wait()
	totalElapsed := time.Since(totalStart)
	t.Logf("Total latency: %s", totalElapsed)

	var avg float64
	for i := 0; i < serviceNumber; i++ {
		avg += latencies[i].Seconds()
	}
	avg /= float64(serviceNumber)
	t.Logf("Average latency: %vs", avg)
}

func testNetperfLatency(t *testing.T, data *TestData, clientNode string, fromNode bool, ip string, commPort, dataPort int32, netperfImage string) {
	var rc int
	var stdout, stderr string
	var fields []string
	var err error
	if fromNode {
		var cmd string
		if clusterInfo.nodesOS[clientNode] == "windows" {
			cmd = fmt.Sprintf("powershell 'netperf -t TCP_RR -H %s -p %d -v 2 -- -P %d|select -last 1'", ip, commPort, dataPort)
		} else {
			cmd = fmt.Sprintf("netperf -t TCP_RR -H %s -p %d -v 2 -- -P %d|tail -n 1", ip, commPort, dataPort)
		}
		rc, stdout, stderr, err = RunCommandOnNode(clientNode, cmd)
		if rc != 0 || stderr != "" || err != nil {
			t.Errorf("Error when running netperf client on Node '%s': cmd '%s', rc %d, stdout: %s, stderr: %s", clientNode, cmd, rc, stdout, stderr)
		}
		fields = strings.Fields(stdout)
		require.GreaterOrEqualf(t, len(fields), 4, fmt.Sprintf("Error when getting stdout fields, node: %s, cmd: '%s', stdout: %s", clientNode, cmd, stdout))
	} else {
		client := randName(fmt.Sprintf("netperf-client-"))
		sleepCmd := []string{"sleep", "3600"}
		netperfCmd := []string{"bash", "-c", fmt.Sprintf("netperf -t TCP_RR -H %s -p %d -v 2 -- -P %d|tail -n 1", ip, commPort, dataPort)}
		netperfImageUsed := netperfImage
		netperfContainerName := netperfLinuxContainerName
		if clusterInfo.nodesOS[clientNode] == "windows" {
			sleepCmd = []string{"powershell", "start-sleep", "3600"}
			netperfCmd = []string{"powershell", fmt.Sprintf("netperf -t TCP_RR -H %s -p %d -v 2 -- -P %d|select -last 1", ip, commPort, dataPort)}
			netperfImageUsed = netperf27WindowsImage
			netperfContainerName = netperfWindowsContainerName
		}
		require.NoErrorf(t, data.createPodOnNode(client, testNamespace, clientNode, netperfImageUsed, sleepCmd, nil, nil, nil, false, nil),
			"Error when creating the netperf client Pod")
		defer data.deletePodAndWait(defaultTimeout, client, testNamespace)
		require.NoErrorf(t, data.podWaitForRunning(defaultTimeout, client, testNamespace), "Error when waiting for the netperf client Pod")

		stdout, stderr, err = data.runCommandFromPod(testNamespace, client, netperfContainerName, netperfCmd)
		require.NoErrorf(t, err, "Error when running netperf client '%s': cmd '%s', stdout: %s, stderr: %s", client, netperfCmd, stdout, stderr)
		fields = strings.Fields(stdout)
		require.GreaterOrEqualf(t, len(fields), 4, fmt.Sprintf("Error when getting stdout fields, Pod: %s, cmd: '%v', stdout: %s", client, netperfCmd, stdout))
	}
	t.Logf("RoundTrip Latency (usec/Tran): %s", fields[4])
}
