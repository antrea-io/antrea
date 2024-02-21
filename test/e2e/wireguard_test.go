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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"

	"antrea.io/antrea/pkg/agent/config"
	agentconfig "antrea.io/antrea/pkg/config/agent"
)

// TestWireGuard checks that Pod traffic across two Nodes over the WireGuard tunnel by creating
// multiple Pods across distinct Nodes and having them ping each other. It will also verify that
// the handshake was established when the wg command line is available.
func TestWireGuard(t *testing.T) {
	skipIfNumNodesLessThan(t, 2)
	skipIfHasWindowsNodes(t)
	skipIfAntreaIPAMTest(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
	skipIfEncapModeIsNot(t, data, config.TrafficEncapModeEncap)
	for _, node := range clusterInfo.nodes {
		skipIfMissingKernelModule(t, data, node.name, []string{"wireguard"})
	}
	var previousTrafficEncryptionMode string
	var previousMulticastEnabledState bool
	ac := func(config *agentconfig.AgentConfig) {
		previousTrafficEncryptionMode = config.TrafficEncryptionMode
		config.TrafficEncryptionMode = "wireguard"
		previousMulticastEnabledState = config.Multicast.Enable
		config.Multicast.Enable = false
	}
	if err := data.mutateAntreaConfigMap(nil, ac, false, true); err != nil {
		t.Fatalf("Failed to enable WireGuard tunnel: %v", err)
	}
	defer func() {
		ac := func(config *agentconfig.AgentConfig) {
			config.TrafficEncryptionMode = previousTrafficEncryptionMode
			config.Multicast.Enable = previousMulticastEnabledState
		}
		if err := data.mutateAntreaConfigMap(nil, ac, false, true); err != nil {
			t.Errorf("Failed to disable WireGuard tunnel: %v", err)
		}
	}()

	t.Run("testPodConnectivity", func(t *testing.T) { testPodConnectivity(t, data) })
	t.Run("testServiceConnectivity", func(t *testing.T) { testServiceConnectivity(t, data) })
}

func testPodConnectivity(t *testing.T, data *TestData) {
	podInfos, deletePods := createPodsOnDifferentNodes(t, data, data.testNamespace, "differentnodes")
	defer deletePods()
	numPods := 2
	data.runPingMesh(t, podInfos[:numPods], toolboxContainerName, true)

	// Make sure that route to Pod on peer Node and route to peer gateway is targeting the WireGuard device.
	srcPod, err := data.getAntreaPodOnNode(nodeName(0))
	require.NoError(t, err)
	var srcIP, peerGatewayIP, peerPodIP string
	ipv4, ipv6 := nodeGatewayIPs(0)
	if ipv4 != "" {
		srcIP = ipv4
	} else {
		srcIP = ipv6
	}
	ipv4, ipv6 = nodeGatewayIPs(1)
	if ipv4 != "" {
		peerGatewayIP = ipv4
	} else {
		peerGatewayIP = ipv6
	}
	podIPs := waitForPodIPs(t, data, podInfos)
	for _, pi := range podInfos {
		if pi.OS == "linux" && pi.NodeName != nodeName(0) {
			if podIPs[pi.Name].IPv4 != nil {
				peerPodIP = podIPs[pi.Name].IPv4.String()
			} else {
				peerPodIP = podIPs[pi.Name].IPv6.String()
			}
			break
		}
	}

	tests := []struct {
		name               string
		dstIP              string
		expectedDeviceName string
		expectedSrcIP      string
	}{
		{
			name:               "routeToPodOnPeerNode",
			dstIP:              peerPodIP,
			expectedDeviceName: "antrea-wg0",
			expectedSrcIP:      srcIP,
		},
		{
			name:               "routeToPeerGateway",
			dstIP:              peerGatewayIP,
			expectedDeviceName: "antrea-wg0",
			expectedSrcIP:      srcIP,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := []string{"ip", "route", "get", tt.dstIP}
			stdout, _, err := data.RunCommandFromPod(antreaNamespace, srcPod, agentContainerName, cmd)
			require.NoError(t, err)
			assert.Contains(t, stdout, tt.expectedDeviceName)
			assert.Contains(t, stdout, tt.expectedSrcIP)
		})
	}
}

// testServiceConnectivity verifies host-to-service can be transferred through the encrypted tunnel correctly.
func testServiceConnectivity(t *testing.T, data *TestData) {
	clientPodName := "hostnetwork-pod"
	svcName := "agnhost"
	clientPodNode := nodeName(0)
	// nodeIP() returns IPv6 address if this is a IPv6 cluster.
	clientPodNodeIP := nodeIP(0)
	serverPodNode := nodeName(1)
	svc, cleanup := data.createAgnhostServiceAndBackendPods(t, svcName, data.testNamespace, serverPodNode, corev1.ServiceTypeNodePort)
	defer cleanup()

	// Create the a hostNetwork Pod on a Node different from the service's backend Pod, so the service traffic will be transferred across the tunnel.
	require.NoError(t, NewPodBuilder(clientPodName, data.testNamespace, ToolboxImage).OnNode(clientPodNode).InHostNetwork().Create(data))
	defer data.DeletePodAndWait(defaultTimeout, clientPodName, data.testNamespace)
	require.NoError(t, data.podWaitForRunning(defaultTimeout, clientPodName, data.testNamespace))

	err := data.runNetcatCommandFromTestPod(clientPodName, data.testNamespace, svc.Spec.ClusterIP, 80)
	require.NoError(t, err, "Pod %s should be able to connect the service's ClusterIP %s, but was not able to connect", clientPodName, net.JoinHostPort(svc.Spec.ClusterIP, fmt.Sprint(80)))

	err = data.runNetcatCommandFromTestPod(clientPodName, data.testNamespace, clientPodNodeIP, svc.Spec.Ports[0].NodePort)
	require.NoError(t, err, "Pod %s should be able to connect the service's NodePort %s:%d, but was not able to connect", clientPodName, clientPodNodeIP, svc.Spec.Ports[0].NodePort)
}
