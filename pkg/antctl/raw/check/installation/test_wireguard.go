// Copyright 2026 Antrea Authors.
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

package installation

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	agentypes "antrea.io/antrea/pkg/agent/types"
	apis "antrea.io/antrea/pkg/apis"
)

const (
	wireGuardToolboxDeploymentName = "wireguard-tcpdump"
	defaultWireGuardPort           = apis.WireGuardListenPort
	wireGuardInterfaceName         = "antrea-wg0"
)

type WireGuardTest struct{}

func init() {
	RegisterTest("wireguard", &WireGuardTest{})
}

func (t *WireGuardTest) Run(ctx context.Context, testContext *testContext) error {
	agentConf, err := getAgentConfig(ctx, testContext)
	if err != nil {
		return fmt.Errorf("failed to get agent config: %w", err)
	}

	if !strings.EqualFold(agentConf.TrafficEncryptionMode, "wireguard") {
		return newNotRunnableError("WireGuard is not enabled (trafficEncryptionMode is not set to 'wireguard')")
	}

	wireGuardPort := agentConf.WireGuard.Port
	if wireGuardPort == 0 {
		wireGuardPort = defaultWireGuardPort
	}
	testContext.Log("WireGuard port: %d", wireGuardPort)

	if testContext.echoOtherNodePod == nil {
		return newNotRunnableError("WireGuard test requires multiple Nodes")
	}

	testContext.Log("Verifying WireGuard public key annotations on all Nodes...")
	nodes, err := testContext.client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list Nodes: %w", err)
	}
	nodesWithKey := 0
	for _, node := range nodes.Items {
		if pubKey, ok := node.Annotations[agentypes.NodeWireGuardPublicAnnotationKey]; ok && pubKey != "" {
			nodesWithKey++
		} else {
			testContext.Warning("Node %q is missing WireGuard public key annotation", node.Name)
		}
	}
	if nodesWithKey != len(nodes.Items) {
		return fmt.Errorf("%d out of %d Nodes have a WireGuard public key annotation", nodesWithKey, len(nodes.Items))
	}
	testContext.Log("All %d Nodes have WireGuard public key annotations", nodesWithKey)

	clientPod := testContext.clientPods[0]

	testContext.Log("Deploying tcpdump Pod on Node %q...", clientPod.Spec.NodeName)
	tcpdumpPod, err := deployTcpdumpPod(ctx, testContext, clientPod.Spec.NodeName, wireGuardToolboxDeploymentName)
	if err != nil {
		return fmt.Errorf("failed to deploy tcpdump Pod: %w", err)
	}
	defer func() {
		testContext.Log("Cleaning up tcpdump Deployment...")
		if err := testContext.client.AppsV1().Deployments(testContext.namespace).Delete(ctx, wireGuardToolboxDeploymentName, metav1.DeleteOptions{}); err != nil {
			testContext.Warning("Failed to delete tcpdump Deployment: %v", err)
		}
	}()

	stopProbes, err := startBackgroundProbes(ctx, testContext, clientPod.Name, testContext.echoOtherNodePod)
	if err != nil {
		return err
	}
	defer func() {
		testContext.Log("Stopping background probes...")
		stopProbes()
	}()

	// Check 1: plaintext Pod traffic is visible on the WireGuard interface (antrea-wg0).
	// This interface carries decrypted traffic on its way in and out of the WireGuard
	// tunnel, so Pod IPs should be visible here in plaintext.
	testContext.Log("Verifying plaintext Pod traffic is visible on the %s interface...", wireGuardInterfaceName)
	for _, podIP := range testContext.echoOtherNodePod.Status.PodIPs {
		targetIP := podIP.IP
		output, err := runTcpdump(ctx, testContext, tcpdumpPod.Name, wireGuardInterfaceName, "host", targetIP)
		if err != nil {
			return fmt.Errorf("failed to capture traffic on %s: %w", wireGuardInterfaceName, err)
		}
		if countNonEmptyLines(output) == 0 {
			return fmt.Errorf("no traffic to/from %s captured on %s - WireGuard may not be routing Pod traffic correctly", targetIP, wireGuardInterfaceName)
		}
		testContext.Log("Plaintext Pod traffic to/from %s confirmed on %s:", targetIP, wireGuardInterfaceName)
		displayPacketCapture(testContext, output)
	}

	// Check 2: WireGuard UDP packets are visible on the transport interface.
	// This confirms that traffic leaving the node is encrypted and carried as WireGuard
	// UDP on the configured port.
	transportIface, err := getNodeTransportInterface(ctx, testContext, clientPod.Spec.NodeName)
	if err != nil {
		return fmt.Errorf("failed to get transport interface for Node %q: %w", clientPod.Spec.NodeName, err)
	}
	testContext.Log("Verifying WireGuard UDP traffic is present on interface %q (port %d)...", transportIface, wireGuardPort)
	wgOutput, err := runTcpdump(ctx, testContext, tcpdumpPod.Name, transportIface, "udp", "port", fmt.Sprint(wireGuardPort))
	if err != nil {
		return fmt.Errorf("failed to capture WireGuard packets on transport interface: %w", err)
	}
	if countNonEmptyLines(wgOutput) == 0 {
		return fmt.Errorf("no WireGuard UDP packets captured on transport interface (port %d) - WireGuard may not be encrypting traffic", wireGuardPort)
	}
	testContext.Log("WireGuard UDP packets confirmed on transport interface:")
	displayPacketCapture(testContext, wgOutput)

	testContext.Log("WireGuard is working correctly")
	return nil
}

// getNodeTransportInterface returns the name of the transport interface for the given Node
// by reading the AntreaAgentInfo CR. If the field is not set (e.g. older Antrea versions),
// it logs a warning and returns "any" so tcpdump still captures on all interfaces.
func getNodeTransportInterface(ctx context.Context, testContext *testContext, nodeName string) (string, error) {
	agentInfo, err := testContext.antreaClient.CrdV1beta1().AntreaAgentInfos().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to get AntreaAgentInfo for Node %q: %w", nodeName, err)
	}
	iface := agentInfo.NetworkInfo.TransportInterface
	if iface == "" {
		testContext.Warning("AntreaAgentInfo for Node %q does not have a transport interface set; capturing on all interfaces", nodeName)
		return "any", nil
	}
	return iface, nil
}
