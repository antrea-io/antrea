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
	"regexp"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/yaml"

	"antrea.io/antrea/pkg/antctl/raw"
	agentconfig "antrea.io/antrea/pkg/config/agent"
)

const (
	antreaConfigMapName        = "antrea-config"
	antreaIPsecSecretName      = "antrea-ipsec" // #nosec G101: false positive triggered by variable name which includes "Secret"
	ipsecToolboxDeploymentName = "ipsec-tcpdump"
	defaultIPsecPSK            = "changeme"
)

type IPsecTest struct{}

// agentConfigInfo holds relevant configuration from the Antrea agent
type agentConfigInfo struct {
	ipsecEnabled bool
	authMode     string
	tunnelType   string
	tunnelPort   int32
}

func init() {
	RegisterTest("ipsec", &IPsecTest{})
}

func (t *IPsecTest) Run(ctx context.Context, testContext *testContext) error {
	configInfo, err := getAgentConfigInfo(ctx, testContext)
	if err != nil {
		return fmt.Errorf("failed to get agent config: %w", err)
	}

	if !configInfo.ipsecEnabled {
		return newNotRunnableError("IPsec is not enabled (trafficEncryptionMode is not set to 'ipsec')")
	}

	testContext.Log("IPsec authentication mode: %s", configInfo.authMode)
	testContext.Log("Tunnel type: %s, Tunnel port: %d", configInfo.tunnelType, configInfo.tunnelPort)

	if configInfo.tunnelType == "stt" {
		return fmt.Errorf("tunnel type %q is not supported for IPsec testing", configInfo.tunnelType)
	}

	// Check if key has been changed in psk mode
	if configInfo.authMode == "psk" {
		ok, err := hasPSKBeenChanged(ctx, testContext)
		if err != nil {
			return fmt.Errorf("failed to check IPsec PSK: %w", err)
		}
		if ok {
			testContext.Log("IPsec PSK has been changed from default")
		} else {
			// Log warning but don't fail the test
			testContext.Warning("IPsec PSK is set to the default value %q - please configure a custom PSK for production use", defaultIPsecPSK)
		}
	}

	if testContext.echoOtherNodePod == nil {
		return newNotRunnableError("IPsec test requires multiple Nodes")
	}

	clientPod := testContext.clientPods[0]

	// Deploy hostNetwork Pod with tcpdump on the same Node as client Pod
	testContext.Log("Deploying tcpdump on Node %q...", clientPod.Spec.NodeName)
	tcpdumpPod, err := deployTcpdumpPod(ctx, testContext, clientPod.Spec.NodeName, ipsecToolboxDeploymentName)
	if err != nil {
		return fmt.Errorf("failed to deploy tcpdump Pod: %w", err)
	}
	defer func() {
		testContext.Log("Cleaning up tcpdump Deployment...")
		if err := testContext.client.AppsV1().Deployments(testContext.namespace).Delete(ctx, ipsecToolboxDeploymentName, metav1.DeleteOptions{}); err != nil {
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

	testContext.Log("Capturing ESP packets...")
	espOutput, err := runTcpdump(ctx, testContext, tcpdumpPod.Name, "any", "esp")
	if err != nil {
		return fmt.Errorf("failed to capture ESP packets: %w", err)
	}

	// Check if we captured any ESP packets
	if !strings.Contains(espOutput, "ESP") {
		return fmt.Errorf("no ESP packets captured - IPsec may not be working correctly. tcpdump output:\n%s", espOutput)
	}

	testContext.Log("ESP packets captured successfully:")
	displayPacketCapture(testContext, espOutput)

	testContext.Log("Verifying no unencrypted %s traffic...", configInfo.tunnelType)
	tunnelOutput, err := captureTunnelTraffic(ctx, testContext, tcpdumpPod.Name, configInfo.tunnelType, configInfo.tunnelPort)
	if err != nil {
		return fmt.Errorf("failed to capture tunnel packets: %w", err)
	}

	capturedPackets := countNonEmptyLines(tunnelOutput)
	if capturedPackets > 0 {
		testContext.Log("Unencrypted tunnel packet capture output:")
		displayPacketCapture(testContext, tunnelOutput)
		return fmt.Errorf("captured %d unencrypted %s packets - encryption is not working correctly", capturedPackets, configInfo.tunnelType)
	}
	testContext.Log("No unencrypted tunnel packets detected - encryption is working correctly")

	testContext.Log("Finding antrea-agent Pod on Node %q...", clientPod.Spec.NodeName)
	agentPod, err := getAntreaAgentPod(ctx, testContext, clientPod.Spec.NodeName)
	if err != nil {
		return fmt.Errorf("failed to get antrea-agent Pod: %w", err)
	}

	testContext.Log("Running 'ipsec status' in antrea-agent Pod %q...", agentPod.Name)
	ipsecOutput, err := getIPsecStatus(ctx, testContext, agentPod.Name)
	if err != nil {
		return fmt.Errorf("failed to get ipsec status: %w", err)
	}

	routedConnections, securityAssociations, err := parseIPsecStatus(ipsecOutput)
	if err != nil {
		return fmt.Errorf("failed to parse ipsec status output: %w", err)
	}

	testContext.Log("Routed connections: %d", routedConnections)
	testContext.Log("Security associations: %d", securityAssociations)

	// Get antrea-agent DaemonSet to check DesiredNumberScheduled
	daemonSet, err := testContext.client.AppsV1().DaemonSets(testContext.antreaNamespace).Get(ctx, agentDaemonSetName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get antrea-agent DaemonSet: %w", err)
	}

	expectedRoutedConnections := int(daemonSet.Status.DesiredNumberScheduled) - 1
	testContext.Log("Expected routed connections: %d (DesiredNumberScheduled - 1)", expectedRoutedConnections)

	if routedConnections != expectedRoutedConnections {
		return fmt.Errorf("expected %d routed connections, but found %d", expectedRoutedConnections, routedConnections)
	}

	if securityAssociations < 1 {
		return fmt.Errorf("expected at least 1 security association, but found %d", securityAssociations)
	}

	testContext.Log("IPsec is working correctly")
	return nil
}

// getAgentConfig retrieves and parses the Antrea agent configuration from the ConfigMap
func getAgentConfig(ctx context.Context, testContext *testContext) (*agentconfig.AgentConfig, error) {
	configMap, err := testContext.client.CoreV1().ConfigMaps(testContext.antreaNamespace).Get(ctx, antreaConfigMapName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get ConfigMap %q: %w", antreaConfigMapName, err)
	}

	agentConfData, ok := configMap.Data["antrea-agent.conf"]
	if !ok {
		return nil, fmt.Errorf("antrea-agent.conf not found in ConfigMap")
	}

	var agentConf agentconfig.AgentConfig
	if err := yaml.Unmarshal([]byte(agentConfData), &agentConf); err != nil {
		return nil, fmt.Errorf("failed to unmarshal antrea-agent.conf: %w", err)
	}

	return &agentConf, nil
}

// getAgentConfigInfo retrieves and parses all necessary configuration from the agent
func getAgentConfigInfo(ctx context.Context, testContext *testContext) (*agentConfigInfo, error) {
	agentConf, err := getAgentConfig(ctx, testContext)
	if err != nil {
		return nil, err
	}

	info := &agentConfigInfo{
		ipsecEnabled: strings.EqualFold(agentConf.TrafficEncryptionMode, "ipsec"),
	}

	info.authMode = agentConf.IPsec.AuthenticationMode
	if info.authMode == "" {
		info.authMode = "psk"
	}

	info.tunnelType = agentConf.TunnelType
	if info.tunnelType == "" {
		info.tunnelType = "geneve"
	}

	info.tunnelPort = agentConf.TunnelPort
	if info.tunnelPort == 0 {
		switch info.tunnelType {
		case "geneve":
			info.tunnelPort = 6081
		case "vxlan":
			info.tunnelPort = 4789
		case "gre":
			info.tunnelPort = 0 // GRE doesn't use a UDP port
		case "stt":
			info.tunnelPort = 7471
		}
	}

	return info, nil
}

// hasPSKBeenChanged returns true if the default PSK has been changed
func hasPSKBeenChanged(ctx context.Context, testContext *testContext) (bool, error) {
	secret, err := testContext.client.CoreV1().Secrets(testContext.antreaNamespace).Get(ctx, antreaIPsecSecretName, metav1.GetOptions{})
	if err != nil {
		return false, fmt.Errorf("failed to get %q Secret: %w", antreaIPsecSecretName, err)
	}

	pskData, ok := secret.Data["psk"]
	if !ok {
		return false, fmt.Errorf("psk key not found in IPsec Secret")
	}

	psk := string(pskData)
	return psk != defaultIPsecPSK, nil
}

// captureTunnelTraffic captures unencrypted tunnel packets using tcpdump.
// If any packets are captured, it means IPsec encryption is not working properly.
func captureTunnelTraffic(ctx context.Context, testContext *testContext, podName, tunnelType string, tunnelPort int32) (string, error) {
	var filter []string
	switch tunnelType {
	case "gre":
		filter = []string{"ip", "proto", "47"}
	case "geneve", "vxlan":
		if tunnelPort == 0 {
			return "", fmt.Errorf("tunnel type %s requires a UDP port, but port is 0", tunnelType)
		}
		filter = []string{"udp", "port", fmt.Sprint(tunnelPort)}
	default:
		return "", fmt.Errorf("unsupported tunnel type: %s", tunnelType)
	}
	return runTcpdump(ctx, testContext, podName, "any", filter...)
}

// getAntreaAgentPod gets the antrea-agent Pod running on the specified Node
func getAntreaAgentPod(ctx context.Context, testContext *testContext, nodeName string) (*corev1.Pod, error) {
	podList, err := testContext.client.CoreV1().Pods(testContext.antreaNamespace).List(ctx, metav1.ListOptions{
		LabelSelector: "app=antrea,component=antrea-agent",
		FieldSelector: fmt.Sprintf("spec.nodeName=%s", nodeName),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list antrea-agent Pods: %w", err)
	}
	if len(podList.Items) == 0 {
		return nil, fmt.Errorf("no antrea-agent Pod found on Node %q", nodeName)
	}
	return &podList.Items[0], nil
}

// getIPsecStatus runs 'ipsec status' in the antrea-ipsec container
func getIPsecStatus(ctx context.Context, testContext *testContext, agentPodName string) (string, error) {
	cmd := []string{"ipsec", "status"}
	stdout, stderr, err := raw.ExecInPod(ctx, testContext.client, testContext.config, testContext.antreaNamespace, agentPodName, "antrea-ipsec", cmd)
	if err != nil {
		testContext.Log("ipsec status command stderr: %s", stderr)
		return "", fmt.Errorf("ipsec status command failed: %w", err)
	}
	return stdout, nil
}

// parseIPsecStatus parses the output of 'ipsec status' to extract the number of routed connections and security associations
func parseIPsecStatus(output string) (routedConnections int, securityAssociations int, err error) {
	// Parse routed connections - count unique connection names (without -in/-out suffix if present)
	// GRE format: "worker2-a0d026-1{1}:  ROUTED, TRANSPORT, reqid 1"
	// Geneve format: "worker2-a0d026-in-1{3}:  ROUTED, TRANSPORT, reqid 3"
	//                "worker2-a0d026-out-1{4}:  ROUTED, TRANSPORT, reqid 4"
	// Match the connection name prefix before the final "-<number>{<id>}" part, ignoring optional "-in" or "-out"
	routedRegex := regexp.MustCompile(`(?m)^(\S+?)(?:-(in|out))?-\d+\{\d+\}:\s+ROUTED`)
	routedMatches := routedRegex.FindAllStringSubmatch(output, -1)

	// Use a set to count unique connections
	uniqueConnections := sets.New[string]()
	for _, match := range routedMatches {
		if len(match) >= 2 {
			// Extract the connection name prefix (e.g., "worker2-a0d026" from both "worker2-a0d026-1" and "worker2-a0d026-in-1")
			connName := match[1]
			uniqueConnections.Insert(connName)
		}
	}

	routedConnections = uniqueConnections.Len()

	// Parse security associations from the summary line
	// Example: "Security Associations (1 up, 0 connecting):"
	saRegex := regexp.MustCompile(`Security Associations \((\d+) up`)
	matches := saRegex.FindStringSubmatch(output)
	if len(matches) >= 2 {
		securityAssociations, err = strconv.Atoi(matches[1])
		if err != nil {
			return 0, 0, fmt.Errorf("failed to parse security associations count: %w", err)
		}
	} else {
		return 0, 0, fmt.Errorf("failed to find security associations summary line in output")
	}

	return routedConnections, securityAssociations, nil
}
