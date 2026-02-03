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
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/yaml"

	"antrea.io/antrea/pkg/antctl/raw"
	"antrea.io/antrea/pkg/antctl/raw/check"
	agentconfig "antrea.io/antrea/pkg/config/agent"
)

const (
	antreaConfigMapName        = "antrea-config"
	antreaIPsecSecretName      = "antrea-ipsec" // #nosec G101: false positive triggered by variable name which includes "Secret"
	ipsecToolboxDeploymentName = "ipsec-tcpdump"
	tcpdumpPacketCount         = 10
	tcpdumpTimeout             = 10 * time.Second
	defaultIPsecPSK            = "changeme"
	pingResponseTimeoutSeconds = 2
	maxDisplayLines            = 10
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
	tcpdumpPod, err := deployTcpdumpPod(ctx, testContext, clientPod.Spec.NodeName)
	if err != nil {
		return fmt.Errorf("failed to deploy tcpdump Pod: %w", err)
	}
	defer func() {
		testContext.Log("Cleaning up tcpdump Deployment...")
		if err := testContext.client.AppsV1().Deployments(testContext.namespace).Delete(ctx, ipsecToolboxDeploymentName, metav1.DeleteOptions{}); err != nil {
			testContext.Warning("Failed to delete tcpdump Deployment: %v", err)
		}
	}()

	for _, podIP := range testContext.echoOtherNodePod.Status.PodIPs {
		targetIP := podIP.IP
		testContext.Log("Verifying connectivity from Pod %q to %s...", clientPod.Name, targetIP)
		if err := verifyConnectivity(ctx, testContext, clientPod.Name, targetIP); err != nil {
			return fmt.Errorf("initial ping failed: %w", err)
		}
		testContext.Log("Ping from Pod %q to %s successful", clientPod.Name, targetIP)

		testContext.Log("Starting background ping from client Pod to echo Pod...")
		stopPing, err := startBackgroundPing(ctx, testContext, clientPod.Name, targetIP)
		if err != nil {
			return fmt.Errorf("failed to start background ping: %w", err)
		}
		defer func() {
			testContext.Log("Stopping background ping...")
			stopPing()
		}()
	}

	testContext.Log("Capturing ESP packets...")
	espOutput, err := captureESPackets(ctx, testContext, tcpdumpPod.Name)
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
	tunnelOutput, err := captureTunnelPackets(ctx, testContext, tcpdumpPod.Name, configInfo.tunnelType, configInfo.tunnelPort)
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

// verifyConnectivity sends 3 pings from the client Pod to the target IP to verify connectivity
// It succeeds if at least one of the 3 pings is successful (ping returns exit code 0 if at least 1 packet is received)
func verifyConnectivity(ctx context.Context, testContext *testContext, clientPodName, targetIP string) error {
	cmd := []string{"ping", "-c", "3", "-W", fmt.Sprint(pingResponseTimeoutSeconds), targetIP}
	_, stderr, err := raw.ExecInPod(ctx, testContext.client, testContext.config, testContext.namespace, clientPodName, "", cmd)
	if err != nil {
		testContext.Log("ping command stderr: %s", stderr)
		return fmt.Errorf("ping command failed: %w", err)
	}
	return nil
}

// startBackgroundPing starts a ping in the background from the client Pod to the target IP
// It returns a cleanup function that should be called to stop the ping goroutine
func startBackgroundPing(ctx context.Context, testContext *testContext, clientPodName, targetIP string) (func(), error) {
	pingCtx, cancelPing := context.WithCancel(ctx)

	var wg sync.WaitGroup

	wg.Go(func() {
		cmd := []string{"ping", "-W", fmt.Sprint(pingResponseTimeoutSeconds), targetIP}
		if _, _, err := raw.ExecInPod(pingCtx, testContext.client, testContext.config, testContext.namespace, clientPodName, "", cmd); err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			testContext.Warning("ping command failed: %v", err)
		}
	})

	cleanup := func() {
		cancelPing()
		wg.Wait()
	}

	return cleanup, nil
}

// deployTcpdumpPod deploys a hostNetwork Pod with tcpdump on the specified Node
func deployTcpdumpPod(ctx context.Context, testContext *testContext, nodeName string) (*corev1.Pod, error) {
	deployment := check.NewDeployment(check.DeploymentParameters{
		Name:        ipsecToolboxDeploymentName,
		Role:        "tcpdump",
		Image:       testContext.testImage,
		HostNetwork: true,
		Affinity: &corev1.Affinity{
			NodeAffinity: &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
					NodeSelectorTerms: []corev1.NodeSelectorTerm{
						{
							MatchExpressions: []corev1.NodeSelectorRequirement{
								{
									Key:      "kubernetes.io/hostname",
									Operator: corev1.NodeSelectorOpIn,
									Values:   []string{nodeName},
								},
							},
						},
					},
				},
			},
		},
		Tolerations: []corev1.Toleration{
			{
				Key:      "node-role.kubernetes.io/control-plane",
				Operator: "Exists",
				Effect:   "NoSchedule",
			},
		},
		SecurityContext: &corev1.SecurityContext{
			Privileged: ptr.To(true),
		},
		Labels: map[string]string{"app": "antrea", "component": "installation-checker", "name": ipsecToolboxDeploymentName},
	})

	if _, err := testContext.client.AppsV1().Deployments(testContext.namespace).Create(ctx, deployment, metav1.CreateOptions{}); err != nil {
		return nil, fmt.Errorf("failed to create tcpdump Deployment: %w", err)
	}

	testContext.Log("Waiting for tcpdump Deployment to be ready...")
	if err := check.WaitForDeploymentsReady(ctx, time.Second, podReadyTimeout, false, testContext.client, testContext.clusterName, testContext.namespace, ipsecToolboxDeploymentName); err != nil {
		return nil, fmt.Errorf("tcpdump Deployment did not become ready: %w", err)
	}

	podList, err := testContext.client.CoreV1().Pods(testContext.namespace).List(ctx, metav1.ListOptions{LabelSelector: "name=" + ipsecToolboxDeploymentName})
	if err != nil {
		return nil, fmt.Errorf("failed to list tcpdump Pods: %w", err)
	}
	if len(podList.Items) == 0 {
		return nil, fmt.Errorf("no tcpdump Pod found")
	}

	return &podList.Items[0], nil
}

// captureESPackets captures ESP packets using tcpdump
func captureESPackets(ctx context.Context, testContext *testContext, podName string) (string, error) {
	cmd := []string{"tcpdump", "-n", "-i", "any", "-c", fmt.Sprint(tcpdumpPacketCount), "esp"}
	ctx, cancel := context.WithTimeout(ctx, tcpdumpTimeout)
	defer cancel()
	stdout, stderr, err := raw.ExecInPod(ctx, testContext.client, testContext.config, testContext.namespace, podName, "", cmd)
	if err != nil {
		testContext.Log("tcpdump command stderr: %s", stderr)
		return "", fmt.Errorf("tcpdump command failed: %w", err)
	}
	return stdout, nil
}

// captureTunnelPackets captures tunnel packets using tcpdump
// If any packets are captured, it means encryption is not working properly
func captureTunnelPackets(ctx context.Context, testContext *testContext, podName, tunnelType string, tunnelPort int32) (string, error) {
	var cmd []string

	switch tunnelType {
	case "gre":
		// GRE uses IP protocol 47
		cmd = []string{"tcpdump", "-n", "-i", "any", "-c", fmt.Sprint(tcpdumpPacketCount), "ip", "proto", "47"}
	case "geneve", "vxlan":
		// Geneve and VXLAN use UDP
		if tunnelPort == 0 {
			return "", fmt.Errorf("tunnel type %s requires a UDP port, but port is 0", tunnelType)
		}
		cmd = []string{"tcpdump", "-n", "-i", "any", "-c", fmt.Sprint(tcpdumpPacketCount), "udp", "port", fmt.Sprint(tunnelPort)}
	default:
		return "", fmt.Errorf("unsupported tunnel type: %s", tunnelType)
	}

	ctx, cancel := context.WithTimeout(ctx, tcpdumpTimeout)
	defer cancel()
	stdout, stderr, err := raw.ExecInPod(ctx, testContext.client, testContext.config, testContext.namespace, podName, "", cmd)
	// tcpdump may return an error if timeout is reached with no packets, which is expected
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		testContext.Log("tcpdump command stderr: %s", stderr)
		testContext.Warning("tcpdump command encountered an error (may be expected): %v", err)
	}
	return stdout, nil
}

// countNonEmptyLines counts non-empty lines in the output
func countNonEmptyLines(output string) int {
	if output == "" {
		return 0
	}
	lines := strings.Split(output, "\n")
	count := 0
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count
}

// displayPacketCapture displays the first few lines of packet capture output
func displayPacketCapture(testContext *testContext, output string) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	displayLines := min(len(lines), maxDisplayLines)
	for i := 0; i < displayLines; i++ {
		testContext.Log("  %s", lines[i])
	}
	if len(lines) > displayLines {
		testContext.Log("  ... (%d more lines)", len(lines)-displayLines)
	}
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
