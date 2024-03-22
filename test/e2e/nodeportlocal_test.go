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
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"

	npltesting "antrea.io/antrea/pkg/agent/nodeportlocal/testing"
	"antrea.io/antrea/pkg/agent/nodeportlocal/types"
	agentconfig "antrea.io/antrea/pkg/config/agent"
)

const (
	defaultStartPort  = 26000
	defaultEndPort    = 27000
	updatedStartPort  = 28000
	updatedEndPort    = 29000
	defaultTargetPort = 80
)

type nplRuleData struct {
	nodeIP   string
	nodePort int
	podPort  int
	podIP    string
	protocol string
}

func newExpectedNPLAnnotations(nplStartPort, nplEndPort int) *npltesting.ExpectedNPLAnnotations {
	return npltesting.NewExpectedNPLAnnotations(nil, nplStartPort, nplEndPort)
}

func skipIfNodePortLocalDisabled(tb testing.TB, data *TestData) {
	agentConf, err := data.GetAntreaAgentConf()
	if err != nil {
		tb.Fatalf("Error getting Antrea Agent configuration: %v:", err)
	}
	if !agentConf.NodePortLocal.Enable {
		tb.Skipf("Skipping test because NodePortLocal is not enabled")
	}
}

func configureNPLForAgent(t *testing.T, data *TestData, startPort, endPort int) {
	ac := func(config *agentconfig.AgentConfig) {
		config.NodePortLocal.Enable = true
		config.NodePortLocal.PortRange = fmt.Sprintf("%d-%d", startPort, endPort)
	}

	if err := data.mutateAntreaConfigMap(nil, ac, false, true); err != nil {
		t.Fatalf("Failed to update NodePortLocal config: %v", err)
	}
}

// TestNodePortLocal is the top-level test which contains all subtests for
// NodePortLocal related test cases so they can share setup, teardown.
func TestNodePortLocal(t *testing.T) {
	skipIfNotIPv4Cluster(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	skipIfNodePortLocalDisabled(t, data)

	configureNPLForAgent(t, data, defaultStartPort, defaultEndPort)
	t.Run("testNPLAddPod", func(t *testing.T) { testNPLAddPod(t, data) })
	t.Run("testNPLMultiplePodsAgentRestart", func(t *testing.T) { testNPLMultiplePodsAgentRestart(t, data) })
	t.Run("testNPLChangePortRangeAgentRestart", func(t *testing.T) { testNPLChangePortRangeAgentRestart(t, data) })
}

func getNPLAnnotations(t *testing.T, data *TestData, r *require.Assertions, testPodName string, conditionFn func(types.NPLAnnotation) bool) ([]types.NPLAnnotation, string) {
	var nplAnnotations []types.NPLAnnotation
	var testPodIP *PodIPs

	var err error
	maxRetries := 0
	podTimeout := defaultTimeout
	if testOptions.enableAntreaIPAM {
		// If enableAntreaIPAM and agent restarted, we'll get error "http2: client connection lost" when getting Pod annotations.
		// Add more retries and reduce the timeout to handle this case.
		maxRetries = 4
		podTimeout = 18 * time.Second
	}
	for i := 0; i <= maxRetries; i++ {
		_, err = data.PodWaitFor(podTimeout, testPodName, data.testNamespace, func(pod *corev1.Pod) (bool, error) {
			var err error
			if pod.Status.Phase != corev1.PodRunning {
				return false, nil
			}

			podIPStrings := sets.New[string](pod.Status.PodIP)
			for _, podIP := range pod.Status.PodIPs {
				ipStr := strings.TrimSpace(podIP.IP)
				if ipStr != "" {
					podIPStrings.Insert(ipStr)
				}
			}

			testPodIP, err = parsePodIPs(podIPStrings)
			if err != nil || testPodIP.IPv4 == nil {
				return false, nil
			}

			ann := pod.GetAnnotations()
			t.Logf("Got annotations %v for Pod with IP %v", ann, testPodIP.IPv4.String())
			nplAnn, found := ann[types.NPLAnnotationKey]
			if !found {
				return false, nil
			}
			json.Unmarshal([]byte(nplAnn), &nplAnnotations)
			if conditionFn != nil {
				for _, annotation := range nplAnnotations {
					if !conditionFn(annotation) {
						return false, nil
					}
				}
			}
			return found, nil
		})
		if err == nil {
			break
		}
		t.Logf("Got error when get Pod annotations, err=%+v", err)
		time.Sleep(time.Millisecond * 100)
	}
	r.NoError(err, "Poll for Pod check failed")
	return nplAnnotations, testPodIP.IPv4.String()
}

func checkNPLRules(t *testing.T, data *TestData, r *require.Assertions, nplAnnotations []types.NPLAnnotation, antreaPod, podIP string, nodeName string, present bool) {
	if clusterInfo.nodesOS[nodeName] == "windows" {
		checkNPLRulesForWindowsPod(t, data, r, nplAnnotations, antreaPod, podIP, nodeName, present)
	} else {
		checkNPLRulesForPod(t, data, r, nplAnnotations, antreaPod, podIP, present)
	}
}

func checkNPLRulesForPod(t *testing.T, data *TestData, r *require.Assertions, nplAnnotations []types.NPLAnnotation, antreaPod, podIP string, present bool) {
	var rules []nplRuleData
	for _, ann := range nplAnnotations {
		rule := nplRuleData{
			nodeIP:   ann.NodeIP,
			nodePort: ann.NodePort,
			podIP:    podIP,
			podPort:  ann.PodPort,
			protocol: ann.Protocol,
		}
		rules = append(rules, rule)
	}
	checkForNPLRuleInIPTables(t, data, r, antreaPod, rules, present)
	checkForNPLListeningSockets(t, data, r, antreaPod, rules, present)
}

func checkNPLRulesForWindowsPod(t *testing.T, data *TestData, r *require.Assertions, nplAnnotations []types.NPLAnnotation, antreaPod, podIP string, nodeName string, present bool) {
	var rules []nplRuleData
	for _, ann := range nplAnnotations {
		rule := nplRuleData{
			nodeIP:   ann.NodeIP,
			nodePort: ann.NodePort,
			podIP:    podIP,
			podPort:  ann.PodPort,
			protocol: ann.Protocol,
		}
		rules = append(rules, rule)
	}
	checkForNPLRuleInNetNat(t, data, r, antreaPod, nodeName, rules, present)
}

func buildRuleForPod(rule nplRuleData) []string {
	return []string{
		"-p", rule.protocol, "-m", rule.protocol, "--dport", fmt.Sprint(rule.nodePort),
		"-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", rule.podIP, rule.podPort),
	}
}

func protocolToString(p corev1.Protocol) string {
	return strings.ToLower(string(p))
}

func checkForNPLRuleInIPTables(t *testing.T, data *TestData, r *require.Assertions, antreaPod string, rules []nplRuleData, present bool) {
	cmd := []string{"iptables", "-t", "nat", "-S"}
	t.Logf("Verifying iptables rules %v, present: %v", rules, present)
	const timeout = 60 * time.Second
	err := wait.PollUntilContextTimeout(context.Background(), time.Second, timeout, false, func(ctx context.Context) (bool, error) {
		stdout, _, err := data.RunCommandFromPod(antreaNamespace, antreaPod, agentContainerName, cmd)
		if err != nil {
			t.Logf("Error while checking rules in iptables: %v", err)
			// Retry, as sometimes error can occur due to concurrent operations on iptables.
			return false, nil
		}
		for _, rule := range rules {
			// For simplicity's sake, we only look for that one rule.
			ruleSpec := buildRuleForPod(rule)
			rs := strings.Join(append([]string{"-A", "ANTREA-NODE-PORT-LOCAL"}, ruleSpec...), " ")
			t.Logf("Searching for iptables rule: '%v'", rs)

			if strings.Contains(stdout, rs) && present {
				t.Logf("Found rule in iptables")
			} else if !strings.Contains(stdout, rs) && !present {
				t.Logf("Rule not found in iptables")
			} else {
				return false, nil
			}
		}
		return true, nil
	})
	r.NoError(err, "Poll for iptables rules check failed")
}

func parseGetNetCmdResult(result string, itemNum int) [][]string {
	scanner := bufio.NewScanner(strings.NewReader(result))
	parsed := [][]string{}
	for scanner.Scan() {
		items := strings.Fields(scanner.Text())
		if len(items) < itemNum {
			// Skip if an empty line or something similar
			continue
		}
		parsed = append(parsed, items)
	}
	return parsed
}

func checkForNPLRuleInNetNat(t *testing.T, data *TestData, r *require.Assertions, antreaPod string, nodeName string, rules []nplRuleData, present bool) {
	defaultnodeIP := "0.0.0.0"
	t.Logf("Verifying NetNat rules %v, present: %v", rules, present)
	const timeout = 60 * time.Second
	err := wait.PollUntilContextTimeout(context.Background(), time.Second, timeout, false, func(ctx context.Context) (bool, error) {
		_, _, _, err := data.RunCommandOnNode(nodeName, "Get-NetNatStaticMapping")
		if err != nil {
			t.Logf("Error while checking NPL rules on Windows Node: %v", err)
			// Retry, as sometimes error can occur due to concurrent operations on iptables.
			return false, nil
		}
		for _, rule := range rules {
			cmd := fmt.Sprintf("Get-NetNatStaticMapping -NatName antrea-nat") +
				fmt.Sprintf("|? ExternalIPAddress -EQ %s", defaultnodeIP) +
				fmt.Sprintf("|? ExternalPort -EQ %d", rule.nodePort) +
				fmt.Sprintf("|? Protocol -EQ %s", rule.protocol) +
				"| Format-Table -HideTableHeaders"
			cmdpwsh := fmt.Sprintf(`powershell.exe -NoLogo -NoProfile -NonInteractive -Command `) +
				fmt.Sprintf(`'$ErrorActionPreference="Stop";try {%s} catch {Write-Host $_;os.Exit(1)}'`, cmd)
			_, stdout, _, err := data.RunCommandOnNode(nodeName, cmdpwsh)
			if err != nil {
				t.Logf("Error while checking NPL rule in NetNat:%s %v", rule.nodeIP, err)
				// Retry, as sometimes error can occur due to concurrent operations on iptables.
				return false, nil
			}
			parsed := parseGetNetCmdResult(stdout, 6)
			if len(parsed) > 0 {
				items := parsed[0]
				if items[4] == rule.podIP && items[5] == strconv.Itoa(rule.podPort) {
					if !present {
						return false, nil
					}
					continue
				}
			}
			if present {
				return false, nil
			}
		}
		return true, nil
	})
	r.NoError(err, "Poll for NetNat rules check failed")
}

func checkForNPLListeningSockets(t *testing.T, data *TestData, r *require.Assertions, antreaPod string, rules []nplRuleData, present bool) {
	t.Logf("Verifying NPL listening sockets")
	const timeout = 30 * time.Second
	err := wait.PollUntilContextTimeout(context.Background(), time.Second, timeout, false, func(ctx context.Context) (bool, error) {
		for _, rule := range rules {
			protocolOption := "--" + rule.protocol
			cmd := []string{"ss", "--listening", protocolOption, "-H", "-n"}
			stdout, _, err := data.RunCommandFromPod(antreaNamespace, antreaPod, agentContainerName, cmd)
			if err != nil {
				return false, fmt.Errorf("error when running 'ss': %v", err)
			}

			t.Logf("Checking if NPL is listening on %s:%d", rule.protocol, rule.nodePort)
			regexString := fmt.Sprintf(`(?m)^LISTEN.*0\.0\.0\.0:%d`, rule.nodePort)
			// UDP is a connectionless protocol and hence, lacks states similar to those of TCP (LISTEN).
			if rule.protocol == "udp" {
				regexString = fmt.Sprintf(`(?m)^UNCONN.*0\.0\.0\.0:%d`, rule.nodePort)
			}
			found, err := regexp.MatchString(regexString, stdout)
			if err != nil {
				return false, fmt.Errorf("error when matching regex: %v", err)
			}
			if found && present {
				t.Logf("NPL listening on %s:%d", rule.protocol, rule.nodePort)
			} else if !found && !present {
				t.Logf("NPL not listening on %s:%d", rule.protocol, rule.nodePort)
			} else {
				return false, nil
			}
		}
		return true, nil
	})
	r.NoError(err, "Check for NPL listening sockets failed")
}

func deleteNPLRuleFromIPTables(t *testing.T, data *TestData, r *require.Assertions, antreaPod string, rule nplRuleData) {
	cmd := append([]string{"iptables", "-w", "10", "-t", "nat", "-D", "ANTREA-NODE-PORT-LOCAL"}, buildRuleForPod(rule)...)
	t.Logf("Deleting iptables rule for %v", rule)
	_, _, err := data.RunCommandFromPod(antreaNamespace, antreaPod, agentContainerName, cmd)
	r.NoError(err, "Error when deleting iptables rule")
}

func deleteNPLRuleFromNetNat(t *testing.T, data *TestData, r *require.Assertions, antreaPod string, rule nplRuleData) {
	t.Logf("Deleting Netnat rule for %v", rule)
	_, _, _, err := data.RunCommandOnNode(rule.nodeIP, "Remove-NetNatStaticMapping -NatName antrea-nat -StaticMappingID 1 -Confirm:$false")
	r.NoError(err, "Error when deleting Netnat rule")
}

func checkTrafficForNPL(data *TestData, r *require.Assertions, nplAnnotations []types.NPLAnnotation, clientName string) {
	for i := range nplAnnotations {
		err := data.runNetcatCommandFromTestPodWithProtocol(clientName, data.testNamespace, "agnhost", nplAnnotations[i].NodeIP, int32(nplAnnotations[i].NodePort), nplAnnotations[i].Protocol)
		r.NoError(err, "Traffic test failed for NodeIP: %s, NodePort: %d, Protocol: %s", nplAnnotations[i].NodeIP, nplAnnotations[i].NodePort, nplAnnotations[i].Protocol)
	}
}

func getTwoNodes() (string, string) {
	clientNode := nodeName(0)
	serverNode := nodeName(1)

	if len(clusterInfo.windowsNodes) > 1 {
		// Same test topology on Windows and Linux testbeds.
		clientNode = workerNodeName(clusterInfo.windowsNodes[0])
		serverNode = workerNodeName(clusterInfo.windowsNodes[1])
	}

	return clientNode, serverNode
}

func testNPLAddPod(t *testing.T, data *TestData) {
	t.Run("NPLTestMultiplePods", func(t *testing.T) { NPLTestMultiplePods(t, data) })
	t.Run("NPLTestPodAddMultiPort", func(t *testing.T) { NPLTestPodAddMultiPort(t, data) })
	t.Run("NPLTestPodAddMultiProtocol", func(t *testing.T) { NPLTestPodAddMultiProtocol(t, data) })
	t.Run("NPLTestLocalAccess", func(t *testing.T) { NPLTestLocalAccess(t, data) })
}

// NPLTestMultiplePods tests NodePortLocal functionalities after adding multiple Pods.
// - Create a Service with nginx Pods.
// - Verify that the required NodePortLocal annotation is added in each test Pod.
// - Make sure iptables rules are correctly added in the Node from Antrea Agent Pod.
// - Create a client Pod and test traffic through netcat.
// - Delete the nginx test Pods and verify that the iptables rules are deleted.
func NPLTestMultiplePods(t *testing.T, data *TestData) {
	r := require.New(t)

	annotation := make(map[string]string)
	annotation[types.NPLEnabledAnnotationKey] = "true"
	ipFamily := corev1.IPv4Protocol
	clientNode, serverNode := getTwoNodes()
	testData.createNginxClusterIPServiceWithAnnotations(serverNode, false, &ipFamily, annotation)
	var testPods []string

	for i := 0; i < 3; i++ {
		testPodName := randName("test-pod-")
		testPods = append(testPods, testPodName)
		err := testData.createNginxPodOnNode(testPodName, data.testNamespace, serverNode, false)
		r.NoError(err, "Error creating test Pod: %v", err)
	}

	clientName := randName("test-client-")
	err := testData.createAgnhostPodOnNode(clientName, data.testNamespace, clientNode, false)
	r.NoError(err, "Error creating AgnhostPod %s: %v", clientName)

	err = testData.podWaitForRunning(defaultTimeout, clientName, data.testNamespace)
	r.NoError(err, "Error when waiting for Pod %s to be running", clientName)

	antreaPod, err := testData.getAntreaPodOnNode(serverNode)
	r.NoError(err, "Error when getting Antrea Agent Pod on Node '%s'", serverNode)

	expectedAnnotations := newExpectedNPLAnnotations(defaultStartPort, defaultEndPort).Add(nil, defaultTargetPort, "tcp")
	for _, testPodName := range testPods {
		nplAnnotations, testPodIP := getNPLAnnotations(t, testData, r, testPodName, nil)

		checkNPLRules(t, testData, r, nplAnnotations, antreaPod, testPodIP, serverNode, true)
		expectedAnnotations.Check(t, nplAnnotations)
		checkTrafficForNPL(testData, r, nplAnnotations, clientName)

		testData.DeletePod(data.testNamespace, testPodName)
		checkNPLRules(t, testData, r, nplAnnotations, antreaPod, testPodIP, serverNode, false)
	}
	testData.DeletePod(data.testNamespace, clientName)
}

// NPLTestPodAddMultiPort tests NodePortLocal functionalities for a Pod with multiple ports.
func NPLTestPodAddMultiPort(t *testing.T, data *TestData) {
	r := require.New(t)

	clientNode, serverNode := getTwoNodes()
	testPodName := randName("test-pod-")

	annotation := make(map[string]string)
	annotation[types.NPLEnabledAnnotationKey] = "true"
	selector := make(map[string]string)
	selector["app"] = "agnhost"
	ipFamily := corev1.IPv4Protocol
	testData.CreateServiceWithAnnotations("agnhost1", data.testNamespace, 80, 80, corev1.ProtocolTCP, selector, false, false, corev1.ServiceTypeClusterIP, &ipFamily, annotation)
	testData.CreateServiceWithAnnotations("agnhost2", data.testNamespace, 80, 8080, corev1.ProtocolTCP, selector, false, false, corev1.ServiceTypeClusterIP, &ipFamily, annotation)
	expectedAnnotations := newExpectedNPLAnnotations(defaultStartPort, defaultEndPort).
		Add(nil, 80, "tcp").Add(nil, 8080, "tcp")

	podCmd := "porter"
	// Creating a Pod using agnhost image to support multiple ports, instead of nginx.
	err := NewPodBuilder(testPodName, data.testNamespace, agnhostImage).OnNode(serverNode).WithArgs([]string{podCmd}).WithEnv([]corev1.EnvVar{
		{
			Name: fmt.Sprintf("SERVE_PORT_%d", 80), Value: "foo",
		},
		{
			Name: fmt.Sprintf("SERVE_PORT_%d", 8080), Value: "bar",
		},
	}).WithPorts([]corev1.ContainerPort{
		{
			Name:          "http1",
			ContainerPort: 80,
			Protocol:      corev1.ProtocolTCP,
		},
		{
			Name:          "http2",
			ContainerPort: 8080,
			Protocol:      corev1.ProtocolTCP,
		},
	}).Create(data)
	r.NoError(err, "Error creating test Pod: %v", err)

	nplAnnotations, testPodIP := getNPLAnnotations(t, testData, r, testPodName, nil)

	clientName := randName("test-client-")
	err = testData.createAgnhostPodOnNode(clientName, data.testNamespace, clientNode, false)
	r.NoError(err, "Error when creating AgnhostPod %s", clientName)

	err = testData.podWaitForRunning(defaultTimeout, clientName, data.testNamespace)
	r.NoError(err, "Error when waiting for Pod %s to be running", clientName)

	antreaPod, err := testData.getAntreaPodOnNode(serverNode)
	r.NoError(err, "Error when getting Antrea Agent Pod on Node '%s'", serverNode)

	checkNPLRules(t, testData, r, nplAnnotations, antreaPod, testPodIP, serverNode, true)
	expectedAnnotations.Check(t, nplAnnotations)
	checkTrafficForNPL(testData, r, nplAnnotations, clientName)

	testData.DeletePod(data.testNamespace, clientName)
	testData.DeletePod(data.testNamespace, testPodName)
	testData.DeleteService(data.testNamespace, "agnhost1")
	testData.DeleteService(data.testNamespace, "agnhost2")
	checkNPLRules(t, testData, r, nplAnnotations, antreaPod, testPodIP, serverNode, false)
}

// NPLTestPodAddMultiProtocol tests NodePortLocal functionalities for a Pod using a single port with multiple protocols.
func NPLTestPodAddMultiProtocol(t *testing.T, data *TestData) {
	r := require.New(t)

	clientNode, serverNode := getTwoNodes()
	testPodName := randName("test-pod-")

	annotation := make(map[string]string)
	annotation[types.NPLEnabledAnnotationKey] = "true"
	selector := make(map[string]string)
	selector["app"] = "agnhost"
	ipFamily := corev1.IPv4Protocol
	testData.CreateServiceWithAnnotations("agnhost1", data.testNamespace, 80, 8080, corev1.ProtocolTCP, selector, false, false, corev1.ServiceTypeClusterIP, &ipFamily, annotation)
	testData.CreateServiceWithAnnotations("agnhost2", data.testNamespace, 80, 8080, corev1.ProtocolUDP, selector, false, false, corev1.ServiceTypeClusterIP, &ipFamily, annotation)
	expectedAnnotations := newExpectedNPLAnnotations(defaultStartPort, defaultEndPort).
		Add(nil, 8080, "tcp").Add(nil, 8080, "udp")

	// Creating a Pod using agnhost image to support multiple protocols, instead of nginx.
	cmd := []string{"/bin/bash", "-c"}
	args := []string{
		fmt.Sprintf("/agnhost serve-hostname --udp --http=false --port %d & /agnhost serve-hostname --tcp --http=false --port %d", 8080, 8080),
	}
	port := corev1.ContainerPort{ContainerPort: 8080}
	containerName := fmt.Sprintf("c%v", 8080)
	err := NewPodBuilder(testPodName, data.testNamespace, agnhostImage).OnNode(serverNode).WithContainerName(containerName).WithCommand(cmd).WithArgs(args).WithPorts([]corev1.ContainerPort{port}).WithLabels(selector).Create(testData)
	r.NoError(err, "Error creating test Pod: %v", err)

	nplAnnotations, testPodIP := getNPLAnnotations(t, testData, r, testPodName, nil)

	clientName := randName("test-client-")
	err = testData.createAgnhostPodOnNode(clientName, data.testNamespace, clientNode, false)
	r.NoError(err, "Error when creating AgnhostPod %s", clientName)

	err = testData.podWaitForRunning(defaultTimeout, clientName, data.testNamespace)
	r.NoError(err, "Error when waiting for Pod %s to be running", clientName)

	antreaPod, err := testData.getAntreaPodOnNode(serverNode)
	r.NoError(err, "Error when getting Antrea Agent Pod on Node '%s'", serverNode)

	checkNPLRules(t, testData, r, nplAnnotations, antreaPod, testPodIP, serverNode, true)

	expectedAnnotations.Check(t, nplAnnotations)
	checkTrafficForNPL(testData, r, nplAnnotations, clientName)

	testData.DeletePod(data.testNamespace, clientName)
	testData.DeletePod(data.testNamespace, testPodName)
	testData.DeleteService(data.testNamespace, "agnhost1")
	testData.DeleteService(data.testNamespace, "agnhost2")
	checkNPLRules(t, testData, r, nplAnnotations, antreaPod, testPodIP, serverNode, false)
}

// NPLTestLocalAccess validates that a NodePortLocal Pod can be accessed locally
// from the host network namespace.
func NPLTestLocalAccess(t *testing.T, data *TestData) {
	r := require.New(t)

	annotation := make(map[string]string)
	annotation[types.NPLEnabledAnnotationKey] = "true"
	ipFamily := corev1.IPv4Protocol

	clientNode, serverNode := getTwoNodes()

	testData.createNginxClusterIPServiceWithAnnotations(serverNode, false, &ipFamily, annotation)
	expectedAnnotations := newExpectedNPLAnnotations(defaultStartPort, defaultEndPort).Add(nil, defaultTargetPort, "tcp")

	testPodName := randName("test-pod-")
	err := testData.createNginxPodOnNode(testPodName, data.testNamespace, serverNode, false)
	r.NoError(err, "Error creating test Pod: %v", err)

	clientName := randName("test-client-")
	err = testData.createAgnhostPodOnNode(clientName, data.testNamespace, clientNode, false)
	r.NoError(err, "Error when creating AgnhostPod %s", clientName)

	err = testData.podWaitForRunning(defaultTimeout, clientName, data.testNamespace)
	r.NoError(err, "Error when waiting for Pod %s to be running", clientName)

	antreaPod, err := testData.getAntreaPodOnNode(serverNode)
	r.NoError(err, "Error when getting Antrea Agent Pod on Node '%s'", serverNode)

	nplAnnotations, testPodIP := getNPLAnnotations(t, testData, r, testPodName, nil)

	checkNPLRules(t, testData, r, nplAnnotations, antreaPod, testPodIP, serverNode, true)
	expectedAnnotations.Check(t, nplAnnotations)
	checkTrafficForNPL(testData, r, nplAnnotations, clientName)

	testData.DeletePod(data.testNamespace, testPodName)
	checkNPLRules(t, testData, r, nplAnnotations, antreaPod, testPodIP, serverNode, false)
	testData.DeletePod(data.testNamespace, clientName)
}

// testNPLMultiplePodsAndAgentRestart tests NodePortLocal functionalities after Antrea Agent restarts.
// - Create multiple Nginx Pods.
// - Delete one of the NPL iptables rules.
// - Restart Antrea Agent Pod.
// - Verify Pod Annotation, iptables rules and traffic to test Pod.
func testNPLMultiplePodsAgentRestart(t *testing.T, data *TestData) {
	r := require.New(t)

	annotation := make(map[string]string)
	annotation[types.NPLEnabledAnnotationKey] = "true"
	ipFamily := corev1.IPv4Protocol

	clientNode, serverNode := getTwoNodes()
	data.createNginxClusterIPServiceWithAnnotations(serverNode, false, &ipFamily, annotation)
	var testPods []string
	var err error
	for i := 0; i < 4; i++ {
		testPodName := randName("test-pod-")
		testPods = append(testPods, testPodName)
		err = data.createNginxPodOnNode(testPodName, data.testNamespace, serverNode, false)
		r.NoError(err, "Error creating test Pod: %v", err)
	}

	clientName := randName("test-client-")
	err = data.createAgnhostPodOnNode(clientName, data.testNamespace, clientNode, false)
	r.NoError(err, "Error when creating AgnhostPod %s", clientName)

	err = data.podWaitForRunning(defaultTimeout, clientName, data.testNamespace)
	r.NoError(err, "Error when waiting for Pod %s to be running", clientName)

	antreaPod, err := data.getAntreaPodOnNode(serverNode)
	r.NoError(err, "Error when getting Antrea Agent Pod on Node '%s'", serverNode)

	// Delete one iptables rule to ensure it gets re-installed correctly on restart.
	nplAnnotations, testPodIP := getNPLAnnotations(t, testData, r, testPods[0], nil)
	r.Len(nplAnnotations, 1)
	// Make sure the rule is present first. It should always be the case if the Pod was already
	// annotated.

	checkNPLRules(t, testData, r, nplAnnotations, antreaPod, testPodIP, serverNode, true)
	ruleToDelete := nplRuleData{
		nodeIP:   serverNode,
		nodePort: nplAnnotations[0].NodePort,
		podIP:    testPodIP,
		podPort:  nplAnnotations[0].PodPort,
		protocol: protocolToString(corev1.ProtocolTCP),
	}
	if len(clusterInfo.windowsNodes) > 1 {
		deleteNPLRuleFromNetNat(t, data, r, antreaPod, ruleToDelete)
	} else {
		deleteNPLRuleFromIPTables(t, data, r, antreaPod, ruleToDelete)
	}

	err = data.RestartAntreaAgentPods(defaultTimeout)
	r.NoError(err, "Error when restarting Antrea Agent Pods")

	antreaPod, err = data.getAntreaPodOnNode(serverNode)
	r.NoError(err, "Error when getting Antrea Agent Pod on Node '%s'", serverNode)

	expectedAnnotations := newExpectedNPLAnnotations(defaultStartPort, defaultEndPort).Add(nil, defaultTargetPort, "tcp")
	for _, testPodName := range testPods {
		nplAnnotations, testPodIP := getNPLAnnotations(t, data, r, testPodName, nil)

		checkNPLRules(t, testData, r, nplAnnotations, antreaPod, testPodIP, serverNode, true)
		expectedAnnotations.Check(t, nplAnnotations)
		checkTrafficForNPL(data, r, nplAnnotations, clientName)
		testData.DeletePod(data.testNamespace, testPodName)
	}
	testData.DeletePod(data.testNamespace, clientName)
}

// testNPLChangePortRangeAgentRestart tests NodePortLocal functionalities after changing port range.
// - Create multiple Nginx Pods.
// - Change the PortRange.
// - Restart Antrea Agent Pods.
// - Verify that updated port range is being used for NPL.
func testNPLChangePortRangeAgentRestart(t *testing.T, data *TestData) {
	r := require.New(t)

	annotation := make(map[string]string)
	annotation[types.NPLEnabledAnnotationKey] = "true"
	ipFamily := corev1.IPv4Protocol

	clientNode, serverNode := getTwoNodes()
	data.createNginxClusterIPServiceWithAnnotations(serverNode, false, &ipFamily, annotation)
	var testPods []string
	var err error
	for i := 0; i < 4; i++ {
		testPodName := randName("test-pod-")
		testPods = append(testPods, testPodName)
		err = data.createNginxPodOnNode(testPodName, data.testNamespace, serverNode, false)
		r.NoError(err, "Error Creating test Pod: %v", err)
	}

	clientName := randName("test-client-")
	err = data.createAgnhostPodOnNode(clientName, data.testNamespace, clientNode, false)
	r.NoError(err, "Error when creating AgnhostPod %s", clientName)

	err = data.podWaitForRunning(defaultTimeout, clientName, data.testNamespace)
	r.NoError(err, "Error when waiting for Pod %s to be running", clientName)

	var rules []nplRuleData
	for _, testPodName := range testPods {
		nplAnnotations, testPodIP := getNPLAnnotations(t, data, r, testPodName, nil)
		for i := range nplAnnotations {
			rule := nplRuleData{
				nodePort: nplAnnotations[i].NodePort,
				podIP:    testPodIP,
				podPort:  nplAnnotations[i].PodPort,
				protocol: nplAnnotations[i].Protocol,
			}
			rules = append(rules, rule)
		}
	}
	configureNPLForAgent(t, data, updatedStartPort, updatedEndPort)

	antreaPod, err := data.getAntreaPodOnNode(serverNode)
	r.NoError(err, "Error when getting Antrea Agent Pod on Node '%s'", serverNode)

	expectedAnnotations := newExpectedNPLAnnotations(updatedStartPort, updatedEndPort).Add(nil, defaultTargetPort, "tcp")

	if clusterInfo.nodesOS[serverNode] == "windows" {
		time.Sleep(10 * time.Second)
		checkForNPLRuleInNetNat(t, data, r, antreaPod, serverNode, rules, false)
	} else {
		checkForNPLRuleInIPTables(t, data, r, antreaPod, rules, false)
		checkForNPLListeningSockets(t, data, r, antreaPod, rules, false)
	}

	for _, testPodName := range testPods {
		conditionFn := func(ann types.NPLAnnotation) bool {
			return ann.NodePort >= updatedStartPort
		}
		nplAnnotations, testPodIP := getNPLAnnotations(t, data, r, testPodName, conditionFn)

		checkNPLRules(t, data, r, nplAnnotations, antreaPod, testPodIP, serverNode, true)
		expectedAnnotations.Check(t, nplAnnotations)
		checkTrafficForNPL(data, r, nplAnnotations, clientName)
		testData.DeletePod(data.testNamespace, testPodName)
	}
	testData.DeletePod(data.testNamespace, clientName)
}
