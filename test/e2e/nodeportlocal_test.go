//go:build !windows
// +build !windows

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
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"

	"antrea.io/antrea/pkg/agent/nodeportlocal/k8s"
)

const (
	defaultStartPort   = 61000
	defaultEndPort     = 62000
	updatedStartPort   = 63000
	updatedEndPort     = 64000
	defaultTargetPort  = 80
	defaultProtocolTCP = corev1.ProtocolTCP
	svcProtocolUDP     = corev1.ProtocolUDP
)

type nplRuleData struct {
	nodePort int
	podPort  int
	podIP    string
	protocol string
}

// TestNodePortLocal is the top-level test which contains all subtests for
// NodePortLocal related test cases so they can share setup, teardown.
func TestNodePortLocal(t *testing.T) {
	skipIfNotIPv4Cluster(t)
	skipIfHasWindowsNodes(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
	t.Run("testNPLAddPod", func(t *testing.T) { testNPLAddPod(t, data) })
	t.Run("testNPLMultiplePodsAgentRestart", func(t *testing.T) { testNPLMultiplePodsAgentRestart(t, data) })
	t.Run("testNPLChangePortRangeAgentRestart", func(t *testing.T) { testNPLChangePortRangeAgentRestart(t, data) })
}

func getNPLAnnotation(t *testing.T, data *TestData, r *require.Assertions, testPodName string) (string, string) {
	var nplAnn string
	var testPodIP *PodIPs
	var found bool

	_, err := data.podWaitFor(defaultTimeout, testPodName, testNamespace, func(pod *corev1.Pod) (bool, error) {
		var err error
		if pod.Status.Phase != corev1.PodRunning {
			return false, nil
		}

		podIPStrings := sets.NewString(pod.Status.PodIP)
		for _, podIP := range pod.Status.PodIPs {
			ipStr := strings.TrimSpace(podIP.IP)
			if ipStr != "" {
				podIPStrings.Insert(ipStr)
			}
		}

		testPodIP, err = parsePodIPs(podIPStrings)
		if err != nil || testPodIP.ipv4 == nil {
			return false, nil
		}

		ann := pod.GetAnnotations()
		t.Logf("Got annotations %v for Pod with IP %v", ann, testPodIP.ipv4.String())
		nplAnn, found = ann[k8s.NPLAnnotationKey]
		return found, nil
	})
	r.NoError(err, "Poll for Pod check failed")
	return nplAnn, testPodIP.ipv4.String()
}

func getNPLAnnotations(t *testing.T, data *TestData, r *require.Assertions, testPodName string) ([]k8s.NPLAnnotation, string) {
	nplAnnotationString, testPodIP := getNPLAnnotation(t, data, r, testPodName)
	var nplAnnotations []k8s.NPLAnnotation
	json.Unmarshal([]byte(nplAnnotationString), &nplAnnotations)
	return nplAnnotations, testPodIP
}

func checkNPLRulesForPod(t *testing.T, data *TestData, r *require.Assertions, nplAnnotations []k8s.NPLAnnotation, antreaPod, podIP string, present bool) {
	var rules []nplRuleData
	for _, ann := range nplAnnotations {
		for _, protocol := range ann.Protocols {
			rule := nplRuleData{
				nodePort: ann.NodePort,
				podIP:    podIP,
				podPort:  ann.PodPort,
				protocol: protocol,
			}
			rules = append(rules, rule)
		}
	}
	checkForNPLRuleInIPTables(t, data, r, antreaPod, rules, present)
	checkForNPLListeningSockets(t, data, r, antreaPod, rules, present)
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
	t.Logf("Verifying iptables rules %v", rules)
	const timeout = 30 * time.Second
	err := wait.Poll(time.Second, timeout, func() (bool, error) {
		stdout, _, err := data.runCommandFromPod(antreaNamespace, antreaPod, agentContainerName, cmd)
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

func checkForNPLListeningSockets(t *testing.T, data *TestData, r *require.Assertions, antreaPod string, rules []nplRuleData, present bool) {
	t.Logf("Verifying NPL listening sockets")
	const timeout = 30 * time.Second
	err := wait.Poll(time.Second, timeout, func() (bool, error) {
		for _, rule := range rules {
			protocolOption := "--" + rule.protocol
			cmd := []string{"ss", "--listening", protocolOption, "-H", "-n"}
			stdout, _, err := data.runCommandFromPod(antreaNamespace, antreaPod, agentContainerName, cmd)
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
	const timeout = 30 * time.Second
	_, _, err := data.runCommandFromPod(antreaNamespace, antreaPod, agentContainerName, cmd)
	r.NoError(err, "Error when deleting iptables rule")
}

func checkTrafficForNPL(data *TestData, r *require.Assertions, nplAnnotations []k8s.NPLAnnotation, clientName string) {
	for i := range nplAnnotations {
		for j := range nplAnnotations[i].Protocols {
			err := data.runNetcatCommandFromTestPodWithProtocol(clientName, testNamespace, nplAnnotations[i].NodeIP, int32(nplAnnotations[i].NodePort), nplAnnotations[i].Protocols[j])
			r.NoError(err, "Traffic test failed for NodeIP: %s, NodePort: %d, Protocol: %s", nplAnnotations[i].NodeIP, nplAnnotations[i].NodePort, nplAnnotations[i].Protocols[j])
		}
	}
}

func enableNPLInConfigmap(t *testing.T, data *TestData) {
	ac := []configChange{
		{"NodePortLocal", "true", true},
		{"nplPortRange", fmt.Sprintf("%d-%d", defaultStartPort, defaultEndPort), false},
	}
	if err := data.mutateAntreaConfigMap(nil, ac, false, true); err != nil {
		t.Fatalf("Failed to enable NodePortLocal feature: %v", err)
	}
}

func updateNPLPortRangeInConfigmap(t *testing.T, data *TestData, newStartPort, newEndPort int) {
	ac := []configChange{
		{"nplPortRange", fmt.Sprintf("%d-%d", newStartPort, newEndPort), false},
	}
	if err := data.mutateAntreaConfigMap(nil, ac, false, true); err != nil {
		t.Fatalf("Failed to update NodePortLocal port range: %v", err)
	}
}

func validatePortsInAnnotation(t *testing.T, r *require.Assertions, nplAnnotations []k8s.NPLAnnotation, start, end int, targetPortsProtocolsProtocols map[int]sets.String) {
	require.Equal(t, len(targetPortsProtocolsProtocols), len(nplAnnotations))
	for i := range nplAnnotations {
		podPort := nplAnnotations[i].PodPort
		protocols := sets.NewString(nplAnnotations[i].Protocols...)
		targetProtocols, podPortInTargetPort := targetPortsProtocolsProtocols[podPort]
		r.True(podPortInTargetPort, "Port %d in Pod annotation not found in set target ports :%v from Services", podPort, targetPortsProtocolsProtocols)
		r.True(protocols.Equal(targetProtocols), "Protocols %v in Pod annotation not found in set target protocols :%v from Services", protocols, targetProtocols)
		delete(targetPortsProtocolsProtocols, podPort)

		nodePort := nplAnnotations[i].NodePort
		if nodePort > end || nodePort < start {
			t.Fatalf("Node port %d not in range: %d - %d", nodePort, start, end)
		}
	}
	r.Emptyf(targetPortsProtocolsProtocols, "Target ports %v not found in Pod annotation", targetPortsProtocolsProtocols)
}

func testNPLAddPod(t *testing.T, data *TestData) {
	enableNPLInConfigmap(t, data)
	t.Run("NPLTestMultiplePods", NPLTestMultiplePods)
	t.Run("NPLTestPodAddMultiPort", NPLTestPodAddMultiPort)
	t.Run("NPLTestPodAddMultiProtocol", NPLTestPodAddMultiProtocol)
	t.Run("NPLTestLocalAccess", NPLTestLocalAccess)
}

// NPLTestMultiplePods tests NodePortLocal functionalities after adding multiple Pods.
// - Create a Service with nginx Pods.
// - Verify that the required NodePortLocal annotation is added in each test Pod.
// - Make sure iptables rules are correctly added in the Node from Antrea Agent Pod.
// - Create a client Pod and test traffic through netcat.
// - Delete the nginx test Pods and verify that the iptables rules are deleted.
func NPLTestMultiplePods(t *testing.T) {
	r := require.New(t)

	annotation := make(map[string]string)
	annotation[k8s.NPLEnabledAnnotationKey] = "true"
	ipFamily := corev1.IPv4Protocol
	testData.createNginxClusterIPServiceWithAnnotations(false, &ipFamily, annotation)
	node := nodeName(0)
	var testPods []string

	for i := 0; i < 4; i++ {
		testPodName := randName("test-pod-")
		testPods = append(testPods, testPodName)
		err := testData.createNginxPodOnNode(testPodName, testNamespace, node, false)
		r.NoError(err, "Error creating test Pod: %v", err)
	}

	clientName := randName("test-client-")
	err := testData.createBusyboxPodOnNode(clientName, testNamespace, node, false)
	r.NoError(err, "Error creating Pod %s: %v", clientName)

	err = testData.podWaitForRunning(defaultTimeout, clientName, testNamespace)
	r.NoError(err, "Error when waiting for Pod %s to be running", clientName)

	antreaPod, err := testData.getAntreaPodOnNode(node)
	r.NoError(err, "Error when getting Antrea Agent Pod on Node '%s'", node)

	targetProtocols := sets.NewString(protocolToString(defaultProtocolTCP))
	for _, testPodName := range testPods {
		targetPortsProtocolsProtocols := map[int]sets.String{defaultTargetPort: targetProtocols}
		nplAnnotations, testPodIP := getNPLAnnotations(t, testData, r, testPodName)

		checkNPLRulesForPod(t, testData, r, nplAnnotations, antreaPod, testPodIP, true)
		validatePortsInAnnotation(t, r, nplAnnotations, defaultStartPort, defaultEndPort, targetPortsProtocolsProtocols)
		checkTrafficForNPL(testData, r, nplAnnotations, clientName)

		testData.deletePod(testNamespace, testPodName)
		checkNPLRulesForPod(t, testData, r, nplAnnotations, antreaPod, testPodIP, false)
	}
}

// NPLTestPodAddMultiPort tests NodePortLocal functionalities for a Pod with multiple ports.
func NPLTestPodAddMultiPort(t *testing.T) {
	r := require.New(t)

	node := nodeName(0)
	testPodName := randName("test-pod-")

	annotation := make(map[string]string)
	annotation[k8s.NPLEnabledAnnotationKey] = "true"
	selector := make(map[string]string)
	selector["app"] = "agnhost"
	ipFamily := corev1.IPv4Protocol
	testData.createServiceWithAnnotations("agnhost1", 80, 80, defaultProtocolTCP, selector, false, corev1.ServiceTypeClusterIP, &ipFamily, annotation)
	testData.createServiceWithAnnotations("agnhost2", 80, 8080, defaultProtocolTCP, selector, false, corev1.ServiceTypeClusterIP, &ipFamily, annotation)
	targetProtocols := sets.NewString(protocolToString(defaultProtocolTCP))
	targetPortsProtocols := map[int]sets.String{80: targetProtocols, 8080: targetProtocols}

	podcmd := "porter"

	// Creating a Pod using agnhost image to support multiple ports, instead of nginx.
	err := testData.createPodOnNode(testPodName, testNamespace, node, agnhostImage, nil, []string{podcmd}, []corev1.EnvVar{
		{
			Name: fmt.Sprintf("SERVE_PORT_%d", 80), Value: "foo",
		},
		{
			Name: fmt.Sprintf("SERVE_PORT_%d", 8080), Value: "bar",
		},
	}, []corev1.ContainerPort{
		{
			Name:          "http1",
			ContainerPort: 80,
			Protocol:      defaultProtocolTCP,
		},
		{
			Name:          "http2",
			ContainerPort: 8080,
			Protocol:      defaultProtocolTCP,
		},
	}, false, nil)

	r.NoError(err, "Error creating test Pod: %v", err)

	nplAnnotations, testPodIP := getNPLAnnotations(t, testData, r, testPodName)

	clientName := randName("test-client-")
	err = testData.createBusyboxPodOnNode(clientName, testNamespace, node, false)
	r.NoError(err, "Error when creating Pod %s", clientName)

	err = testData.podWaitForRunning(defaultTimeout, clientName, testNamespace)
	r.NoError(err, "Error when waiting for Pod %s to be running", clientName)

	antreaPod, err := testData.getAntreaPodOnNode(node)
	r.NoError(err, "Error when getting Antrea Agent Pod on Node '%s'", node)

	checkNPLRulesForPod(t, testData, r, nplAnnotations, antreaPod, testPodIP, true)
	validatePortsInAnnotation(t, r, nplAnnotations, defaultStartPort, defaultEndPort, targetPortsProtocols)
	checkTrafficForNPL(testData, r, nplAnnotations, clientName)

	testData.deletePod(testNamespace, testPodName)
	testData.deleteService("agnhost1")
	testData.deleteService("agnhost2")
	checkNPLRulesForPod(t, testData, r, nplAnnotations, antreaPod, testPodIP, false)
}

// NPLTestPodAddMultiProtocol tests NodePortLocal functionalities for a Pod with single port multiple protocols.
func NPLTestPodAddMultiProtocol(t *testing.T) {
	r := require.New(t)

	node := nodeName(0)
	testPodName := randName("test-pod-")

	annotation := make(map[string]string)
	annotation[k8s.NPLEnabledAnnotationKey] = "true"
	selector := make(map[string]string)
	selector["app"] = "agnhost"
	ipFamily := corev1.IPv4Protocol
	testData.createServiceWithAnnotations("agnhost1", 80, 8080, defaultProtocolTCP, selector, false, corev1.ServiceTypeClusterIP, &ipFamily, annotation)
	testData.createServiceWithAnnotations("agnhost2", 80, 8080, svcProtocolUDP, selector, false, corev1.ServiceTypeClusterIP, &ipFamily, annotation)
	targetProtocols := sets.NewString(protocolToString(defaultProtocolTCP), protocolToString(svcProtocolUDP))
	targetPortsProtocols := map[int]sets.String{8080: targetProtocols}

	// Creating a Pod using agnhost image to support multiple protocols, instead of nginx.
	cmd := []string{"/bin/bash", "-c"}
	args := []string{
		fmt.Sprintf("/agnhost serve-hostname --udp --http=false --port %d & /agnhost serve-hostname --tcp --http=false --port %d", 8080, 8080),
	}
	image := "k8s.gcr.io/e2e-test-images/agnhost:2.29"
	env := corev1.EnvVar{Name: fmt.Sprintf("SERVE_SCTP_PORT_%d", 8080), Value: "foo"}
	port := corev1.ContainerPort{ContainerPort: 8080}
	containerName := fmt.Sprintf("c%v", 8080)
	mutateLabels := func(pod *corev1.Pod) {
		for k, v := range selector {
			pod.Labels[k] = v
		}
	}
	err := testData.createPodOnNodeInNamespace(testPodName, testNamespace, node, containerName, image, cmd, args, []corev1.EnvVar{env}, []corev1.ContainerPort{port}, false, mutateLabels)

	r.NoError(err, "Error creating test Pod: %v", err)

	nplAnnotations, testPodIP := getNPLAnnotations(t, testData, r, testPodName)

	clientName := randName("test-client-")
	err = testData.createBusyboxPodOnNode(clientName, testNamespace, node, false)
	r.NoError(err, "Error when creating Pod %s", clientName)

	err = testData.podWaitForRunning(defaultTimeout, clientName, testNamespace)
	r.NoError(err, "Error when waiting for Pod %s to be running", clientName)

	antreaPod, err := testData.getAntreaPodOnNode(node)
	r.NoError(err, "Error when getting Antrea Agent Pod on Node '%s'", node)

	checkNPLRulesForPod(t, testData, r, nplAnnotations, antreaPod, testPodIP, true)
	validatePortsInAnnotation(t, r, nplAnnotations, defaultStartPort, defaultEndPort, targetPortsProtocols)
	checkTrafficForNPL(testData, r, nplAnnotations, clientName)

	testData.deletePod(testNamespace, testPodName)
	testData.deleteService("agnhost1")
	testData.deleteService("agnhost2")
	checkNPLRulesForPod(t, testData, r, nplAnnotations, antreaPod, testPodIP, false)
}

// NPLTestLocalAccess validates that a NodePortLocal Pod can be accessed locally
// from the host network namespace.
func NPLTestLocalAccess(t *testing.T) {
	r := require.New(t)

	annotation := make(map[string]string)
	annotation[k8s.NPLEnabledAnnotationKey] = "true"
	ipFamily := corev1.IPv4Protocol
	testData.createNginxClusterIPServiceWithAnnotations(false, &ipFamily, annotation)
	targetProtocols := sets.NewString(protocolToString(defaultProtocolTCP))
	targetPortsProtocols := map[int]sets.String{defaultTargetPort: targetProtocols}

	node := nodeName(0)

	testPodName := randName("test-pod-")
	err := testData.createNginxPodOnNode(testPodName, testNamespace, node, false)
	r.NoError(err, "Error creating test Pod: %v", err)

	clientName := randName("test-client-")
	err = testData.createBusyboxPodOnNode(clientName, testNamespace, node, true)
	r.NoError(err, "Error creating hostNetwork Pod %s: %v", clientName)

	err = testData.podWaitForRunning(defaultTimeout, clientName, testNamespace)
	r.NoError(err, "Error when waiting for Pod %s to be running", clientName)

	antreaPod, err := testData.getAntreaPodOnNode(node)
	r.NoError(err, "Error when getting Antrea Agent Pod on Node '%s'", node)

	nplAnnotations, testPodIP := getNPLAnnotations(t, testData, r, testPodName)

	checkNPLRulesForPod(t, testData, r, nplAnnotations, antreaPod, testPodIP, true)
	validatePortsInAnnotation(t, r, nplAnnotations, defaultStartPort, defaultEndPort, targetPortsProtocols)
	checkTrafficForNPL(testData, r, nplAnnotations, clientName)

	testData.deletePod(testNamespace, testPodName)
	checkNPLRulesForPod(t, testData, r, nplAnnotations, antreaPod, testPodIP, false)
}

// testNPLMultiplePodsAndAgentRestart tests NodePortLocal functionalities after Antrea Agent restarts.
// - Create multiple Nginx Pods.
// - Delete one of the NPL iptables rules.
// - Restart Antrea Agent Pod.
// - Verify Pod Annotation, iptables rules and traffic to test Pod.
func testNPLMultiplePodsAgentRestart(t *testing.T, data *TestData) {
	enableNPLInConfigmap(t, data)
	r := require.New(t)

	annotation := make(map[string]string)
	annotation[k8s.NPLEnabledAnnotationKey] = "true"
	ipFamily := corev1.IPv4Protocol
	data.createNginxClusterIPServiceWithAnnotations(false, &ipFamily, annotation)

	node := nodeName(0)
	var testPods []string
	var err error
	for i := 0; i < 4; i++ {
		testPodName := randName("test-pod-")
		testPods = append(testPods, testPodName)
		err = data.createNginxPodOnNode(testPodName, testNamespace, node, false)
		r.NoError(err, "Error creating test Pod: %v", err)
	}

	clientName := randName("test-client-")
	err = data.createBusyboxPodOnNode(clientName, testNamespace, node, false)
	r.NoError(err, "Error when creating Pod %s", clientName)

	err = data.podWaitForRunning(defaultTimeout, clientName, testNamespace)
	r.NoError(err, "Error when waiting for Pod %s to be running", clientName)

	antreaPod, err := data.getAntreaPodOnNode(node)
	r.NoError(err, "Error when getting Antrea Agent Pod on Node '%s'", node)

	// Delete one iptables rule to ensure it gets re-installed correctly on restart.
	nplAnnotations, testPodIP := getNPLAnnotations(t, testData, r, testPods[0])
	r.Len(nplAnnotations, 1)
	// Make sure the rule is present first. It should always be the case if the Pod was already
	// annotated.
	checkNPLRulesForPod(t, data, r, nplAnnotations, antreaPod, testPodIP, true)
	ruleToDelete := nplRuleData{
		nodePort: nplAnnotations[0].NodePort,
		podIP:    testPodIP,
		podPort:  nplAnnotations[0].PodPort,
		protocol: protocolToString(defaultProtocolTCP),
	}
	deleteNPLRuleFromIPTables(t, data, r, antreaPod, ruleToDelete)

	err = data.restartAntreaAgentPods(defaultTimeout)
	r.NoError(err, "Error when restarting Antrea Agent Pods")

	antreaPod, err = data.getAntreaPodOnNode(node)
	r.NoError(err, "Error when getting Antrea Agent Pod on Node '%s'", node)

	targetProtocols := sets.NewString(protocolToString(defaultProtocolTCP))
	for _, testPodName := range testPods {
		targetPortsProtocols := map[int]sets.String{defaultTargetPort: targetProtocols}
		nplAnnotations, testPodIP := getNPLAnnotations(t, data, r, testPodName)

		checkNPLRulesForPod(t, data, r, nplAnnotations, antreaPod, testPodIP, true)
		validatePortsInAnnotation(t, r, nplAnnotations, defaultStartPort, defaultEndPort, targetPortsProtocols)
		checkTrafficForNPL(data, r, nplAnnotations, clientName)
	}

}

// testNPLChangePortRangeAgentRestart tests NodePortLocal functionalities after changing port range.
// - Create multiple Nginx Pods.
// - Change nplPortRange.
// - Restart Antrea Agent Pods.
// - Verify that updated port range is being used for NPL.
func testNPLChangePortRangeAgentRestart(t *testing.T, data *TestData) {
	enableNPLInConfigmap(t, data)
	r := require.New(t)

	annotation := make(map[string]string)
	annotation[k8s.NPLEnabledAnnotationKey] = "true"
	ipFamily := corev1.IPv4Protocol
	data.createNginxClusterIPServiceWithAnnotations(false, &ipFamily, annotation)

	node := nodeName(0)
	var testPods []string
	var err error
	for i := 0; i < 4; i++ {
		testPodName := randName("test-pod-")
		testPods = append(testPods, testPodName)
		err = data.createNginxPodOnNode(testPodName, testNamespace, node, false)
		r.NoError(err, "Error Creating test Pod: %v", err)
	}

	clientName := randName("test-client-")
	err = data.createBusyboxPodOnNode(clientName, testNamespace, node, false)
	r.NoError(err, "Error when creating Pod %s", clientName)

	err = data.podWaitForRunning(defaultTimeout, clientName, testNamespace)
	r.NoError(err, "Error when waiting for Pod %s to be running", clientName)

	var rules []nplRuleData
	for _, testPodName := range testPods {
		nplAnnotations, testPodIP := getNPLAnnotations(t, data, r, testPodName)
		for i := range nplAnnotations {
			for j := range nplAnnotations[i].Protocols {
				rule := nplRuleData{
					nodePort: nplAnnotations[i].NodePort,
					podIP:    testPodIP,
					podPort:  nplAnnotations[i].PodPort,
					protocol: nplAnnotations[i].Protocols[j],
				}
				rules = append(rules, rule)
			}
		}
	}

	updateNPLPortRangeInConfigmap(t, data, updatedStartPort, updatedEndPort)

	antreaPod, err := data.getAntreaPodOnNode(node)
	r.NoError(err, "Error when getting Antrea Agent Pod on Node '%s'", node)

	targetProtocols := sets.NewString(protocolToString(defaultProtocolTCP))
	for _, testPodName := range testPods {
		targetPortsProtocols := map[int]sets.String{defaultTargetPort: targetProtocols}
		nplAnnotations, testPodIP := getNPLAnnotations(t, data, r, testPodName)

		checkNPLRulesForPod(t, data, r, nplAnnotations, antreaPod, testPodIP, true)
		validatePortsInAnnotation(t, r, nplAnnotations, updatedStartPort, updatedEndPort, targetPortsProtocols)
		checkTrafficForNPL(data, r, nplAnnotations, clientName)
	}

	checkForNPLRuleInIPTables(t, data, r, antreaPod, rules, false)
	checkForNPLListeningSockets(t, data, r, antreaPod, rules, false)
}
