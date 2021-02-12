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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/vmware-tanzu/antrea/pkg/agent/nodeportlocal/k8s"
)

const (
	defaultStartPort = 40000
	defaultEndPort   = 41000
	updatedStartPort = 42000
	updatedEndPort   = 43000
	nplSvcAnnotation = "nodeportlocal.antrea.io/enabled"
)

func getNPLAnnotation(t *testing.T, data *TestData, r *require.Assertions, testPodName string) (string, *PodIPs) {
	var nplAnn string
	var testPodIP *PodIPs
	var found bool
	var err error
	err = wait.Poll(time.Second, defaultTimeout, func() (bool, error) {
		updatedPod, _ := data.podWaitFor(defaultTimeout, testPodName, testNamespace, func(pod *corev1.Pod) (bool, error) {
			return pod.Status.Phase == corev1.PodRunning, nil
		})
		testPodIP, err = data.podWaitForIPs(defaultTimeout, testPodName, testNamespace)
		if err != nil {
			t.Logf("Error when waiting for IP for Pod '%s': %v", testPodName, err)
			return false, nil
		}
		r.Nil(err, "Failed to get Pod")
		ann := updatedPod.GetAnnotations()
		t.Logf("Got annotation %v for pod IP %v", ann, testPodIP.ipv4.String())
		nplAnn, found = ann[k8s.NPLAnnotationKey]
		return found, nil
	})
	r.Nil(err, "Poll for Pod Annotation check failed: %v", err)
	return nplAnn, testPodIP
}

func checkForNPLRuleInIPTABLES(t *testing.T, data *TestData, r *require.Assertions, nplAnnotation []k8s.NPLAnnotation, antreaPod, podIP string, present bool) {
	cmd := []string{"iptables", "-t", "nat", "-S"}
	t.Logf("Verifying %d annotations for Pod IP: %s", len(nplAnnotation), podIP)
	err := wait.Poll(time.Second, defaultTimeout, func() (bool, error) {
		stdout, _, err := data.runCommandFromPod("kube-system", antreaPod, "antrea-agent", cmd)
		if err != nil {
			t.Logf("Error while checking rules in IPTABLES: %v", err)
			// In case of error, retry
			return false, nil
		}
		for i := range nplAnnotation {
			ruleSpec := []string{
				"-p", "tcp", "-m", "tcp", "--dport",
				fmt.Sprint(nplAnnotation[i].NodePort), "-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", podIP, nplAnnotation[i].PodPort),
			}
			rs := strings.Join(append([]string{"-A", "ANTREA-NODE-PORT-LOCAL"}, ruleSpec...), " ")
			t.Logf("Searching for IPTABLES rule: %v", rs)

			if strings.Contains(stdout, rs) && present {
				t.Logf("Found rule in IPTABLES")
			} else if !strings.Contains(stdout, rs) && !present {
				t.Logf("Rule not found in IPTABLES")
			} else {
				return false, nil
			}
		}
		return true, nil
	})
	r.Nil(err, "Poll for IPTABLES rules check failed")
}

func checkTrafficForNPL(t *testing.T, data *TestData, r *require.Assertions, nplAnnotation []k8s.NPLAnnotation, clientName string) {
	err := wait.Poll(time.Second, defaultTimeout, func() (bool, error) {
		for i := range nplAnnotation {
			err := data.runNetcatCommandFromTestPod(clientName, nplAnnotation[i].NodeIP, nplAnnotation[i].NodePort)
			if err != nil {
				t.Logf("Traffic test failed with error: %v", err)
				return false, nil
			}
		}
		return true, nil
	})
	r.Nil(err, "Poll for traffic check failed: %v", err)
}

func enableNPLInConfigmap(t *testing.T, data *TestData) {
	if err := data.mutateAntreaConfigMap(func(data map[string]string) {
		antreaAgentConf, _ := data["antrea-agent.conf"]
		antreaAgentConf = strings.Replace(antreaAgentConf, "#  NodePortLocal: false", "  NodePortLocal: true", 1)
		antreaAgentConf = strings.Replace(antreaAgentConf, "#nplPortRange: 40000-41000", "nplPortRange: 40000-41000", 1)
		t.Logf("Updated antreaAgentConf after enabling NodePortLocal: %v", antreaAgentConf)
		data["antrea-agent.conf"] = antreaAgentConf
	}, false, true); err != nil {
		t.Fatalf("Failed to enable NodePortLocal feature: %v", err)
	}
}

func updateNPLPortRangeInConfigmap(t *testing.T, data *TestData, oldStartPort, oldEndPort, newStartPort, newEndPort int) {
	if err := data.mutateAntreaConfigMap(func(data map[string]string) {
		antreaAgentConf, _ := data["antrea-agent.conf"]
		oldPortRange := fmt.Sprintf("nplPortRange: %d-%d", oldStartPort, oldEndPort)
		newPortRange := fmt.Sprintf("nplPortRange: %d-%d", newStartPort, newEndPort)
		antreaAgentConf = strings.Replace(antreaAgentConf, oldPortRange, newPortRange, 1)
		t.Logf("Updated antreaAgentConf after updating port range for NodePortLocal: %v", antreaAgentConf)
		data["antrea-agent.conf"] = antreaAgentConf
	}, false, true); err != nil {
		t.Fatalf("Failed to update NodePortLocal port range: %v", err)
	}
}

func validatePortInRange(t *testing.T, nplAnnotations []k8s.NPLAnnotation, start, end int) {
	for i := range nplAnnotations {
		if nplAnnotations[i].NodePort > end || nplAnnotations[i].NodePort < start {
			t.Fatalf("Node port %d not in range: %d - %d", nplAnnotations[i].NodePort, start, end)
		}
	}
}

var nplTestData *TestData

func TestNPLAddPod(t *testing.T) {
	skipIfNotIPv4Cluster(t)
	var err error
	nplTestData, err = setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, nplTestData)
	enableNPLInConfigmap(t, nplTestData)
	t.Run("NPLTestMultiplePods", NPLTestMultiplePods)
	t.Run("NPLTestPodAddMultiPort", NPLTestPodAddMultiPort)
}

// NPLTestMultiplePods tests NodePortLocal functionalities after adding multiple Pods.
// - Enable NodePortLocal if not already enabled.
// - Create a Service nginx test Pods.
// - Verify that the required NodePortLocal annoation is added in each test Pod.
// - Make sure IPTABLES rules are correctly added in the Node from Antrea Agent Pod.
// - Create a client Pod and test traffic through netcat.
// - Delete the nginx test Pods and verify that the IPTABLES rules are deleted.
func NPLTestMultiplePods(t *testing.T) {
	r := require.New(t)

	annotation := make(map[string]string)
	annotation[nplSvcAnnotation] = "true"
	ipFamily := corev1.IPv4Protocol
	nplTestData.createNginxClusterIPServiceWithAnnotation(false, &ipFamily, annotation)

	node := nodeName(0)
	var testPods []string

	for i := 0; i < 4; i++ {
		testPodName := randName("test-pod-")
		testPods = append(testPods, testPodName)
		err := nplTestData.createNginxPod(testPodName, node)
		r.Nil(err, "Error creating test Pod: %v", err)
	}

	clientName := randName("test-client-")
	if err := nplTestData.createBusyboxPodOnNode(clientName, node); err != nil {
		t.Fatalf("Error creating Pod %s: %v", clientName, err)
	}

	_, err := nplTestData.podWaitForIPs(defaultTimeout, clientName, testNamespace)
	r.Nil(err, "Error when waiting for IP for Pod '%s'", clientName)

	antreaPod, err := nplTestData.getAntreaPodOnNode(node)
	r.Nil(err, "Error when getting Antrea Agent Pod on Node '%s'", node)

	for _, testPodName := range testPods {
		nplAnnotationString, testPodIP := getNPLAnnotation(t, nplTestData, r, testPodName)
		var nplAnnotations []k8s.NPLAnnotation
		json.Unmarshal([]byte(nplAnnotationString), &nplAnnotations)

		checkForNPLRuleInIPTABLES(t, nplTestData, r, nplAnnotations, antreaPod, testPodIP.ipv4.String(), true)
		validatePortInRange(t, nplAnnotations, defaultStartPort, defaultEndPort)
		checkTrafficForNPL(t, nplTestData, r, nplAnnotations, clientName)

		nplTestData.deletePod(testPodName)
		checkForNPLRuleInIPTABLES(t, nplTestData, r, nplAnnotations, antreaPod, testPodIP.ipv4.String(), false)
	}
}

// NPLTestPodAddMultiPort tests NodePortLocal functionalities for a Pod with multiple ports.
func NPLTestPodAddMultiPort(t *testing.T) {
	r := require.New(t)

	node := nodeName(0)
	testPodName := randName("test-pod-")

	annotation := make(map[string]string)
	annotation[nplSvcAnnotation] = "true"
	selector := make(map[string]string)
	selector["app"] = "agnhost"
	ipFamily := corev1.IPv4Protocol
	nplTestData.createServiceWithAnnotation("agnhost", 80, 80, selector, false, corev1.ServiceTypeClusterIP, &ipFamily, annotation)

	podcmd := "porter"

	// Creating a Pod using agnhost image to support multiple ports, instead of nginx.
	err := nplTestData.createPodOnNode(testPodName, node, agnhostImage, nil, []string{podcmd}, []corev1.EnvVar{
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
			Protocol:      corev1.ProtocolTCP,
		},
		{
			Name:          "http2",
			ContainerPort: 8080,
			Protocol:      corev1.ProtocolTCP,
		},
	}, false, nil)

	r.Nil(err, "Error Creating test Pod: %v", err)

	nplAnnotationString, testPodIP := getNPLAnnotation(t, nplTestData, r, testPodName)

	var nplAnnotations []k8s.NPLAnnotation
	json.Unmarshal([]byte(nplAnnotationString), &nplAnnotations)

	clientName := randName("test-client-")
	if err := nplTestData.createBusyboxPodOnNode(clientName, node); err != nil {
		t.Fatalf("Error when creating Pod '%s': %v", clientName, err)
	}

	_, err = nplTestData.podWaitForIPs(defaultTimeout, clientName, testNamespace)
	if err != nil {
		t.Fatalf("Error when waiting for IP for Pod '%s': %v", clientName, err)
	}

	antreaPod, err := nplTestData.getAntreaPodOnNode(node)
	r.Nil(err, "Error when getting Antrea Agent Pod on Node '%s'", node)

	checkForNPLRuleInIPTABLES(t, nplTestData, r, nplAnnotations, antreaPod, testPodIP.ipv4.String(), true)
	validatePortInRange(t, nplAnnotations, defaultStartPort, defaultEndPort)
	checkTrafficForNPL(t, nplTestData, r, nplAnnotations, clientName)

	nplTestData.deletePod(testPodName)
	checkForNPLRuleInIPTABLES(t, nplTestData, r, nplAnnotations, antreaPod, testPodIP.ipv4.String(), false)
}

// TestNPLMultiplePodsAndAgentRestart tests NodePortLocal functionalities after Antrea Agent restart.
// - Create Multiple Nginx Pods.
// - Restart Antrea Agent Pods.
// - Verify Pod Annotation, IPTABLES rules and traffic to test Pod.
func TestNPLMultiplePodsAgentRestart(t *testing.T) {
	skipIfNotIPv4Cluster(t)
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
	enableNPLInConfigmap(t, data)
	r := require.New(t)

	annotation := make(map[string]string)
	annotation[nplSvcAnnotation] = "true"
	ipFamily := corev1.IPv4Protocol
	data.createNginxClusterIPServiceWithAnnotation(false, &ipFamily, annotation)

	node := nodeName(0)
	var testPods []string

	for i := 0; i < 4; i++ {
		testPodName := randName("test-pod-")
		testPods = append(testPods, testPodName)
		err = data.createNginxPod(testPodName, node)
		r.Nil(err, "Error Creating test Pod: %v", err)
	}

	clientName := randName("test-client-")
	if err := data.createBusyboxPodOnNode(clientName, node); err != nil {
		t.Fatalf("Error when creating Pod '%s': %v", clientName, err)
	}
	_, err = data.podWaitForIPs(defaultTimeout, clientName, testNamespace)
	if err != nil {
		t.Fatalf("Error when waiting for IP for Pod '%s': %v", clientName, err)
	}

	if err := data.restartAntreaAgentPods(defaultTimeout); err != nil {
		t.Fatalf("Error when restarting Antrea: %v", err)
	}

	antreaPod, err := data.getAntreaPodOnNode(node)
	r.Nil(err, "Error when getting Antrea Agent Pod on Node '%s'", node)

	for _, testPodName := range testPods {
		nplAnnotationString, testPodIP := getNPLAnnotation(t, data, r, testPodName)
		var nplAnnotations []k8s.NPLAnnotation
		json.Unmarshal([]byte(nplAnnotationString), &nplAnnotations)

		checkForNPLRuleInIPTABLES(t, data, r, nplAnnotations, antreaPod, testPodIP.ipv4.String(), true)
		validatePortInRange(t, nplAnnotations, defaultStartPort, defaultEndPort)
		checkTrafficForNPL(t, data, r, nplAnnotations, clientName)

		data.deletePod(testPodName)
		checkForNPLRuleInIPTABLES(t, data, r, nplAnnotations, antreaPod, testPodIP.ipv4.String(), false)
	}

}

// TestNPLChangePortRangeAgentRestart tests NodePortLocal functionalities after changing port range.
// - Create Multiple Nginx Pods.
// - Change nplPortRange.
// - Restart Antrea Agent Pods.
// - Verify that updated port range is being used for NPL.
func TestNPLChangePortRangeAgentRestart(t *testing.T) {
	skipIfNotIPv4Cluster(t)
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)
	enableNPLInConfigmap(t, data)
	r := require.New(t)

	annotation := make(map[string]string)
	annotation[nplSvcAnnotation] = "true"
	ipFamily := corev1.IPv4Protocol
	data.createNginxClusterIPServiceWithAnnotation(false, &ipFamily, annotation)

	node := nodeName(0)
	var testPods []string

	for i := 0; i < 4; i++ {
		testPodName := randName("test-pod-")
		testPods = append(testPods, testPodName)
		err = data.createNginxPod(testPodName, node)
		r.Nil(err, "Error Creating test Pod: %v", err)
	}

	clientName := randName("test-client-")
	if err := data.createBusyboxPodOnNode(clientName, node); err != nil {
		t.Fatalf("Error when creating Pod '%s': %v", clientName, err)
	}
	_, err = data.podWaitForIPs(defaultTimeout, clientName, testNamespace)
	if err != nil {
		t.Fatalf("Error when waiting for IP for Pod '%s': %v", clientName, err)
	}

	updateNPLPortRangeInConfigmap(t, data, defaultStartPort, defaultEndPort, updatedStartPort, updatedEndPort)
	defer updateNPLPortRangeInConfigmap(t, data, updatedStartPort, updatedEndPort, defaultStartPort, defaultEndPort)

	antreaPod, _ := data.getAntreaPodOnNode(node)

	for _, testPodName := range testPods {
		nplAnnotationString, testPodIP := getNPLAnnotation(t, data, r, testPodName)
		var nplAnnotations []k8s.NPLAnnotation
		json.Unmarshal([]byte(nplAnnotationString), &nplAnnotations)

		checkForNPLRuleInIPTABLES(t, data, r, nplAnnotations, antreaPod, testPodIP.ipv4.String(), true)
		validatePortInRange(t, nplAnnotations, updatedStartPort, updatedEndPort)
		checkTrafficForNPL(t, data, r, nplAnnotations, clientName)

		data.deletePod(testPodName)
		checkForNPLRuleInIPTABLES(t, data, r, nplAnnotations, antreaPod, testPodIP.ipv4.String(), false)
	}
}
