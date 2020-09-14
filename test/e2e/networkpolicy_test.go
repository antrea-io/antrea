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
	"context"
	"encoding/json"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/vmware-tanzu/antrea/pkg/agent/apiserver/handlers/agentinfo"
	"github.com/vmware-tanzu/antrea/pkg/apis/clusterinformation/v1beta1"
)

func TestDifferentNamedPorts(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	server0Port := 80
	_, server0IP, cleanupFunc := createAndWaitForPod(t, data, func(name string, nodeName string) error {
		return data.createServerPod(name, "http", server0Port, false)
	}, "test-server-", "")
	defer cleanupFunc()

	server1Port := 8080
	_, server1IP, cleanupFunc := createAndWaitForPod(t, data, func(name string, nodeName string) error {
		return data.createServerPod(name, "http", server1Port, false)
	}, "test-server-", "")
	defer cleanupFunc()

	client0Name, _, cleanupFunc := createAndWaitForPod(t, data, data.createBusyboxPodOnNode, "test-client-", "")
	defer cleanupFunc()

	client1Name, _, cleanupFunc := createAndWaitForPod(t, data, data.createBusyboxPodOnNode, "test-client-", "")
	defer cleanupFunc()

	// Both clients can connect to both servers.
	for _, clientName := range []string{client0Name, client1Name} {
		if err = data.runNetcatCommandFromTestPod(clientName, server0IP, server0Port); err != nil {
			t.Fatalf("Pod %s should be able to connect %s:%d, but was not able to connect", clientName, server0IP, server0Port)
		}
		if err = data.runNetcatCommandFromTestPod(clientName, server1IP, server1Port); err != nil {
			t.Fatalf("Pod %s should be able to connect %s:%d, but was not able to connect", clientName, server1IP, server1Port)
		}
	}

	spec := &networkingv1.NetworkPolicySpec{
		// Apply to all Pods.
		PodSelector: metav1.LabelSelector{},
		// Allow client0 to access named port: "http".
		Ingress: []networkingv1.NetworkPolicyIngressRule{{
			Ports: []networkingv1.NetworkPolicyPort{{
				Port: &intstr.IntOrString{Type: intstr.String, StrVal: "http"},
			}},
			From: []networkingv1.NetworkPolicyPeer{{
				PodSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"antrea-e2e": client0Name,
					},
				}},
			},
		}},
	}
	np, err := data.createNetworkPolicy("test-networkpolicy-allow-client0-to-http", spec)
	if err != nil {
		t.Fatalf("Error when creating network policy: %v", err)
	}
	defer func() {
		if err = data.deleteNetworkpolicy(np); err != nil {
			t.Fatalf("Error when deleting network policy: %v", err)
		}
	}()

	// client0 can connect to both servers.
	if err = data.runNetcatCommandFromTestPod(client0Name, server0IP, server0Port); err != nil {
		t.Fatalf("Pod %s should be able to connect %s:%d, but was not able to connect", client0Name, server0IP, server0Port)
	}
	if err = data.runNetcatCommandFromTestPod(client0Name, server1IP, server1Port); err != nil {
		t.Fatalf("Pod %s should be able to connect %s:%d, but was not able to connect", client0Name, server1IP, server1Port)
	}
	// client1 cannot connect to both servers.
	if err = data.runNetcatCommandFromTestPod(client1Name, server0IP, server0Port); err == nil {
		t.Fatalf("Pod %s should not be able to connect %s:%d, but was able to connect", client1Name, server0IP, server0Port)
	}
	if err = data.runNetcatCommandFromTestPod(client1Name, server1IP, server1Port); err == nil {
		t.Fatalf("Pod %s should not be able to connect %s:%d, but was able to connect", client1Name, server1IP, server1Port)
	}
}

func TestDefaultDenyEgressPolicy(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	serverPort := 80
	_, serverIP, cleanupFunc := createAndWaitForPod(t, data, data.createNginxPodOnNode, "test-server-", "")
	defer cleanupFunc()

	clientName, _, cleanupFunc := createAndWaitForPod(t, data, data.createBusyboxPodOnNode, "test-client-", "")
	defer cleanupFunc()

	if err = data.runNetcatCommandFromTestPod(clientName, serverIP, serverPort); err != nil {
		t.Fatalf("Pod %s should be able to connect %s:%d, but was not able to connect", clientName, serverIP, serverPort)
	}

	spec := &networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{},
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
		Egress:      []networkingv1.NetworkPolicyEgressRule{},
	}
	np, err := data.createNetworkPolicy("test-networkpolicy-deny-all-egress", spec)
	if err != nil {
		t.Fatalf("Error when creating network policy: %v", err)
	}
	defer func() {
		if err = data.deleteNetworkpolicy(np); err != nil {
			t.Fatalf("Error when deleting network policy: %v", err)
		}
	}()

	if err = data.runNetcatCommandFromTestPod(clientName, serverIP, serverPort); err == nil {
		t.Fatalf("Pod %s should not be able to connect %s:%d, but was able to connect", clientName, serverIP, serverPort)
	}
}

func TestNetworkPolicyResyncAfterRestart(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	workerNode := workerNodeName(1)
	antreaPod, err := data.getAntreaPodOnNode(workerNode)
	if err != nil {
		t.Fatalf("Error when getting antrea-agent pod name: %v", err)
	}

	server0Name, server0IP, cleanupFunc := createAndWaitForPod(t, data, data.createNginxPodOnNode, "test-server-", workerNode)
	defer cleanupFunc()

	server1Name, server1IP, cleanupFunc := createAndWaitForPod(t, data, data.createNginxPodOnNode, "test-server-", workerNode)
	defer cleanupFunc()

	client0Name, _, cleanupFunc := createAndWaitForPod(t, data, data.createBusyboxPodOnNode, "test-client-", workerNode)
	defer cleanupFunc()

	client1Name, _, cleanupFunc := createAndWaitForPod(t, data, data.createBusyboxPodOnNode, "test-client-", workerNode)
	defer cleanupFunc()

	netpol0, err := data.createNetworkPolicy("test-isolate-server0", &networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{
			MatchLabels: map[string]string{
				"antrea-e2e": server0Name,
			},
		},
	})
	if err != nil {
		t.Fatalf("Error when creating network policy: %v", err)
	}
	cleanupNetpol0 := func() {
		if netpol0 == nil {
			return
		}
		if err = data.deleteNetworkpolicy(netpol0); err != nil {
			t.Fatalf("Error when deleting network policy: %v", err)
		}
		netpol0 = nil
	}
	defer cleanupNetpol0()

	if err = data.runNetcatCommandFromTestPod(client0Name, server0IP, 80); err == nil {
		t.Fatalf("Pod %s should not be able to connect %s, but was able to connect", client0Name, server0Name)
	}
	if err = data.runNetcatCommandFromTestPod(client1Name, server1IP, 80); err != nil {
		t.Fatalf("Pod %s should be able to connect %s, but was not able to connect", client1Name, server1Name)
	}

	scaleFunc := func(replicas int32) {
		scale, err := data.clientset.AppsV1().Deployments(antreaNamespace).GetScale(context.TODO(), antreaDeployment, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("error when getting scale of Antrea Deployment: %v", err)
		}
		scale.Spec.Replicas = replicas
		if _, err := data.clientset.AppsV1().Deployments(antreaNamespace).UpdateScale(context.TODO(), antreaDeployment, scale, metav1.UpdateOptions{}); err != nil {
			t.Fatalf("error when scaling Antrea Deployment to %d: %v", replicas, err)
		}
	}

	// Scale antrea-controller to 0 so antrea-agent will lose connection with antrea-controller.
	scaleFunc(0)
	defer scaleFunc(1)
	// Make sure antrea-agent disconnects from antrea-controller.
	waitForAgentCondition(t, data, antreaPod, v1beta1.ControllerConnectionUp, corev1.ConditionFalse)

	// Remove netpol0, we expect client0 can connect server0 after antrea-controller is up.
	cleanupNetpol0()
	// Create netpol1, we expect client1 cannot connect server1 after antrea-controller is up.
	netpol1, err := data.createNetworkPolicy("test-isolate-server1", &networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{
			MatchLabels: map[string]string{
				"antrea-e2e": server1Name,
			},
		},
	})
	if err != nil {
		t.Fatalf("Error when creating network policy: %v", err)
	}
	defer func() {
		if err = data.deleteNetworkpolicy(netpol1); err != nil {
			t.Fatalf("Error when deleting network policy: %v", err)
		}
	}()

	// Scale antrea-controller to 1 so antrea-agent will connect to antrea-controller.
	scaleFunc(1)
	// Make sure antrea-agent connects to antrea-controller.
	waitForAgentCondition(t, data, antreaPod, v1beta1.ControllerConnectionUp, corev1.ConditionTrue)

	if err = data.runNetcatCommandFromTestPod(client0Name, server0IP, 80); err != nil {
		t.Fatalf("Pod %s should be able to connect %s, but was not able to connect", client0Name, server0Name)
	}
	if err = data.runNetcatCommandFromTestPod(client1Name, server1IP, 80); err == nil {
		t.Fatalf("Pod %s should not be able to connect %s, but was able to connect", client1Name, server1Name)
	}
}

func TestIngressPolicyWithoutPortNumber(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	serverPort := 80
	_, serverIP, cleanupFunc := createAndWaitForPod(t, data, data.createNginxPodOnNode, "test-server-", "")
	defer cleanupFunc()

	client0Name, _, cleanupFunc := createAndWaitForPod(t, data, data.createBusyboxPodOnNode, "test-client-", "")
	defer cleanupFunc()

	client1Name, _, cleanupFunc := createAndWaitForPod(t, data, data.createBusyboxPodOnNode, "test-client-", "")
	defer cleanupFunc()

	// Both clients can connect to server.
	for _, clientName := range []string{client0Name, client1Name} {
		if err = data.runNetcatCommandFromTestPod(clientName, serverIP, serverPort); err != nil {
			t.Fatalf("Pod %s should be able to connect %s:%d, but was not able to connect", clientName, serverIP, serverPort)
		}
	}

	protocol := corev1.ProtocolTCP
	spec := &networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{},
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		Ingress: []networkingv1.NetworkPolicyIngressRule{
			{
				Ports: []networkingv1.NetworkPolicyPort{
					{
						Protocol: &protocol,
					},
				},
				From: []networkingv1.NetworkPolicyPeer{{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"antrea-e2e": client0Name,
						},
					}},
				},
			},
		},
	}
	np, err := data.createNetworkPolicy("test-networkpolicy-ingress-no-portnumber", spec)
	if err != nil {
		t.Fatalf("Error when creating network policy: %v", err)
	}
	defer func() {
		if err = data.deleteNetworkpolicy(np); err != nil {
			t.Fatalf("Error when deleting network policy: %v", err)
		}
	}()

	// Client0 can access server.
	if err = data.runNetcatCommandFromTestPod(client0Name, serverIP, serverPort); err != nil {
		t.Fatalf("Pod %s should be able to connect %s:%d, but was not able to connect", client0Name, serverIP, serverPort)
	}
	// Client1 can't access server.
	if err = data.runNetcatCommandFromTestPod(client1Name, serverIP, serverPort); err == nil {
		t.Fatalf("Pod %s should not be able to connect %s:%d, but was able to connect", client1Name, serverIP, serverPort)
	}
}

func createAndWaitForPod(t *testing.T, data *TestData, createFunc func(name string, nodeName string) error, namePrefix string, nodeName string) (string, string, func()) {
	name := randName(namePrefix)
	if err := createFunc(name, nodeName); err != nil {
		t.Fatalf("Error when creating busybox test Pod: %v", err)
	}
	cleanupFunc := func() {
		deletePodWrapper(t, data, name)
	}
	podIP, err := data.podWaitForIP(defaultTimeout, name, testNamespace)
	if err != nil {
		cleanupFunc()
		t.Fatalf("Error when waiting for IP for Pod '%s': %v", name, err)
	}
	return name, podIP, cleanupFunc
}

func waitForAgentCondition(t *testing.T, data *TestData, podName string, conditionType v1beta1.AgentConditionType, expectedStatus corev1.ConditionStatus) {
	if err := wait.Poll(1*time.Second, defaultTimeout, func() (bool, error) {
		cmds := []string{"antctl", "get", "agentinfo", "-o", "json"}
		stdout, _, err := runAntctl(podName, cmds, data)
		if err != nil {
			return true, err
		}
		var agentInfo agentinfo.AntreaAgentInfoResponse
		err = json.Unmarshal([]byte(stdout), &agentInfo)
		if err != nil {
			return true, err
		}
		for _, condition := range agentInfo.AgentConditions {
			if condition.Type == conditionType && condition.Status == expectedStatus {
				return true, nil
			}
		}
		return false, nil
	}); err != nil {
		t.Fatalf("Error when waiting for condition '%s'=='%s': %v", conditionType, expectedStatus, err)
	}
}
