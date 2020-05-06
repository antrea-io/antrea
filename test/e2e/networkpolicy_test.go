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
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestDifferentNamedPorts(t *testing.T) {
	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	server0Name := randName("test-server-")
	server0Port := 80
	if err = data.createServerPod(server0Name, "http", server0Port, false); err != nil {
		t.Fatalf("Error when creating server pod: %v", err)
	}
	defer deletePodWrapper(t, data, server0Name)
	server0IP, err := data.podWaitForIP(defaultTimeout, server0Name, testNamespace)
	if err != nil {
		t.Fatalf("Error when waiting for IP for Pod '%s': %v", server0Name, err)
	}

	server1Name := randName("test-server-")
	server1Port := 8080
	if err = data.createServerPod(server1Name, "http", server1Port, false); err != nil {
		t.Fatalf("Error when creating server pod: %v", err)
	}
	defer deletePodWrapper(t, data, server1Name)
	server1IP, err := data.podWaitForIP(defaultTimeout, server1Name, testNamespace)
	if err != nil {
		t.Fatalf("Error when waiting for IP for Pod '%s': %v", server1Name, err)
	}

	client0Name := randName("test-client-")
	if err := data.createBusyboxPod(client0Name); err != nil {
		t.Fatalf("Error when creating busybox test Pod: %v", err)
	}
	defer deletePodWrapper(t, data, client0Name)
	if _, err := data.podWaitForIP(defaultTimeout, client0Name, testNamespace); err != nil {
		t.Fatalf("Error when waiting for IP for Pod '%s': %v", client0Name, err)
	}

	client1Name := randName("test-client-")
	if err := data.createBusyboxPod(client1Name); err != nil {
		t.Fatalf("Error when creating busybox test Pod: %v", err)
	}
	defer deletePodWrapper(t, data, client1Name)
	if _, err := data.podWaitForIP(defaultTimeout, client1Name, testNamespace); err != nil {
		t.Fatalf("Error when waiting for IP for Pod '%s': %v", client1Name, err)
	}

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

	serverName := randName("test-server-")
	serverPort := 80
	if err = data.createServerPod(serverName, "http", serverPort, false); err != nil {
		t.Fatalf("Error when creating server pod: %v", err)
	}
	defer deletePodWrapper(t, data, serverName)
	serverIP, err := data.podWaitForIP(defaultTimeout, serverName, testNamespace)
	if err != nil {
		t.Fatalf("Error when waiting for IP for Pod '%s': %v", serverName, err)
	}

	clientName := randName("test-client-")
	if err := data.createBusyboxPod(clientName); err != nil {
		t.Fatalf("Error when creating busybox test Pod: %v", err)
	}
	defer deletePodWrapper(t, data, clientName)
	if _, err := data.podWaitForIP(defaultTimeout, clientName, testNamespace); err != nil {
		t.Fatalf("Error when waiting for IP for Pod '%s': %v", clientName, err)
	}

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
