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
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"

	"antrea.io/antrea/pkg/agent/apiserver/handlers/agentinfo"
	"antrea.io/antrea/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/pkg/apis/stats/v1alpha1"
	"antrea.io/antrea/pkg/features"
)

func skipIfNetworkPolicyStatsDisabled(tb testing.TB) {
	skipIfFeatureDisabled(tb, features.NetworkPolicyStats, true, true)
}

// TestNetworkPolicy is the top-level test which contains all subtests for
// NetworkPolicy related test cases so they can share setup, teardown.
func TestNetworkPolicy(t *testing.T) {
	skipIfHasWindowsNodes(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	t.Run("testNetworkPolicyStats", func(t *testing.T) {
		skipIfNotIPv4Cluster(t)
		skipIfNetworkPolicyStatsDisabled(t)
		testNetworkPolicyStats(t, data)
	})
	t.Run("testDifferentNamedPorts", func(t *testing.T) {
		testDifferentNamedPorts(t, data)
	})
	t.Run("testDefaultDenyIngressPolicy", func(t *testing.T) {
		testDefaultDenyIngressPolicy(t, data)
	})
	t.Run("testDefaultDenyEgressPolicy", func(t *testing.T) {
		testDefaultDenyEgressPolicy(t, data)
	})
	t.Run("testEgressToServerInCIDRBlock", func(t *testing.T) {
		skipIfNotIPv6Cluster(t)
		testEgressToServerInCIDRBlock(t, data)
	})
	t.Run("testEgressToServerInCIDRBlockWithException", func(t *testing.T) {
		skipIfNotIPv6Cluster(t)
		testEgressToServerInCIDRBlockWithException(t, data)
	})
	t.Run("testNetworkPolicyResyncAfterRestart", func(t *testing.T) {
		testNetworkPolicyResyncAfterRestart(t, data)
	})
	t.Run("testIngressPolicyWithoutPortNumber", func(t *testing.T) {
		testIngressPolicyWithoutPortNumber(t, data)
	})
	t.Run("testIngressPolicyWithEndPort", func(t *testing.T) {
		testIngressPolicyWithEndPort(t, data)
	})
}

func testNetworkPolicyStats(t *testing.T, data *TestData) {
	serverName, serverIPs, cleanupFunc := createAndWaitForPod(t, data, data.createNginxPodOnNode, "test-server-", "", testNamespace)
	defer cleanupFunc()

	clientName, _, cleanupFunc := createAndWaitForPod(t, data, data.createBusyboxPodOnNode, "test-client-", "", testNamespace)
	defer cleanupFunc()

	// When using the userspace OVS datapath and tunneling,
	// the first IP packet sent on a tunnel is always dropped because of a missing ARP entry.
	// So we need to  "warm-up" the tunnel.
	if clusterInfo.podV4NetworkCIDR != "" {
		cmd := []string{"/bin/sh", "-c", fmt.Sprintf("nc -vz -w 4 %s 80", serverIPs.ipv4.String())}
		data.runCommandFromPod(testNamespace, clientName, busyboxContainerName, cmd)
	}
	if clusterInfo.podV6NetworkCIDR != "" {
		cmd := []string{"/bin/sh", "-c", fmt.Sprintf("nc -vz -w 4 %s 80", serverIPs.ipv6.String())}
		data.runCommandFromPod(testNamespace, clientName, busyboxContainerName, cmd)
	}

	np1, err := data.createNetworkPolicy("test-networkpolicy-ingress", &networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{},
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		Ingress: []networkingv1.NetworkPolicyIngressRule{{
			From: []networkingv1.NetworkPolicyPeer{{
				PodSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"antrea-e2e": clientName,
					},
				}},
			},
		}},
	})
	if err != nil {
		t.Fatalf("Error when creating network policy: %v", err)
	}
	defer func() {
		if err = data.deleteNetworkpolicy(np1); err != nil {
			t.Fatalf("Error when deleting network policy: %v", err)
		}
	}()
	np2, err := data.createNetworkPolicy("test-networkpolicy-egress", &networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{},
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
		Egress: []networkingv1.NetworkPolicyEgressRule{{
			To: []networkingv1.NetworkPolicyPeer{{
				PodSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"antrea-e2e": serverName,
					},
				}},
			},
		}},
	})
	if err != nil {
		t.Fatalf("Error when creating network policy: %v", err)
	}
	defer func() {
		if err = data.deleteNetworkpolicy(np2); err != nil {
			t.Fatalf("Error when deleting network policy: %v", err)
		}
	}()

	// Wait for a few seconds in case that connections are established before policies are enforced.
	time.Sleep(2 * time.Second)

	sessionsPerAddressFamily := 10
	var wg sync.WaitGroup
	for i := 0; i < sessionsPerAddressFamily; i++ {
		wg.Add(1)
		go func() {
			if clusterInfo.podV4NetworkCIDR != "" {
				cmd := []string{"/bin/sh", "-c", fmt.Sprintf("nc -vz -w 4 %s 80", serverIPs.ipv4.String())}
				data.runCommandFromPod(testNamespace, clientName, busyboxContainerName, cmd)
			}
			if clusterInfo.podV6NetworkCIDR != "" {
				cmd := []string{"/bin/sh", "-c", fmt.Sprintf("nc -vz -w 4 %s 80", serverIPs.ipv6.String())}
				data.runCommandFromPod(testNamespace, clientName, busyboxContainerName, cmd)
			}
			wg.Done()
		}()
	}
	wg.Wait()

	totalSessions := 0
	if clusterInfo.podV4NetworkCIDR != "" {
		totalSessions += sessionsPerAddressFamily
	}
	if clusterInfo.podV6NetworkCIDR != "" {
		totalSessions += sessionsPerAddressFamily
	}

	if err := wait.Poll(5*time.Second, defaultTimeout, func() (bool, error) {
		var ingressStats *v1alpha1.NetworkPolicyStats
		for _, np := range []string{"test-networkpolicy-ingress", "test-networkpolicy-egress"} {
			stats, err := data.crdClient.StatsV1alpha1().NetworkPolicyStats(testNamespace).Get(context.TODO(), np, metav1.GetOptions{})
			if err != nil {
				return false, err
			}
			t.Logf("Got NetworkPolicy stats: %v", stats)
			if ingressStats != nil {
				if stats.TrafficStats.Packets != ingressStats.TrafficStats.Packets {
					return false, nil
				}
				if stats.TrafficStats.Bytes != ingressStats.TrafficStats.Bytes {
					return false, nil
				}
			} else {
				ingressStats = stats
			}
			if stats.TrafficStats.Sessions != int64(totalSessions) {
				return false, nil
			}
			if stats.TrafficStats.Packets < stats.TrafficStats.Sessions || stats.TrafficStats.Bytes < stats.TrafficStats.Sessions {
				return false, fmt.Errorf("Neither 'Packets' nor 'Bytes' should be smaller than 'Sessions'")
			}
		}
		return true, nil
	}); err != nil {
		t.Fatalf("Error when waiting for NetworkPolicy stats: %v", err)
	}
}

func testDifferentNamedPorts(t *testing.T, data *TestData) {
	checkFn, cleanupFn := data.setupDifferentNamedPorts(t)
	defer cleanupFn()
	checkFn()
}

func (data *TestData) setupDifferentNamedPorts(t *testing.T) (checkFn func(), cleanupFn func()) {
	var success bool
	var cleanupFuncs []func()
	cleanupFn = func() {
		for i := len(cleanupFuncs) - 1; i >= 0; i-- {
			cleanupFuncs[i]()
		}
	}
	// Call cleanupFn only if the function fails. In case of success, we will call cleanupFn in callers.
	defer func() {
		if !success {
			cleanupFn()
		}
	}()

	server0Port := int32(80)
	server0Name, server0IPs, cleanupFunc := createAndWaitForPod(t, data, func(name string, ns string, nodeName string) error {
		return data.createServerPod(name, testNamespace, "http", server0Port, false, false)
	}, "test-server-", "", testNamespace)
	cleanupFuncs = append(cleanupFuncs, cleanupFunc)

	server1Port := int32(8080)
	server1Name, server1IPs, cleanupFunc := createAndWaitForPod(t, data, func(name string, ns string, nodeName string) error {
		return data.createServerPod(name, testNamespace, "http", server1Port, false, false)
	}, "test-server-", "", testNamespace)
	cleanupFuncs = append(cleanupFuncs, cleanupFunc)

	client0Name, _, cleanupFunc := createAndWaitForPod(t, data, data.createBusyboxPodOnNode, "test-client-", "", testNamespace)
	cleanupFuncs = append(cleanupFuncs, cleanupFunc)

	client1Name, _, cleanupFunc := createAndWaitForPod(t, data, data.createBusyboxPodOnNode, "test-client-", "", testNamespace)
	cleanupFuncs = append(cleanupFuncs, cleanupFunc)

	preCheckFunc := func(server0IP, server1IP string) {
		// Both clients can connect to both servers.
		for _, clientName := range []string{client0Name, client1Name} {
			if err := data.runNetcatCommandFromTestPod(clientName, testNamespace, server0IP, server0Port); err != nil {
				t.Fatalf("Pod %s should be able to connect %s, but was not able to connect", clientName, net.JoinHostPort(server0IP, fmt.Sprint(server0Port)))
			}
			if err := data.runNetcatCommandFromTestPod(clientName, testNamespace, server1IP, server1Port); err != nil {
				t.Fatalf("Pod %s should be able to connect %s, but was not able to connect", clientName, net.JoinHostPort(server1IP, fmt.Sprint(server1Port)))
			}
		}
	}
	// Precondition check: client is able to access server with the given IP address.
	if clusterInfo.podV4NetworkCIDR != "" {
		preCheckFunc(server0IPs.ipv4.String(), server1IPs.ipv4.String())
	}

	if clusterInfo.podV6NetworkCIDR != "" {
		preCheckFunc(server0IPs.ipv6.String(), server1IPs.ipv6.String())
	}

	if testOptions.providerName == "kind" {
		// Due to netdev datapath bug, sometimes datapath flows are not flushed after new openflows that change the
		// actions are installed, causing client1 to still be able to connect to the servers after creating a policy
		// that disallows it. The test waits for 10 seconds so that the datapath flows will expire.
		// See https://github.com/antrea-io/antrea/issues/1608 for more details.
		time.Sleep(10 * time.Second)
	}

	// Create NetworkPolicy rule.
	spec := &networkingv1.NetworkPolicySpec{
		// Apply to two server Pods.
		PodSelector: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
			{
				Key:      "antrea-e2e",
				Operator: metav1.LabelSelectorOpIn,
				Values:   []string{server0Name, server1Name},
			},
		}},
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
	np, err := data.createNetworkPolicy(randName("test-networkpolicy-allow-client0-to-http"), spec)
	if err != nil {
		t.Fatalf("Error when creating network policy: %v", err)
	}
	cleanupFuncs = append(cleanupFuncs, func() {
		if err = data.deleteNetworkpolicy(np); err != nil {
			t.Fatalf("Error when deleting network policy: %v", err)
		}
	})

	npCheck := func(server0IP, server1IP string) {
		server0Address := net.JoinHostPort(server0IP, fmt.Sprint(server0Port))
		server1Address := net.JoinHostPort(server1IP, fmt.Sprint(server1Port))
		// client0 can connect to both servers.
		if err = data.runNetcatCommandFromTestPod(client0Name, testNamespace, server0IP, server0Port); err != nil {
			t.Fatalf("Pod %s should be able to connect %s, but was not able to connect", client0Name, server0Address)
		}
		if err = data.runNetcatCommandFromTestPod(client0Name, testNamespace, server1IP, server1Port); err != nil {
			t.Fatalf("Pod %s should be able to connect %s, but was not able to connect", client0Name, server1Address)
		}
		// client1 cannot connect to both servers.
		if err = data.runNetcatCommandFromTestPod(client1Name, testNamespace, server0IP, server0Port); err == nil {
			t.Fatalf("Pod %s should not be able to connect %s, but was able to connect", client1Name, server0Address)
		}
		if err = data.runNetcatCommandFromTestPod(client1Name, testNamespace, server1IP, server1Port); err == nil {
			t.Fatalf("Pod %s should not be able to connect %s, but was able to connect", client1Name, server1Address)
		}
	}

	checkFn = func() {
		// NetworkPolicy check.
		if clusterInfo.podV4NetworkCIDR != "" {
			npCheck(server0IPs.ipv4.String(), server1IPs.ipv4.String())
		}

		if clusterInfo.podV6NetworkCIDR != "" {
			npCheck(server0IPs.ipv6.String(), server1IPs.ipv6.String())
		}
	}
	success = true
	return
}

// testDefaultDenyIngressPolicy performs additional validation to the upstream test for deny-all policy:
// 1. The traffic initiated from the host network namespace cannot be dropped.
// 2. The traffic initiated externally that access the Pod via NodePort service can be dropped (skipped if provider is kind).
func testDefaultDenyIngressPolicy(t *testing.T, data *TestData) {
	serverNode := workerNodeName(1)
	serverNodeIP := workerNodeIP(1)
	serverPort := int32(80)
	_, serverIPs, cleanupFunc := createAndWaitForPod(t, data, data.createNginxPodOnNode, "test-server-", serverNode, testNamespace)
	defer cleanupFunc()

	service, err := data.createService("nginx", serverPort, serverPort, map[string]string{"app": "nginx"}, false, corev1.ServiceTypeNodePort, nil)
	if err != nil {
		t.Fatalf("Error when creating nginx NodePort service: %v", err)
	}
	defer data.deleteService(service.Name)

	// client1 is a host network Pod and is on the same node as the server Pod, simulating kubelet probe traffic.
	client1Name, _, cleanupFunc := createAndWaitForPod(t, data, data.createHostNetworkBusyboxPodOnNode, "test-hostnetwork-client-", serverNode, testNamespace)
	defer cleanupFunc()

	// client2 is a host network Pod and is on a different node from the server Pod, accessing the server Pod via the NodePort service.
	client2Name, _, cleanupFunc := createAndWaitForPod(t, data, data.createHostNetworkBusyboxPodOnNode, "test-hostnetwork-client-", controlPlaneNodeName(), testNamespace)
	defer cleanupFunc()

	spec := &networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{},
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		Ingress:     []networkingv1.NetworkPolicyIngressRule{},
	}
	np, err := data.createNetworkPolicy("test-networkpolicy-deny-all-ingress", spec)
	if err != nil {
		t.Fatalf("Error when creating network policy: %v", err)
	}
	defer func() {
		if err = data.deleteNetworkpolicy(np); err != nil {
			t.Fatalf("Error when deleting network policy: %v", err)
		}
	}()

	npCheck := func(clientName, serverIP string, serverPort int32, wantErr bool) {
		if err = data.runNetcatCommandFromTestPod(clientName, testNamespace, serverIP, serverPort); wantErr && err == nil {
			t.Fatalf("Pod %s should not be able to connect %s, but was able to connect", clientName, net.JoinHostPort(serverIP, fmt.Sprint(serverPort)))
		} else if !wantErr && err != nil {
			t.Fatalf("Pod %s should be able to connect %s, but was not able to connect", clientName, net.JoinHostPort(serverIP, fmt.Sprint(serverPort)))
		}
	}

	// Locally generated traffic can always access the Pods regardless of NetworkPolicy configuration.
	if clusterInfo.podV4NetworkCIDR != "" {
		npCheck(client1Name, serverIPs.ipv4.String(), serverPort, false)
	}
	if clusterInfo.podV6NetworkCIDR != "" {
		npCheck(client1Name, serverIPs.ipv6.String(), serverPort, false)
	}

	if testOptions.providerName == "kind" {
		t.Logf("Skipped testing NodePort traffic for TestDefaultDenyIngressPolicy because pkt_mark is not properly supported on OVS netdev datapath")
	} else {
		if clusterInfo.podV4NetworkCIDR != "" {
			npCheck(client2Name, serverIPs.ipv4.String(), serverPort, true)
		}
		if clusterInfo.podV6NetworkCIDR != "" {
			npCheck(client2Name, serverIPs.ipv6.String(), serverPort, true)
		}
		npCheck(client2Name, serverNodeIP, service.Spec.Ports[0].NodePort, true)
	}
}

func testDefaultDenyEgressPolicy(t *testing.T, data *TestData) {
	serverPort := int32(80)
	_, serverIPs, cleanupFunc := createAndWaitForPod(t, data, data.createNginxPodOnNode, "test-server-", "", testNamespace)
	defer cleanupFunc()

	clientName, _, cleanupFunc := createAndWaitForPod(t, data, data.createBusyboxPodOnNode, "test-client-", "", testNamespace)
	defer cleanupFunc()

	preCheckFunc := func(serverIP string) {
		if err := data.runNetcatCommandFromTestPod(clientName, testNamespace, serverIP, serverPort); err != nil {
			t.Fatalf("Pod %s should be able to connect %s, but was not able to connect", clientName, net.JoinHostPort(serverIP, fmt.Sprint(serverPort)))
		}
	}
	if clusterInfo.podV4NetworkCIDR != "" {
		preCheckFunc(serverIPs.ipv4.String())
	}
	if clusterInfo.podV6NetworkCIDR != "" {
		preCheckFunc(serverIPs.ipv6.String())
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

	npCheck := func(serverIP string) {
		if err = data.runNetcatCommandFromTestPod(clientName, testNamespace, serverIP, serverPort); err == nil {
			t.Fatalf("Pod %s should not be able to connect %s, but was able to connect", clientName, net.JoinHostPort(serverIP, fmt.Sprint(serverPort)))
		}
	}

	if clusterInfo.podV4NetworkCIDR != "" {
		npCheck(serverIPs.ipv4.String())
	}
	if clusterInfo.podV6NetworkCIDR != "" {
		npCheck(serverIPs.ipv6.String())
	}
}

// testEgressToServerInCIDRBlock is a duplicate of upstream test case "should allow egress access to server in CIDR block
// [Feature:NetworkPolicy]", which is currently buggy in v1.19 release for clusters which use IPv6.
// This should be deleted when upstream is updated.
// https://github.com/kubernetes/kubernetes/blob/v1.20.0-alpha.0/test/e2e/network/network_policy.go#L1365
// https://github.com/kubernetes/kubernetes/pull/93583
func testEgressToServerInCIDRBlock(t *testing.T, data *TestData) {
	workerNode := workerNodeName(1)
	serverAName, serverAIPs, cleanupFunc := createAndWaitForPod(t, data, data.createNginxPodOnNode, "test-server-", workerNode, testNamespace)
	defer cleanupFunc()
	serverBName, serverBIPs, cleanupFunc := createAndWaitForPod(t, data, data.createNginxPodOnNode, "test-server-", workerNode, testNamespace)
	defer cleanupFunc()

	clientA, _, cleanupFunc := createAndWaitForPod(t, data, data.createBusyboxPodOnNode, "test-client-", workerNode, testNamespace)
	defer cleanupFunc()
	var serverCIDR string
	var serverAIP, serverBIP string
	if serverAIPs.ipv6 == nil {
		t.Fatal("server IPv6 address is empty")
	}
	serverCIDR = fmt.Sprintf("%s/128", serverAIPs.ipv6.String())
	serverAIP = serverAIPs.ipv6.String()
	serverBIP = serverBIPs.ipv6.String()

	if err := data.runNetcatCommandFromTestPod(clientA, testNamespace, serverAIP, 80); err != nil {
		t.Fatalf("%s should be able to netcat %s", clientA, serverAName)
	}
	if err := data.runNetcatCommandFromTestPod(clientA, testNamespace, serverBIP, 80); err != nil {
		t.Fatalf("%s should be able to netcat %s", clientA, serverBName)
	}

	np, err := data.createNetworkPolicy("allow-client-a-via-cidr-egress-rule", &networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{
			MatchLabels: map[string]string{
				"antrea-e2e": clientA,
			},
		},
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
		Egress: []networkingv1.NetworkPolicyEgressRule{
			{
				To: []networkingv1.NetworkPolicyPeer{
					{
						IPBlock: &networkingv1.IPBlock{
							CIDR: serverCIDR,
						},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Error when creating network policy: %v", err)
	}
	cleanupNP := func() {
		if err = data.deleteNetworkpolicy(np); err != nil {
			t.Errorf("Error when deleting network policy: %v", err)
		}
	}
	defer cleanupNP()

	if err := data.runNetcatCommandFromTestPod(clientA, testNamespace, serverAIP, 80); err != nil {
		t.Fatalf("%s should be able to netcat %s", clientA, serverAName)
	}
	if err := data.runNetcatCommandFromTestPod(clientA, testNamespace, serverBIP, 80); err == nil {
		t.Fatalf("%s should not be able to netcat %s", clientA, serverBName)
	}
}

// testEgressToServerInCIDRBlockWithException is a duplicate of upstream test case "should allow egress access to server
// in CIDR block [Feature:NetworkPolicy]", which is currently buggy in v1.19 release for clusters which use IPv6.
// This should be deleted when upstream is updated.
// https://github.com/kubernetes/kubernetes/blob/v1.20.0-alpha.0/test/e2e/network/network_policy.go#L1444
// https://github.com/kubernetes/kubernetes/pull/93583
func testEgressToServerInCIDRBlockWithException(t *testing.T, data *TestData) {
	workerNode := workerNodeName(1)
	serverAName, serverAIPs, cleanupFunc := createAndWaitForPod(t, data, data.createNginxPodOnNode, "test-server-", workerNode, testNamespace)
	defer cleanupFunc()

	clientA, _, cleanupFunc := createAndWaitForPod(t, data, data.createBusyboxPodOnNode, "test-client-", workerNode, testNamespace)
	defer cleanupFunc()
	var serverAAllowCIDR string
	var serverAExceptList []string
	var serverAIP string
	if serverAIPs.ipv6 == nil {
		t.Fatal("server IPv6 address is empty")
	}
	_, serverAAllowSubnet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", serverAIPs.ipv6.String(), 64))
	if err != nil {
		t.Fatalf("could not parse allow subnet")
	}
	serverAAllowCIDR = serverAAllowSubnet.String()
	serverAExceptList = []string{fmt.Sprintf("%s/%d", serverAIPs.ipv6.String(), 128)}
	serverAIP = serverAIPs.ipv6.String()

	if err := data.runNetcatCommandFromTestPod(clientA, testNamespace, serverAIP, 80); err != nil {
		t.Fatalf("%s should be able to netcat %s", clientA, serverAName)
	}

	np, err := data.createNetworkPolicy("deny-client-a-via-except-cidr-egress-rule", &networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{
			MatchLabels: map[string]string{
				"antrea-e2e": clientA,
			},
		},
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
		Egress: []networkingv1.NetworkPolicyEgressRule{
			{
				To: []networkingv1.NetworkPolicyPeer{
					{
						IPBlock: &networkingv1.IPBlock{
							CIDR:   serverAAllowCIDR,
							Except: serverAExceptList,
						},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Error when creating network policy: %v", err)
	}
	cleanupNP := func() {
		if err = data.deleteNetworkpolicy(np); err != nil {
			t.Errorf("Error when deleting network policy: %v", err)
		}
	}
	defer cleanupNP()

	if err := data.runNetcatCommandFromTestPod(clientA, testNamespace, serverAIP, 80); err == nil {
		t.Fatalf("%s should not be able to netcat %s", clientA, serverAName)
	}
}

func testNetworkPolicyResyncAfterRestart(t *testing.T, data *TestData) {
	workerNode := workerNodeName(1)
	antreaPod, err := data.getAntreaPodOnNode(workerNode)
	if err != nil {
		t.Fatalf("Error when getting antrea-agent pod name: %v", err)
	}

	server0Name, server0IPs, cleanupFunc := createAndWaitForPod(t, data, data.createNginxPodOnNode, "test-server-", workerNode, testNamespace)
	defer cleanupFunc()

	server1Name, server1IPs, cleanupFunc := createAndWaitForPod(t, data, data.createNginxPodOnNode, "test-server-", workerNode, testNamespace)
	defer cleanupFunc()

	client0Name, _, cleanupFunc := createAndWaitForPod(t, data, data.createBusyboxPodOnNode, "test-client-", workerNode, testNamespace)
	defer cleanupFunc()

	client1Name, _, cleanupFunc := createAndWaitForPod(t, data, data.createBusyboxPodOnNode, "test-client-", workerNode, testNamespace)
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

	preCheckFunc := func(server0IP, server1IP string) {
		if err = data.runNetcatCommandFromTestPod(client0Name, testNamespace, server0IP, 80); err == nil {
			t.Fatalf("Pod %s should not be able to connect %s, but was able to connect", client0Name, server0Name)
		}
		if err = data.runNetcatCommandFromTestPod(client1Name, testNamespace, server1IP, 80); err != nil {
			t.Fatalf("Pod %s should be able to connect %s, but was not able to connect", client1Name, server1Name)
		}
	}
	if clusterInfo.podV4NetworkCIDR != "" {
		preCheckFunc(server0IPs.ipv4.String(), server1IPs.ipv4.String())
	}
	if clusterInfo.podV6NetworkCIDR != "" {
		preCheckFunc(server0IPs.ipv6.String(), server1IPs.ipv6.String())
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

	npCheck := func(server0IP, server1IP string) {
		if err = data.runNetcatCommandFromTestPod(client0Name, testNamespace, server0IP, 80); err != nil {
			t.Fatalf("Pod %s should be able to connect %s, but was not able to connect", client0Name, server0Name)
		}
		if err = data.runNetcatCommandFromTestPod(client1Name, testNamespace, server1IP, 80); err == nil {
			t.Fatalf("Pod %s should not be able to connect %s, but was able to connect", client1Name, server1Name)
		}
	}

	if clusterInfo.podV4NetworkCIDR != "" {
		npCheck(server0IPs.ipv4.String(), server1IPs.ipv4.String())
	}
	if clusterInfo.podV6NetworkCIDR != "" {
		npCheck(server0IPs.ipv6.String(), server1IPs.ipv6.String())
	}
}

func testIngressPolicyWithoutPortNumber(t *testing.T, data *TestData) {
	serverPort := int32(80)
	_, serverIPs, cleanupFunc := createAndWaitForPod(t, data, data.createNginxPodOnNode, "test-server-", "", testNamespace)
	defer cleanupFunc()

	client0Name, _, cleanupFunc := createAndWaitForPod(t, data, data.createBusyboxPodOnNode, "test-client-", "", testNamespace)
	defer cleanupFunc()

	client1Name, _, cleanupFunc := createAndWaitForPod(t, data, data.createBusyboxPodOnNode, "test-client-", "", testNamespace)
	defer cleanupFunc()

	preCheckFunc := func(serverIP string) {
		// Both clients can connect to server.
		for _, clientName := range []string{client0Name, client1Name} {
			if err := data.runNetcatCommandFromTestPod(clientName, testNamespace, serverIP, serverPort); err != nil {
				t.Fatalf("Pod %s should be able to connect %s, but was not able to connect", clientName, net.JoinHostPort(serverIP, fmt.Sprint(serverPort)))
			}
		}
	}

	if clusterInfo.podV4NetworkCIDR != "" {
		preCheckFunc(serverIPs.ipv4.String())
	}
	if clusterInfo.podV6NetworkCIDR != "" {
		preCheckFunc(serverIPs.ipv6.String())
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

	npCheck := func(serverIP string) {
		serverAddress := net.JoinHostPort(serverIP, fmt.Sprint(serverPort))
		// Client0 can access server.
		if err = data.runNetcatCommandFromTestPod(client0Name, testNamespace, serverIP, serverPort); err != nil {
			t.Fatalf("Pod %s should be able to connect %s, but was not able to connect", client0Name, serverAddress)
		}
		// Client1 can't access server.
		if err = data.runNetcatCommandFromTestPod(client1Name, testNamespace, serverIP, serverPort); err == nil {
			t.Fatalf("Pod %s should not be able to connect %s, but was able to connect", client1Name, serverAddress)
		}
	}

	if clusterInfo.podV4NetworkCIDR != "" {
		npCheck(serverIPs.ipv4.String())
	}
	if clusterInfo.podV6NetworkCIDR != "" {
		npCheck(serverIPs.ipv6.String())
	}
}

func testIngressPolicyWithEndPort(t *testing.T, data *TestData) {
	serverPort := int32(80)
	serverEndPort := int32(84)
	policyPort := int32(81)
	policyEndPort := int32(83)

	var serverPorts []int32
	for i := serverPort; i <= serverEndPort; i++ {
		serverPorts = append(serverPorts, i)
	}

	// makeContainerSpec creates a Container listening on a specific port.
	makeContainerSpec := func(port int32) corev1.Container {
		return corev1.Container{
			Name:            fmt.Sprintf("c%d", port),
			ImagePullPolicy: corev1.PullIfNotPresent,
			Image:           agnhostImage,
			Command:         []string{"/bin/bash", "-c"},
			Args:            []string{fmt.Sprintf("/agnhost serve-hostname --tcp --http=false --port=%d", port)},
			Ports: []corev1.ContainerPort{
				{
					ContainerPort: port,
					Name:          fmt.Sprintf("serve-%d", port),
					Protocol:      corev1.ProtocolTCP,
				},
			},
		}
	}

	// createAgnhostPodOnNodeWithMultiPort creates a Pod in the test namespace with
	// multiple agnhost containers listening on multiple ports.
	// The Pod will be scheduled on the specified Node (if nodeName is not empty).
	createAgnhostPodOnNodeWithMultiPort := func(name string, ns string, nodeName string) error {
		var containers []corev1.Container
		for _, port := range serverPorts {
			containers = append(containers, makeContainerSpec(port))
		}
		podSpec := corev1.PodSpec{
			Containers:    containers,
			RestartPolicy: corev1.RestartPolicyNever,
			HostNetwork:   false,
		}
		if nodeName != "" {
			podSpec.NodeSelector = map[string]string{
				"kubernetes.io/hostname": nodeName,
			}
		}
		if nodeName == controlPlaneNodeName() {
			// tolerate NoSchedule taint if we want Pod to run on control-plane Node
			noScheduleToleration := controlPlaneNoScheduleToleration()
			podSpec.Tolerations = []corev1.Toleration{noScheduleToleration}
		}
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
				Labels: map[string]string{
					"antrea-e2e": name,
					"app":        getImageName(agnhostImage),
				},
			},
			Spec: podSpec,
		}
		if _, err := data.clientset.CoreV1().Pods(ns).Create(context.TODO(), pod, metav1.CreateOptions{}); err != nil {
			return err
		}
		return nil
	}

	serverName, serverIPs, cleanupFunc := createAndWaitForPod(t, data, createAgnhostPodOnNodeWithMultiPort, "test-server-", "", testNamespace)
	defer cleanupFunc()

	clientName, _, cleanupFunc := createAndWaitForPod(t, data, data.createBusyboxPodOnNode, "test-client-", "", testNamespace)
	defer cleanupFunc()

	preCheck := func(serverIP string) {
		// The client can connect to server on all ports.
		for _, port := range serverPorts {
			if err := data.runNetcatCommandFromTestPod(clientName, testNamespace, serverIP, port); err != nil {
				t.Fatalf("Pod %s should be able to connect %s, but was not able to connect", clientName, net.JoinHostPort(serverIP, fmt.Sprint(port)))
			}
		}
	}

	if clusterInfo.podV4NetworkCIDR != "" {
		preCheck(serverIPs.ipv4.String())
	}
	if clusterInfo.podV6NetworkCIDR != "" {
		preCheck(serverIPs.ipv6.String())
	}

	protocol := corev1.ProtocolTCP
	spec := &networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{
			MatchLabels: map[string]string{
				"antrea-e2e": serverName,
			},
		},
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		Ingress: []networkingv1.NetworkPolicyIngressRule{
			{
				Ports: []networkingv1.NetworkPolicyPort{
					{
						Protocol: &protocol,
						Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: policyPort},
						EndPort:  &policyEndPort,
					},
				},
				From: []networkingv1.NetworkPolicyPeer{{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"antrea-e2e": clientName,
						},
					}},
				},
			},
		},
	}
	np, err := data.createNetworkPolicy("test-networkpolicy-ingress-with-endport", spec)
	if err != nil {
		t.Fatalf("Error when creating NetworkPolicy: %v", err)
	}
	defer func() {
		if err = data.deleteNetworkpolicy(np); err != nil {
			t.Errorf("Error when deleting NetworkPolicy: %v", err)
		}
	}()

	if np.Spec.Ingress[0].Ports[0].EndPort == nil {
		t.Skipf("Skipping test as the kube-apiserver doesn't support `endPort` " +
			"or `NetworkPolicyEndPort` feature-gate is not enabled.")
	}

	npCheck := func(serverIP string) {
		for _, port := range serverPorts {
			err = data.runNetcatCommandFromTestPod(clientName, testNamespace, serverIP, port)
			if port >= policyPort && port <= policyEndPort {
				if err != nil {
					t.Errorf("Pod %s should be able to connect %s, but was not able to connect", clientName, net.JoinHostPort(serverIP, fmt.Sprint(port)))
				}
			} else if err == nil {
				t.Errorf("Pod %s should be not able to connect %s, but was able to connect", clientName, net.JoinHostPort(serverIP, fmt.Sprint(port)))
			}
		}
	}

	if clusterInfo.podV4NetworkCIDR != "" {
		npCheck(serverIPs.ipv4.String())
	}
	if clusterInfo.podV6NetworkCIDR != "" {
		npCheck(serverIPs.ipv6.String())
	}
}

func createAndWaitForPod(t *testing.T, data *TestData, createFunc func(name string, ns string, nodeName string) error, namePrefix string, nodeName string, ns string) (string, *PodIPs, func()) {
	name := randName(namePrefix)
	if err := createFunc(name, ns, nodeName); err != nil {
		t.Fatalf("Error when creating busybox test Pod: %v", err)
	}
	cleanupFunc := func() {
		deletePodWrapper(t, data, name)
	}
	podIP, err := data.podWaitForIPs(defaultTimeout, name, ns)
	if err != nil {
		cleanupFunc()
		t.Fatalf("Error when waiting for IP for Pod '%s': %v", name, err)
	}
	return name, podIP, cleanupFunc
}

func createAndWaitForPodWithLabels(t *testing.T, data *TestData, createFunc func(name, ns string, portNum int32, labels map[string]string) error, name, ns string, portNum int32, labels map[string]string) (string, *PodIPs, func() error) {
	if err := createFunc(name, ns, portNum, labels); err != nil {
		t.Fatalf("Error when creating busybox test Pod: %v", err)
	}
	cleanupFunc := func() error {
		if err := data.deletePod(ns, name); err != nil {
			return fmt.Errorf("error when deleting Pod: %v", err)
		}
		return nil
	}
	podIP, err := data.podWaitForIPs(defaultTimeout, name, ns)
	if err != nil {
		cleanupFunc()
		t.Fatalf("Error when waiting for IP for Pod '%s': %v", name, err)
	}
	return name, podIP, cleanupFunc
}

func waitForAgentCondition(t *testing.T, data *TestData, podName string, conditionType v1beta1.AgentConditionType, expectedStatus corev1.ConditionStatus) {
	if err := wait.Poll(defaultInterval, defaultTimeout, func() (bool, error) {
		cmds := []string{"antctl", "get", "agentinfo", "-o", "json"}
		t.Logf("cmds: %s", cmds)

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
