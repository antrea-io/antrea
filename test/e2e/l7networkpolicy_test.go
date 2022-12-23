// Copyright 2022 Antrea Authors
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
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	agentconfig "antrea.io/antrea/pkg/config/agent"
	"antrea.io/antrea/pkg/features"
	. "antrea.io/antrea/test/e2e/utils"
)

func TestL7NetworkPolicy(t *testing.T) {
	skipIfHasWindowsNodes(t)
	skipIfFeatureDisabled(t, features.L7NetworkPolicy, true, true)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	ac := func(config *agentconfig.AgentConfig) { config.DisableTXChecksumOffload = true }
	if err = data.mutateAntreaConfigMap(nil, ac, false, true); err != nil {
		t.Fatalf("Failed to enable option DisableTXChecksumOffload: %v", err)
	}
	defer func() {
		ac = func(config *agentconfig.AgentConfig) { config.DisableTXChecksumOffload = false }
		if err = data.mutateAntreaConfigMap(nil, ac, false, true); err != nil {
			t.Fatalf("Failed to disable option DisableTXChecksumOffload: %v", err)
		}
	}()

	t.Run("HTTP", func(t *testing.T) {
		testL7NetworkPolicyHTTP(t, data)
	})
}

func createL7NetworkPolicy(t *testing.T,
	data *TestData,
	isIngress bool,
	name string,
	priority float64,
	podSelector,
	appliedToPodSelector map[string]string,
	l4Protocol AntreaPolicyProtocol,
	port int32,
	l7Protocols []crdv1alpha1.L7Protocol) {
	anpBuilder := &AntreaNetworkPolicySpecBuilder{}
	anpBuilder = anpBuilder.SetName(data.testNamespace, name).SetPriority(priority)
	if isIngress {
		anpBuilder.AddIngress(l4Protocol,
			&port,
			nil,
			nil,
			nil,
			nil,
			nil,
			l7Protocols,
			nil,
			nil,
			podSelector,
			nil,
			nil,
			nil,
			nil,
			nil,
			[]ANPAppliedToSpec{{PodSelector: appliedToPodSelector}},
			crdv1alpha1.RuleActionAllow,
			"",
			"")
	} else {
		anpBuilder.AddEgress(l4Protocol,
			&port,
			nil,
			nil,
			nil,
			nil,
			nil,
			l7Protocols,
			nil,
			nil,
			podSelector,
			nil,
			nil,
			nil,
			nil,
			nil,
			[]ANPAppliedToSpec{{PodSelector: appliedToPodSelector}},
			crdv1alpha1.RuleActionAllow,
			"",
			"")
	}

	anp := anpBuilder.Get()
	t.Logf("Creating ANP %v", anp.Name)
	_, err := data.crdClient.CrdV1alpha1().NetworkPolicies(data.testNamespace).Create(context.TODO(), anp, metav1.CreateOptions{})
	assert.NoError(t, err)
}

func testL7NetworkPolicyHTTP(t *testing.T, data *TestData) {
	clientPodName := "test-l7-http-client-selected"
	clientPodLabels := map[string]string{"test-l7-http-e2e": "client"}
	cmd := []string{"bash", "-c", "sleep 3600"}

	// Create a client Pod which will be selected by test L7 NetworkPolices.
	require.NoError(t, NewPodBuilder(clientPodName, data.testNamespace, agnhostImage).OnNode(nodeName(0)).WithCommand(cmd).WithLabels(clientPodLabels).Create(data))
	if _, err := data.podWaitForIPs(defaultTimeout, clientPodName, data.testNamespace); err != nil {
		t.Fatalf("Error when waiting for IP for Pod '%s': %v", clientPodName, err)
	}
	require.NoError(t, data.podWaitForRunning(defaultTimeout, clientPodName, data.testNamespace))

	serverPodName := "test-l7-http-server"
	serverPodLabels := map[string]string{"test-l7-http-e2e": "server"}
	cmd = []string{"bash", "-c", "/agnhost netexec --http-port=8080"}
	require.NoError(t, NewPodBuilder(serverPodName, data.testNamespace, agnhostImage).OnNode(nodeName(0)).WithCommand(cmd).WithLabels(serverPodLabels).Create(data))
	podIPs, err := data.podWaitForIPs(defaultTimeout, serverPodName, data.testNamespace)
	if err != nil {
		t.Fatalf("Error when waiting for IP for Pod '%s': %v", serverPodName, err)
	}
	require.NoError(t, data.podWaitForRunning(defaultTimeout, serverPodName, data.testNamespace))
	var serverIPs []*net.IP
	if podIPs.ipv4 != nil {
		serverIPs = append(serverIPs, podIPs.ipv4)
	}
	if podIPs.ipv6 != nil {
		serverIPs = append(serverIPs, podIPs.ipv6)
	}

	l7ProtocolAllowsPathHostname := []crdv1alpha1.L7Protocol{
		{
			HTTP: &crdv1alpha1.HTTPProtocol{
				Method: "GET",
				Path:   "/host*",
			},
		},
	}
	l7ProtocolAllowsAnyPath := []crdv1alpha1.L7Protocol{
		{
			HTTP: &crdv1alpha1.HTTPProtocol{
				Method: "GET",
			},
		},
	}

	policyAllowPathHostname := "test-l7-http-allow-path-hostname"
	policyAllowAnyPath := "test-l7-http-allow-any-path"

	probeFn := func(allowHTTPPathHostname, allowHTTPPathClientIP bool) {
		for _, ip := range serverIPs {
			baseURL := net.JoinHostPort(ip.String(), "8080")

			// To verify that if path 'hostname' is Allowed.
			hostname, err := probeHostnameFromPod(data, clientPodName, agnhostContainerName, baseURL)
			if allowHTTPPathHostname {
				assert.NoError(t, err)
				assert.Equal(t, serverPodName, hostname)
			} else {
				assert.NotNil(t, err)
			}

			// To verify that if path 'clientip' is Allowted.
			_, err = probeClientIPFromPod(data, clientPodName, agnhostContainerName, baseURL)
			if allowHTTPPathClientIP {
				assert.NoError(t, err)
			} else {
				assert.NotNil(t, err)
			}

			// For IPv4, non-HTTP connections should be rejected by Suricata. For IPv6, there is an issue that reject
			// packet cannot be generated by Suricata and sent back to client.
			if ip.To4() != nil {
				cmd = []string{"bash", "-c", fmt.Sprintf("dig @%s google.com a +tcp -p 8080", ip)}
				stdout, _, err := data.RunCommandFromPod(data.testNamespace, clientPodName, agnhostContainerName, cmd)
				// For the client Pod which is selected by the L7 NetworkPolicy, the expected output returned
				// from Suricata should contain "connection reset".
				assert.NoError(t, err)
				assert.Contains(t, stdout, fmt.Sprintf("communications error to %s#8080: connection reset", ip))
			}
		}

	}

	t.Run("Ingress", func(t *testing.T) {
		// Create two L7 NetworkPolicies, one allows HTTP path 'hostname', the other allows any HTTP path. Note that,
		// the priority of the first one is higher than the second one, and they have the same appliedTo labels and Pod
		// selector labels.
		createL7NetworkPolicy(t, data, true, policyAllowPathHostname, 1, clientPodLabels, serverPodLabels, ProtocolTCP, 8080, l7ProtocolAllowsPathHostname)
		createL7NetworkPolicy(t, data, true, policyAllowAnyPath, 2, clientPodLabels, serverPodLabels, ProtocolTCP, 8080, l7ProtocolAllowsAnyPath)
		time.Sleep(networkPolicyDelay)

		// HTTP path 'hostname' is allowed by the first L7 NetworkPolicy, and the priority of the second L7 NetworkPolicy
		// is lower than the first L7 NetworkPolicy. Since they have the appliedTo labels and Pod selector labels and
		// the first L7 NetworkPolicy has higher priority, matched packets will be only matched by the first L7 NetworkPolicy.
		// As a result, only HTTP path 'hostname' is allowed by the first L7 NetworkPolicy, other HTTP path like 'clientip'
		// will be rejected.
		probeFn(true, false)

		// Delete the first L7 NetworkPolicy that only allows HTTP path 'hostname'.
		data.crdClient.CrdV1alpha1().NetworkPolicies(data.testNamespace).Delete(context.TODO(), policyAllowPathHostname, metav1.DeleteOptions{})
		time.Sleep(networkPolicyDelay)

		// Since the fist L7 NetworkPolicy has been deleted, corresponding packets will be matched by the second L7 NetworkPolicy,
		// and the second L7 NetworkPolicy allows any HTTP path, then both path 'hostname' and 'clientip' are allowed.
		probeFn(true, true)

		data.crdClient.CrdV1alpha1().NetworkPolicies(data.testNamespace).Delete(context.TODO(), policyAllowAnyPath, metav1.DeleteOptions{})
	})

	time.Sleep(networkPolicyDelay)
	t.Run("Egress", func(t *testing.T) {
		// Create two L7 NetworkPolicies, one allows HTTP path 'hostname', the other allows any HTTP path. Note that,
		// the priority of the first one is higher than the second one, and they have the same appliedTo labels and Pod
		// selector labels.
		createL7NetworkPolicy(t, data, false, policyAllowPathHostname, 1, serverPodLabels, clientPodLabels, ProtocolTCP, 8080, l7ProtocolAllowsPathHostname)
		createL7NetworkPolicy(t, data, false, policyAllowAnyPath, 2, serverPodLabels, clientPodLabels, ProtocolTCP, 8080, l7ProtocolAllowsAnyPath)
		time.Sleep(networkPolicyDelay)

		// HTTP path 'hostname' is allowed by the first L7 NetworkPolicy, and the priority of the second L7 NetworkPolicy
		// is lower than the first L7 NetworkPolicy. Since they have the appliedTo labels and Pod selector labels and
		// the first L7 NetworkPolicy has higher priority, matched packets will be only matched by the first L7 NetworkPolicy.
		// As a result, only HTTP path 'hostname' is allowed by the first L7 NetworkPolicy, other HTTP path like 'clientip'
		// will be rejected.
		probeFn(true, false)

		// Delete the first L7 NetworkPolicy that only allows HTTP path 'hostname'.
		data.crdClient.CrdV1alpha1().NetworkPolicies(data.testNamespace).Delete(context.TODO(), policyAllowPathHostname, metav1.DeleteOptions{})
		time.Sleep(networkPolicyDelay)

		// Since the fist L7 NetworkPolicy has been deleted, corresponding packets will be matched by the second L7 NetworkPolicy,
		// and the second L7 NetworkPolicy allows any HTTP path, then both path 'hostname' and 'clientip' are allowed.
		probeFn(true, true)
	})
}
