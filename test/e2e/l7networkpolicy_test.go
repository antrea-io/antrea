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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/ptr"

	crdv1beta1 "antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
	agentconfig "antrea.io/antrea/v2/pkg/config/agent"
	"antrea.io/antrea/v2/pkg/features"
	. "antrea.io/antrea/v2/test/e2e/utils"
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

	t.Run("HTTP with large response", func(t *testing.T) {
		testL7NetworkPolicyHTTPLargeResponse(t, data)
	})
	t.Run("HTTP", func(t *testing.T) {
		testL7NetworkPolicyHTTP(t, data)
	})
	t.Run("TLS", func(t *testing.T) {
		testL7NetworkPolicyTLS(t, data)
	})
	t.Run("HTTP with large request", func(t *testing.T) {
		testL7NetworkPolicyHTTPLargeRequest(t, data)
	})
	t.Run("Isolation between policies", func(t *testing.T) {
		testL7NetworkPolicyIsolation(t, data)
	})
	t.Run("Whole protocol", func(t *testing.T) {
		testL7NetworkPolicyWholeProtocol(t, data)
	})
	t.Run("Protocol impersonation", func(t *testing.T) {
		testL7NetworkPolicyProtocolImpersonation(t, data)
	})
	t.Run("Multiple criteria", func(t *testing.T) {
		testL7NetworkPolicyMultipleCriteria(t, data)
	})
	t.Run("HTTP with large body", func(t *testing.T) {
		testL7NetworkPolicyHTTPLargeBody(t, data)
	})
	t.Run("Unidentified traffic", func(t *testing.T) {
		testL7NetworkPolicyUnidentifiedTraffic(t, data)
	})
	t.Run("Logging", func(t *testing.T) {
		testL7NetworkPolicyLogging(t, data)
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
	l7Protocols []crdv1beta1.L7Protocol) {
	annpBuilder := &AntreaNetworkPolicySpecBuilder{}
	annpBuilder = annpBuilder.SetName(data.testNamespace, name).SetPriority(priority)
	if isIngress {
		annpBuilder.AddIngress(ANNPRuleBuilder{
			AppliedToSpecs: []ANNPAppliedToSpec{{PodSelector: appliedToPodSelector}},
			L7Protocols:    l7Protocols,
			BaseRuleBuilder: BaseRuleBuilder{
				Protoc:      l4Protocol,
				Port:        &port,
				PodSelector: podSelector,
				Action:      crdv1beta1.RuleActionAllow,
			}})
	} else {
		annpBuilder.AddEgress(ANNPRuleBuilder{
			L7Protocols:    l7Protocols,
			AppliedToSpecs: []ANNPAppliedToSpec{{PodSelector: appliedToPodSelector}},
			BaseRuleBuilder: BaseRuleBuilder{
				Protoc:      l4Protocol,
				Port:        &port,
				PodSelector: podSelector,
				Action:      crdv1beta1.RuleActionAllow,
			}})
	}

	annp := annpBuilder.Get()
	t.Logf("Creating ANNP %v", annp.Name)
	_, err := data.CRDClient.CrdV1beta1().NetworkPolicies(data.testNamespace).Create(context.TODO(), annp, metav1.CreateOptions{})
	assert.NoError(t, err)
}

func probeL7NetworkPolicyHTTP(t *testing.T, data *TestData, serverPodName, clientPodName string, targetIPs []*net.IP, allowHTTPPathHostname, allowHTTPPathClientIP bool) {
	for _, ip := range targetIPs {
		baseURL := net.JoinHostPort(ip.String(), "8080")

		// Verify that access to path /clientip is as expected.
		assert.Eventually(t, func() bool {
			cmd := []string{"wget", "-O", "-", fmt.Sprintf("%s/%s", baseURL, "clientip"), "-T", "1", "-t", "1"}
			_, _, err := data.RunCommandFromPod(data.testNamespace, clientPodName, agnhostContainerName, cmd)
			if (allowHTTPPathClientIP && err != nil) || (!allowHTTPPathClientIP && err == nil) {
				return false
			}
			return true
		}, 5*time.Second, time.Second)

		// Verify that access to path /hostname is as expected.
		assert.Eventually(t, func() bool {
			cmd := []string{"wget", "-O", "-", fmt.Sprintf("%s/%s", baseURL, "hostname"), "-T", "1", "-t", "1"}
			hostname, _, err := data.RunCommandFromPod(data.testNamespace, clientPodName, agnhostContainerName, cmd)
			if (allowHTTPPathHostname && err != nil) || (!allowHTTPPathHostname && err == nil) {
				return false
			}
			if allowHTTPPathHostname && serverPodName != hostname {
				return false
			}
			return true
		}, 5*time.Second, time.Second)
	}
}

func probeL7NetworkPolicyTLS(t *testing.T, data *TestData, clientPodName string, serverIPs []*net.IP, serverName string, canAccess bool) {
	for _, serverIP := range serverIPs {
		url := fmt.Sprintf("https://%s", serverName)
		resolve := fmt.Sprintf("%s:443:%s", serverName, serverIP.String())
		assert.Eventually(t, func() bool {
			// The built-in certificate of the test HTTPS server Pod does not include the test server name. Therefore,
			// the test client Pod should not verify the test HTTPS server's certificate.
			cmd := []string{"curl", "-k", "--resolve", resolve, url, "--connect-timeout", "1"}
			stdout, stderr, err := data.RunCommandFromPod(data.testNamespace, clientPodName, agnhostContainerName, cmd)
			if canAccess && err != nil {
				t.Logf("Failed to access %s: %v\nStdout: %s\nStderr: %s\n", url, err, stdout, stderr)
				return false
			} else if !canAccess && err == nil {
				t.Logf("Expected not to access the server, but the request succeeded.\nStdout: %s\nStderr: %s\n", stdout, stderr)
				return false
			}
			t.Logf("Access to server %s: %t", url, canAccess)
			return true
		}, 5*time.Second, time.Second)
	}
}

func testL7NetworkPolicyHTTP(t *testing.T, data *TestData) {
	clientPodName := "test-l7-http-client-selected"
	clientPodLabels := map[string]string{"test-l7-http-e2e": "client"}

	// Create a client Pod which will be selected by test L7 NetworkPolices.
	require.NoError(t, NewPodBuilder(clientPodName, data.testNamespace, agnhostImage).OnNode(nodeName(0)).WithLabels(clientPodLabels).Create(data))
	_, err := data.podWaitForIPs(defaultTimeout, clientPodName, data.testNamespace)
	require.NoError(t, err, "Expected IP for Pod '%s'", clientPodName)

	serverPodName := "test-l7-http-server"
	serverPodLabels := map[string]string{"test-l7-http-e2e": "server"}
	cmd := []string{"/agnhost", "netexec", "--http-port=8080"}
	require.NoError(t, NewPodBuilder(serverPodName, data.testNamespace, agnhostImage).OnNode(nodeName(0)).WithCommand(cmd).WithLabels(serverPodLabels).Create(data))
	podIPs, err := data.podWaitForIPs(defaultTimeout, serverPodName, data.testNamespace)
	require.NoError(t, err, "Expected IP for Pod '%s'", serverPodName)
	dstPodIPs := podIPs.AsSlice()

	// Create a Service whose backend is the above backend Pod.
	mutator := func(service *corev1.Service) {
		service.Spec.IPFamilyPolicy = ptr.To(corev1.IPFamilyPolicyPreferDualStack)
	}
	svc, err := data.CreateServiceWithAnnotations("svc-agnhost", data.testNamespace, p8080, p8080, corev1.ProtocolTCP, serverPodLabels, false, false, corev1.ServiceTypeClusterIP, nil, nil, mutator)
	require.NoError(t, err)
	var serviceIPs []*net.IP
	for _, clusterIP := range svc.Spec.ClusterIPs {
		serviceIP := net.ParseIP(clusterIP)
		serviceIPs = append(serviceIPs, &serviceIP)
	}

	l7ProtocolAllowsPathHostname := []crdv1beta1.L7Protocol{
		{
			HTTP: &crdv1beta1.HTTPProtocol{
				Method: "GET",
				Path:   "/host*",
			},
		},
	}
	l7ProtocolAllowsAnyPath := []crdv1beta1.L7Protocol{
		{
			HTTP: &crdv1beta1.HTTPProtocol{
				Method: "GET",
			},
		},
	}

	policyAllowPathHostname := "test-l7-http-allow-path-hostname"
	policyAllowAnyPath := "test-l7-http-allow-any-path"

	t.Run("Ingress", func(t *testing.T) {
		// Create two L7 NetworkPolicies, one allows HTTP path 'hostname', the other allows any HTTP path. Note that,
		// the priority of the first one is higher than the second one, and they have the same appliedTo labels and Pod
		// selector labels.
		createL7NetworkPolicy(t, data, true, policyAllowPathHostname, 1, clientPodLabels, serverPodLabels, ProtocolTCP, p8080, l7ProtocolAllowsPathHostname)
		createL7NetworkPolicy(t, data, true, policyAllowAnyPath, 2, clientPodLabels, serverPodLabels, ProtocolTCP, p8080, l7ProtocolAllowsAnyPath)
		time.Sleep(networkPolicyDelay)

		// HTTP path 'hostname' is allowed by the first L7 NetworkPolicy, and the priority of the second L7 NetworkPolicy
		// is lower than the first L7 NetworkPolicy. Since they have the appliedTo labels and Pod selector labels and
		// the first L7 NetworkPolicy has higher priority, matched packets will be only matched by the first L7 NetworkPolicy.
		// As a result, only HTTP path 'hostname' is allowed by the first L7 NetworkPolicy, other HTTP path like 'clientip'
		// will be rejected.
		probeL7NetworkPolicyHTTP(t, data, serverPodName, clientPodName, dstPodIPs, true, false)
		probeL7NetworkPolicyHTTP(t, data, serverPodName, clientPodName, serviceIPs, true, false)

		// Delete the first L7 NetworkPolicy that only allows HTTP path 'hostname'.
		data.CRDClient.CrdV1beta1().NetworkPolicies(data.testNamespace).Delete(context.TODO(), policyAllowPathHostname, metav1.DeleteOptions{})
		time.Sleep(networkPolicyDelay)

		// Since the fist L7 NetworkPolicy has been deleted, corresponding packets will be matched by the second L7 NetworkPolicy,
		// and the second L7 NetworkPolicy allows any HTTP path, then both path 'hostname' and 'clientip' are allowed.
		probeL7NetworkPolicyHTTP(t, data, serverPodName, clientPodName, dstPodIPs, true, true)
		probeL7NetworkPolicyHTTP(t, data, serverPodName, clientPodName, serviceIPs, true, true)

		data.CRDClient.CrdV1beta1().NetworkPolicies(data.testNamespace).Delete(context.TODO(), policyAllowAnyPath, metav1.DeleteOptions{})
	})

	time.Sleep(networkPolicyDelay)
	t.Run("Egress", func(t *testing.T) {
		// Create two L7 NetworkPolicies, one allows HTTP path 'hostname', the other allows any HTTP path. Note that,
		// the priority of the first one is higher than the second one, and they have the same appliedTo labels and Pod
		// selector labels.
		createL7NetworkPolicy(t, data, false, policyAllowPathHostname, 1, serverPodLabels, clientPodLabels, ProtocolTCP, p8080, l7ProtocolAllowsPathHostname)
		createL7NetworkPolicy(t, data, false, policyAllowAnyPath, 2, serverPodLabels, clientPodLabels, ProtocolTCP, p8080, l7ProtocolAllowsAnyPath)
		time.Sleep(networkPolicyDelay)

		// HTTP path 'hostname' is allowed by the first L7 NetworkPolicy, and the priority of the second L7 NetworkPolicy
		// is lower than the first L7 NetworkPolicy. Since they have the appliedTo labels and Pod selector labels and
		// the first L7 NetworkPolicy has higher priority, matched packets will be only matched by the first L7 NetworkPolicy.
		// As a result, only HTTP path 'hostname' is allowed by the first L7 NetworkPolicy, other HTTP path like 'clientip'
		// will be rejected.
		probeL7NetworkPolicyHTTP(t, data, serverPodName, clientPodName, dstPodIPs, true, false)
		probeL7NetworkPolicyHTTP(t, data, serverPodName, clientPodName, serviceIPs, true, false)

		// Delete the first L7 NetworkPolicy that only allows HTTP path 'hostname'.
		data.CRDClient.CrdV1beta1().NetworkPolicies(data.testNamespace).Delete(context.TODO(), policyAllowPathHostname, metav1.DeleteOptions{})
		time.Sleep(networkPolicyDelay)

		// Since the fist L7 NetworkPolicy has been deleted, corresponding packets will be matched by the second L7 NetworkPolicy,
		// and the second L7 NetworkPolicy allows any HTTP path, then both path 'hostname' and 'clientip' are allowed.
		probeL7NetworkPolicyHTTP(t, data, serverPodName, clientPodName, dstPodIPs, true, true)
		probeL7NetworkPolicyHTTP(t, data, serverPodName, clientPodName, serviceIPs, true, true)
	})
}

func testL7NetworkPolicyHTTPLargeResponse(t *testing.T, data *TestData) {
	skipIfNumNodesLessThan(t, 2)
	clientPodName := "test-l7-http-large-resp-client-selected"
	clientPodLabels := map[string]string{"test-l7-http-large-resp-e2e": "client"}

	// Create a client Pod, with the Pod being selected by the test L7 NetworkPolicy as target.
	require.NoError(t, NewPodBuilder(clientPodName, data.testNamespace, agnhostImage).OnNode(nodeName(0)).WithLabels(clientPodLabels).Create(data))
	_, err := data.podWaitForIPs(defaultTimeout, clientPodName, data.testNamespace)
	require.NoError(t, err, "Expected IP for Pod '%s'", clientPodName)

	// Create a hostNetwork server Pod as the destination selected by the test L7 NetworkPolicy, ensuring test traffic
	// traverses antrea-gw0.
	serverPodName := "test-l7-http-large-resp-server"
	cmd := []string{"/agnhost", "netexec", "--http-port=8081"}
	require.NoError(t, NewPodBuilder(serverPodName, data.testNamespace, agnhostImage).
		WithHostNetwork(true).
		OnNode(nodeName(1)).
		WithCommand(cmd).
		Create(data))
	podIPs, err := data.podWaitForIPs(defaultTimeout, serverPodName, data.testNamespace)
	require.NoError(t, err, "Expected IP for Pod '%s'", serverPodName)
	serverIPs := podIPs.AsSlice()

	l7ProtocolAllowsPathShell := []crdv1beta1.L7Protocol{
		{
			HTTP: &crdv1beta1.HTTPProtocol{
				Path: "/shell*",
			},
		},
	}
	// Create a test egress L7NetworkPolicy allowing HTTP path "shell*".
	policyAllowPathShellName := "test-l7-http-allow-path-shell"
	createL7NetworkPolicy(t, data, false, policyAllowPathShellName, 1, nil, clientPodLabels, ProtocolTCP, 8081, l7ProtocolAllowsPathShell)
	time.Sleep(networkPolicyDelay)

	// Get the MTU of the test client Pod, assuming it's the MTU of the K8s cluster.
	mtuStdout, _, err := data.RunCommandFromPod(data.testNamespace, clientPodName, agnhostContainerName, []string{"cat", "/sys/class/net/eth0/mtu"})
	require.NoError(t, err)
	mtu, err := strconv.Atoi(strings.TrimSpace(mtuStdout))
	require.NoError(t, err)

	for _, ip := range serverIPs {
		baseURL := net.JoinHostPort(ip.String(), "8081")
		// Verify that the test L7 NetworkPolicy denies access to the "/hostname" path.
		assert.Eventually(t, func() bool {
			cmd := []string{"wget", "-O", "-", fmt.Sprintf("%s/%s", baseURL, "hostname"), "-T", "1", "-t", "1"}
			_, _, err := data.RunCommandFromPod(data.testNamespace, clientPodName, agnhostContainerName, cmd)
			return err != nil
		}, 5*time.Second, time.Second)

		// Verify that the test L7 NetworkPolicy allows access to the "/shell" path with large body payload.
		assert.EventuallyWithT(t, func(t *assert.CollectT) {
			// Run the command that makes the test server send an HTTP response with a body larger than the MTU on the
			// test client Pod.
			testBodySize := mtu * 2
			cmd := []string{"curl", "--data-urlencode", fmt.Sprintf(`cmd=head -c %d </dev/zero | tr '\0' 'A'`, testBodySize), fmt.Sprintf("http://%s/shell?cmd", baseURL)}
			stdout, _, err := data.RunCommandFromPod(data.testNamespace, clientPodName, agnhostContainerName, cmd)
			if !assert.NoError(t, err) {
				return
			}
			assert.Contains(t, stdout, strings.Repeat("A", testBodySize))
		}, 5*time.Second, time.Second)
	}
}

func testL7NetworkPolicyTLS(t *testing.T, data *TestData) {
	clientPodName := "test-l7-tls-client-selected"
	clientPodLabels := map[string]string{"test-l7-tls-e2e": "client"}

	// Create a client Pod which will be selected by test L7 NetworkPolices.
	require.NoError(t, NewPodBuilder(clientPodName, data.testNamespace, agnhostImage).OnNode(nodeName(0)).WithLabels(clientPodLabels).Create(data))
	_, err := data.podWaitForIPs(defaultTimeout, clientPodName, data.testNamespace)
	require.NoError(t, err, "Expected IP for Pod '%s'", clientPodName)

	serverPodName := "test-l7-tls-server"
	serverPodLabels := map[string]string{"test-l7-tls-e2e": "server"}
	// Start an HTTPS server with the agnhost image build-in certificate.
	cmd := []string{"/agnhost", "netexec", "--http-port=443", "--tls-cert-file=/localhost.crt", "--tls-private-key-file=/localhost.key"}
	require.NoError(t, NewPodBuilder(serverPodName, data.testNamespace, agnhostImage).OnNode(nodeName(0)).WithCommand(cmd).WithLabels(serverPodLabels).Create(data))
	podIPs, err := data.podWaitForIPs(defaultTimeout, serverPodName, data.testNamespace)
	require.NoError(t, err, "Expected IP for Pod '%s'", serverPodName)
	serverIPs := podIPs.AsSlice()
	serverNameAlfa := "www.alfa.test.l7.tls"
	serverNameBravo := "mail.bravo.test.l7.tls"
	l7ProtocolAllowsAlfa := []crdv1beta1.L7Protocol{
		{
			TLS: &crdv1beta1.TLSProtocol{
				SNI: "*.alfa.test.l7.tls",
			},
		},
	}
	l7ProtocolAllowsBravo := []crdv1beta1.L7Protocol{
		{
			TLS: &crdv1beta1.TLSProtocol{
				SNI: "*.bravo.test.l7.tls",
			},
		},
	}

	policyAllowSNIAlfa := "test-l7-tls-allow-sni-alfa"
	policyAllowSNIBravo := "test-l7-tls-allow-sni-bravo"

	// Create two L7 NetworkPolicies, one allows server name '*.alfa.test.l7.tls', the other allows '*.bravo.test.l7.tls'.
	// Note that the priority of the first one is higher than the second one, and they have the same appliedTo labels
	// and Pod selector labels.
	createL7NetworkPolicy(t, data, false, policyAllowSNIAlfa, 1, nil, clientPodLabels, ProtocolTCP, 443, l7ProtocolAllowsAlfa)
	createL7NetworkPolicy(t, data, false, policyAllowSNIBravo, 2, nil, clientPodLabels, ProtocolTCP, 443, l7ProtocolAllowsBravo)
	time.Sleep(networkPolicyDelay)

	probeL7NetworkPolicyTLS(t, data, clientPodName, serverIPs, serverNameAlfa, true)
	probeL7NetworkPolicyTLS(t, data, clientPodName, serverIPs, serverNameBravo, false)

	// Delete the first L7 NetworkPolicy that allows server name '*.alfa.test.l7.tls'.
	data.CRDClient.CrdV1beta1().NetworkPolicies(data.testNamespace).Delete(context.TODO(), policyAllowSNIAlfa, metav1.DeleteOptions{})
	time.Sleep(networkPolicyDelay)

	probeL7NetworkPolicyTLS(t, data, clientPodName, serverIPs, serverNameAlfa, false)
	probeL7NetworkPolicyTLS(t, data, clientPodName, serverIPs, serverNameBravo, true)
}

// probeL7NetworkPolicyHTTPPath verifies whether the client Pod can reach the given HTTP path of the
// server.
func probeL7NetworkPolicyHTTPPath(t *testing.T, data *TestData, clientPodName string, targetIPs []*net.IP, path string, canAccess bool) {
	t.Helper()
	for _, ip := range targetIPs {
		url := fmt.Sprintf("%s/%s", net.JoinHostPort(ip.String(), "8080"), path)
		assert.Eventually(t, func() bool {
			cmd := []string{"wget", "-O", "-", url, "-T", "1", "-t", "1"}
			stdout, stderr, err := data.RunCommandFromPod(data.testNamespace, clientPodName, agnhostContainerName, cmd)
			if canAccess && err != nil {
				t.Logf("Failed to access %s: %v\nStdout: %s\nStderr: %s", truncateForLog(url), err, stdout, stderr)
				return false
			} else if !canAccess && err == nil {
				t.Logf("Expected not to access %s, but the request succeeded", truncateForLog(url))
				return false
			}
			return true
		}, 5*time.Second, time.Second)
	}
}

func truncateForLog(s string) string {
	if len(s) <= 64 {
		return s
	}
	return fmt.Sprintf("%s...(%d bytes)", s[:64], len(s))
}

// testL7NetworkPolicyHTTPLargeRequest verifies that an HTTP request whose request line does not fit
// in a single packet is evaluated on its merits rather than rejected before the engine has parsed
// the path it is matched on.
func testL7NetworkPolicyHTTPLargeRequest(t *testing.T, data *TestData) {
	clientPodName := "test-l7-http-large-req-client-selected"
	clientPodLabels := map[string]string{"test-l7-http-large-req-e2e": "client"}

	require.NoError(t, NewPodBuilder(clientPodName, data.testNamespace, agnhostImage).OnNode(nodeName(0)).WithLabels(clientPodLabels).Create(data))
	_, err := data.podWaitForIPs(defaultTimeout, clientPodName, data.testNamespace)
	require.NoError(t, err, "Expected IP for Pod '%s'", clientPodName)

	serverPodName := "test-l7-http-large-req-server"
	serverPodLabels := map[string]string{"test-l7-http-large-req-e2e": "server"}
	cmd := []string{"/agnhost", "netexec", "--http-port=8080"}
	require.NoError(t, NewPodBuilder(serverPodName, data.testNamespace, agnhostImage).OnNode(nodeName(0)).WithCommand(cmd).WithLabels(serverPodLabels).Create(data))
	podIPs, err := data.podWaitForIPs(defaultTimeout, serverPodName, data.testNamespace)
	require.NoError(t, err, "Expected IP for Pod '%s'", serverPodName)
	dstPodIPs := podIPs.AsSlice()

	l7Protocols := []crdv1beta1.L7Protocol{
		{
			HTTP: &crdv1beta1.HTTPProtocol{
				Method: "GET",
				Path:   "/echo*",
			},
		},
	}
	policyName := "test-l7-http-large-req"
	createL7NetworkPolicy(t, data, true, policyName, 1, clientPodLabels, serverPodLabels, ProtocolTCP, p8080, l7Protocols)
	defer data.CRDClient.CrdV1beta1().NetworkPolicies(data.testNamespace).Delete(context.TODO(), policyName, metav1.DeleteOptions{})
	time.Sleep(networkPolicyDelay)

	// The query string makes the request line larger than the MTU, so the engine only has the path to
	// match on after reassembling more than one packet.
	largeQuery := "echo?msg=" + strings.Repeat("a", 2500)

	// The path is allowed, so the request must succeed even though its request line spans more than
	// one packet.
	probeL7NetworkPolicyHTTPPath(t, data, clientPodName, dstPodIPs, largeQuery, true)
	// The same request to a path which is not allowed must still be rejected.
	probeL7NetworkPolicyHTTPPath(t, data, clientPodName, dstPodIPs, "hostname?msg="+strings.Repeat("a", 2500), false)
	// A request which fits in a single packet behaves the same way.
	probeL7NetworkPolicyHTTPPath(t, data, clientPodName, dstPodIPs, "echo?msg=small", true)
	probeL7NetworkPolicyHTTPPath(t, data, clientPodName, dstPodIPs, "hostname", false)
}

// testL7NetworkPolicyIsolation verifies that the rules of one L7 NetworkPolicy do not apply to the
// traffic of another. Each policy allows a different HTTP path, and neither its allow nor its deny
// may affect the other policy's traffic.
func testL7NetworkPolicyIsolation(t *testing.T, data *TestData) {
	clientAPodName := "test-l7-isolation-client-a"
	clientAPodLabels := map[string]string{"test-l7-isolation-e2e": "client-a"}
	clientBPodName := "test-l7-isolation-client-b"
	clientBPodLabels := map[string]string{"test-l7-isolation-e2e": "client-b"}

	for podName, labels := range map[string]map[string]string{clientAPodName: clientAPodLabels, clientBPodName: clientBPodLabels} {
		require.NoError(t, NewPodBuilder(podName, data.testNamespace, agnhostImage).OnNode(nodeName(0)).WithLabels(labels).Create(data))
		_, err := data.podWaitForIPs(defaultTimeout, podName, data.testNamespace)
		require.NoError(t, err, "Expected IP for Pod '%s'", podName)
	}

	serverPodName := "test-l7-isolation-server"
	serverPodLabels := map[string]string{"test-l7-isolation-e2e": "server"}
	cmd := []string{"/agnhost", "netexec", "--http-port=8080"}
	require.NoError(t, NewPodBuilder(serverPodName, data.testNamespace, agnhostImage).OnNode(nodeName(0)).WithCommand(cmd).WithLabels(serverPodLabels).Create(data))
	podIPs, err := data.podWaitForIPs(defaultTimeout, serverPodName, data.testNamespace)
	require.NoError(t, err, "Expected IP for Pod '%s'", serverPodName)
	dstPodIPs := podIPs.AsSlice()

	l7ProtocolsHostname := []crdv1beta1.L7Protocol{{HTTP: &crdv1beta1.HTTPProtocol{Method: "GET", Path: "/host*"}}}
	l7ProtocolsClientIP := []crdv1beta1.L7Protocol{{HTTP: &crdv1beta1.HTTPProtocol{Method: "GET", Path: "/clientip*"}}}

	policyA := "test-l7-isolation-a"
	policyB := "test-l7-isolation-b"
	createL7NetworkPolicy(t, data, true, policyA, 1, clientAPodLabels, serverPodLabels, ProtocolTCP, p8080, l7ProtocolsHostname)
	createL7NetworkPolicy(t, data, true, policyB, 2, clientBPodLabels, serverPodLabels, ProtocolTCP, p8080, l7ProtocolsClientIP)
	defer func() {
		data.CRDClient.CrdV1beta1().NetworkPolicies(data.testNamespace).Delete(context.TODO(), policyA, metav1.DeleteOptions{})
		data.CRDClient.CrdV1beta1().NetworkPolicies(data.testNamespace).Delete(context.TODO(), policyB, metav1.DeleteOptions{})
	}()
	time.Sleep(networkPolicyDelay)

	// Each client may only reach the path its own policy allows. The other policy's allow rule must not
	// let it through, and the other policy's deny rule must not block what its own policy allows.
	probeL7NetworkPolicyHTTPPath(t, data, clientAPodName, dstPodIPs, "hostname", true)
	probeL7NetworkPolicyHTTPPath(t, data, clientAPodName, dstPodIPs, "clientip", false)
	probeL7NetworkPolicyHTTPPath(t, data, clientBPodName, dstPodIPs, "clientip", true)
	probeL7NetworkPolicyHTTPPath(t, data, clientBPodName, dstPodIPs, "hostname", false)

	// Deleting one policy must not change the behaviour of the other.
	require.NoError(t, data.CRDClient.CrdV1beta1().NetworkPolicies(data.testNamespace).Delete(context.TODO(), policyA, metav1.DeleteOptions{}))
	time.Sleep(networkPolicyDelay)
	probeL7NetworkPolicyHTTPPath(t, data, clientBPodName, dstPodIPs, "clientip", true)
	probeL7NetworkPolicyHTTPPath(t, data, clientBPodName, dstPodIPs, "hostname", false)
}

// testL7NetworkPolicyWholeProtocol verifies a rule which allows a protocol without narrowing it,
// written as "http: {}" or "tls: {}". Every connection of that protocol is allowed and everything
// else is rejected.
func testL7NetworkPolicyWholeProtocol(t *testing.T, data *TestData) {
	t.Run("HTTP", func(t *testing.T) {
		clientPodName := "test-l7-any-http-client"
		clientPodLabels := map[string]string{"test-l7-any-http-e2e": "client"}
		require.NoError(t, NewPodBuilder(clientPodName, data.testNamespace, agnhostImage).OnNode(nodeName(0)).WithLabels(clientPodLabels).Create(data))
		_, err := data.podWaitForIPs(defaultTimeout, clientPodName, data.testNamespace)
		require.NoError(t, err, "Expected IP for Pod '%s'", clientPodName)

		serverPodName := "test-l7-any-http-server"
		serverPodLabels := map[string]string{"test-l7-any-http-e2e": "server"}
		cmd := []string{"/agnhost", "netexec", "--http-port=8080"}
		require.NoError(t, NewPodBuilder(serverPodName, data.testNamespace, agnhostImage).OnNode(nodeName(0)).WithCommand(cmd).WithLabels(serverPodLabels).Create(data))
		podIPs, err := data.podWaitForIPs(defaultTimeout, serverPodName, data.testNamespace)
		require.NoError(t, err, "Expected IP for Pod '%s'", serverPodName)

		policyName := "test-l7-any-http"
		createL7NetworkPolicy(t, data, true, policyName, 1, clientPodLabels, serverPodLabels, ProtocolTCP, p8080,
			[]crdv1beta1.L7Protocol{{HTTP: &crdv1beta1.HTTPProtocol{}}})
		defer data.CRDClient.CrdV1beta1().NetworkPolicies(data.testNamespace).Delete(context.TODO(), policyName, metav1.DeleteOptions{})
		time.Sleep(networkPolicyDelay)

		// Every HTTP path is allowed. That a non-HTTP connection to the port is rejected is covered by
		// testL7NetworkPolicyProtocolImpersonation.
		probeL7NetworkPolicyHTTP(t, data, serverPodName, clientPodName, podIPs.AsSlice(), true, true)
	})

	t.Run("TLS", func(t *testing.T) {
		clientPodName := "test-l7-any-tls-client"
		clientPodLabels := map[string]string{"test-l7-any-tls-e2e": "client"}
		require.NoError(t, NewPodBuilder(clientPodName, data.testNamespace, agnhostImage).OnNode(nodeName(0)).WithLabels(clientPodLabels).Create(data))
		_, err := data.podWaitForIPs(defaultTimeout, clientPodName, data.testNamespace)
		require.NoError(t, err, "Expected IP for Pod '%s'", clientPodName)

		serverPodName := "test-l7-any-tls-server"
		serverPodLabels := map[string]string{"test-l7-any-tls-e2e": "server"}
		cmd := []string{"/agnhost", "netexec", "--http-port=443", "--tls-cert-file=/localhost.crt", "--tls-private-key-file=/localhost.key"}
		require.NoError(t, NewPodBuilder(serverPodName, data.testNamespace, agnhostImage).OnNode(nodeName(0)).WithCommand(cmd).WithLabels(serverPodLabels).Create(data))
		podIPs, err := data.podWaitForIPs(defaultTimeout, serverPodName, data.testNamespace)
		require.NoError(t, err, "Expected IP for Pod '%s'", serverPodName)
		serverIPs := podIPs.AsSlice()

		policyName := "test-l7-any-tls"
		createL7NetworkPolicy(t, data, false, policyName, 1, nil, clientPodLabels, ProtocolTCP, 443,
			[]crdv1beta1.L7Protocol{{TLS: &crdv1beta1.TLSProtocol{}}})
		defer data.CRDClient.CrdV1beta1().NetworkPolicies(data.testNamespace).Delete(context.TODO(), policyName, metav1.DeleteOptions{})
		time.Sleep(networkPolicyDelay)

		// The rule narrows nothing, so every server name is allowed. Rejecting them instead is the
		// failure this test exists to catch.
		probeL7NetworkPolicyTLS(t, data, clientPodName, serverIPs, "www.alfa.test.l7.tls", true)
		probeL7NetworkPolicyTLS(t, data, clientPodName, serverIPs, "mail.bravo.test.l7.tls", true)
	})
}

// testL7NetworkPolicyMultipleCriteria verifies that a rule listing several criteria allows a request
// matching any one of them, and rejects a request matching none.
func testL7NetworkPolicyMultipleCriteria(t *testing.T, data *TestData) {
	clientPodName := "test-l7-multi-criteria-client"
	clientPodLabels := map[string]string{"test-l7-multi-criteria-e2e": "client"}
	require.NoError(t, NewPodBuilder(clientPodName, data.testNamespace, agnhostImage).OnNode(nodeName(0)).WithLabels(clientPodLabels).Create(data))
	_, err := data.podWaitForIPs(defaultTimeout, clientPodName, data.testNamespace)
	require.NoError(t, err, "Expected IP for Pod '%s'", clientPodName)

	serverPodName := "test-l7-multi-criteria-server"
	serverPodLabels := map[string]string{"test-l7-multi-criteria-e2e": "server"}
	cmd := []string{"/agnhost", "netexec", "--http-port=8080"}
	require.NoError(t, NewPodBuilder(serverPodName, data.testNamespace, agnhostImage).OnNode(nodeName(0)).WithCommand(cmd).WithLabels(serverPodLabels).Create(data))
	podIPs, err := data.podWaitForIPs(defaultTimeout, serverPodName, data.testNamespace)
	require.NoError(t, err, "Expected IP for Pod '%s'", serverPodName)
	dstPodIPs := podIPs.AsSlice()

	policyName := "test-l7-multi-criteria"
	createL7NetworkPolicy(t, data, true, policyName, 1, clientPodLabels, serverPodLabels, ProtocolTCP, p8080,
		[]crdv1beta1.L7Protocol{
			{HTTP: &crdv1beta1.HTTPProtocol{Method: "GET", Path: "/host*"}},
			{HTTP: &crdv1beta1.HTTPProtocol{Method: "GET", Path: "/echo*"}},
		})
	defer data.CRDClient.CrdV1beta1().NetworkPolicies(data.testNamespace).Delete(context.TODO(), policyName, metav1.DeleteOptions{})
	time.Sleep(networkPolicyDelay)

	probeL7NetworkPolicyHTTPPath(t, data, clientPodName, dstPodIPs, "hostname", true)
	probeL7NetworkPolicyHTTPPath(t, data, clientPodName, dstPodIPs, "echo?msg=hello", true)
	probeL7NetworkPolicyHTTPPath(t, data, clientPodName, dstPodIPs, "clientip", false)
}

// testL7NetworkPolicyHTTPLargeBody verifies that a large request body does not cause the connection
// to be cut. The request is allowed on its request line, so neither the size of the body nor the time
// it takes to send it is subject to the limit on how long a connection may go unmatched.
func testL7NetworkPolicyHTTPLargeBody(t *testing.T, data *TestData) {
	clientPodName := "test-l7-large-body-client"
	clientPodLabels := map[string]string{"test-l7-large-body-e2e": "client"}
	require.NoError(t, NewPodBuilder(clientPodName, data.testNamespace, agnhostImage).OnNode(nodeName(0)).WithLabels(clientPodLabels).Create(data))
	_, err := data.podWaitForIPs(defaultTimeout, clientPodName, data.testNamespace)
	require.NoError(t, err, "Expected IP for Pod '%s'", clientPodName)

	serverPodName := "test-l7-large-body-server"
	serverPodLabels := map[string]string{"test-l7-large-body-e2e": "server"}
	cmd := []string{"/agnhost", "netexec", "--http-port=8080"}
	require.NoError(t, NewPodBuilder(serverPodName, data.testNamespace, agnhostImage).OnNode(nodeName(0)).WithCommand(cmd).WithLabels(serverPodLabels).Create(data))
	podIPs, err := data.podWaitForIPs(defaultTimeout, serverPodName, data.testNamespace)
	require.NoError(t, err, "Expected IP for Pod '%s'", serverPodName)

	policyName := "test-l7-large-body"
	createL7NetworkPolicy(t, data, true, policyName, 1, clientPodLabels, serverPodLabels, ProtocolTCP, p8080,
		[]crdv1beta1.L7Protocol{{HTTP: &crdv1beta1.HTTPProtocol{Path: "/echo*"}}})
	defer data.CRDClient.CrdV1beta1().NetworkPolicies(data.testNamespace).Delete(context.TODO(), policyName, metav1.DeleteOptions{})
	time.Sleep(networkPolicyDelay)

	for _, ip := range podIPs.AsSlice() {
		url := fmt.Sprintf("http://%s/echo?msg=hello", net.JoinHostPort(ip.String(), "8080"))
		// Sent slowly enough that the connection outlives the limit, which the request line being
		// allowed must exempt it from.
		cmd := []string{"bash", "-c", fmt.Sprintf("(for i in $(seq 10); do head -c 26214 /dev/zero | tr '\\0' 'a'; sleep 1; done) | curl -s -o /dev/null --data-binary @- -H 'Transfer-Encoding: chunked' --connect-timeout 5 --max-time 60 %s", url)}
		assert.Eventually(t, func() bool {
			stdout, stderr, err := data.RunCommandFromPod(data.testNamespace, clientPodName, agnhostContainerName, cmd)
			if err != nil {
				t.Logf("Failed to post a large body to %s: %v\nStdout: %s\nStderr: %s", url, err, stdout, stderr)
				return false
			}
			return true
		}, 30*time.Second, 2*time.Second)
	}
}

// testL7NetworkPolicyUnidentifiedTraffic verifies that a connection no rule has matched is cut. A
// connection carrying bytes of no known protocol to a peer which never answers is never identified,
// so no rule can reject it on its protocol, and the limit on how long a connection may go unmatched
// is what cuts it.
//
// The test reads the number of bytes the server received rather than the exit status of the client,
// because a client whose connection is reset mid-write still exits successfully.
func testL7NetworkPolicyUnidentifiedTraffic(t *testing.T, data *TestData) {
	const port = 9999
	const sent = 262144

	clientPodName := "test-l7-unidentified-client"
	clientPodLabels := map[string]string{"test-l7-unidentified-e2e": "client"}
	require.NoError(t, NewPodBuilder(clientPodName, data.testNamespace, agnhostImage).OnNode(nodeName(0)).WithLabels(clientPodLabels).Create(data))
	_, err := data.podWaitForIPs(defaultTimeout, clientPodName, data.testNamespace)
	require.NoError(t, err, "Expected IP for Pod '%s'", clientPodName)

	// A server which accepts the connection, reads everything it is sent and never answers. Its silence
	// is what keeps the protocol unidentified.
	serverPodName := "test-l7-unidentified-server"
	serverPodLabels := map[string]string{"test-l7-unidentified-e2e": "server"}
	cmd := []string{"bash", "-c", fmt.Sprintf("nc -l -k %d > /tmp/received", port)}
	require.NoError(t, NewPodBuilder(serverPodName, data.testNamespace, agnhostImage).OnNode(nodeName(0)).WithCommand(cmd).WithLabels(serverPodLabels).Create(data))
	podIPs, err := data.podWaitForIPs(defaultTimeout, serverPodName, data.testNamespace)
	require.NoError(t, err, "Expected IP for Pod '%s'", serverPodName)

	policyName := "test-l7-unidentified"
	createL7NetworkPolicy(t, data, true, policyName, 1, clientPodLabels, serverPodLabels, ProtocolTCP, port,
		[]crdv1beta1.L7Protocol{{HTTP: &crdv1beta1.HTTPProtocol{}}})
	defer data.CRDClient.CrdV1beta1().NetworkPolicies(data.testNamespace).Delete(context.TODO(), policyName, metav1.DeleteOptions{})
	time.Sleep(networkPolicyDelay)

	// Only one address is probed, because the server counts what it received in one file and a second
	// connection would add to the same count.
	ip := podIPs.AsSlice()[0]
	// Trickle the bytes out so that the connection is still open when it is cut.
	pushCmd := []string{"bash", "-c", fmt.Sprintf("(for i in $(seq 20); do head -c %d /dev/zero | tr '\\0' 'a'; sleep 1; done) | nc -w 30 %s %d", sent/20, ip.String(), port)}
	_, _, err = data.RunCommandFromPod(data.testNamespace, clientPodName, agnhostContainerName, pushCmd)
	require.NoError(t, err)

	countCmd := []string{"bash", "-c", "wc -c < /tmp/received"}
	assert.Eventually(t, func() bool {
		stdout, _, err := data.RunCommandFromPod(data.testNamespace, serverPodName, agnhostContainerName, countCmd)
		if err != nil {
			return false
		}
		received, err := strconv.Atoi(strings.TrimSpace(stdout))
		if err != nil {
			return false
		}
		t.Logf("Server received %d of the %d bytes sent", received, sent)
		return received < sent
	}, 20*time.Second, 2*time.Second, "The connection should have been cut before all of it was delivered")
}

// testL7NetworkPolicyProtocolImpersonation verifies that a rule allowing one protocol does not let
// another through, whichever protocol the server behind the port actually speaks.
//
// Two real servers are used, one plain HTTP and one HTTPS, and each is given a rule allowing its own
// protocol and then a rule allowing the other one. A client speaking the protocol the server speaks
// is allowed only in the first case. The allowing case is what makes the denying case meaningful,
// since without it a rule that denied everything would pass just as well.
func testL7NetworkPolicyProtocolImpersonation(t *testing.T, data *TestData) {
	clientPodName := "test-l7-impersonation-client"
	clientPodLabels := map[string]string{"test-l7-impersonation-e2e": "client"}
	require.NoError(t, NewPodBuilder(clientPodName, data.testNamespace, agnhostImage).OnNode(nodeName(0)).WithLabels(clientPodLabels).Create(data))
	_, err := data.podWaitForIPs(defaultTimeout, clientPodName, data.testNamespace)
	require.NoError(t, err, "Expected IP for Pod '%s'", clientPodName)

	httpPodName := "test-l7-impersonation-http-server"
	httpPodLabels := map[string]string{"test-l7-impersonation-e2e": "http-server"}
	httpCmd := []string{"/agnhost", "netexec", "--http-port=8080"}
	require.NoError(t, NewPodBuilder(httpPodName, data.testNamespace, agnhostImage).OnNode(nodeName(0)).WithCommand(httpCmd).WithLabels(httpPodLabels).Create(data))
	httpPodIPs, err := data.podWaitForIPs(defaultTimeout, httpPodName, data.testNamespace)
	require.NoError(t, err, "Expected IP for Pod '%s'", httpPodName)

	tlsPodName := "test-l7-impersonation-tls-server"
	tlsPodLabels := map[string]string{"test-l7-impersonation-e2e": "tls-server"}
	tlsCmd := []string{"/agnhost", "netexec", "--http-port=443", "--tls-cert-file=/localhost.crt", "--tls-private-key-file=/localhost.key"}
	require.NoError(t, NewPodBuilder(tlsPodName, data.testNamespace, agnhostImage).OnNode(nodeName(0)).WithCommand(tlsCmd).WithLabels(tlsPodLabels).Create(data))
	tlsPodIPs, err := data.podWaitForIPs(defaultTimeout, tlsPodName, data.testNamespace)
	require.NoError(t, err, "Expected IP for Pod '%s'", tlsPodName)

	httpOnly := []crdv1beta1.L7Protocol{{HTTP: &crdv1beta1.HTTPProtocol{}}}
	tlsOnly := []crdv1beta1.L7Protocol{{TLS: &crdv1beta1.TLSProtocol{}}}

	// Each case creates one rule per server, so that the traffic the case does not probe is covered
	// as well and neither server is ever left without a rule.
	testCases := []struct {
		name          string
		httpServerL7  []crdv1beta1.L7Protocol
		tlsServerL7   []crdv1beta1.L7Protocol
		canAccessHTTP bool
		canAccessTLS  bool
	}{
		{
			name:          "rule allows the protocol the server speaks",
			httpServerL7:  httpOnly,
			tlsServerL7:   tlsOnly,
			canAccessHTTP: true,
			canAccessTLS:  true,
		},
		{
			name:          "rule allows the other protocol",
			httpServerL7:  tlsOnly,
			tlsServerL7:   httpOnly,
			canAccessHTTP: false,
			canAccessTLS:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpPolicyName := "test-l7-impersonation-http"
			tlsPolicyName := "test-l7-impersonation-tls"
			createL7NetworkPolicy(t, data, true, httpPolicyName, 1, clientPodLabels, httpPodLabels, ProtocolTCP, p8080, tc.httpServerL7)
			createL7NetworkPolicy(t, data, true, tlsPolicyName, 1, clientPodLabels, tlsPodLabels, ProtocolTCP, 443, tc.tlsServerL7)
			defer func() {
				data.CRDClient.CrdV1beta1().NetworkPolicies(data.testNamespace).Delete(context.TODO(), httpPolicyName, metav1.DeleteOptions{})
				data.CRDClient.CrdV1beta1().NetworkPolicies(data.testNamespace).Delete(context.TODO(), tlsPolicyName, metav1.DeleteOptions{})
			}()
			time.Sleep(networkPolicyDelay)

			probeL7NetworkPolicyCurl(t, data, clientPodName, httpPodIPs.AsSlice(), "http", 8080, tc.canAccessHTTP)
			probeL7NetworkPolicyCurl(t, data, clientPodName, tlsPodIPs.AsSlice(), "https", 443, tc.canAccessTLS)
		})
	}
}

// probeL7NetworkPolicyCurl verifies whether the client Pod can reach the server with the given
// scheme. It asserts on whether the request succeeds rather than on the error the client reports,
// because which side ends the connection first, and therefore what the client reports, depends on
// how far the engine got before rejecting it.
func probeL7NetworkPolicyCurl(t *testing.T, data *TestData, clientPodName string, serverIPs []*net.IP, scheme string, port int32, canAccess bool) {
	t.Helper()
	for _, ip := range serverIPs {
		url := fmt.Sprintf("%s://%s/hostname", scheme, net.JoinHostPort(ip.String(), strconv.Itoa(int(port))))
		assert.Eventually(t, func() bool {
			// The server's certificate does not include its address, so the client must not verify it.
			cmd := []string{"curl", "-s", "-k", "-o", "/dev/null", "--connect-timeout", "2", "--max-time", "5", url}
			stdout, stderr, err := data.RunCommandFromPod(data.testNamespace, clientPodName, agnhostContainerName, cmd)
			if canAccess && err != nil {
				t.Logf("Failed to access %s: %v\nStdout: %s\nStderr: %s", url, err, stdout, stderr)
				return false
			} else if !canAccess && err == nil {
				t.Logf("Expected not to access %s, but the request succeeded", url)
				return false
			}
			return true
		}, 15*time.Second, 2*time.Second)
	}
}

func testL7NetworkPolicyLogging(t *testing.T, data *TestData) {
	l7LoggingNode := nodeName(0)

	clientPodName := "test-l7-logging-client-selected"
	clientPodLabels := map[string]string{"test-l7-logging-e2e": "client"}
	require.NoError(t, NewPodBuilder(clientPodName, data.testNamespace, agnhostImage).OnNode(l7LoggingNode).WithLabels(clientPodLabels).Create(data))
	_, err := data.podWaitForIPs(defaultTimeout, clientPodName, data.testNamespace)
	require.NoError(t, err, "Expected IP for Pod '%s'", clientPodName)

	serverPodName := "test-l7-logging-server"
	serverPodLabels := map[string]string{"test-l7-logging-e2e": "server"}
	cmd := []string{"/agnhost", "netexec", "--http-port=8080"}
	require.NoError(t, NewPodBuilder(serverPodName, data.testNamespace, agnhostImage).OnNode(l7LoggingNode).WithCommand(cmd).WithLabels(serverPodLabels).Create(data))
	podIPs, err := data.podWaitForIPs(defaultTimeout, serverPodName, data.testNamespace)
	require.NoError(t, err, "Expected IP for Pod '%s'", serverPodName)
	serverIPs := podIPs.AsSlice()

	antreaPodName, err := data.getAntreaPodOnNode(l7LoggingNode)
	require.NoError(t, err, "Error occurred when trying to get the antrea-agent Pod running on Node %s", l7LoggingNode)

	// Find filename of L7 log file.
	// Filename is determined by generated Suricata config https://github.com/antrea-io/antrea/blob/main/pkg/agent/controller/networkpolicy/l7engine/reconciler.go.
	stdout, _, err := data.RunCommandFromPod(antreaNamespace, antreaPodName, "antrea-agent", []string{"find", "/var/log/antrea/networkpolicy/l7engine/", "-regex", `.*\/eve\-.*\.json`})
	require.NoError(t, err)
	l7LogFiles := strings.Fields(stdout)
	require.NotEmpty(t, l7LogFiles, "L7 log file is missing")
	// In case there is more than one file, take the latest (date is encoded in filename).
	slices.Sort(l7LogFiles)
	l7LogFile := l7LogFiles[len(l7LogFiles)-1]

	// Truncate existing log file if applicable to avoid interference between test runs.
	// Note that the file cannot simply be removed, as Suricata will not recreate it. See https://docs.suricata.io/en/suricata-7.0.0/output/log-rotation.html.
	_, _, err = data.RunCommandFromPod(antreaNamespace, antreaPodName, "antrea-agent", []string{"truncate", "-c", "-s", "0", l7LogFile})
	require.NoError(t, err)

	policyAllowPathHostname := "test-l7-http-allow-path-hostname"
	l7ProtocolAllowsPathHostname := []crdv1beta1.L7Protocol{
		{
			HTTP: &crdv1beta1.HTTPProtocol{
				Method: "GET",
				Path:   "/host*",
			},
		},
	}
	// Create one L7 NetworkPolicy that allows HTTP path 'hostname', and probe twice
	// where HTTP path 'hostname' is allowed yet 'clientip' will be rejected.
	createL7NetworkPolicy(t, data, true, policyAllowPathHostname, 1, clientPodLabels, serverPodLabels, ProtocolTCP, p8080, l7ProtocolAllowsPathHostname)
	time.Sleep(networkPolicyDelay)
	probeL7NetworkPolicyHTTP(t, data, serverPodName, clientPodName, serverIPs, true, false)

	// Define log matchers for expected L7 NetworkPolicies log entries.
	var l7LogMatchers []*L7LogEntry
	for _, ip := range serverIPs {
		clientMatcher := &L7LogEntry{
			EventType:           "alert",
			DestIP:              ip.String(),
			DestPort:            8080,
			Protocol:            "TCP",
			AppProtocol:         "http",
			expectedPacketRegex: regexp.MustCompile(fmt.Sprintf("%s|HTTP|GET|%s", ip.String(), "/clientip")),
			Alert: &L7LogAlertEntry{
				Action:    "blocked",
				Signature: fmt.Sprintf("Reject by AntreaNetworkPolicy:%s/%s", data.testNamespace, policyAllowPathHostname),
			},
			// The rejection is decided once the request has been parsed, so the alert names the request
			// it rejected.
			Http: &L7LogHttpEntry{Hostname: ip.String(), Port: 8080, Url: "/clientip"},
		}
		hostMatcher := &L7LogEntry{
			EventType: "http",
			DestIP:    ip.String(),
			DestPort:  8080,
			Protocol:  "TCP",
			Http:      &L7LogHttpEntry{Hostname: ip.String(), Port: 8080, Url: "/hostname"},
		}
		l7LogMatchers = append(l7LogMatchers, clientMatcher, hostMatcher)
	}

	checkL7LoggingResult(t, data, antreaPodName, l7LogFile, l7LogMatchers)
}

// Partial entries of L7 NetworkPolicy logging necessary for testing.
type L7LogHttpEntry struct {
	Hostname string `json:"hostname"`
	Port     int32  `json:"http_port"`
	Url      string `json:"url"`
}

type L7LogAlertEntry struct {
	Action    string `json:"action"`
	Signature string `json:"signature"`
}

type L7LogEntry struct {
	EventType           string           `json:"event_type"`
	DestIP              string           `json:"dest_ip"`
	DestPort            int32            `json:"dest_port"`
	Protocol            string           `json:"proto"`
	AppProtocol         string           `json:"app_proto,omitempty"`
	PacketBytes         []byte           `json:"packet,omitempty"`
	Http                *L7LogHttpEntry  `json:"http,omitempty"`
	Alert               *L7LogAlertEntry `json:"alert,omitempty"`
	expectedPacketRegex *regexp.Regexp
}

// Matches the 2 L7LogEntries. If an L7LogEntry includes an expectedPacketRegex, the
// PacketBytes field in the other L7LogEntry must match the regex. If none of the
// L7LogEntries include an expectedPacketRegex, the PacketBytes fields must be
// strictly equal for both entries.
func (e *L7LogEntry) Match(x *L7LogEntry) bool {
	packetMatch := func(e, x *L7LogEntry) bool {
		if e.expectedPacketRegex != nil {
			if !e.expectedPacketRegex.Match(x.PacketBytes) {
				return false
			}
		}
		if x.expectedPacketRegex != nil {
			if !x.expectedPacketRegex.Match(e.PacketBytes) {
				return false
			}
		}
		if e.expectedPacketRegex == nil && x.expectedPacketRegex == nil {
			if !bytes.Equal(e.PacketBytes, x.PacketBytes) {
				return false
			}
		}
		return true
	}

	return e.EventType == x.EventType && e.DestIP == x.DestIP && e.DestPort == x.DestPort &&
		e.Protocol == x.Protocol && e.AppProtocol == x.AppProtocol && packetMatch(e, x) &&
		reflect.DeepEqual(e.Http, x.Http) && reflect.DeepEqual(e.Alert, x.Alert)
}

func (e *L7LogEntry) String() string {
	b, _ := json.Marshal(e)
	return string(b)
}

func checkL7LoggingResult(t *testing.T, data *TestData, antreaPodName string, l7LogFile string, expected []*L7LogEntry) {
	cmd := []string{"cat", l7LogFile}

	t.Logf("Checking L7NP logs on Pod '%s'", antreaPodName)

	if err := wait.PollUntilContextTimeout(context.Background(), 1*time.Second, 30*time.Second, false, func(ctx context.Context) (bool, error) {
		stdout, stderr, err := data.RunCommandFromPod(antreaNamespace, antreaPodName, "antrea-agent", cmd)
		if err != nil {
			// file may not exist yet
			t.Logf("Error when reading L7NP log file '%s', err: %v, stderr: %s", l7LogFile, err, stderr)
			return false, nil
		}

		var actual []*L7LogEntry
		dec := json.NewDecoder(strings.NewReader(stdout))
		for dec.More() {
			log := &L7LogEntry{}
			if err := dec.Decode(log); err != nil {
				// log format error, fail immediately
				return false, err
			}
			// ignore unexpected log entries and duplicates
			if slices.ContainsFunc(expected, log.Match) && !slices.ContainsFunc(actual, log.Match) {
				actual = append(actual, log)
			}
		}
		if !slices.EqualFunc(actual, expected, func(e1, e2 *L7LogEntry) bool { return e1.Match(e2) }) {
			t.Logf("L7NP log mismatch")
			t.Logf("Expected: %v", expected)
			t.Logf("Actual: %v", actual)
			return false, nil
		}
		return true, nil
	}); err != nil {
		t.Errorf("Error when polling L7 audit log files for required entries: %v", err)
	}
}
