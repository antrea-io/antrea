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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/ptr"

	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
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
	t.Run("TLS", func(t *testing.T) {
		testL7NetworkPolicyTLS(t, data)
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
		annpBuilder.AddIngress(l4Protocol,
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
			[]ANNPAppliedToSpec{{PodSelector: appliedToPodSelector}},
			crdv1beta1.RuleActionAllow,
			"",
			"")
	} else {
		annpBuilder.AddEgress(l4Protocol,
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
			[]ANNPAppliedToSpec{{PodSelector: appliedToPodSelector}},
			crdv1beta1.RuleActionAllow,
			"",
			"")
	}

	annp := annpBuilder.Get()
	t.Logf("Creating ANNP %v", annp.Name)
	_, err := data.crdClient.CrdV1beta1().NetworkPolicies(data.testNamespace).Create(context.TODO(), annp, metav1.CreateOptions{})
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

		// For IPv4, non-HTTP connections should be rejected by Suricata. For IPv6, there is an issue that reject
		// packet cannot be generated by Suricata and sent back to client.
		if ip.To4() != nil {
			cmd := []string{"bash", "-c", fmt.Sprintf("dig @%s google.com a +tcp -p 8080", ip)}
			assert.Eventually(t, func() bool {
				stdout, _, err := data.RunCommandFromPod(data.testNamespace, clientPodName, agnhostContainerName, cmd)
				// For the client Pod which is selected by the L7 NetworkPolicy, the expected output returned
				// from Suricata should contain "connection reset".
				if err != nil {
					return false
				}
				if !strings.Contains(stdout, fmt.Sprintf("communications error to %s#8080: connection reset", ip)) {
					return false
				}
				return true
			}, 5*time.Second, time.Second)
		}
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
		data.crdClient.CrdV1beta1().NetworkPolicies(data.testNamespace).Delete(context.TODO(), policyAllowPathHostname, metav1.DeleteOptions{})
		time.Sleep(networkPolicyDelay)

		// Since the fist L7 NetworkPolicy has been deleted, corresponding packets will be matched by the second L7 NetworkPolicy,
		// and the second L7 NetworkPolicy allows any HTTP path, then both path 'hostname' and 'clientip' are allowed.
		probeL7NetworkPolicyHTTP(t, data, serverPodName, clientPodName, dstPodIPs, true, true)
		probeL7NetworkPolicyHTTP(t, data, serverPodName, clientPodName, serviceIPs, true, true)

		data.crdClient.CrdV1beta1().NetworkPolicies(data.testNamespace).Delete(context.TODO(), policyAllowAnyPath, metav1.DeleteOptions{})
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
		data.crdClient.CrdV1beta1().NetworkPolicies(data.testNamespace).Delete(context.TODO(), policyAllowPathHostname, metav1.DeleteOptions{})
		time.Sleep(networkPolicyDelay)

		// Since the fist L7 NetworkPolicy has been deleted, corresponding packets will be matched by the second L7 NetworkPolicy,
		// and the second L7 NetworkPolicy allows any HTTP path, then both path 'hostname' and 'clientip' are allowed.
		probeL7NetworkPolicyHTTP(t, data, serverPodName, clientPodName, dstPodIPs, true, true)
		probeL7NetworkPolicyHTTP(t, data, serverPodName, clientPodName, serviceIPs, true, true)
	})
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
	data.crdClient.CrdV1beta1().NetworkPolicies(data.testNamespace).Delete(context.TODO(), policyAllowSNIAlfa, metav1.DeleteOptions{})
	time.Sleep(networkPolicyDelay)

	probeL7NetworkPolicyTLS(t, data, clientPodName, serverIPs, serverNameAlfa, false)
	probeL7NetworkPolicyTLS(t, data, clientPodName, serverIPs, serverNameBravo, true)
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
