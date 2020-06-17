// Copyright 2020 Antrea Authors
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
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/prometheus/common/expfmt"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const monitoringNamespace string = "monitoring"

// Agent metrics to validate
var antreaAgentMetrics = []string{
	"antrea_agent_egress_networkpolicy_rule_count",
	"antrea_agent_ingress_networkpolicy_rule_count",
	"antrea_agent_local_pod_count",
	"antrea_agent_networkpolicy_count",
	"antrea_agent_ovs_total_flow_count",
	"antrea_agent_ovs_flow_count",
	"antrea_agent_runtime_info",
}

// Controller metrics to validate
var antreaControllerMetrics = []string{
	"antrea_controller_address_group_processed",
	"antrea_controller_address_group_sync_duration_milliseconds",
	"antrea_controller_applied_to_group_processed",
	"antrea_controller_applied_to_group_sync_duration_milliseconds",
	"antrea_controller_length_address_group_queue",
	"antrea_controller_length_applied_to_group_queue",
	"antrea_controller_length_network_policy_queue",
	"antrea_controller_network_policy_processed",
	"antrea_controller_network_policy_sync_duration_milliseconds",
	"antrea_controller_runtime_info",
}

var prometheusEnabled bool

// Prometheus server JSON output
type prometheusServerOutput struct {
	Status string
	Data   []map[string]string
}

func init() {
	flag.BoolVar(&prometheusEnabled, "prometheus", false, "Enables Prometheus tests")
}

// skipIfPrometheusDisabled checks if Prometheus testing enabled, skip otherwise
func skipIfPrometheusDisabled(t *testing.T) {
	if !prometheusEnabled {
		t.Skip("Prometheus testing is disabled")
	}
}

// getMonitoringAuthToken retrieves monitoring authorization token, required for access to Antrea apiserver/metrics
// resource
func getMonitoringAuthToken(t *testing.T, data *TestData) string {
	secrets, err := data.clientset.CoreV1().Secrets(monitoringNamespace).List(metav1.ListOptions{})
	if err != nil {
		t.Fatalf("Error fetching monitoring secrets: %v", err)
	}

	var token string
	for _, secret := range secrets.Items {
		if secret.Annotations["kubernetes.io/service-account.name"] == "prometheus" {
			token = string(secret.Data[v1.ServiceAccountTokenKey])
		}
	}

	if len(token) == 0 {
		t.Fatal("Prometheus ServiceAccount secret not found")
	}

	return token
}

// getMetricsFromApiServer retrieves Antrea metrics from Pod apiserver
func getMetricsFromApiServer(t *testing.T, url string, token string) string {
	config := &tls.Config{
		InsecureSkipVerify: true,
	}
	tr := &http.Transport{TLSClientConfig: config}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatalf("Error creating HTTP request: %v", err)
	}

	if token != "" {
		req.Header.Add("Authorization", "Bearer "+token)
	}

	// Query metrics via HTTPS from Pod
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Error fetching metrics from %s: %v", url, err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Error retrieving metrics from %s. response: %v", url, err)
	}

	return string(body)
}

// testPrometheusMetricsOnPods locates Antrea Pods from the specified component, then retrieves and validates that all
// the supplied metrics exist
func testPrometheusMetricsOnPods(t *testing.T, data *TestData, component string, metrics []string) {
	token := getMonitoringAuthToken(t, data)

	listOptions := metav1.ListOptions{
		LabelSelector: "app=antrea,component=" + component,
	}
	pods, err := data.clientset.CoreV1().Pods(antreaNamespace).List(listOptions)
	if err != nil {
		t.Fatalf("Error fetching agent Pods: %v", err)
	}

	var hostIP = ""
	var hostPort int32 = 0
	var parser expfmt.TextParser

	// Find Pods' API endpoints, check for metrics existence on each of them
	for _, pod := range pods.Items {
		hostIP = pod.Status.HostIP
		metricsFound := true

		for _, container := range pod.Spec.Containers {
			for _, port := range container.Ports {
				hostPort = port.HostPort
				t.Logf("Found %s %d", hostIP, hostPort)
				respBody := getMetricsFromApiServer(t, fmt.Sprintf("https://%s:%d/metrics", hostIP, hostPort), token)

				parsed, err := parser.TextToMetricFamilies(strings.NewReader(respBody))
				if err != nil {
					t.Fatalf("Parsing Prometheus metrics failed with: %v", err)
				}

				// Create a map of all the metrics which were found on the server
				testMap := make(map[string]bool)
				for _, mf := range parsed {
					testMap[mf.GetName()] = true
				}

				// Validate that all the required metrics exist in the server's output
				for _, metric := range metrics {
					if !testMap[metric] {
						metricsFound = false
						t.Errorf("Metric %s not found on %s:%d", metric, hostIP, hostPort)
					}
				}
			}
		}
		if !metricsFound {
			t.Fatalf("Some metrics do not exist in pods on %s:%d", hostIP, hostPort)
		}
	}
}

// getPrometheusEndpoint retrieves Prometheus endpoint from K8S
func getPrometheusEndpoint(t *testing.T, data *TestData) (string, int32) {
	pods, err := data.clientset.CoreV1().Pods("monitoring").List(metav1.ListOptions{})
	if err != nil {
		t.Fatalf("Error fetching monitoring pods: %v", err)
	}

	// Find hostIP by querying the Prometheus Pod
	var hostIP = ""
	for _, pod := range pods.Items {
		hostIP = pod.Status.HostIP
	}

	// Find nodePort by querying the Prometheus Service
	services, err := data.clientset.CoreV1().Services("monitoring").List(metav1.ListOptions{})
	if err != nil {
		t.Fatalf("Error fetching monitoring Services: %v", err)
	}

	var nodePort int32 = 0
	for _, service := range services.Items {
		for _, port := range service.Spec.Ports {
			nodePort = port.NodePort
		}
	}
	if hostIP == "" || nodePort == 0 {
		t.Fatal("Failed to locate Prometheus endpoint")
	}

	return hostIP, nodePort
}

// TestPrometheusMetricsOnController validates that metrics are returned from Prometheus client on the Antrea Controller
// and checks that metrics in antreaControllerMetrics exists in the controller output
func TestPrometheusMetricsOnController(t *testing.T) {
	skipIfPrometheusDisabled(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	testPrometheusMetricsOnPods(t, data, "antrea-controller", antreaControllerMetrics)
}

// TestPrometheusMetricsOnAgent validates that metrics are returned from Prometheus client on the Antrea Agent
// and checks that metrics in antreaAgentMetrics exists in the agent's output
func TestPrometheusMetricsOnAgent(t *testing.T) {
	skipIfPrometheusDisabled(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	testPrometheusMetricsOnPods(t, data, "antrea-agent", antreaAgentMetrics)
}

// testMetricsFromPrometheusServer validates that a list of metrics is available on the Prometheus server, for the
// specified Prometheus job
func testMetricsFromPrometheusServer(t *testing.T, data *TestData, prometheusJob string, metrics []string) {
	hostIP, nodePort := getPrometheusEndpoint(t, data)

	// Build the Prometheus query URL
	path := url.PathEscape("match[]={job=\"" + prometheusJob + "\"}")
	queryUrl := fmt.Sprintf("http://%s:%d/api/v1/series?%s", hostIP, nodePort, path)

	client := &http.Client{}
	resp, err := client.Get(queryUrl)
	if err != nil {
		t.Fatalf("Error fetching metrics from %s: %v", queryUrl, err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to retrieve JSON data from Prometheus: %v", err)
	}

	// Parse JSON results
	var output prometheusServerOutput
	err = json.Unmarshal(body, &output)
	if err != nil {
		t.Fatalf("Failed to parse JSON data from Prometheus: %v", err)
	}

	// Create a map of all the metrics which were found on the server
	testMap := make(map[string]bool)
	for _, metric := range output.Data {
		testMap[metric["__name__"]] = true
	}

	// Validate that all the required metrics exist in the server's output
	metricsFound := true
	for _, metric := range metrics {
		if !testMap[metric] {
			metricsFound = false
			t.Errorf("Metric %s not found in job %s", metric, prometheusJob)
		}
	}
	if !metricsFound {
		t.Fatalf("Some metrics do not exist in job %s", prometheusJob)
	}
}

func TestControllerMetricsOnPrometheusServer(t *testing.T) {
	skipIfPrometheusDisabled(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	testMetricsFromPrometheusServer(t, data, "antrea-controllers", antreaControllerMetrics)
}

func TestAgentMetricsOnPrometheusServer(t *testing.T) {
	skipIfPrometheusDisabled(t)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	testMetricsFromPrometheusServer(t, data, "antrea-agents", antreaAgentMetrics)
}
