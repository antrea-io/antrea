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
	"flag"
	"fmt"
	"math/rand"
	"net/url"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"antrea.io/antrea/pkg/agent/openflow"
)

const (
	seed = 0xA1E47 // Use a specific rand seed to make the generated workloads always same

	perfTestAppLabel                = "antrea-perf-test"
	podsConnectionNetworkPolicyName = "pods.ingress"
	workloadNetworkPolicyName       = "workloads.ingress"
)

var (
	benchNginxPodName = randName(nginxContainerName + "-")
	toolboxPodName    = randName(toolboxContainerName + "-")

	customizeRequests    = flag.Int("perf.http.requests", 0, "Number of http requests")
	customizePolicyRules = flag.Int("perf.http.policy_rules", 0, "Number of CIDRs in the network policy")
	httpConcurrency      = flag.Int("perf.http.concurrency", 1, "Number of multiple requests to make at a time")
	realizeTimeout       = flag.Duration("perf.realize.timeout", 5*time.Minute, "Timeout of the realization of network policies")
	labelSelector        = &metav1.LabelSelector{
		MatchLabels: map[string]string{"app": perfTestAppLabel},
	}
)

func BenchmarkHTTPRequest(b *testing.B) {
	skipIfNotIPv4Cluster(b)
	for _, scale := range []struct{ requests, policyRules int }{
		{100000, 0},
		{1000000, 0},
		{100000, 5000},
		{100000, 10000},
		{100000, 15000},
	} {
		b.Run(fmt.Sprintf("Request:%d,PolicyRules:%d", scale.requests, scale.policyRules), func(b *testing.B) {
			withPerfTestSetup(func(data *TestData) { httpRequest(scale.requests, scale.policyRules, data, b) }, b)
		})
	}
}

func BenchmarkRealizeNetworkPolicy(b *testing.B) {
	skipIfNotIPv4Cluster(b)
	for _, policyRules := range []int{5000, 10000, 15000} {
		b.Run(fmt.Sprintf("RealizeNetworkPolicy%d", policyRules), func(b *testing.B) {
			withPerfTestSetup(func(data *TestData) { networkPolicyRealize(policyRules, data, b) }, b)
		})
	}
}

func BenchmarkCustomizeHTTPRequest(b *testing.B) {
	skipIfNotIPv4Cluster(b)
	if *customizeRequests == 0 {
		b.Skip("The value of perf.http.requests=0, skipped")
	}
	withPerfTestSetup(func(data *TestData) { httpRequest(*customizeRequests, *customizePolicyRules, data, b) }, b)
}

func BenchmarkCustomizeRealizeNetworkPolicy(b *testing.B) {
	skipIfNotIPv4Cluster(b)
	if *customizePolicyRules == 0 {
		b.Skip("The value of perf.http.policy_rules=0, skipped")
	}
	withPerfTestSetup(func(data *TestData) { networkPolicyRealize(*customizePolicyRules, data, b) }, b)
}

func randCidr(rnd *rand.Rand) string {
	getByte := func() int {
		return rnd.Intn(255) + 1
	}
	return fmt.Sprintf("%d.%d.%d.%d/32", getByte(), getByte(), getByte(), getByte())
}

// createPerfTestPodDefinition creates the Pod specification for the perf test.
// The Pod will be scheduled on the control-plane Node.
func createPerfTestPodDefinition(name, containerName, image string) *corev1.Pod {
	podSpec := corev1.PodSpec{
		Containers: []corev1.Container{
			{
				Name:            containerName,
				Image:           image,
				ImagePullPolicy: corev1.PullIfNotPresent,
			},
		},
		RestartPolicy: corev1.RestartPolicyAlways,
	}
	podSpec.NodeSelector = map[string]string{
		"kubernetes.io/hostname": controlPlaneNodeName(),
	}

	podSpec.Tolerations = controlPlaneNoScheduleTolerations()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{"app": perfTestAppLabel},
		},
		Spec: podSpec,
	}
	return pod
}

// setupTestPodsConnection applies the network policy which enables connectivity between test Pods in the cluster.
func setupTestPodsConnection(data *TestData) error {
	npSpec := networkv1.NetworkPolicySpec{
		PodSelector: *labelSelector,
		Ingress: []networkv1.NetworkPolicyIngressRule{
			{
				From: []networkv1.NetworkPolicyPeer{{PodSelector: labelSelector}},
			},
		},
		PolicyTypes: []networkv1.PolicyType{networkv1.PolicyTypeIngress},
	}
	np := &networkv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: podsConnectionNetworkPolicyName},
		Spec:       npSpec,
	}
	_, err := data.clientset.NetworkingV1().NetworkPolicies(data.testNamespace).Create(context.TODO(), np, metav1.CreateOptions{})
	return err
}

func generateWorkloadNetworkPolicy(policyRules int) *networkv1.NetworkPolicy {
	ingressRules := make([]networkv1.NetworkPolicyPeer, policyRules)
	// #nosec G404: random number generator not used for security purposes
	rnd := rand.New(rand.NewSource(seed))
	existingCIDRs := make(map[string]struct{}) // ensure no duplicated cidrs
	for i := 0; i < policyRules; i++ {
		cidr := randCidr(rnd)
		for _, ok := existingCIDRs[cidr]; ok; {
			cidr = randCidr(rnd)
		}
		existingCIDRs[cidr] = struct{}{}
		ingressRules[i] = networkv1.NetworkPolicyPeer{IPBlock: &networkv1.IPBlock{CIDR: cidr}}
	}
	npSpec := networkv1.NetworkPolicySpec{
		PodSelector: *labelSelector,
		Ingress:     []networkv1.NetworkPolicyIngressRule{{From: ingressRules}},
		PolicyTypes: []networkv1.PolicyType{networkv1.PolicyTypeIngress},
	}
	return &networkv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: workloadNetworkPolicyName},
		Spec:       npSpec,
	}
}

func populateWorkloadNetworkPolicy(np *networkv1.NetworkPolicy, data *TestData) error {
	_, err := data.clientset.NetworkingV1().NetworkPolicies(data.testNamespace).Create(context.TODO(), np, metav1.CreateOptions{})
	return err
}

func setupTestPods(data *TestData, b *testing.B) (nginxPodIP, perfPodIP *PodIPs) {
	b.Logf("Creating a nginx test Pod")
	nginxPod := createPerfTestPodDefinition(benchNginxPodName, nginxContainerName, nginxImage)
	_, err := data.clientset.CoreV1().Pods(data.testNamespace).Create(context.TODO(), nginxPod, metav1.CreateOptions{})
	if err != nil {
		b.Fatalf("Error when creating nginx test pod: %v", err)
	}
	b.Logf("Waiting IP assignment of the nginx test Pod")
	nginxPodIP, err = data.podWaitForIPs(defaultTimeout, benchNginxPodName, data.testNamespace)
	if err != nil {
		b.Fatalf("Error when waiting for IP assignment of nginx test Pod: %v", err)
	}

	b.Logf("Creating a toolbox test Pod")
	perfPod := createPerfTestPodDefinition(toolboxPodName, toolboxContainerName, ToolboxImage)
	_, err = data.clientset.CoreV1().Pods(data.testNamespace).Create(context.TODO(), perfPod, metav1.CreateOptions{})
	if err != nil {
		b.Fatalf("Error when creating toolbox test Pod: %v", err)
	}
	b.Logf("Waiting for IP assignment of the toolbox test Pod")
	perfPodIP, err = data.podWaitForIPs(defaultTimeout, toolboxPodName, data.testNamespace)
	if err != nil {
		b.Fatalf("Error when waiting for IP assignment of toolbox test Pod: %v", err)
	}
	return nginxPodIP, perfPodIP
}

// httpRequest runs a benchmark to measure intra-Node Pod-to-Pod HTTP request performance. It creates one toolbox
// Pod and one Nginx Pod, both on the control-plane Node. The toolbox will use apache-bench tool to issue perf.http.requests
// number of requests to the Nginx Pod. The number of concurrent requests will be determined by the value provided with
// the http.perf.concurrency command-line flag (default is 1, for sequential requests). policyRules indicates how many CIDR
// rules should be included in the network policy applied to the Pods.
func httpRequest(requests, policyRules int, data *TestData, b *testing.B) {
	nginxPodIP, _ := setupTestPods(data, b)

	// performance_test only runs in IPv4 cluster, so here only check the IPv4 address of nginx server Pod.
	nginxPodIPStr := nginxPodIP.IPv4.String()

	err := setupTestPodsConnection(data) // enable Pods connectivity policy first
	if err != nil {
		b.Fatalf("Error when adding network policy to set up connection between test Pods")
	}

	b.Log("Populating the workload network policy")
	err = populateWorkloadNetworkPolicy(generateWorkloadNetworkPolicy(policyRules), data)
	if err != nil {
		b.Fatalf("Error when populating workload network policy: %v", err)
	}

	b.Log("Waiting for the workload network policy to be realized")
	err = WaitNetworkPolicyRealize(controlPlaneNodeName(), openflow.IngressRuleTable, policyRules, data)
	if err != nil {
		b.Fatalf("Checking network policies realization failed: %v", err)
	}
	b.Log("Network policy realized")

	serverURL := &url.URL{Scheme: "http", Host: nginxPodIPStr, Path: "/"}
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		b.Logf("Running http request bench %d/%d", i+1, b.N)
		cmd := []string{"ab", "-n", fmt.Sprint(requests), "-c", fmt.Sprint(*httpConcurrency), serverURL.String()}
		stdout, stderr, err := data.RunCommandFromPod(data.testNamespace, toolboxPodName, toolboxContainerName, cmd)
		if err != nil {
			b.Errorf("Error when running http request %dx: %v, stdout: %s, stderr: %s\n", requests, err, stdout, stderr)
		}
	}
}

// networkPolicyRealize runs a benchmark to measure how long it takes for a Network Policy with policyRules CIDR rules
// to be realized as OVS flows. In order to have entities for the Network Policy to be applied to, we create two dummy
// Pods with the "antrea-perf-test" app label, but they do not generate any traffic.
func networkPolicyRealize(policyRules int, data *TestData, b *testing.B) {
	setupTestPods(data, b)
	for i := 0; i < b.N; i++ {
		go func() {
			err := populateWorkloadNetworkPolicy(generateWorkloadNetworkPolicy(policyRules), data)
			if err != nil {
				// cannot use Fatal in a goroutine
				// if populating policies fails, WaitNetworkPolicyRealize will
				// eventually time out and the test will fail, although it would be
				// better to fail early in that case.
				b.Errorf("Error when populating workload network policy: %v", err)
			}
		}()

		b.Log("Waiting for the network policy to be realized")
		b.StartTimer()
		err := WaitNetworkPolicyRealize(controlPlaneNodeName(), openflow.IngressRuleTable, policyRules, data)
		if err != nil {
			b.Fatalf("Checking network policies realization failed: %v", err)
		}
		b.StopTimer()
		b.Log("Network policy realized")

		err = data.clientset.NetworkingV1().NetworkPolicies(data.testNamespace).Delete(context.TODO(), workloadNetworkPolicyName, metav1.DeleteOptions{})
		if err != nil {
			b.Fatalf("Error when cleaning up network policies after running one bench iteration: %v", err)
		}
	}
}

func WaitNetworkPolicyRealize(nodeName string, table *openflow.Table, policyRules int, data *TestData) error {
	return wait.PollImmediate(50*time.Millisecond, *realizeTimeout, func() (bool, error) {
		return checkRealize(nodeName, table, policyRules, data)
	})
}

// checkRealize checks if all CIDR rules in the Network Policy have been realized as OVS flows. It counts the number of
// flows installed in the ingressRuleTable of the OVS bridge of the control-plane Node. This relies on the implementation
// knowledge that given a single ingress policy, the Antrea agent will install exactly one flow per CIDR rule in table
// IngressRule. checkRealize returns true when the number of flows exceeds the number of CIDR, because each table has a
// default flow entry which is used for default matching.
// Since the check is done over SSH, the time measurement is not completely accurate.
func checkRealize(nodeName string, table *openflow.Table, policyRules int, data *TestData) (bool, error) {
	antreaPodName, err := data.getAntreaPodOnNode(nodeName)
	if err != nil {
		return false, err
	}
	// table IngressRule is the ingressRuleTable where the rules in workload network policy is being applied to.
	cmd := []string{"ovs-ofctl", "dump-flows", defaultBridgeName, fmt.Sprintf("table=%s", table.GetName())}
	stdout, _, err := data.RunCommandFromPod(antreaNamespace, antreaPodName, "antrea-agent", cmd)
	if err != nil {
		return false, err
	}
	flowNums := strings.Count(stdout, "\n")
	return flowNums > policyRules, nil
}

// withPerfTestSetup runs function fn in a clean test environment.
// It ensures no stale flow rules in ovs and the bench timer is stopped and reset.
func withPerfTestSetup(fn func(data *TestData), b *testing.B) {
	b.StopTimer()
	b.ResetTimer()
	defer b.StopTimer()

	data, err := setupTest(b)
	if err != nil {
		b.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(b, data)

	b.Logf("Deleting Antrea Agent DaemonSet to flush ovs cache")
	if err := data.deleteAntrea(defaultTimeout); err != nil {
		b.Fatalf("Error when deleting Antrea DaemonSet: %v", err)
	}
	b.Logf("Applying Antrea YAML")
	if err := data.deployAntrea(deployAntreaDefault); err != nil {
		b.Fatalf("Error when restarting Antrea: %v", err)
	}
	b.Logf("Waiting for all Antrea DaemonSet Pods")
	if err := data.waitForAntreaDaemonSetPods(defaultTimeout); err != nil {
		b.Fatalf("Error when restarting Antrea: %v", err)
	}

	fn(data)
}
