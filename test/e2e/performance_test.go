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
	"flag"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/exp/rand"
	"k8s.io/apimachinery/pkg/util/wait"

	v1 "k8s.io/api/core/v1"
	networkv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	seed                            uint64 = 0xA1E47 // Use a specific rand seed to make the generated workloads always same
	performanceAppLabel                    = "antrea-performance-test"
	podsConnectionNetworkPolicyName        = "pods.ingress"
	workloadNetworkPolicyName              = "workloads.ingress"
	abImage                                = "antrea/apache-bench"
	nginxImage                             = "nginx"
	abContainerName                        = "apache-bench"
	nginxContainerName                     = "nginx"
)

var (
	benchNginxPodName = randName(abContainerName + "-")
	benchABPodName    = randName(nginxContainerName + "-")

	requestsNumber  = flag.Int("performance.http.requests", 0, "Number of http requests")
	workloads       = flag.Int("performance.http.workloads", 0, "Number of CIDRs in the network policy workload")
	httpConcurrency = flag.Int("performance.http.concurrency", 1, "Number of multiple requests to make at a time")
	realizeTimeout  = flag.Duration("performance.realize.timeout", 5*time.Minute, "Timeout of the realization of network policies")
)

func BenchmarkHTTPRequest(b *testing.B) {
	for _, scale := range []struct{ requests, workloads int }{
		{100000, 0},
		{1000000, 0},
		{100000, 5000},
		{100000, 10000},
		{100000, 15000},
	} {
		b.Run(fmt.Sprintf("Request%dWorkloads%d", scale.requests, scale.workloads), func(b *testing.B) {
			withPerformanceTestSetup(func(data *TestData) { httpRequest(scale.requests, scale.workloads, data, b) }, b)
		})
	}
}

func BenchmarkRealizeNetworkPolicy(b *testing.B) {
	for _, scale := range []int{5000, 10000, 15000} {
		b.Run(fmt.Sprintf("RealizeNetworkPolicy%d", scale), func(b *testing.B) {
			withPerformanceTestSetup(func(data *TestData) { networkPolicyRealize(scale, data, b) }, b)
		})
	}
}

func BenchmarkCustomizeHTTPRequest(b *testing.B) {
	if *requestsNumber == 0 {
		b.Skip("The value of performance.http.requests=0, skipped")
	}
	withPerformanceTestSetup(func(data *TestData) { httpRequest(*requestsNumber, *workloads, data, b) }, b)
}

func BenchmarkCustomizeRealizeNetworkPolicy(b *testing.B) {
	if *workloads == 0 {
		b.Skip("The value of performance.http.workload=0, skipped")
	}
	withPerformanceTestSetup(func(data *TestData) { networkPolicyRealize(*workloads, data, b) }, b)
}

func randCidr(rndSrc rand.Source) string {
	return fmt.Sprintf("%d.%d.%d.%d/32", rndSrc.Uint64()%255+1, rndSrc.Uint64()%255+1, rndSrc.Uint64()%255+1, rndSrc.Uint64()%255+1)
}

// createPerformanceTestPodSpec creates Pod description for the performance test.
// The Pod will be scheduled on the master Node.
func createPerformanceTestPodSpec(name, containerName, image string) *v1.Pod {
	podSpec := v1.PodSpec{
		Containers: []v1.Container{
			{
				Name:            containerName,
				Image:           image,
				ImagePullPolicy: v1.PullIfNotPresent,
			},
		},
		RestartPolicy: v1.RestartPolicyNever,
	}
	podSpec.NodeSelector = map[string]string{
		"kubernetes.io/hostname": masterNodeName(),
	}
	// tolerate NoSchedule taint to let the Pod run on master Node
	noScheduleToleration := v1.Toleration{
		Key:      "node-role.kubernetes.io/master",
		Operator: v1.TolerationOpExists,
		Effect:   v1.TaintEffectNoSchedule,
	}
	podSpec.Tolerations = []v1.Toleration{noScheduleToleration}
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{"app": performanceAppLabel},
		},
		Spec: podSpec,
	}
	return pod
}

// createPerformanceNginx creates the nginx Pod and waits for it to be ready.
func createPerformanceNginx(data *TestData, b *testing.B) (string, error) {
	b.Logf("Creating a nginx test Pod")
	nginxPod := createPerformanceTestPodSpec(benchNginxPodName, nginxContainerName, nginxImage)
	_, err := data.clientset.CoreV1().Pods(testNamespace).Create(nginxPod)
	if err != nil {
		b.Fatalf("Error when creating nginx test pod: %v", err)
	}
	b.Logf("Waiting IP assignment of the nginx test Pod")
	return data.podWaitForIP(defaultTimeout, benchNginxPodName)
}

// createPerformanceAB creates the apache-bench Pod and waits for it to be ready.
func createPerformanceAB(data *TestData, b *testing.B) (string, error) {
	b.Logf("Creating an apache-bench test Pod")
	sleepDuration := "3600" // seconds
	abPod := createPerformanceTestPodSpec(benchABPodName, abContainerName, abImage)
	abPod.Spec.Containers[0].Command = []string{"sleep", sleepDuration}
	_, err := data.clientset.CoreV1().Pods(testNamespace).Create(abPod)
	if err != nil {
		b.Fatalf("Error when creating apache-bench test Pod: %v", err)
	}
	b.Logf("Waiting IP assignment of the apache-bench test Pod")
	return data.podWaitForIP(defaultTimeout, benchABPodName)
}

// setupPerformanceTestPodsConnection applies the network policy which enables connectivity between test Pods in the cluster.
func setupPerformanceTestPodsConnection(data *TestData) error {
	npSpec := networkv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": performanceAppLabel}},
		Ingress: []networkv1.NetworkPolicyIngressRule{
			{
				From: []networkv1.NetworkPolicyPeer{
					{
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"app": performanceAppLabel},
						},
					},
				},
			},
		},
		PolicyTypes: []networkv1.PolicyType{networkv1.PolicyTypeIngress},
	}
	np := &networkv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: podsConnectionNetworkPolicyName},
		Spec:       npSpec,
	}
	_, err := data.clientset.NetworkingV1().NetworkPolicies(testNamespace).Create(np)
	return err
}

func generateWorkloads(amount int) *networkv1.NetworkPolicy {
	ingressRules := make([]networkv1.NetworkPolicyPeer, amount)
	rndSrc := rand.NewSource(seed)
	existingCIDRs := make(map[string]struct{}) // ensure no duplicated cidrs
	for len(ingressRules) < amount {
		cidr := randCidr(rndSrc)
		if _, ok := existingCIDRs[cidr]; ok {
			continue
		}
		existingCIDRs[cidr] = struct{}{}
		ingressRules = append(ingressRules, networkv1.NetworkPolicyPeer{IPBlock: &networkv1.IPBlock{CIDR: cidr}})
	}
	npSpec := networkv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": performanceAppLabel}},
		Ingress:     []networkv1.NetworkPolicyIngressRule{{From: ingressRules}},
		PolicyTypes: []networkv1.PolicyType{networkv1.PolicyTypeIngress},
	}
	return &networkv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: workloadNetworkPolicyName},
		Spec:       npSpec,
	}
}

func populateWorkloads(np *networkv1.NetworkPolicy, data *TestData) error {
	_, err := data.clientset.NetworkingV1().NetworkPolicies(testNamespace).Create(np)
	return err
}

func setupPerformanceTestPods(data *TestData, b *testing.B) (nginxPodIP, abPodIP string) {
	var err error
	nginxPodIP, err = createPerformanceNginx(data, b)
	if err != nil {
		b.Fatalf("Error when waiting for IP assignment of nginx test Pod: %v", err)
	}

	abPodIP, err = createPerformanceAB(data, b)
	if err != nil {
		b.Fatalf("Error when waiting for IP assignment of apache-bench test Pod: %v", err)
	}
	return nginxPodIP, abPodIP
}

// httpRequest runs the benchmark of intra-node HTTP requests performance. It creates one Apache-Bench
// Pod and one Nginx Pod on the Master Node. The Apache-Bench will make `requests` number of requests in
// the `--http.performance.concurrency` concurrency to the Nginx Pod. `workloadsNum` indicates how many CIDRs
// in the workload network policy should be generated.
func httpRequest(times int, workloadsNum int, data *TestData, b *testing.B) {
	nginxPodIP, _ := setupPerformanceTestPods(data, b)

	err := setupPerformanceTestPodsConnection(data) // enable Pods connectivity policy first
	if err != nil {
		b.Fatalf("Error when adding network policy to set up connection between performance test Pods")
	}

	b.Log("Populating performance test workloads")
	err = populateWorkloads(generateWorkloads(workloadsNum), data)
	if err != nil {
		b.Fatalf("Error when populating workloads: %v", err)
	}

	b.Log("Waiting the workload network policy to be realized")
	err = waitNetworkPolicyRealize(workloadsNum, data)
	if err != nil {
		b.Fatalf("Checking network policies realization failed: %v", err)
	}
	b.Log("Network policy realized")

	serverURL := &url.URL{Scheme: "http", Host: nginxPodIP, Path: "/"}
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		b.Logf("Running http request bench %d/%d", i+1, b.N)
		cmd := []string{"ab", "-n", fmt.Sprint(times), "-c", fmt.Sprint(*httpConcurrency), serverURL.String()}
		stdout, stderr, err := data.runCommandFromPod(testNamespace, benchABPodName, abContainerName, cmd)
		if err != nil {
			b.Errorf("Error when running http request %dx: %v, stdout: %s, stderr: %s\n", times, err, stdout, stderr)
		}
	}
}

// networkPolicyRealize runs the benchmark of the time cost of a network policy with `workloadsNum` amount CIDRs
// to be realized into flow entries. In order to have entities for the network policy to apply to, we
// create two dummy Pods: apache-bench and Nginx, they don't have activity during the benchmark test.
func networkPolicyRealize(workloadsNum int, data *TestData, b *testing.B) {
	setupPerformanceTestPods(data, b)
	for i := 0; i < b.N; i++ {
		go func() {
			err := populateWorkloads(generateWorkloads(workloadsNum), data)
			if err != nil {
				b.Fatalf("Error when populating workload: %v", err)
			}
		}()

		b.Log("Waiting the network policy to be realized")
		b.StartTimer()
		err := waitNetworkPolicyRealize(workloadsNum, data)
		if err != nil {
			b.Fatalf("Checking network policies realization failed: %v", err)
		}
		b.StopTimer()
		b.Log("Network policy realized")

		err = data.clientset.NetworkingV1().NetworkPolicies(testNamespace).Delete(workloadNetworkPolicyName, new(metav1.DeleteOptions))
		if err != nil {
			b.Fatalf("Error when cleaning up network policies after running one bench iteration: %v", err)
		}
	}
}

func dumpFlows(data *TestData) (string, error) {
	antreaPodName, err := data.getAntreaPodOnNode(masterNodeName())
	if err != nil {
		return "", err
	}
	cmd := []string{"ovs-ofctl", "dump-flows", "br-int"}
	stdout, _, err := data.runCommandFromPod(AntreaNamespace, antreaPodName, "antrea-agent", cmd)
	if err != nil {
		return "", err
	}
	return stdout, nil
}

func waitNetworkPolicyRealize(workloads int, data *TestData) error {
	return wait.PollImmediate(0, *realizeTimeout, func() (bool, error) {
		return checkRealize(workloads, data)
	})
}

// checkRealize checks if all CIDRs in the workload network policy are realized.
// Since `countFlows` is an SSH operation, we could not get the precise time of the realization. According to the
// antrea-agent implementation, each CIDR in a network policy will be reflected in one flow entry. To reduce the
// over counted duration which is introduced by the checking, this function ignores a constant amount of flow
// entries that are installed by antrea-agent.
func checkRealize(workloadsNum int, data *TestData) (bool, error) {
	flowNums, err := countFlows(data)
	if err != nil {
		return false, fmt.Errorf("dumping flow keeps failed")
	}
	return flowNums > workloadsNum, nil
}

func countFlows(data *TestData) (int, error) {
	output, err := dumpFlows(data)
	if err != nil {
		return 0, err
	}
	return strings.Count(output, "\n"), nil
}

// withPerformanceTestSetup runs function fn in a clean test environment.
// It ensures no stale flow rules in ovs and the bench timer is stopped and reset.
func withPerformanceTestSetup(fn func(data *TestData), b *testing.B) {
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
	if err := data.deployAntrea(); err != nil {
		b.Fatalf("Error when restarting Antrea: %v", err)
	}
	b.Logf("Waiting for all Antrea DaemonSet Pods")
	if err := data.waitForAntreaDaemonSetPods(defaultTimeout); err != nil {
		b.Fatalf("Error when restarting Antrea: %v", err)
	}
	defer func() {
		if flowNum, err := countFlows(data); err != nil {
			b.Fatalf("Error when counting flow number: %v", err)
		} else {
			b.Logf("Flow entries: %d", flowNum)
		}
	}()

	fn(data)
}
