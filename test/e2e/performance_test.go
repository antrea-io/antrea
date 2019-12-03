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

	customizeTimes    = flag.Int("performance.http.times", 0, "Times of http requests")
	customizeWorkload = flag.Int("performance.http.workload", 0, "Number of network policy workloads")
	httpConcurrency   = flag.Int("performance.http.concurrency", 1, "Number of multiple requests to make at a time")
	realizeTimeout    = flag.Duration("performance.realize.timeout", 5*time.Minute, "Timeout of the realization of network policies")
)

func BenchmarkHTTPRequest(b *testing.B) {
	for _, scale := range []struct{ times, workloads int }{
		{100000, 0},
		{1000000, 0},
		{100000, 5000},
		{100000, 10000},
		{100000, 15000},
	} {
		b.Run(fmt.Sprintf("Request%dWorkloads%d", scale.times, scale.workloads), func(b *testing.B) {
			withPerformanceTestSetup(func(data *TestData) { httpRequest(scale.times, scale.workloads, data, b) }, b)
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
	if *customizeTimes == 0 {
		b.Skip("The value of performance.http.times=0, skipped")
	}
	withPerformanceTestSetup(func(data *TestData) { httpRequest(*customizeTimes, *customizeWorkload, data, b) }, b)
}

func BenchmarkCustomizeRealizeNetworkPolicy(b *testing.B) {
	if *customizeWorkload == 0 {
		b.Skip("The value of performance.http.workload=0, skipped")
	}
	withPerformanceTestSetup(func(data *TestData) { networkPolicyRealize(*customizeWorkload, data, b) }, b)
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

// createPerformanceNginx creates the nginx Pod and wait it to be ready.
func createPerformanceNginx(data *TestData, b *testing.B) (string, error) {
	b.Logf("Creating a nginx test Pod")
	nginxPod := createPerformanceTestPodSpec(benchNginxPodName, nginxContainerName, nginxImage)
	if _, err := data.clientset.CoreV1().Pods(testNamespace).Create(nginxPod); err != nil {
		b.Fatalf("Error when creating nginx test pod: %v", err)
	}
	b.Logf("Waiting IP assignment of the nginx test Pod")
	return data.podWaitForIP(defaultTimeout, benchNginxPodName)
}

// createPerformanceAB creates the apache-bench Pod and wait it to be ready.
func createPerformanceAB(data *TestData, b *testing.B) (string, error) {
	b.Logf("Creating an apache-bench test Pod")
	sleepDuration := "3600" // seconds
	abPod := createPerformanceTestPodSpec(benchABPodName, abContainerName, abImage)
	abPod.Spec.Containers[0].Command = []string{"sleep", sleepDuration}
	if _, err := data.clientset.CoreV1().Pods(testNamespace).Create(abPod); err != nil {
		b.Fatalf("Error when creating apache-bench test Pod: %v", err)
	}
	b.Logf("Waiting IP assignment of the apache-bench test Pod")
	return data.podWaitForIP(defaultTimeout, benchABPodName)
}

// setupPerformanceTestPodsConnection applies the network policy which enable connectivity between test Pods to the cluster.
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

func generateWorkload(amount int) *networkv1.NetworkPolicy {
	var ingressRules []networkv1.NetworkPolicyPeer
	rndSrc := rand.NewSource(seed)
	existed := make(map[string]struct{}) // ensure no duplicated cidrs
	for len(ingressRules) < amount {
		cidr := randCidr(rndSrc)
		if _, ok := existed[cidr]; ok {
			continue
		} else {
			existed[cidr] = struct{}{}
		}
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

func populateWorkload(np *networkv1.NetworkPolicy, data *TestData) error {
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
// Pod and one Nginx Pod on the Master Node. The Apache-Bench would make `times` requests in the
// `--http.performance.concurrency` concurrency to the Nginx Pod. `workloads` indicates how many CIDRs
// in the workload network policy should be generated.
func httpRequest(times int, workloads int, data *TestData, b *testing.B) {
	nginxPodIP, _ := setupPerformanceTestPods(data, b)
	// enable Pods connectivity policy first
	if err := setupPerformanceTestPodsConnection(data); err != nil {
		b.Fatalf("Error when adding network policy to set up connection between performance test Pods")
	}
	b.Log("Populating performance test workloads")
	if err := populateWorkload(generateWorkload(workloads), data); err != nil {
		b.Fatalf("Error when populating workloads: %v", err)
	}

	if err := waitNetworkPolicyRealize(workloads, data); err != nil {
		b.Fatalf("Checking network policies realization failed: %v", err)
	} else {
		b.Log("Network policy realized")
	}

	serverURL := &url.URL{Scheme: "http", Host: nginxPodIP, Path: "/"}
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		b.Logf("Running http request bench %d/%d", i+1, b.N)
		cmd := []string{"ab", "-n", fmt.Sprint(times), "-c", fmt.Sprint(*httpConcurrency), serverURL.String()}
		if stdout, stderr, err := data.runCommandFromPod(testNamespace, benchABPodName, abContainerName, cmd); err != nil {
			b.Errorf("Error when running http request %dx: %v, stdout: %s, stderr: %s\n", times, err, stdout, stderr)
		}
	}
}

// networkPolicyRealize runs the benchmark of time cost of a network policy with `workloads` amount CIDRs
// to be realized into flow entries. In order to have entities for the network policy to apply to, we
// create two dummy Pods: apache-bench and Nginx, they don't have activity during the benchmark test.
func networkPolicyRealize(workloads int, data *TestData, b *testing.B) {
	setupPerformanceTestPods(data, b)
	for i := 0; i < b.N; i++ {
		go func() {
			if err := populateWorkload(generateWorkload(workloads), data); err != nil {
				b.Fatalf("Error when populating workload: %v", err)
			}
		}()

		b.StartTimer()
		if err := waitNetworkPolicyRealize(workloads, data); err != nil {
			b.Fatalf("Checking network policies realization failed: %v", err)
		} else {
			b.Log("Network policy realized")
		}
		b.StopTimer()

		if err := data.clientset.NetworkingV1().NetworkPolicies(testNamespace).Delete(workloadNetworkPolicyName, new(metav1.DeleteOptions)); err != nil {
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
	done := make(chan struct{})
	return wait.WaitFor(
		func(stopCh <-chan struct{}) <-chan struct{} {
			checkCh := make(chan struct{})
			timeout := time.After(*realizeTimeout)
			go func() {
				defer close(done)
				for {
					select {
					case <-stopCh: // realized
						break
					case <-timeout: // timeout
						break
					case checkCh <- struct{}{}: // signal next check
					}
				}
			}()
			return checkCh
		},
		func() (bool, error) { return checkRealize(workloads, data) },
		done,
	)
}

func checkRealize(workloads int, data *TestData) (bool, error) {
	flowNums, err := countFlows(data)
	if err != nil {
		return false, fmt.Errorf("dumping flow keeps failed")
	}
	return flowNums > workloads, nil
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
	b.StopTimer()
}
