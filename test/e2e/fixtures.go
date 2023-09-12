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
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	v1net "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/component-base/featuregate"

	"antrea.io/antrea/pkg/agent/config"
	crdv1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/pkg/features"
	"antrea.io/antrea/test/e2e/utils"
)

func skipIfNotBenchmarkTest(tb testing.TB) {
	if !testOptions.withBench {
		tb.Skipf("Skipping benchmark test: %s", tb.Name())
	}
}

func skipIfNotAntreaIPAMTest(tb testing.TB) {
	if !testOptions.enableAntreaIPAM {
		tb.Skipf("Skipping AntreaIPAM test: %s", tb.Name())
	}
}

func skipIfAntreaIPAMTest(tb testing.TB) {
	if testOptions.enableAntreaIPAM {
		tb.Skipf("Skipping test when running AntreaIPAM: %s", tb.Name())
	}
}

func skipIfAntreaPolicyDisabled(tb testing.TB) {
	skipIfFeatureDisabled(tb, features.AntreaPolicy, true, true)
}

func skipIfNotFlowVisibilityTest(tb testing.TB) {
	if !testOptions.flowVisibility {
		tb.Skipf("Skipping when not running flow visibility test")
	}
}

func skipIfNamespaceIsNotEqual(tb testing.TB, actualNamespace, expectNamespace string) {
	if actualNamespace != expectNamespace {
		tb.Skipf("Skipping test when namespace is not: %s", expectNamespace)
	}
}

func skipIfProviderIs(tb testing.TB, name string, reason string) {
	if testOptions.ProviderName == name {
		tb.Skipf("Skipping test for the '%s' provider: %s", name, reason)
	}
}

func skipIfNotRequired(tb testing.TB, keys ...string) {
	for _, v := range keys {
		if strings.Contains(testOptions.skipCases, v) {
			tb.Skipf("Skipping test as %s is in skip list %s", v, testOptions.skipCases)
		}
	}
}

func skipIfNumNodesLessThan(tb testing.TB, required int) {
	if clusterInfo.numNodes < required {
		tb.Skipf("Skipping test as it requires %d different Nodes but cluster only has %d", required, clusterInfo.numNodes)
	}
}

func skipIfRunCoverage(tb testing.TB, reason string) {
	if testOptions.EnableCoverage {
		tb.Skipf("Skipping test for the '%s' when run coverage: %s", tb.Name(), reason)
	}
}

func skipIfNotIPv4Cluster(tb testing.TB) {
	if clusterInfo.podV4NetworkCIDR == "" {
		tb.Skipf("Skipping test as it requires IPv4 addresses but the IPv4 network CIDR is not set")
	}
}

func SkipIfIPv6Cluster(tb testing.TB) {
	if clusterInfo.podV6NetworkCIDR != "" {
		tb.Skipf("Skipping test as it is not supported in IPv6 cluster")
	}
}

func skipIfNotIPv6Cluster(tb testing.TB) {
	if clusterInfo.podV6NetworkCIDR == "" {
		tb.Skipf("Skipping test as it requires IPv6 addresses but the IPv6 network CIDR is not set")
	}
}

func skipIfMissingKernelModule(tb testing.TB, data *TestData, nodeName string, requiredModules []string) {
	for _, module := range requiredModules {
		// modprobe with "--dry-run" does not require root privileges
		cmd := fmt.Sprintf("modprobe --dry-run %s", module)
		rc, stdout, stderr, err := data.RunCommandOnNode(nodeName, cmd)
		if err != nil {
			tb.Skipf("Skipping test as modprobe could not be run to confirm the presence of module '%s': %v", module, err)
		}
		if rc != 0 {
			tb.Skipf("Skipping test as modprobe exited with an error when trying to confirm the presence of module '%s' - stdout: %s - stderr: %s", module, stdout, stderr)
		}
	}
	tb.Logf("The following modules have been found on Node '%s': %v", nodeName, requiredModules)
}

func skipIfEncapModeIsNot(tb testing.TB, data *TestData, encapMode config.TrafficEncapModeType) {
	currentEncapMode, err := data.GetEncapMode()
	if err != nil {
		tb.Fatalf("Failed to get encap mode: %v", err)
	}
	if currentEncapMode != encapMode {
		tb.Skipf("Skipping test for encap mode '%s', test requires '%s'", currentEncapMode.String(), encapMode.String())
	}
}

func skipIfHasWindowsNodes(tb testing.TB) {
	if len(clusterInfo.windowsNodes) != 0 {
		tb.Skipf("Skipping test as the cluster has Windows Nodes")
	}
}

func skipIfNoWindowsNodes(tb testing.TB) {
	if len(clusterInfo.windowsNodes) == 0 {
		tb.Skipf("Skipping test as the cluster has no Windows Nodes")
	}
}

func skipIfNoVMs(tb testing.TB) {
	if testOptions.linuxVMs == "" && testOptions.windowsVMs == "" {
		tb.Skipf("Skipping test as there no Linux or Windows VMs")
	}
}

func skipIfFeatureDisabled(tb testing.TB, feature featuregate.Feature, checkAgent bool, checkController bool) {
	if checkAgent {
		if featureGate, err := GetAgentFeatures(); err != nil {
			tb.Fatalf("Cannot determine if %s is enabled in the Agent: %v", feature, err)
		} else if !featureGate.Enabled(feature) {
			tb.Skipf("Skipping test because %s is not enabled in the Agent", feature)
		}
	}
	if checkController {
		if featureGate, err := GetControllerFeatures(); err != nil {
			tb.Fatalf("Cannot determine if %s is enabled in the Controller: %v", feature, err)
		} else if !featureGate.Enabled(feature) {
			tb.Skipf("Skipping test because %s is not enabled in the Controller", feature)
		}
	}
}

func skipIfProxyDisabled(t *testing.T) {
	skipIfFeatureDisabled(t, features.AntreaProxy, true /* checkAgent */, false /* checkController */)
}

func skipIfProxyAllDisabled(t *testing.T, data *TestData) {
	isProxyAll, err := data.isProxyAll()
	if err != nil {
		t.Fatalf("Error getting option antreaProxy.proxyAll value")
	}
	if !isProxyAll {
		t.Skipf("Skipping test because option antreaProxy.proxyAll is not enabled")
	}
}

func EnsureAntreaRunning(data *TestData) error {
	if testOptions.DeployAntrea {
		log.Println("Applying Antrea YAML")
		if err := data.deployAntrea(deployAntreaDefault); err != nil {
			return err
		}
	}
	log.Println("Waiting for all Antrea DaemonSet Pods")
	if err := data.waitForAntreaDaemonSetPods(defaultTimeout); err != nil {
		return err
	}
	log.Println("Checking CoreDNS deployment")
	if err := data.checkCoreDNSPods(defaultTimeout); err != nil {
		return err
	}
	return nil
}

func createDirectory(path string) error {
	return os.Mkdir(path, 0700)
}

func (data *TestData) setupLogDirectoryForTest(testName string) error {
	// sanitize the testName: it can contain '/' if the test is a subtest
	testName = strings.ReplaceAll(testName, string(filepath.Separator), "_")
	path := filepath.Join(testOptions.logsExportDir, testName)
	// remove directory if it already exists. This ensures that we start with an empty
	// directory
	_ = os.RemoveAll(path)
	err := createDirectory(path)
	if err != nil {
		return err
	}
	data.logsDirForTestCase = path
	return nil
}

func SetupTest(tb testing.TB) (*TestData, error) {
	if err := testData.setupLogDirectoryForTest(tb.Name()); err != nil {
		tb.Errorf("Error creating logs directory '%s': %v", testData.logsDirForTestCase, err)
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			tb.Fail()
			exportLogs(tb, testData, "afterSetupTest", true)
		}
	}()
	// sanitize the name: the final name must be a valid lowercase RFC 1123 label
	name := tb.Name()
	// 50 is a conservative length here (we will append a random suffix)
	if len(name) > 50 {
		name = name[:50]
	}
	replacer := strings.NewReplacer("/", "-", ",", "-", ":", "-")
	name = replacer.Replace(name)
	name = strings.ToLower(name)
	testData.testNamespace = RandName(name + "-")
	tb.Logf("Creating '%s' K8s Namespace", testData.testNamespace)
	if err := EnsureAntreaRunning(testData); err != nil {
		return nil, err
	}
	if err := testData.CreateNamespace(testData.testNamespace, nil); err != nil {
		return nil, err
	}
	success = true
	return testData, nil
}

func setupTestForFlowAggregator(tb testing.TB, o flowVisibilityTestOptions) (*TestData, bool, bool, error) {
	v4Enabled := clusterInfo.podV4NetworkCIDR != ""
	v6Enabled := clusterInfo.podV6NetworkCIDR != ""
	testData, err := SetupTest(tb)
	if err != nil {
		return testData, v4Enabled, v6Enabled, err
	}
	// Create pod using ipfix collector image
	if err := NewPodBuilder("ipfix-collector", testData.testNamespace, ipfixCollectorImage).InHostNetwork().Create(testData); err != nil {
		tb.Errorf("Error when creating the ipfix collector Pod: %v", err)
	}
	ipfixCollectorIP, err := testData.podWaitForIPs(defaultTimeout, "ipfix-collector", testData.testNamespace)
	if err != nil || len(ipfixCollectorIP.ipStrings) == 0 {
		tb.Errorf("Error when waiting to get ipfix collector Pod IP: %v", err)
		return nil, v4Enabled, v6Enabled, err
	}
	var ipStr string
	if v6Enabled && ipfixCollectorIP.ipv6 != nil {
		ipStr = ipfixCollectorIP.ipv6.String()
	} else {
		ipStr = ipfixCollectorIP.ipv4.String()
	}
	ipfixCollectorAddr := fmt.Sprintf("%s:tcp", net.JoinHostPort(ipStr, ipfixCollectorPort))

	tb.Logf("Deploying ClickHouse")
	chSvcIP, err := testData.deployFlowVisibilityClickHouse(o)
	if err != nil {
		return testData, v4Enabled, v6Enabled, err
	}
	tb.Logf("ClickHouse Service created with ClusterIP: %v", chSvcIP)
	tb.Logf("Applying flow aggregator YAML with ipfix collector: %s and clickHouse enabled",
		ipfixCollectorAddr)

	if err := testData.deployFlowAggregator(ipfixCollectorAddr, o); err != nil {
		return testData, v4Enabled, v6Enabled, err
	}

	return testData, v4Enabled, v6Enabled, nil
}

func exportLogsForSubtest(tb testing.TB, data *TestData) func() {
	substrings := strings.Split(tb.Name(), "/")
	subDir := substrings[len(substrings)-1]
	return func() {
		exportLogs(tb, data, subDir, true)
	}
}

func exportLogs(tb testing.TB, data *TestData, logsSubDir string, writeNodeLogs bool) {
	if tb.Skipped() {
		return
	}
	// if test was successful and --logs-export-on-success was not provided, we do not export
	// any logs.
	if !tb.Failed() && !testOptions.logsExportOnSuccess {
		return
	}
	const timeFormat = "Jan02-15-04-05"
	timeStamp := time.Now().Format(timeFormat)
	logsDir := filepath.Join(data.logsDirForTestCase, fmt.Sprintf("%s.%s", logsSubDir, timeStamp))
	err := createDirectory(logsDir)
	if err != nil {
		tb.Errorf("Error when creating logs directory '%s': %v", logsDir, err)
		return
	}
	tb.Logf("Exporting test logs to '%s'", logsDir)
	// for now we just retrieve the logs for the Antrea Pods, but maybe we can find a good way to
	// retrieve the logs for the test Pods in the future (before deleting them) if it is useful
	// for debugging.

	// getPodWriter creates the file with name nodeName-podName-suffix. It returns nil if the
	// file cannot be created. File must be closed by the caller.
	getPodWriter := func(nodeName, podName, suffix string) *os.File {
		logFile := filepath.Join(logsDir, fmt.Sprintf("%s-%s-%s", nodeName, podName, suffix))
		f, err := os.Create(logFile)
		if err != nil {
			tb.Errorf("Error when creating log file '%s': '%v'", logFile, err)
			return nil
		}
		return f
	}

	// runKubectl runs the provided kubectl command on the control-plane Node and returns the
	// output. It returns an empty string in case of error.
	runKubectl := func(cmd string) string {
		rc, stdout, _, err := data.RunCommandOnNode(controlPlaneNodeName(), cmd)
		if err != nil || rc != 0 {
			tb.Errorf("Error when running this kubectl command on control-plane Node: %s", cmd)
			return ""
		}
		return stdout
	}

	// dump the logs for Antrea Pods to disk.
	writePodLogs := func(nodeName, podName, nsName string) error {
		w := getPodWriter(nodeName, podName, "logs")
		if w == nil {
			return nil
		}
		defer w.Close()
		cmd := fmt.Sprintf("kubectl -n %s logs --all-containers %s", nsName, podName)
		stdout := runKubectl(cmd)
		if stdout == "" {
			return nil
		}
		w.WriteString(stdout)
		return nil
	}
	data.forAllMatchingPodsInNamespace("k8s-app=kube-proxy", kubeNamespace, writePodLogs)

	data.forAllMatchingPodsInNamespace("app=antrea", antreaNamespace, writePodLogs)

	// dump the logs for monitoring Pods to disk.
	data.forAllMatchingPodsInNamespace("", monitoringNamespace, writePodLogs)

	// dump the logs for flow-aggregator Pods to disk.
	data.forAllMatchingPodsInNamespace("", flowAggregatorNamespace, writePodLogs)

	// dump the logs for flow-visibility Pods to disk.
	data.forAllMatchingPodsInNamespace("", flowVisibilityNamespace, writePodLogs)

	// dump the logs for clickhouse operator Pods to disk.
	data.forAllMatchingPodsInNamespace("app=clickhouse-operator", kubeNamespace, writePodLogs)

	// dump the output of "kubectl describe" for Antrea pods to disk.
	data.forAllMatchingPodsInNamespace("app=antrea", antreaNamespace, func(nodeName, podName, nsName string) error {
		w := getPodWriter(nodeName, podName, "describe")
		if w == nil {
			return nil
		}
		defer w.Close()
		cmd := fmt.Sprintf("kubectl -n %s describe pod %s", nsName, podName)
		stdout := runKubectl(cmd)
		if stdout == "" {
			return nil
		}
		w.WriteString(stdout)
		return nil
	})

	if !writeNodeLogs {
		return
	}
	// getNodeWriter creates the file with name nodeName-suffix. It returns nil if the file
	// cannot be created. File must be closed by the caller.
	getNodeWriter := func(nodeName, suffix string) *os.File {
		logFile := filepath.Join(logsDir, fmt.Sprintf("%s-%s", nodeName, suffix))
		f, err := os.Create(logFile)
		if err != nil {
			tb.Errorf("Error when creating log file '%s': '%v'", logFile, err)
			return nil
		}
		return f
	}
	// export kubelet logs with journalctl for each Node. If the Nodes do not use journalctl we
	// print a log message. If kubelet is not run with systemd, the log file will be empty.
	if err := forAllNodes(func(nodeName string) error {
		const numLines = 100
		// --no-pager ensures the command does not hang.
		cmd := fmt.Sprintf("journalctl -u kubelet -n %d --no-pager", numLines)
		if clusterInfo.nodesOS[nodeName] == "windows" {
			cmd = "Get-EventLog -LogName \"System\" -Source \"Service Control Manager\" | grep kubelet ; Get-EventLog -LogName \"Application\" -Source \"nssm\" | grep kubelet"
		}
		rc, stdout, _, err := data.RunCommandOnNode(nodeName, cmd)
		if err != nil || rc != 0 {
			// return an error and skip subsequent Nodes
			return fmt.Errorf("error when running journalctl on Node '%s', is it available? Error: %v", nodeName, err)
		}
		w := getNodeWriter(nodeName, "kubelet")
		if w == nil {
			// move on to the next Node
			return nil
		}
		defer w.Close()
		w.WriteString(stdout)
		return nil
	}); err != nil {
		tb.Logf("Error when exporting kubelet logs: %v", err)
	}

	writeVMAgentLog := func(cmd string, targetVMs string) {
		vms := strings.Split(targetVMs, " ")
		for _, vm := range vms {
			tb.Logf("Exporting logs from %s", vm)
			_, stdout, _, err := data.RunCommandOnNode(vm, cmd)
			if err != nil {
				tb.Errorf("Error when exporting antrea-agent logs from %s: %v", vm, err)
			}
			w := getNodeWriter(vm, "antrea-agent")
			if w == nil {
				// move on to the next VM
				continue
			}
			w.WriteString(stdout)
			w.Close()
		}
	}
	if testOptions.linuxVMs != "" {
		cmd := "cat /var/log/antrea/antrea-agent.log"
		writeVMAgentLog(cmd, testOptions.linuxVMs)
	}
	if testOptions.windowsVMs != "" {
		cmd := "cat c:/antrea-agent/logs/antrea-agent.log"
		writeVMAgentLog(cmd, testOptions.windowsVMs)
	}
}

// PrintResults summarizes test results for all the testcases
func PrintResults() {
	fmt.Printf("\n---------------- Test Results ------------------\n")
	failCount := 0
	for _, testCase := range allTestList {
		fmt.Printf("Test %s:\n", testCase.Name)
		testFailed := false
		for _, step := range testCase.Steps {
			if step.Reachability == nil {
				continue
			}
			_, wrong, comparison := step.Reachability.Summary()
			var result string
			if wrong == 0 {
				result = "success"
			} else {
				result = fmt.Sprintf("failure -- %d wrong results", wrong)
				testFailed = true
			}
			fmt.Printf("\tStep %s on port %d, duration %d seconds, result: %s\n",
				step.Name, step.Ports, int(step.Duration.Seconds()), result)
			if wrong != 0 {
				fmt.Printf("\n%s\n", comparison.PrettyPrint("\t\t"))
			}
		}
		if testFailed {
			failCount++
		}
	}
	fmt.Printf("=== TEST FAILURES: %d/%d ===\n\n", failCount, len(allTestList))
}

// common for all tests.
var (
	allPods                                     []Pod
	podsByNamespace                             map[string][]Pod
	k8sUtils                                    *KubernetesUtils
	allTestList                                 []*TestCase
	pods                                        []string
	namespaces                                  map[string]string
	podIPs                                      map[string][]string
	p80, p81, p8080, p8081, p8082, p8085, p6443 int32
)

func failOnError(err error, t *testing.T) {
	if err != nil {
		log.Errorf("%+v", err)
		k8sUtils.Cleanup(namespaces)
		t.Fatalf("test failed: %v", err)
	}
}

func InitializeTestbed(t *testing.T, data *TestData) {
	p80 = 80
	p81 = 81
	p8080 = 8080
	p8081 = 8081
	p8082 = 8082
	p8085 = 8085
	pods = []string{"a", "b", "c"}
	namespaces = make(map[string]string)
	suffix := RandName("")
	namespaces["x"] = "x-" + suffix
	namespaces["y"] = "y-" + suffix
	namespaces["z"] = "z-" + suffix
	// This function "InitializeTestbed" will be used more than once, and variable "allPods" is global.
	// It should be empty every time when "InitializeTestbed" is performed, otherwise there will be unexpected
	// results.
	allPods = []Pod{}
	podsByNamespace = make(map[string][]Pod)

	for _, podName := range pods {
		for _, ns := range namespaces {
			allPods = append(allPods, NewPod(ns, podName))
			podsByNamespace[ns] = append(podsByNamespace[ns], NewPod(ns, podName))
		}
	}
	skipIfAntreaPolicyDisabled(t)

	var err error
	// k8sUtils is a global var
	k8sUtils, err = NewKubernetesUtils(data)
	failOnError(err, t)
	ips, err := k8sUtils.Bootstrap(namespaces, pods, true)
	failOnError(err, t)
	podIPs = ips
}

func GetTestbedK8sUtils() *KubernetesUtils {
	return k8sUtils
}

func GetTestbedNamespaces() (map[string][]Pod, map[string]string) {
	return podsByNamespace, namespaces
}

func GetTestbedPods() ([]Pod, []string, map[string][]string) {
	return allPods, pods, podIPs
}

// ExecuteTests runs all the tests in testList and prints results
func ExecuteTests(t *testing.T, testList []*TestCase) {
	executeTestsWithData(t, testList, nil)
}

func executeTestsWithData(t *testing.T, testList []*TestCase, data *TestData) {
	for _, testCase := range testList {
		log.Infof("running test case %s", testCase.Name)
		for _, step := range testCase.Steps {
			log.Infof("running step %s of test case %s", step.Name, testCase.Name)
			applyTestStepResources(t, step)

			reachability := step.Reachability
			if reachability != nil {
				start := time.Now()
				k8sUtils.Validate(allPods, reachability, step.Ports, step.Protocol)
				step.Duration = time.Now().Sub(start)

				_, wrong, _ := step.Reachability.Summary()
				if wrong != 0 {
					t.Errorf("Failure -- %d wrong results", wrong)
					reachability.PrintSummary(true, true, true)
				}
			}
			if len(step.CustomProbes) > 0 && data == nil {
				t.Errorf("test case %s with custom probe must set test data", testCase.Name)
				continue
			}
			for _, p := range step.CustomProbes {
				doProbe(t, data, p, step.Protocol)
			}
		}
		log.Debug("Cleaning-up all policies and groups created by this Testcase")
		cleanupTestCaseResources(t, testCase)
	}
	allTestList = append(allTestList, testList...)
}

func doProbe(t *testing.T, data *TestData, p *CustomProbe, protocol utils.AntreaPolicyProtocol) {
	// Bootstrap Pods
	_, _, srcPodCleanupFunc := createAndWaitForPodWithLabels(t, data, data.createServerPodWithLabels, p.SourcePod.Pod.PodName(), p.SourcePod.Pod.Namespace(), p.Port, p.SourcePod.Labels)
	defer srcPodCleanupFunc()
	_, _, dstPodCleanupFunc := createAndWaitForPodWithLabels(t, data, data.createServerPodWithLabels, p.DestPod.Pod.PodName(), p.DestPod.Pod.Namespace(), p.Port, p.DestPod.Labels)
	defer dstPodCleanupFunc()
	log.Tracef("Probing: %s -> %s", p.SourcePod.Pod.PodName(), p.DestPod.Pod.PodName())
	connectivity, err := k8sUtils.Probe(p.SourcePod.Pod.Namespace(), p.SourcePod.Pod.PodName(), p.DestPod.Pod.Namespace(), p.DestPod.Pod.PodName(), p.Port, protocol, nil, &p.ExpectConnectivity)
	if err != nil {
		t.Errorf("Failure -- could not complete probe: %v", err)
	}
	if connectivity != p.ExpectConnectivity {
		t.Errorf("Failure -- wrong results for custom probe: Source %s/%s --> Dest %s/%s connectivity: %v, expected: %v",
			p.SourcePod.Pod.Namespace(), p.SourcePod.Pod.PodName(), p.DestPod.Pod.Namespace(), p.DestPod.Pod.PodName(), connectivity, p.ExpectConnectivity)
	}
}

// applyTestStepResources creates in the resources of a testStep in specified order.
// The ordering can be used to test different scenarios, like creating an ACNP before
// creating its referred ClusterGroup, and vice versa.
func applyTestStepResources(t *testing.T, step *TestStep) {
	for _, r := range step.TestResources {
		switch o := r.(type) {
		case *crdv1beta1.ClusterNetworkPolicy:
			_, err := k8sUtils.CreateOrUpdateACNP(o)
			failOnError(err, t)
		case *crdv1beta1.NetworkPolicy:
			_, err := k8sUtils.CreateOrUpdateANNP(o)
			failOnError(err, t)
		case *v1net.NetworkPolicy:
			_, err := k8sUtils.CreateOrUpdateNetworkPolicy(o)
			failOnError(err, t)
		case *crdv1beta1.ClusterGroup:
			_, err := k8sUtils.CreateOrUpdateCG(o)
			failOnError(err, t)
		case *crdv1beta1.Group:
			_, err := k8sUtils.CreateOrUpdateGroup(o)
			failOnError(err, t)
		case *v1.Service:
			_, err := k8sUtils.CreateOrUpdateService(o)
			failOnError(err, t)
		}

	}
	failOnError(waitForResourcesReady(t, 10*time.Second, step.TestResources...), t)
}

func cleanupTestCaseResources(t *testing.T, c *TestCase) {
	// TestSteps in a TestCase may first create and then update the same resource.
	// Use sets to avoid duplicates.
	acnpsToDelete, annpsToDelete, npsToDelete := sets.Set[string]{}, sets.Set[string]{}, sets.Set[string]{}
	svcsToDelete, v1a3ClusterGroupsToDelete, v1a3GroupsToDelete := sets.Set[string]{}, sets.Set[string]{}, sets.Set[string]{}
	for _, step := range c.Steps {
		for _, r := range step.TestResources {
			switch o := r.(type) {
			case *crdv1beta1.ClusterNetworkPolicy:
				acnpsToDelete.Insert(o.Name)
			case *crdv1beta1.NetworkPolicy:
				annpsToDelete.Insert(o.Namespace + "/" + o.Name)
			case *v1net.NetworkPolicy:
				npsToDelete.Insert(o.Namespace + "/" + o.Name)
			case *crdv1beta1.ClusterGroup:
				v1a3ClusterGroupsToDelete.Insert(o.Name)
			case *crdv1beta1.Group:
				v1a3GroupsToDelete.Insert(o.Namespace + "/" + o.Name)
			case *v1.Service:
				svcsToDelete.Insert(o.Namespace + "/" + o.Name)
			}
		}
	}
	for acnp := range acnpsToDelete {
		failOnError(k8sUtils.DeleteACNP(acnp), t)
	}
	for annp := range annpsToDelete {
		namespace := strings.Split(annp, "/")[0]
		name := strings.Split(annp, "/")[1]
		failOnError(k8sUtils.DeleteANNP(namespace, name), t)
	}
	for np := range npsToDelete {
		namespace := strings.Split(np, "/")[0]
		name := strings.Split(np, "/")[1]
		failOnError(k8sUtils.DeleteNetworkPolicy(namespace, name), t)
	}
	for cg := range v1a3ClusterGroupsToDelete {
		failOnError(k8sUtils.DeleteCG(cg), t)
	}
	for grp := range v1a3GroupsToDelete {
		namespace := strings.Split(grp, "/")[0]
		name := strings.Split(grp, "/")[1]
		failOnError(k8sUtils.DeleteGroup(namespace, name), t)
	}
	for svc := range svcsToDelete {
		namespace := strings.Split(svc, "/")[0]
		name := strings.Split(svc, "/")[1]
		failOnError(k8sUtils.DeleteService(namespace, name), t)
	}
}

func waitForResourceReady(t *testing.T, timeout time.Duration, obj metav1.Object) error {
	defer timeCost()("ready")
	switch p := obj.(type) {
	case *crdv1beta1.ClusterNetworkPolicy:
		return k8sUtils.waitForACNPRealized(t, p.Name, timeout)
	case *crdv1beta1.NetworkPolicy:
		return k8sUtils.waitForANNPRealized(t, p.Namespace, p.Name, timeout)
	case *v1net.NetworkPolicy:
		time.Sleep(100 * time.Millisecond)
	case *v1.Service:
		// The minInterval of AntreaProxy's BoundedFrequencyRunner is 1s, which means a Service may be handled after 1s.
		time.Sleep(1 * time.Second)
	case *crdv1beta1.Tier:
	case *crdv1beta1.ClusterGroup:
	case *crdv1beta1.Group:
	}
	return nil
}

func waitForResourcesReady(t *testing.T, timeout time.Duration, objs ...metav1.Object) error {
	resultCh := make(chan error, len(objs))
	for _, obj := range objs {
		go func(o metav1.Object) {
			resultCh <- waitForResourceReady(t, timeout, o)
		}(obj)
	}

	for i := 0; i < len(objs); i++ {
		if err := <-resultCh; err != nil {
			return err
		}
	}
	return nil
}

func teardownFlowAggregator(tb testing.TB, data *TestData) {
	if testOptions.EnableCoverage {
		if err := testData.gracefulExitFlowAggregator(testOptions.coverageDir); err != nil {
			tb.Fatalf("Error when gracefully exiting Flow Aggregator: %v", err)
		}
	}
	tb.Logf("Deleting '%s' K8s Namespace", flowAggregatorNamespace)
	if err := data.DeleteNamespace(flowAggregatorNamespace, defaultTimeout); err != nil {
		tb.Logf("Error when tearing down flow aggregator: %v", err)
	}
	tb.Logf("Deleting K8s resources created by flow visibility YAML")
	if err := data.deleteFlowVisibility(); err != nil {
		tb.Logf("Error when deleting K8s resources created by flow visibility YAML: %v", err)
	}
	tb.Logf("Deleting '%s' K8s Namespace", flowVisibilityNamespace)
	if err := data.DeleteNamespace(flowVisibilityNamespace, defaultTimeout); err != nil {
		tb.Logf("Error when deleting flow-visibility namespace: %v", err)
	}
	tb.Logf("Deleting ClickHouse Operator")
	if err := data.deleteClickHouseOperator(); err != nil {
		tb.Logf("Error when removing ClickHouse Operator: %v", err)
	}
}

func TeardownTest(tb testing.TB, data *TestData) {
	exportLogs(tb, data, "beforeTeardown", true)
	if empty, _ := IsDirEmpty(data.logsDirForTestCase); empty {
		_ = os.Remove(data.logsDirForTestCase)
	}
	tb.Logf("Deleting '%s' K8s Namespace", testData.testNamespace)
	if err := data.DeleteNamespace(testData.testNamespace, -1); err != nil {
		tb.Logf("Error when tearing down test: %v", err)
	}
}

func deletePodWrapper(tb testing.TB, data *TestData, namespace, name string) {
	tb.Logf("Deleting Pod '%s'", name)
	if err := data.DeletePod(namespace, name); err != nil {
		tb.Logf("Error when deleting Pod: %v", err)
	}
}

// createTestBusyboxPods creates the desired number of busybox Pods and wait for their IP address to
// become available. This is a common patter in our tests, so having this helper function makes
// sense. It calls Fatalf in case of error, so it must be called from the goroutine running the test
// or benchmark function. You can create all the Pods on the same Node by setting nodeName. If
// nodeName is the empty string, each Pod will be created on an arbitrary
// Node. createTestBusyboxPods returns the cleanupFn function which can be used to delete the
// created Pods. Pods are created in parallel to reduce the time required to run the tests.
func createTestBusyboxPods(tb testing.TB, data *TestData, num int, ns string, nodeName string) (
	podNames []string, podIPs []*PodIPs, cleanupFn func(),
) {
	return createTestPods(tb, data, num, ns, nodeName, false, data.createBusyboxPodOnNode)
}

func createTestAgnhostPods(tb testing.TB, data *TestData, num int, ns string, nodeName string) (
	podNames []string, podIPs []*PodIPs, cleanupFn func(),
) {
	return createTestPods(tb, data, num, ns, nodeName, false, data.createAgnhostPodOnNode)
}

func createTestPods(tb testing.TB, data *TestData, num int, ns string, nodeName string, hostNetwork bool, createFunc func(string, string, string, bool) error) (
	podNames []string, podIPs []*PodIPs, cleanupFn func(),
) {
	cleanupFn = func() {
		var wg sync.WaitGroup
		for _, podName := range podNames {
			wg.Add(1)
			go func(name string) {
				deletePodWrapper(tb, data, ns, name)
				wg.Done()
			}(podName)
		}
		wg.Wait()
	}

	type podData struct {
		podName string
		podIP   *PodIPs
		err     error
	}

	createPodAndGetIP := func() (string, *PodIPs, error) {
		podName := RandName("test-pod-")
		tb.Logf("Creating a test Pod '%s' and waiting for IP", podName)
		if err := createFunc(podName, ns, nodeName, hostNetwork); err != nil {
			tb.Errorf("Error when creating test Pod '%s': %v", podName, err)
			return "", nil, err
		}
		podIP, err := data.podWaitForIPs(defaultTimeout, podName, ns)
		if err != nil {
			tb.Errorf("Error when waiting for IP for Pod '%s': %v", podName, err)
			return podName, nil, err
		}
		return podName, podIP, nil
	}

	podsCh := make(chan podData, num)

	for i := 0; i < num; i++ {
		go func() {
			podName, podIP, err := createPodAndGetIP()
			podsCh <- podData{podName, podIP, err}
		}()
	}

	errCnt := 0
	for i := 0; i < num; i++ {
		pod := <-podsCh
		if pod.podName != "" {
			podNames = append(podNames, pod.podName)
			podIPs = append(podIPs, pod.podIP)
		}
		if pod.err != nil {
			errCnt++
		}
	}
	if errCnt > 0 {
		defer cleanupFn()
		tb.Fatalf("%d / %d Pods could not be created successfully", errCnt, num)
	}

	return podNames, podIPs, cleanupFn
}
