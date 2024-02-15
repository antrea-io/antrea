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
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"k8s.io/component-base/featuregate"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/features"
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
	if testOptions.providerName == name {
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
	if testOptions.enableCoverage {
		tb.Skipf("Skipping test for the '%s' when run coverage: %s", tb.Name(), reason)
	}
}

func skipIfNotIPv4Cluster(tb testing.TB) {
	if clusterInfo.podV4NetworkCIDR == "" {
		tb.Skipf("Skipping test as it requires IPv4 addresses but the IPv4 network CIDR is not set")
	}
}

func skipIfIPv6Cluster(tb testing.TB) {
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

func skipIfProxyDisabled(t *testing.T, data *TestData) {
	if featureGate, err := GetAgentFeatures(); err != nil {
		t.Fatalf("Cannot determine if %s is enabled in the Agent: %v", features.AntreaProxy, err)
	} else if !featureGate.Enabled(features.AntreaProxy) {
		t.Skipf("Skipping test because %s is not enabled in the Agent", features.AntreaProxy)
	}
	agentConf, err := data.GetAntreaAgentConf()
	if err != nil {
		t.Fatalf("Error getting Antrea Agent config: %v", err)
	}
	if agentConf.AntreaProxy.Enable != nil && !*agentConf.AntreaProxy.Enable {
		t.Skipf("Skipping test because AntreaProxy is not enabled")
	}
}

func skipIfEgressShapingDisabled(t *testing.T) {
	skipIfFeatureDisabled(t, features.EgressTrafficShaping, true /* checkAgent */, false /* checkController */)
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

func ensureAntreaRunning(data *TestData) error {
	if testOptions.deployAntrea {
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

func (data *TestData) SetupLogDirectoryForTest(testName string) error {
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

func setupTest(tb testing.TB) (*TestData, error) {
	if err := testData.SetupLogDirectoryForTest(tb.Name()); err != nil {
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
	testData.testNamespace = randName(name + "-")
	if err := ensureAntreaRunning(testData); err != nil {
		return nil, err
	}
	tb.Logf("Creating '%s' K8s Namespace", testData.testNamespace)
	if err := testData.CreateNamespace(testData.testNamespace, nil); err != nil {
		return nil, err
	}
	success = true
	return testData, nil
}

func setupTestForFlowAggregator(tb testing.TB, o flowVisibilityTestOptions) (*TestData, bool, bool, error) {
	v4Enabled := clusterInfo.podV4NetworkCIDR != ""
	v6Enabled := clusterInfo.podV6NetworkCIDR != ""
	testData, err := setupTest(tb)
	if err != nil {
		return testData, v4Enabled, v6Enabled, err
	}
	// Create pod using ipfix collector image
	if err := NewPodBuilder("ipfix-collector", testData.testNamespace, ipfixCollectorImage).InHostNetwork().Create(testData); err != nil {
		tb.Errorf("Error when creating the ipfix collector Pod: %v", err)
	}
	ipfixCollectorIP, err := testData.podWaitForIPs(defaultTimeout, "ipfix-collector", testData.testNamespace)
	if err != nil || len(ipfixCollectorIP.IPStrings) == 0 {
		tb.Errorf("Error when waiting to get ipfix collector Pod IP: %v", err)
		return nil, v4Enabled, v6Enabled, err
	}
	var ipStr string
	if v6Enabled && ipfixCollectorIP.IPv6 != nil {
		ipStr = ipfixCollectorIP.IPv6.String()
	} else {
		ipStr = ipfixCollectorIP.IPv4.String()
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

func teardownFlowAggregator(tb testing.TB, data *TestData) {
	if testOptions.enableCoverage {
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

func teardownTest(tb testing.TB, data *TestData) {
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
		podName := randName("test-pod-")
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

// setupLogging creates a temporary directory to export the test logs if necessary. If a directory
// was provided by the user, it checks that the directory exists.
func (tOptions *TestOptions) setupLogging() func() {
	if tOptions.logsExportDir == "" {
		name, err := os.MkdirTemp("", "antrea-test-")
		if err != nil {
			log.Fatalf("Error when creating temporary directory to export logs: %v", err)
		}
		log.Printf("Test logs (if any) will be exported under the '%s' directory", name)
		tOptions.logsExportDir = name
		// we will delete the temporary directory if no logs are exported
		return func() {
			if empty, _ := IsDirEmpty(name); empty {
				log.Printf("Removing empty logs directory '%s'", name)
				_ = os.Remove(name)
			} else {
				log.Printf("Logs exported under '%s', it is your responsibility to delete the directory when you no longer need it", name)
			}
		}
	}
	fInfo, err := os.Stat(tOptions.logsExportDir)
	if err != nil {
		log.Fatalf("Cannot stat provided directory '%s': %v", tOptions.logsExportDir, err)
	}
	if !fInfo.Mode().IsDir() {
		log.Fatalf("'%s' is not a valid directory", tOptions.logsExportDir)
	}
	// no-op cleanup function
	return func() {}
}

// setupCoverage checks if the directory provided by the user exists.
func (tOptions *TestOptions) setupCoverage(data *TestData) func() {
	if tOptions.coverageDir != "" {
		fInfo, err := os.Stat(tOptions.coverageDir)
		if err != nil {
			log.Fatalf("Cannot stat provided directory '%s': %v", tOptions.coverageDir, err)
		}
		if !fInfo.Mode().IsDir() {
			log.Fatalf("'%s' is not a valid directory", tOptions.coverageDir)
		}

	}
	// cpNodeCoverageDir is a directory on the control-plane Node, where tests can deposit test
	// coverage data.
	log.Printf("Creating directory '%s' on Node '%s'\n", cpNodeCoverageDir, controlPlaneNodeName())
	rc, _, _, err := data.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("mkdir -p %s", cpNodeCoverageDir))
	if err != nil || rc != 0 {
		log.Fatalf("Failed to create directory '%s' on control-plane Node", cpNodeCoverageDir)
	}
	return func() {
		log.Printf("Removing directory '%s' on Node '%s'\n", cpNodeCoverageDir, controlPlaneNodeName())
		// best effort
		data.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("rm -rf %s", cpNodeCoverageDir))
	}

}

// testMain is meant to be called by TestMain and enables the use of defer statements.
func testMain(m *testing.M) int {
	flag.StringVar(&testOptions.providerName, "provider", "vagrant", "K8s test cluster provider")
	flag.StringVar(&testOptions.providerConfigPath, "provider-cfg-path", "", "Optional config file for provider")
	flag.StringVar(&testOptions.logsExportDir, "logs-export-dir", "", "Export directory for test logs")
	flag.BoolVar(&testOptions.logsExportOnSuccess, "logs-export-on-success", false, "Export logs even when a test is successful")
	flag.BoolVar(&testOptions.withBench, "benchtest", false, "Run tests include benchmark tests")
	flag.BoolVar(&testOptions.enableCoverage, "coverage", false, "Run tests and measure coverage")
	flag.BoolVar(&testOptions.enableAntreaIPAM, "antrea-ipam", false, "Run tests with AntreaIPAM")
	flag.BoolVar(&testOptions.flowVisibility, "flow-visibility", false, "Run flow visibility tests")
	flag.BoolVar(&testOptions.deployAntrea, "deploy-antrea", true, "Deploy Antrea before running tests")
	flag.StringVar(&testOptions.coverageDir, "coverage-dir", "", "Directory for coverage data files")
	flag.StringVar(&testOptions.skipCases, "skip-cases", "", "Key words to skip cases")
	flag.StringVar(&testOptions.linuxVMs, "linuxVMs", "", "hostname of Linux VMs")
	flag.StringVar(&testOptions.windowsVMs, "windowsVMs", "", "hostname of Windows VMs")
	flag.StringVar(&testOptions.externalServerIPs, "external-server-ips", "", "IP addresses of external server, at most one IP per IP family")
	flag.StringVar(&testOptions.vlanSubnets, "vlan-subnets", "", "IP subnets of the VLAN network the Nodes reside in, at most one subnet per IP family")
	flag.IntVar(&testOptions.vlanID, "vlan-id", 0, "ID of the VLAN network the Nodes reside in")
	flag.Parse()

	cleanupLogging := testOptions.setupLogging()
	defer cleanupLogging()

	testData = &TestData{}
	if err := testData.InitProvider(testOptions.providerName, testOptions.providerConfigPath); err != nil {
		log.Fatalf("Error when initializing provider: %v", err)
	}
	log.Println("Creating K8s ClientSet")
	kubeconfigPath, err := testData.provider.GetKubeconfigPath()
	if err != nil {
		log.Fatalf("Error when getting Kubeconfig path: %v", err)
	}
	if err := testData.CreateClient(kubeconfigPath); err != nil {
		log.Fatalf("Error when creating K8s ClientSet: %v", err)
	}
	log.Println("Collecting information about K8s cluster")
	if err := testData.collectClusterInfo(); err != nil {
		log.Fatalf("Error when collecting information about K8s cluster: %v", err)
	}
	if clusterInfo.podV4NetworkCIDR != "" {
		log.Printf("Pod IPv4 network: '%s'", clusterInfo.podV4NetworkCIDR)
	}
	if clusterInfo.podV6NetworkCIDR != "" {
		log.Printf("Pod IPv6 network: '%s'", clusterInfo.podV6NetworkCIDR)
	}
	if clusterInfo.svcV4NetworkCIDR != "" {
		log.Printf("Service IPv4 network: '%s'", clusterInfo.svcV4NetworkCIDR)
	}
	if clusterInfo.svcV6NetworkCIDR != "" {
		log.Printf("Service IPv6 network: '%s'", clusterInfo.svcV6NetworkCIDR)
	}
	log.Printf("Num nodes: %d", clusterInfo.numNodes)
	if err := testData.collectExternalInfo(); err != nil {
		log.Fatalf("Error when collecting external information: %v", err)
	}
	err = ensureAntreaRunning(testData)
	if err != nil {
		log.Fatalf("Error when deploying Antrea: %v", err)
	}
	// Collect PodCIDRs after Antrea is running as Antrea is responsible for allocating PodCIDRs in some cases.
	// Polling is not needed here because antrea-agents won't be up and running if PodCIDRs of their Nodes are not set.
	if err = testData.collectPodCIDRs(); err != nil {
		log.Fatalf("Error collecting PodCIDRs: %v", err)
	}
	AntreaConfigMap, err = testData.GetAntreaConfigMap(antreaNamespace)
	if err != nil {
		log.Fatalf("Error when getting antrea-config configmap: %v", err)
	}
	if testOptions.enableCoverage {
		cleanupCoverage := testOptions.setupCoverage(testData)
		defer cleanupCoverage()
		defer gracefulExitAntrea(testData)
	}
	ret := m.Run()
	return ret
}

func gracefulExitAntrea(testData *TestData) {
	if err := testData.gracefulExitAntreaController(testOptions.coverageDir); err != nil {
		log.Fatalf("Error when gracefully exit antrea controller: %v", err)
	}
	if err := testData.gracefulExitAntreaAgent(testOptions.coverageDir, "all"); err != nil {
		log.Fatalf("Error when gracefully exit antrea agent: %v", err)
	}
	if err := testData.collectAntctlCovFilesFromControlPlaneNode(testOptions.coverageDir); err != nil {
		log.Fatalf("Error when collecting antctl coverage files from control-plane Node: %v", err)
	}
}

// The following funcs are used in e2e-secondary-network.

func RunTests(m *testing.M) int {
	return testMain(m)
}

func SetupTest(tb testing.TB) (*TestData, error) {
	return setupTest(tb)
}

func TeardownTest(tb testing.TB, data *TestData) {
	teardownTest(tb, data)
}

func NodeName(idx int) string {
	return nodeName(idx)
}

func NodeCount() int {
	return clusterInfo.numNodes
}

func (data *TestData) GetTestNamespace() string {
	return data.testNamespace
}
