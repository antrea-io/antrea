// Copyright 2026 Antrea Authors
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

// This file tests "antctl observe" (pkg/antctl/raw/observe), which streams live flow records from
// a Flow Aggregator's FlowStreamService without requiring the caller to exec into the Flow
// Aggregator Pod.

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/kubectl/pkg/util/podutils"
	"k8s.io/utils/ptr"

	secv1beta1 "antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
	"antrea.io/antrea/v2/test/e2e/utils"
)

// observeRecord mirrors the JSON shape "antctl observe -o json" emits, one object per line
// (pkg/antctl/raw/observe/render.go's "record" type, which is unexported and not reused directly
// here: it is not meant to be depended on across package boundaries, and a purpose-built shape
// keeps this test file decoupled from render.go's internals).
type observeRecord struct {
	EndTime                 string
	SourceIP                string
	DestinationIP           string
	Protocol                uint32
	SourcePort              uint32
	DestinationPort         uint32
	SourcePodNamespace      string
	SourcePodName           string
	DestinationPodNamespace string
	DestinationPodName      string
	DestinationServiceName  string
	FlowType                string
	SourceDisclosure        string
	DestinationDisclosure   string
	OctetTotalCount         uint64
	ReverseOctetTotalCount  uint64
}

// parseObserveJSON parses "antctl observe -o json" output: one JSON object per line, not a single
// closing array, since --follow's output has no final line to close an array at. A line that does
// not start with "{" is skipped: the logs of a Pod running antctl observe interleave its stderr
// status lines, such as "Discovering Flow Aggregator instance...", with the records.
func parseObserveJSON(t require.TestingT, output string) []observeRecord {
	var records []observeRecord
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var r observeRecord
		require.NoErrorf(t, json.Unmarshal([]byte(line), &r), "failed to parse JSON line: %s", line)
		records = append(records, r)
	}
	return records
}

// restartFlowAggregator deletes the Flow Aggregator Pod(s) in namespace and waits for the
// Deployment to replace them with Pods that are Ready. There is a single replica in Aggregate mode
// (the mode this file's tests use throughout), so this is simpler than a rolling restart:
// delete-and-recreate is not observably different from one here. Readiness is what the chart's
// readiness probe reports: /readyz includes the check that fails whenever FlowStreamService is not
// serving, so a Ready Pod accepts connections on its gRPC port.
func (data *TestData) restartFlowAggregator(namespace string) error {
	pods, err := data.getFlowAggregators(namespace)
	if err != nil {
		return err
	}
	deleted := sets.New[string]()
	for i := range pods {
		if err := data.clientset.CoreV1().Pods(namespace).Delete(context.TODO(), pods[i].Name, metav1.DeleteOptions{}); err != nil {
			return fmt.Errorf("failed to delete Flow Aggregator Pod %s: %w", pods[i].Name, err)
		}
		deleted.Insert(pods[i].Name)
	}
	return wait.PollUntilContextTimeout(context.Background(), defaultInterval, defaultTimeout, false, func(ctx context.Context) (bool, error) {
		// A Pod that was deleted is still listed, and Ready, until it has shut down: only the Pods
		// that replace it count.
		newPods, err := data.getFlowAggregators(namespace)
		if err != nil {
			return false, nil
		}
		for i := range newPods {
			pod := &newPods[i]
			if deleted.Has(pod.Name) || pod.DeletionTimestamp != nil || !podutils.IsPodReady(pod) {
				return false, nil
			}
		}
		return true, nil
	})
}

// antctlObserveServiceAccountName and antctlObservePodName name the ServiceAccount and the
// long-lived, host-network stand-in "remote antctl" Pod shared by every synchronous (no --follow,
// i.e. the default, or bounded "--max-count") test in this file. It is deliberately host-network, matching the
// existing testAntctlControllerRemoteAccess/testAntctlProxy convention: for these tests, a direct
// connection to the Flow Aggregator's Pod IP is expected to succeed, and host networking is what
// makes that reachability available to a test Pod regardless of which Node it lands on. Tests
// that specifically need to prove the *fallback* tunnel works (see testAntctlObserveConnectionModes)
// use a separate, non-host-network Pod instead: see that test for why.
const (
	antctlObserveServiceAccountName = "antctl-observe-e2e"
	antctlObservePodName            = "antctl-observe"
	antctlObserveContainerName      = "antctl"
)

// grantFlowViewer lets a ServiceAccount stream flows cluster-wide, by binding it to the
// antrea-flow-viewer ClusterRole that the Flow Aggregator chart ships. FlowStreamService authorizes
// every stream against the virtual "flows" resource (see docs/network-flow-visibility.md), and the
// antctl ClusterRole deliberately does not include it: an identity that may run antctl is not thereby
// allowed to see every flow in the cluster.
func grantFlowViewer(t *testing.T, data *TestData, saName string) {
	bindClusterRoleToServiceAccount(t, data, saName, "antrea-flow-viewer", saName+"-flow-viewer")
}

// antctlObserveDiscoveryClusterRoleName names the ClusterRole that stands for what a user has to be
// granted for "antctl observe" to find and reach the Flow Aggregator from outside its Pod. It is
// the ClusterRole that docs/antctl.md documents, and deliberately not the antctl ClusterRole: that
// one belongs to the antctl ServiceAccount, whose token is sent to Agents, and "antctl observe"
// authenticates as the caller's own identity instead.
const antctlObserveDiscoveryClusterRoleName = "antctl-observe-e2e-discovery"

// createAntctlObserveDiscoveryClusterRole creates antctlObserveDiscoveryClusterRoleName. Keep its
// rules in line with the ClusterRole in the "Observing live flows" section of docs/antctl.md.
func createAntctlObserveDiscoveryClusterRole(t *testing.T, data *TestData) {
	clusterRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: antctlObserveDiscoveryClusterRoleName},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"services"}, Verbs: []string{"get", "list"}},
			{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"list"}},
			{APIGroups: []string{""}, Resources: []string{"pods/portforward"}, Verbs: []string{"create"}},
			{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"flow-aggregator-ca"}, Verbs: []string{"get"}},
		},
	}
	_, err := data.clientset.RbacV1().ClusterRoles().Create(context.TODO(), clusterRole, metav1.CreateOptions{})
	require.NoErrorf(t, err, "failed to create ClusterRole %s", antctlObserveDiscoveryClusterRoleName)
	t.Cleanup(func() {
		assert.NoError(t, data.clientset.RbacV1().ClusterRoles().Delete(context.TODO(), antctlObserveDiscoveryClusterRoleName, metav1.DeleteOptions{}))
	})
}

// bindClusterRoleToServiceAccount binds a ClusterRole to a ServiceAccount of the test Namespace,
// cluster-wide, for the duration of the test.
func bindClusterRoleToServiceAccount(t *testing.T, data *TestData, saName, clusterRole, bindingName string) {
	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: bindingName},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: saName, Namespace: data.testNamespace}},
		RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: clusterRole},
	}
	_, err := data.clientset.RbacV1().ClusterRoleBindings().Create(context.TODO(), crb, metav1.CreateOptions{})
	require.NoErrorf(t, err, "failed to bind ServiceAccount %s/%s to the %s ClusterRole", data.testNamespace, saName, clusterRole)
	t.Cleanup(func() {
		assert.NoError(t, data.clientset.RbacV1().ClusterRoleBindings().Delete(context.TODO(), bindingName, metav1.DeleteOptions{}))
	})
}

// setupAntctlObserveStandinPod creates the shared long-running stand-in Pod used by every
// synchronous "antctl observe" test below, mirroring runAntctlPod (antctl_test.go) but under this
// file's own naming so its lifecycle is easy to reason about independently.
func setupAntctlObserveStandinPod(t *testing.T, data *TestData, antreaImage string) {
	createAntctlServiceAccount(t, data, antctlObserveServiceAccountName)
	createAntctlObserveDiscoveryClusterRole(t, data)
	bindClusterRoleToServiceAccount(t, data, antctlObserveServiceAccountName, antctlObserveDiscoveryClusterRoleName,
		antctlObserveServiceAccountName+"-discovery")
	grantFlowViewer(t, data, antctlObserveServiceAccountName)

	b := NewPodBuilder(antctlObservePodName, data.testNamespace, antreaImage).
		WithServiceAccountName(antctlObserveServiceAccountName).
		WithContainerName(antctlObserveContainerName).
		WithCommand([]string{"sleep", "3600"}).
		OnNode(controlPlaneNodeName()).
		InHostNetwork()
	if testOptions.enableCoverage {
		// Mirrors runAntctlPod (antctl_test.go): without this, every "antctl observe" exec'd into
		// this Pod still writes real coverage data to /tmp/coverage (GOCOVERDIR is baked into the
		// coverage-instrumented image), but that data is never collected — it is only harvested
		// from cpNodeCoverageDir on the control-plane Node itself
		// (collectAntctlCovFilesFromControlPlaneNode), which this hostPath mount backs.
		b = b.MountHostPath(cpNodeCoverageDir, corev1.HostPathDirectory, "/tmp/coverage", "antctl-coverage")
	}
	require.NoError(t, b.Create(data), "error when creating antctl observe stand-in Pod")
	t.Cleanup(func() {
		require.NoError(t, data.DeletePodAndWait(defaultTimeout, antctlObservePodName, data.testNamespace))
	})
	require.NoError(t, data.podWaitForRunning(defaultTimeout, antctlObservePodName, data.testNamespace), "antctl observe stand-in Pod not in the Running state")
}

// runObserve execs "antctl observe <args>" once, synchronously, in the shared stand-in Pod. Use
// only for invocations that are expected to terminate on their own (i.e. never pass --follow,
// or rely on --max-count) — this blocks until the process exits.
func runObserve(data *TestData, args ...string) (string, string, error) {
	return runAntctlCommandFromPod(data, antctlObservePodName, append([]string{"antctl", "observe"}, args...))
}

// startObservePod creates a dedicated, independent Pod whose sole container command is a
// long-running "antctl observe <args>" invocation targeting flowAggregatorNamespace (typically
// --follow, with no --max-count),
// rather than exec-ing into an already-running Pod. This lets a test inspect the command's
// output at any point via the Pod's own logs (data.GetPodLogs) while the process keeps running —
// there is otherwise no way to observe partial output from a command that is expected to keep
// streaming indefinitely. Mirrors runAntctProxy's approach to the same "long-running antctl
// process" problem (antctl_test.go), which reads a proxy's responses from a separate client
// rather than from the exec call that started the proxy itself.
//
// GetPodLogs returns stdout and stderr interleaved into one stream, which is what a test that
// looks for antctl's own "Error: ..." text needs: see parseObserveJSON for reading the records.
func startObservePod(t *testing.T, data *TestData, podName string, hostNetwork bool, extraLabels map[string]string, args ...string) func() {
	command := append([]string{"antctl", "observe", "--flow-aggregator-namespace", flowAggregatorNamespace}, args...)
	b := NewPodBuilder(podName, data.testNamespace, controlPlaneNodeAntreaImage(t, data)).
		WithServiceAccountName(antctlObserveServiceAccountName).
		WithContainerName(antctlObserveContainerName).
		WithCommand(command).
		OnNode(controlPlaneNodeName())
	if hostNetwork {
		b = b.InHostNetwork()
	}
	if len(extraLabels) > 0 {
		b = b.WithLabels(extraLabels)
	}
	if testOptions.enableCoverage {
		// See the identical mount in setupAntctlObserveStandinPod for why this is needed. Here,
		// antctl is the container's own entrypoint rather than something exec'd in afterward. A
		// caller that bounds it (--max-count) or that severs its stream makes it exit on its own,
		// and so flush coverage data normally. testAntctlObserveFollow does neither: its Pod is
		// deleted while antctl is still running, and as antctl does not handle SIGTERM, that run
		// writes no coverage data. It cannot be bounded, as how many records a flow produces is
		// not deterministic (see generateOneFlow), so a --max-count would either stop it before the
		// live record or never be reached.
		b = b.MountHostPath(cpNodeCoverageDir, corev1.HostPathDirectory, "/tmp/coverage", "antctl-coverage")
	}
	require.NoErrorf(t, b.Create(data), "error when creating Pod %s running antctl observe", podName)
	cleanup := func() {
		assert.NoError(t, data.DeletePodAndWait(defaultTimeout, podName, data.testNamespace))
	}
	// Not podWaitForRunning: a bounded invocation (no --follow, or --max-count reached quickly)
	// can run to completion and reach Succeeded before a poll for "Running" specifically ever
	// observes that phase, since a container that starts and exits within roughly one poll
	// interval can transition Pending -> Running -> Succeeded between two checks. Waiting for
	// "has started" (any phase past Pending) is correct for both this file's long-running
	// (--follow) and bounded (no --follow / --max-count) uses.
	require.NoError(t, wait.PollUntilContextTimeout(context.Background(), defaultInterval, defaultTimeout, false, func(ctx context.Context) (bool, error) {
		pod, err := data.clientset.CoreV1().Pods(data.testNamespace).Get(ctx, podName, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		return pod.Status.Phase != corev1.PodPending && pod.Status.Phase != "", nil
	}), "Pod %s running antctl observe did not start", podName)
	return cleanup
}

// controlPlaneNodeAntreaImage returns the Antrea container image in use on the cluster, the same
// image "antctl" ships in (see testAntctlControllerRemoteAccess, antctl_test.go, for the identical
// lookup used by the existing remote-mode antctl tests).
func controlPlaneNodeAntreaImage(t *testing.T, data *TestData) string {
	ds, err := data.clientset.AppsV1().DaemonSets(antreaNamespace).Get(context.TODO(), antreaDaemonSet, metav1.GetOptions{})
	require.NoError(t, err, "Error when getting antrea DaemonSet")
	return ds.Spec.Template.Spec.Containers[0].Image
}

// TestAntctlObserve is the top-level test for "antctl observe", following the same
// shared-setup-then-subtests structure as TestFlowAggregator. The flows that most subtests read are
// generated once, up front (see generateObserveFlows). Only the subtests that depend on a flow
// appearing after they started (--follow), or on the Flow Aggregator going away, generate their own.
func TestAntctlObserve(t *testing.T) {
	skipIfNotFlowVisibilityTest(t)
	skipIfHasWindowsNodes(t)
	skipIfNumNodesLessThan(t, 2)
	// The export protocol only changes how flows reach the Flow Aggregator, and TestFlowExporter and
	// TestFlowAggregator cover both protocols. antctl observe reads the ring buffer, after that step.
	if !isTestProtocolGRPC() {
		t.Skip("antctl observe does not depend on the flow export protocol")
	}

	// setupFlowAggregatorTest (used by TestFlowAggregator) unconditionally deploys an IPFIX
	// collector and ClickHouse alongside the Flow Aggregator, neither of which this file's tests
	// use — "antctl observe" only cares about the ring buffer / FlowStreamService, not any
	// configured export destination. deployFlowAggregator is the lower-level call that skips
	// both: an empty ipfixCollectorAddr disables the IPFIX collector (mutateFlowAggregatorConfigMap
	// sets flowCollector.enable based on it being non-empty), and omitting databaseURL leaves
	// ClickHouse disabled the same way. This is the same call testAntctlObserveMultiInstance
	// already uses for its second instance, just for instance 0 (the default Namespace,
	// "flow-aggregator") here.
	data, err := setupTest(t)
	require.NoError(t, err, "Error when setting up test")
	t.Cleanup(func() { teardownFlowAggregator(t, data) })
	// Cleanup runs in reverse order: export logs before deleting the Flow Aggregator.
	t.Cleanup(func() { teardownTest(t, data) })
	require.NoError(t, data.deployFlowAggregator("", nil, nil, nil, flowVisibilityTestOptions{}), "Error when deploying Flow Aggregator")
	// Wait for every Agent to connect to the newly deployed Flow Aggregator before generating flows.
	// Delayed IPFIX connections can otherwise exceed the inter-Node correlation window.
	require.NoError(t, getAndCheckFlowAggregatorMetrics(t, data, false, false, flowAggregatorNamespace), "Error when checking metrics of Flow Aggregator")
	// k8sUtils is a package-level global that every ANNP-creating test in this package expects
	// its own top-level test function to have initialized (see TestFlowAggregator); it is not
	// initialized anywhere else automatically. generateObserveFlows and
	// testAntctlObserveConnectionModes use it to create Antrea NetworkPolicies.
	k8sUtils, err = NewKubernetesUtils(data)
	require.NoError(t, err, "Error when creating Kubernetes utils client")

	if !isIPv4Enabled() {
		t.Skip("This test requires IPv4 to be enabled")
	}

	podAIPs, podBIPs, podCIPs, podDIPs, podEIPs, err = createPerftestPods(data)
	require.NoError(t, err, "Error when creating perftest Pods")

	antreaImage := controlPlaneNodeAntreaImage(t, data)
	setupAntctlObserveStandinPod(t, data, antreaImage)

	flows := generateObserveFlows(t, data)

	t.Run("IntraNodeFlow", func(t *testing.T) {
		t.Cleanup(exportLogsForSubtest(t, data))
		testAntctlObserveIntraNodeFlow(t, data, flows)
	})
	t.Run("InterNodeFlowMetadata", func(t *testing.T) {
		t.Cleanup(exportLogsForSubtest(t, data))
		testAntctlObserveInterNodeFlowMetadata(t, data, flows)
	})
	t.Run("PodToExternalFlow", func(t *testing.T) {
		t.Cleanup(exportLogsForSubtest(t, data))
		testAntctlObservePodToExternalFlow(t, data, flows)
	})
	t.Run("ExternalToPodFlow", func(t *testing.T) {
		t.Cleanup(exportLogsForSubtest(t, data))
		testAntctlObserveExternalToPodFlow(t, data, flows)
	})
	t.Run("TextOutput", func(t *testing.T) {
		t.Cleanup(exportLogsForSubtest(t, data))
		testAntctlObserveTextOutput(t, data, flows)
	})
	t.Run("FollowShowsHistoricalThenLiveFlows", func(t *testing.T) {
		t.Cleanup(exportLogsForSubtest(t, data))
		testAntctlObserveFollow(t, data, flows)
	})
	t.Run("ClientCertAuth", func(t *testing.T) {
		t.Cleanup(exportLogsForSubtest(t, data))
		testAntctlObserveClientCertAuth(t, data, flows)
	})
	t.Run("MultiInstanceDiscovery", func(t *testing.T) {
		t.Cleanup(exportLogsForSubtest(t, data))
		testAntctlObserveMultiInstance(t, data)
	})
	t.Run("InPod", func(t *testing.T) {
		t.Cleanup(exportLogsForSubtest(t, data))
		testAntctlObserveInPod(t, data)
	})
	t.Run("ConnectionModes", func(t *testing.T) {
		t.Cleanup(exportLogsForSubtest(t, data))
		testAntctlObserveConnectionModes(t, data)
	})
	// The disconnect test restarts the Flow Aggregator, and so it has to come last.
	t.Run("ExitsOnDisconnect", func(t *testing.T) {
		t.Cleanup(exportLogsForSubtest(t, data))
		testAntctlObserveExitsOnDisconnect(t, data)
	})
}

// perftestListenPort is the port createPerftestPods' Pods listen on (iperf3 -s); generateOneFlow
// only needs a listener to complete a TCP handshake against, not an actual iperf3 session.
const perftestListenPort = iperfPort

// generateOneFlow holds a single TCP connection open for three seconds, spanning several
// conntrack polls with ci/kind/values-flow-exporter.yml's 1s poll interval. A successful immediate
// connect-and-close does not establish that the exporter observed the connection. The toolbox
// image provides Ncat, whose --exec option runs the command after connecting and closes the
// connection when it exits. The exporter may still produce multiple records for this connection.
func generateOneFlow(t *testing.T, data *TestData, srcPodName, dstIP string, dstPort int32) {
	cmd := []string{"nc", "-w", "2", "--exec", "/usr/bin/sleep 3", dstIP, strconv.Itoa(int(dstPort))}
	_, stderr, err := data.RunCommandFromPod(data.testNamespace, srcPodName, "iperf", cmd)
	require.NoErrorf(t, err, "Error when connecting from %s to %s:%d: %s", srcPodName, dstIP, dstPort, stderr)
}

// observeFlows are the flows that TestAntctlObserve generates once, and that most of its subtests
// then read.
type observeFlows struct {
	// label is carried by the Pods that take part in the flows, so that a subtest selects exactly
	// these flows out of the unrelated background traffic of the cluster.
	label string
	// externalToPodPodName is the destination of the external-to-Pod flow.
	externalToPodPodName string
}

// selector returns the arguments that restrict "antctl observe" to the flows of f.
func (f observeFlows) selector() []string {
	return []string{"--selector", "targetLabel=" + f.label}
}

// first returns the first record of the flows of f of the given type, as --flow-type spells it.
// Its arguments make observe stop at that record.
func (f observeFlows) first(t *testing.T, data *TestData, flowType string) observeRecord {
	args := append(f.selector(), "--flow-type", flowType, "--max-count", "1")
	return observeUntilNonEmpty(t, data, args...)[0]
}

// generateObserveFlows generates one flow of each type, and returns once all of them can be read.
// perftest-a connects to perftest-b (intra-Node), to perftest-c (inter-Node, with an Antrea
// NetworkPolicy applied on each end, so that the flow carries policy metadata) and to an external
// server, and an external client connects to a Pod through a NodePort Service. The flows stay in
// the Flow Aggregator's ring buffer (8192 records by default) for the rest of the test.
func generateObserveFlows(t *testing.T, data *TestData) observeFlows {
	serverIPs := createToExternalTestServer(t, data)

	nginxPodName, _, cleanupFunc := createAndWaitForPod(t, data, data.createNginxPodOnNode, "observe-ext-to-pod-", workerNodeName(1), data.testNamespace, false)
	t.Cleanup(cleanupFunc)
	svcIPFamily := corev1.IPv4Protocol
	service, err := data.CreateServiceWithAnnotations("observe-ext-to-pod-svc", data.testNamespace, 80, containerPort, corev1.ProtocolTCP,
		map[string]string{"antrea-e2e": nginxPodName}, false, false, corev1.ServiceTypeNodePort, &svcIPFamily, nil)
	require.NoError(t, err, "failed to create NodePort Service for external-to-Pod test")
	t.Cleanup(func() { assert.NoError(t, data.deleteService(data.testNamespace, service.Name)) })

	f := observeFlows{label: randSeq(8), externalToPodPodName: nginxPodName}
	addLabelToTestPods(t, data, f.label, []string{"perftest-a", "perftest-b", "perftest-c", nginxPodName})
	deployAntreaNetworkPolicies(t, data, "perftest-a", "perftest-c", controlPlaneNodeName(), workerNodeName(1))

	generateOneFlow(t, data, "perftest-a", podBIPs.IPv4.String(), perftestListenPort)
	generateOneFlow(t, data, "perftest-a", podCIPs.IPv4.String(), perftestListenPort)
	generateOneFlow(t, data, "perftest-a", serverIPs.IPv4.String(), serverPodPort)
	createExternalToPodConnection(t, data, service, 0, false)

	// Wait once, here, so that no subtest has to.
	for _, flowType := range []string{"intra-node", "inter-node", "to-external", "from-external"} {
		f.first(t, data, flowType)
	}
	return f
}

// observeUntilNonEmpty polls "antctl observe -o json <extraArgs>" (no --follow, i.e. the default:
// exit once historical flows are drained) until it returns at least one record or the default
// timeout elapses.
func observeUntilNonEmpty(t *testing.T, data *TestData, extraArgs ...string) []observeRecord {
	args := append([]string{"--flow-aggregator-namespace", flowAggregatorNamespace, "-o", "json"}, extraArgs...)
	var records []observeRecord
	require.NoError(t, wait.PollUntilContextTimeout(context.Background(), defaultInterval, defaultTimeout, false, func(ctx context.Context) (bool, error) {
		stdout, stderr, err := runObserve(data, args...)
		if err != nil {
			t.Logf("antctl observe not ready yet: %v (stderr: %s)", err, stderr)
			return false, nil
		}
		records = parseObserveJSON(t, stdout)
		return len(records) > 0, nil
	}), "antctl observe %v never returned any matching record", args)
	return records
}

// The tests of each flow type verify that the flow shows up through "antctl observe" with the
// endpoints, Namespaces and flow type that are expected. They do not assert on the exact source
// port: with this file's aggressively short flow-export timeouts (see generateOneFlow), the ring
// buffer can hold more than one snapshot per logical connection, and these only need to confirm the
// record's identity.
func testAntctlObserveIntraNodeFlow(t *testing.T, data *TestData, f observeFlows) {
	r := f.first(t, data, "intra-node")
	assert.Equal(t, "perftest-a", r.SourcePodName)
	assert.Equal(t, data.testNamespace, r.SourcePodNamespace)
	assert.Equal(t, "perftest-b", r.DestinationPodName)
	assert.Equal(t, data.testNamespace, r.DestinationPodNamespace)
	assert.EqualValues(t, perftestListenPort, r.DestinationPort)
	assert.Equal(t, "FLOW_TYPE_INTRA_NODE", r.FlowType)
}

// testAntctlObserveInterNodeFlowMetadata verifies the metadata of the inter-Node flow, as only a
// real Agent, Flow Aggregator and cluster can provide it: the Pods' labels and Nodes, and the
// Antrea NetworkPolicies on each end.
func testAntctlObserveInterNodeFlowMetadata(t *testing.T, data *TestData, f observeFlows) {
	source, err := data.clientset.CoreV1().Pods(data.testNamespace).Get(context.TODO(), "perftest-a", metav1.GetOptions{})
	require.NoError(t, err)
	destination, err := data.clientset.CoreV1().Pods(data.testNamespace).Get(context.TODO(), "perftest-c", metav1.GetOptions{})
	require.NoError(t, err)
	want := map[string]any{
		"sourceIP":                       podAIPs.IPv4.String(),
		"destinationIP":                  podCIPs.IPv4.String(),
		"sourcePodNamespace":             data.testNamespace,
		"sourcePodName":                  source.Name,
		"destinationPodNamespace":        data.testNamespace,
		"destinationPodName":             destination.Name,
		"sourcePodLabels":                source.Labels,
		"destinationPodLabels":           destination.Labels,
		"sourceNodeName":                 source.Spec.NodeName,
		"destinationNodeName":            destination.Spec.NodeName,
		"protocol":                       6,
		"destinationPort":                perftestListenPort,
		"flowType":                       "FLOW_TYPE_INTER_NODE",
		"sourceDisclosure":               "full",
		"destinationDisclosure":          "full",
		"destinationServiceDisclosure":   "full",
		"ingressNetworkPolicyNamespace":  data.testNamespace,
		"ingressNetworkPolicyName":       ingressAntreaNetworkPolicyName,
		"ingressNetworkPolicyType":       "NETWORK_POLICY_TYPE_ANP",
		"ingressNetworkPolicyRuleName":   testIngressRuleName,
		"ingressNetworkPolicyRuleAction": "NETWORK_POLICY_RULE_ACTION_ALLOW",
		"egressNetworkPolicyNamespace":   data.testNamespace,
		"egressNetworkPolicyName":        egressAntreaNetworkPolicyName,
		"egressNetworkPolicyType":        "NETWORK_POLICY_TYPE_ANP",
		"egressNetworkPolicyRuleName":    testEgressRuleName,
		"egressNetworkPolicyRuleAction":  "NETWORK_POLICY_RULE_ACTION_ALLOW",
	}

	args := append([]string{"--flow-aggregator-namespace", flowAggregatorNamespace, "-o", "json", "--flow-type", "inter-node", "--max-count", "1"}, f.selector()...)
	stdout, stderr, err := runObserve(data, args...)
	require.NoErrorf(t, err, "antctl observe -o json failed: %s", stderr)
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	require.Len(t, lines, 1, "--max-count 1 must emit exactly one JSON record")
	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &fields))
	for name, value := range want {
		require.Contains(t, fields, name)
		expected, err := json.Marshal(value)
		require.NoError(t, err)
		assert.JSONEq(t, string(expected), string(fields[name]), name)
	}
	// JSON includes the whole record, including the fields that the default text table does not show.
	for _, name := range []string{
		"endTime", "startTime", "endReason", "tcpState", "sourcePort", "destinationServiceName",
		"destinationServiceIP", "destinationServicePort", "packetTotalCount", "reversePacketTotalCount",
		"octetTotalCount", "reverseOctetTotalCount", "packetDeltaCount", "reversePacketDeltaCount",
		"octetDeltaCount", "reverseOctetDeltaCount", "egressName", "egressIP", "egressNodeName",
		"proxySnatIP", "proxySnatPort", "throughput", "reverseThroughput",
	} {
		assert.Contains(t, fields, name)
	}
}

func testAntctlObservePodToExternalFlow(t *testing.T, data *TestData, f observeFlows) {
	r := f.first(t, data, "to-external")
	assert.Equal(t, "FLOW_TYPE_TO_EXTERNAL", r.FlowType)
	assert.Equal(t, "perftest-a", r.SourcePodName)
}

func testAntctlObserveExternalToPodFlow(t *testing.T, data *TestData, f observeFlows) {
	r := f.first(t, data, "from-external")
	assert.Equal(t, "FLOW_TYPE_FROM_EXTERNAL", r.FlowType)
	assert.Equal(t, f.externalToPodPodName, r.DestinationPodName)
}

// testAntctlObserveTextOutput verifies the text output, which is the default, and the table output,
// of the inter-Node flow. How they are formatted is covered by unit tests: this only checks what the
// real command prints.
func testAntctlObserveTextOutput(t *testing.T, data *TestData, f observeFlows) {
	args := append([]string{"--flow-aggregator-namespace", flowAggregatorNamespace, "--flow-type", "inter-node", "--max-count", "1"}, f.selector()...)
	source, destination := data.testNamespace+"/perftest-a", data.testNamespace+"/perftest-c"

	stdout, stderr, err := runObserve(data, args...)
	require.NoErrorf(t, err, "antctl observe failed: %s", stderr)
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	require.Len(t, lines, 1, "--max-count 1 must emit exactly one line, and no header")
	assert.Contains(t, lines[0], source+"(")
	assert.Contains(t, lines[0], " -> "+destination+"(")
	assert.Contains(t, lines[0], "  inter-node  ")
	assert.Contains(t, lines[0], "  Policy verdict: ")

	stdout, stderr, err = runObserve(data, append(args, "-o", "table")...)
	require.NoErrorf(t, err, "antctl observe -o table failed: %s", stderr)
	rows := strings.Split(strings.TrimSpace(stdout), "\n")
	require.Len(t, rows, 2, "--max-count 1 must emit a header and exactly one record")
	header, row := strings.Split(rows[0], "\t"), strings.Split(rows[1], "\t")
	require.Equal(t, []string{"endTime", "source", "destination", "protocol", "sourcePort", "destinationPort",
		"destinationServiceName", "flowType", "totalBytes"}, header)
	require.Len(t, row, len(header))
	assert.Equal(t, source, row[1])
	assert.Equal(t, destination, row[2])
	assert.Equal(t, "FLOW_TYPE_INTER_NODE", row[7])
}

// testAntctlObserveFollow: --follow must show historical flows first and then flows generated after
// the stream opened, proving it streams live data rather than only replaying history. The
// historical flow is the intra-Node one of the shared flows; the live one goes to perftest-d, which
// takes part in no other flow.
func testAntctlObserveFollow(t *testing.T, data *TestData, f observeFlows) {
	podName := "antctl-observe-follow-" + randSeq(6)
	cleanup := startObservePod(t, data, podName, true, nil, append(f.selector(), "-o", "json", "--follow")...)
	defer cleanup()

	sawDestination := func(destinationPodName string) bool {
		logs, err := data.GetPodLogs(context.TODO(), data.testNamespace, podName, antctlObserveContainerName)
		if err != nil {
			return false
		}
		for _, r := range parseObserveJSON(t, logs) {
			if r.DestinationPodName == destinationPodName {
				return true
			}
		}
		return false
	}

	// Wait for the historical flow: it shows that observe has connected, so that the flow generated
	// next reaches the Flow Aggregator after the stream opened. Otherwise observe could read it as
	// history, and the test would pass without showing that --follow delivers live flows.
	require.Eventually(t, func() bool { return sawDestination("perftest-b") },
		defaultTimeout, defaultInterval, "--follow did not show the historical flow")

	// Live: generated after the stream opened.
	generateOneFlow(t, data, "perftest-a", podDIPs.IPv4.String(), perftestListenPort)

	require.Eventually(t, func() bool { return sawDestination("perftest-d") },
		defaultTimeout, defaultInterval, "--follow did not show the live-generated flow")
}

// testAntctlObserveMultiInstance: with two Flow Aggregator instances serving FlowStreamService deployed, an
// explicit trusted Namespace is required. Namespace discovery, --flow-aggregator-address, and --flow-aggregator succeed. Reuses
// exactly the two-instance deployment mechanism from setupFlowExporterDestinationTest.
func testAntctlObserveMultiInstance(t *testing.T, data *TestData) {
	// This exercises two instances at once: the default one TestAntctlObserve's own setup
	// deployed (Namespace flow-aggregator), plus this subtest's own instance 1 (Namespace
	// flow-aggregator-1). Every instance is named "flow-aggregator": only the Namespace and the
	// names of the cluster-scoped objects (clusterScopedNameSuffix) differ.

	// Registered before the deployment, so that a partially deployed instance (for example one whose
	// Pod crash-loops) is still deleted when the deployment fails. Otherwise the parent test's
	// teardownFlowAggregator finds it and aborts before deleting any Namespace.
	t.Cleanup(func() {
		// Not teardownFlowAggregator: that deletes every flowAggregator* Namespace,
		// including the default instance TestAntctlObserve's own setup deployed and every other
		// subtest in this file depends on. This subtest only owns instance 1.
		if err := data.DeleteNamespace(flowAggregatorNamespace1, defaultTimeout); err != nil {
			t.Logf("Error when deleting %s Namespace: %v", flowAggregatorNamespace1, err)
		}
	})
	opts := flowVisibilityTestOptions{flowAggregator: flowAggregatorTestOptions{selectedAggregator: 1}}
	require.NoError(t, data.deployFlowAggregator("", nil, nil, nil, opts), "failed to deploy second Flow Aggregator instance")

	_, stderr, err := runObserve(data, "--max-count", "1")
	require.Error(t, err, "discovery must require an explicitly trusted Namespace")
	assert.Contains(t, stderr, "requires --flow-aggregator-namespace or --flow-aggregator")
	for _, namespace := range []string{flowAggregatorNamespace, flowAggregatorNamespace1} {
		_, stderr, err = runObserve(data, "--max-count", "1", "--flow-aggregator-namespace", namespace)
		assert.NoErrorf(t, err, "discovery in explicitly selected Namespace %s should succeed: %s", namespace, stderr)
	}

	pods, err := data.getFlowAggregators(flowAggregatorNamespace1)
	require.NoError(t, err)
	require.NotEmpty(t, pods)
	addr := fmt.Sprintf("%s:14740", pods[0].Status.PodIP)
	// --flow-aggregator-namespace must match the instance being dialed: with --flow-aggregator-address
	// there is no discovered Pod to read a Namespace from. The explicit Namespace selects both
	// the trusted CA and the server name (whose SAN is namespace-specific, see connect.go/discovery.go).
	_, stderr, err = runObserve(data, "--max-count", "1", "--flow-aggregator-address", addr, "--flow-aggregator-namespace", flowAggregatorNamespace1)
	assert.NoErrorf(t, err, "explicit --flow-aggregator-address should bypass discovery: %s", stderr)

	_, stderr, err = runObserve(data, "--max-count", "1", "--flow-aggregator", flowAggregatorNamespace1+"/flow-aggregator")
	assert.NoErrorf(t, err, "explicit --flow-aggregator should bypass discovery: %s", stderr)
}

// testAntctlObserveInPod: running "antctl observe" from inside the Flow Aggregator's own Pod uses the
// Pod's ServiceAccount, which the chart binds to the antrea-flow-viewer ClusterRole. That binding is
// what makes the stream cluster-wide, so nothing is redacted.
func testAntctlObserveInPod(t *testing.T, data *TestData) {
	faPods, err := data.getFlowAggregators(flowAggregatorNamespace)
	require.NoError(t, err)
	require.NotEmpty(t, faPods)

	stdout, stderr, err := data.RunCommandFromPod(flowAggregatorNamespace, faPods[0].Name, "flow-aggregator",
		[]string{"antctl", "observe", "--max-count", "1", "-o", "json"})
	require.NoErrorf(t, err, "antctl observe failed in the Flow Aggregator Pod: %s", stderr)
	records := parseObserveJSON(t, stdout)
	require.Len(t, records, 1, "--max-count 1 must emit exactly one record")
	assert.Equal(t, "full", records[0].SourceDisclosure)
	assert.Equal(t, "full", records[0].DestinationDisclosure)
}

// testAntctlObserveConnectionModes: with the direct path to the Flow Aggregator blocked by a real
// network policy, the automatic mode must fall back to a tunnel through the API server, and
// --connection-mode=direct must fail rather than silently tunnel.
// It uses Pods without host networking, deliberately: a host-network Pod's traffic is sourced from
// the Node's IP, so a policy scoped to "this one Pod" would actually block the whole Node.
// This could be a source of flakiness for tests.
func testAntctlObserveConnectionModes(t *testing.T, data *TestData) {
	faPods, err := data.getFlowAggregators(flowAggregatorNamespace)
	require.NoError(t, err)
	require.NotEmpty(t, faPods)
	faPodIP := faPods[0].Status.PodIP

	blockLabel := map[string]string{"antrea-e2e": "observe-block-direct"}

	// add a network policy to block direct connections to the FA pod.
	builder := &utils.AntreaNetworkPolicySpecBuilder{}
	builder.SetName(data.testNamespace, "observe-block-direct-to-fa").
		SetPriority(1.0).
		SetAppliedToGroup([]utils.ANNPAppliedToSpec{{PodSelector: blockLabel}}).
		AddEgress(utils.ANNPRuleBuilder{
			BaseRuleBuilder: utils.BaseRuleBuilder{
				Protoc:  utils.ProtocolTCP,
				Port:    ptr.To(int32(14740)),
				IPBlock: &secv1beta1.IPBlock{CIDR: faPodIP + "/32"},
				Action:  secv1beta1.RuleActionDrop,
				Name:    "block-flowstream-port",
			},
		})
	anp, err := k8sUtils.CreateOrUpdateANNP(builder.Get())
	require.NoError(t, err, "failed to create Antrea NetworkPolicy blocking direct access to the Flow Aggregator")
	t.Cleanup(func() { assert.NoError(t, data.deleteAntreaNetworkpolicy(anp)) })
	time.Sleep(5 * time.Second) // allow the policy to be realized, matching the convention used elsewhere in this package

	t.Run("AutoFallsBackToTunnel", func(t *testing.T) {
		// The direct attempt is expected to time out against the blocked port (directDialTimeout, 2s)
		// before falling back.
		podName := "antctl-observe-fallback-" + randSeq(6)
		cleanup := startObservePod(t, data, podName, false, blockLabel, "--max-count", "1")
		defer cleanup()
		terminated, logs := waitForObservePodExit(t, data, podName, defaultTimeout)
		assert.Zerof(t, terminated.ExitCode, "antctl observe (auto mode) did not succeed despite the direct path being blocked; logs: %s", logs)
		// Succeeding does not show that observe fell back: a direct connection that got through
		// anyway would succeed too.
		assert.Contains(t, logs, "Connected via tunnel", "antctl observe did not use a tunnel")
	})

	t.Run("DirectDoesNotFallBack", func(t *testing.T) {
		podName := "antctl-observe-direct-" + randSeq(6)
		cleanup := startObservePod(t, data, podName, false, blockLabel, "--max-count", "1", "--connection-mode", "direct")
		defer cleanup()
		terminated, logs := waitForObservePodExit(t, data, podName, defaultTimeout)
		assert.NotZerof(t, terminated.ExitCode, "antctl observe --connection-mode=direct must fail when the direct path is blocked; logs: %s", logs)
		assert.Contains(t, logs, "direct connection to")
		assert.NotContains(t, logs, "Connected via tunnel", "--connection-mode=direct must not tunnel")
	})
}

// waitForObservePodExit waits for the antctl container of the Pod to terminate, and returns how it
// did, with the logs of the Pod.
func waitForObservePodExit(t *testing.T, data *TestData, podName string, bound time.Duration) (*corev1.ContainerStateTerminated, string) {
	// PodBuilder.Create (framework.go) hardcodes RestartPolicy: Never for every Pod it
	// creates, this one included: a container that exits simply stays exited (Pod phase
	// Succeeded/Failed), it is never restarted. So the signal to look for is the container's
	// own Terminated state, not RestartCount, which can never leave 0 here regardless of
	// whether antctl observe exited promptly or not.
	var terminated *corev1.ContainerStateTerminated
	err := wait.PollUntilContextTimeout(context.Background(), defaultInterval, bound, true, func(ctx context.Context) (bool, error) {
		pod, err := data.clientset.CoreV1().Pods(data.testNamespace).Get(ctx, podName, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		for _, cs := range pod.Status.ContainerStatuses {
			if cs.Name == antctlObserveContainerName && cs.State.Terminated != nil {
				terminated = cs.State.Terminated
				return true, nil
			}
		}
		return false, nil
	})
	logs, logsErr := data.GetPodLogs(context.Background(), data.testNamespace, podName, antctlObserveContainerName)
	require.NoError(t, logsErr, "failed to get antctl observe logs")
	require.NoErrorf(t, err, "antctl observe in Pod %s did not exit within %v; logs: %s", podName, bound, logs)
	return terminated, logs
}

// testAntctlObserveExitsOnDisconnect: observe must exit promptly when the Flow Aggregator it
// streams from goes away mid-stream, not hang waiting for it to come back.
func testAntctlObserveExitsOnDisconnect(t *testing.T, data *TestData) {
	podName := "antctl-observe-disconnect-" + randSeq(6)
	cleanup := startObservePod(t, data, podName, true, nil, "-o", "table", "--follow")
	defer cleanup()

	// Wait for the stream to carry flows before pulling the rug out from under it: the header of
	// the table output is printed once the first flows arrive. A Pod that failed to connect at
	// all for an unrelated reason would otherwise be misattributed to this test's own disconnect,
	// and the logs of a Pod that has just started are empty and show no error either.
	require.Eventually(t, func() bool {
		logs, err := data.GetPodLogs(context.TODO(), data.testNamespace, podName, antctlObserveContainerName)
		return err == nil && strings.Contains("\n"+logs, "\nendTime\t")
	}, 30*time.Second, defaultInterval, "antctl observe did not receive flows before the Flow Aggregator was restarted")

	require.NoError(t, data.restartFlowAggregator(flowAggregatorNamespace), "failed to restart the Flow Aggregator to sever the connection")

	// Deleting the Flow Aggregator Pod shuts it down gracefully, which ends the stream cleanly. As
	// observe follows the stream and was not given a --max-count, it takes that for the Flow
	// Aggregator going away and exits with an error, rather than successfully as for a stream that
	// was complete. Were the stream cut short instead, the error would be that it ended unexpectedly.
	terminated, logs := waitForObservePodExit(t, data, podName, 30*time.Second)
	assert.NotZero(t, terminated.ExitCode, "observe must not exit successfully when the Flow Aggregator goes away; logs: %s", logs)
	assert.Regexp(t, "the Flow Aggregator ended the stream, it may have restarted|flow stream ended unexpectedly", logs)
}
