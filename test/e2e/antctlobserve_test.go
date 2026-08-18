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
// Aggregator Pod. See docs/antctl-observe-design.md (outside this repository, alongside the
// vgl-62473 workspace) for the full design and test plan this file implements.

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
	"go.yaml.in/yaml/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/ptr"

	secv1beta1 "antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
	flowaggregatorconfig "antrea.io/antrea/v2/pkg/config/flowaggregator"
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
	OctetTotalCount         uint64
	ReverseOctetTotalCount  uint64
}

// parseObserveJSON parses "antctl observe -o json" output: one JSON object per line, not a single
// closing array, since --follow's output has no final line to close an array at.
func parseObserveJSON(t require.TestingT, output string) []observeRecord {
	var records []observeRecord
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var r observeRecord
		require.NoErrorf(t, json.Unmarshal([]byte(line), &r), "failed to parse JSON line: %s", line)
		records = append(records, r)
	}
	return records
}

// parseObserveText parses "antctl observe" default text output: one header line (skipped), then
// one whitespace-separated row per flow, in the exact column order render.go's textHeader defines.
// Relies on every column always having a visible, non-whitespace value (render.go substitutes "-"
// for empty ones) so that positional whitespace-splitting is unambiguous.
func parseObserveText(t require.TestingT, output string) []observeRecord {
	var records []observeRecord
	for _, line := range strings.Split(strings.TrimRight(output, "\n"), "\n") {
		if line == "" || strings.HasPrefix(line, "TIME") || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		require.GreaterOrEqualf(t, len(fields), 9, "unexpected text output row: %q", line)
		proto, err := strconv.ParseUint(fields[3], 10, 32)
		require.NoError(t, err)
		sport, err := strconv.ParseUint(fields[4], 10, 32)
		require.NoError(t, err)
		dport, err := strconv.ParseUint(fields[5], 10, 32)
		require.NoError(t, err)
		octets, err := strconv.ParseUint(fields[8], 10, 64)
		require.NoError(t, err)
		r := observeRecord{
			EndTime:         fields[0],
			Protocol:        uint32(proto),
			SourcePort:      uint32(sport),
			DestinationPort: uint32(dport),
			FlowType:        fields[7],
			OctetTotalCount: octets,
		}
		if ns, name, ok := strings.Cut(fields[1], "/"); ok {
			r.SourcePodNamespace, r.SourcePodName = ns, name
		} else {
			r.SourceIP = fields[1]
		}
		if ns, name, ok := strings.Cut(fields[2], "/"); ok {
			r.DestinationPodNamespace, r.DestinationPodName = ns, name
		} else {
			r.DestinationIP = fields[2]
		}
		if fields[6] != "-" {
			r.DestinationServiceName = fields[6]
		}
		records = append(records, r)
	}
	return records
}

// enableFlowStreamService patches the Flow Aggregator's ConfigMap to turn on the FlowStreamService
// gRPC server (disabled by default: see pkg/config/flowaggregator/default.go) and to include Pod
// labels in flow records (also disabled by default), then restarts the Deployment so the new Pod
// picks up both changes. Pod labels are needed because most tests below isolate "the one flow this
// subtest just generated" from unrelated background cluster traffic and other subtests' leftover
// flows by giving the relevant Pods a fresh, unique label (addLabelToTestPods) and filtering
// "antctl observe" on it (--selector) — which only works if the Flow Aggregator actually attaches
// Pod labels to records at all.
//
// The e2e framework's own deployFlowAggregator/mutateFlowAggregatorConfigMap helpers do not
// expose either field as a flowVisibilityTestOptions knob, so this decodes, mutates, and
// re-encodes the ConfigMap's YAML content directly via the real config struct, rather than via
// fragile text-based editing of a document this test does not otherwise need to parse.
func enableFlowStreamService(t *testing.T, data *TestData, namespace string) {
	const configKey = "flow-aggregator.conf"

	// The ConfigMap's own name is release-name-derived (distinct per multi-instance deployment),
	// so it must be resolved via the Deployment's volume spec rather than assumed.
	configMapName, err := data.getFlowAggregatorConfigMapName(namespace)
	require.NoErrorf(t, err, "failed to determine Flow Aggregator ConfigMap name in Namespace %s", namespace)

	cm, err := data.clientset.CoreV1().ConfigMaps(namespace).Get(context.TODO(), configMapName, metav1.GetOptions{})
	require.NoErrorf(t, err, "failed to get ConfigMap %s/%s", namespace, configMapName)

	var conf flowaggregatorconfig.FlowAggregatorConfig
	require.NoError(t, yaml.Unmarshal([]byte(cm.Data[configKey]), &conf), "failed to parse existing Flow Aggregator config")

	conf.FlowStreamService.Enable = ptr.To(true)
	conf.RecordContents.PodLabels = true

	newContent, err := yaml.Marshal(&conf)
	require.NoError(t, err, "failed to serialize updated Flow Aggregator config")
	cm.Data[configKey] = string(newContent)

	_, err = data.clientset.CoreV1().ConfigMaps(namespace).Update(context.TODO(), cm, metav1.UpdateOptions{})
	require.NoErrorf(t, err, "failed to update ConfigMap %s/%s", namespace, configMapName)

	require.NoError(t, data.restartFlowAggregator(namespace), "failed to restart Flow Aggregator after enabling FlowStreamService")
}

// restartFlowAggregator deletes the Flow Aggregator Pod(s) in namespace and waits for the
// Deployment to become available again with the new configuration. There is a single replica in
// Aggregate mode (the mode this file's tests use throughout), so this is simpler than a rolling
// restart: delete-and-recreate is not observably different from one here.
func (data *TestData) restartFlowAggregator(namespace string) error {
	pods, err := data.getFlowAggregators(namespace)
	if err != nil {
		return err
	}
	for i := range pods {
		if err := data.clientset.CoreV1().Pods(namespace).Delete(context.TODO(), pods[i].Name, metav1.DeleteOptions{}); err != nil {
			return fmt.Errorf("failed to delete Flow Aggregator Pod %s: %w", pods[i].Name, err)
		}
	}
	return wait.PollUntilContextTimeout(context.Background(), defaultInterval, defaultTimeout, false, func(ctx context.Context) (bool, error) {
		newPods, err := data.getFlowAggregators(namespace)
		if err != nil || len(newPods) == 0 {
			return false, nil
		}
		for i := range newPods {
			pod := newPods[i]
			if pod.Status.Phase != corev1.PodRunning || pod.Status.PodIP == "" {
				return false, nil
			}
			if !data.isFlowStreamServiceListening(pod.Status.PodIP) {
				return false, nil
			}
		}
		return true, nil
	})
}

// isFlowStreamServiceListening checks whether the FlowStreamService gRPC server at podIP:14740 is
// actually accepting connections.
// The Flow Aggregator chart currently does not define a readiness probe so a Pod becomes Running
// as soon as its container process  starts, well before FlowStreamService finishes initializing
// and binds its listener.
// Therefore, tests could try to connect before the port is actually up.
// curl runs on the control-plane Node, which has a route to every Pod IP over Antrea's own network.
// curl needs no shell quoting to invoke here. Exit code 7 ("Failed to connect") and 28 ("Operation timeout")
// specifically mean the TCP handshake itself never completed; any other outcome — including a
// protocol-level error from curl misinterpreting the gRPC/HTTP2 response as HTTP — means the
// connection itself succeeded, which is all this needs to confirm.
func (data *TestData) isFlowStreamServiceListening(podIP string) bool {
	rc, _, _, err := data.RunCommandOnNode(controlPlaneNodeName(), fmt.Sprintf("curl --connect-timeout 2 -s -o /dev/null http://%s:14740", podIP))
	return err == nil && rc != 7 && rc != 28
}

// antctlObserveServiceAccountName and antctlObservePodName name the ServiceAccount and the
// long-lived, host-network stand-in "remote antctl" Pod shared by every synchronous (no --follow,
// i.e. the default, or bounded "--max-count") test in this file. It is deliberately host-network, matching the
// existing testAntctlControllerRemoteAccess/testAntctlProxy convention: for these tests, a direct
// connection to the Flow Aggregator's Pod IP is expected to succeed, and host networking is what
// makes that reachability available to a test Pod regardless of which Node it lands on. Tests
// that specifically need to prove the *fallback* tunnel works (see testAntctlObserveConnectionFallback)
// use a separate, non-host-network Pod instead: see that test for why.
const (
	antctlObserveServiceAccountName = "antctl-observe-e2e"
	antctlObservePodName            = "antctl-observe"
	antctlObserveContainerName      = "antctl"
)

// setupAntctlObserveStandinPod creates the shared long-running stand-in Pod used by every
// synchronous "antctl observe" test below, mirroring runAntctlPod (antctl_test.go) but under this
// file's own naming so its lifecycle is easy to reason about independently.
func setupAntctlObserveStandinPod(t *testing.T, data *TestData, antreaImage string) {
	createAntctlServiceAccount(t, data, antctlObserveServiceAccountName)

	b := NewPodBuilder(antctlObservePodName, data.testNamespace, antreaImage).
		WithServiceAccountName(antctlObserveServiceAccountName).
		WithContainerName(antctlObserveContainerName).
		WithCommand([]string{"sleep", "3600"}).
		OnNode(controlPlaneNodeName()).
		InHostNetwork()
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
// long-running "antctl observe <args>" invocation (typically --follow, with no --max-count),
// rather than exec-ing into an already-running Pod. This lets a test inspect the command's
// output at any point via the Pod's own logs (data.GetPodLogs) while the process keeps running —
// there is otherwise no way to observe partial output from a command that is expected to keep
// streaming indefinitely. Mirrors runAntctProxy's approach to the same "long-running antctl
// process" problem (antctl_test.go), which reads a proxy's responses from a separate client
// rather than from the exec call that started the proxy itself.
//
// discardStderr redirects the container's stderr to /dev/null before it ever reaches the
// container runtime's combined log.
// GetPodLogs always returns stdout/stderr interleaved into one stream, so a caller that parses
// the Pod's logs as pure "antctl observe -o json" output (one JSON object per line) would otherwise
// choke on antctl's own stderr status lines (e.g. "Discovering Flow Aggregator instance...").
// Only set this for callers that parse logs as structured output; testAntctlObserveExitsOnDisconnect,
// for example, deliberately relies on antctl's stderr "Error: ..." text surviving in the combined
// log, so it must pass false.
func startObservePod(t *testing.T, data *TestData, podName string, hostNetwork bool, extraLabels map[string]string, discardStderr bool, args ...string) func() {
	command := append([]string{"antctl", "observe"}, args...)
	if discardStderr {
		command = []string{"sh", "-c", shellJoin(command) + " 2>/dev/null"}
	}
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

// shellJoin renders command as a POSIX shell command line, single-quoting every argument (and
// escaping any embedded single quote) so it can be safely passed to "sh -c". Only used by
// startObservePod, to append a "2>/dev/null" redirection after the otherwise-argv command.
func shellJoin(command []string) string {
	quoted := make([]string, len(command))
	for i, arg := range command {
		quoted[i] = "'" + strings.ReplaceAll(arg, "'", `'\''`) + "'"
	}
	return strings.Join(quoted, " ")
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
// shared-setup-then-subtests structure as TestFlowAggregator.
func TestAntctlObserve(t *testing.T) {
	skipIfNotFlowVisibilityTest(t)
	skipIfHasWindowsNodes(t)
	skipIfNumNodesLessThan(t, 2)

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
	t.Cleanup(func() { teardownTest(t, data) })
	t.Cleanup(func() { teardownFlowAggregator(t, data) })
	require.NoError(t, data.deployFlowAggregator("", nil, nil, nil, flowVisibilityTestOptions{}), "Error when deploying Flow Aggregator")
	enableFlowStreamService(t, data, flowAggregatorNamespace)
	// k8sUtils is a package-level global that every ANNP-creating test in this package expects
	// its own top-level test function to have initialized (see TestFlowAggregator); it is not
	// initialized anywhere else automatically. testAntctlObserveConnectionFallback uses it to
	// create an Antrea NetworkPolicy.
	k8sUtils, err = NewKubernetesUtils(data)
	require.NoError(t, err, "Error when creating Kubernetes utils client")

	if !isIPv4Enabled() {
		t.Skip("This test requires IPv4 to be enabled")
	}

	podAIPs, podBIPs, podCIPs, podDIPs, podEIPs, err = createPerftestPods(data)
	require.NoError(t, err, "Error when creating perftest Pods")

	antreaImage := controlPlaneNodeAntreaImage(t, data)
	setupAntctlObserveStandinPod(t, data, antreaImage)

	t.Run("CapturesIntraNodeFlow", func(t *testing.T) { testAntctlObserveCapturesFlow(t, data, false) })
	t.Run("CapturesInterNodeFlow", func(t *testing.T) { testAntctlObserveCapturesFlow(t, data, true) })
	t.Run("CapturesPodToExternalFlow", func(t *testing.T) { testAntctlObserveCapturesExternalFlow(t, data, true) })
	t.Run("CapturesExternalToPodFlow", func(t *testing.T) { testAntctlObserveCapturesExternalFlow(t, data, false) })
	t.Run("Filters", func(t *testing.T) { testAntctlObserveFilters(t, data) })
	t.Run("DirectionFilter", func(t *testing.T) { testAntctlObserveDirectionFilter(t, data) })
	t.Run("SinceFilter", func(t *testing.T) { testAntctlObserveSince(t, data) })
	t.Run("MaxCount", func(t *testing.T) { testAntctlObserveMaxCount(t, data) })
	t.Run("Follow", func(t *testing.T) { testAntctlObserveFollow(t, data) })
	t.Run("CombinedSinceMaxCountFollow", func(t *testing.T) { testAntctlObserveCombinedParameters(t, data) })
	t.Run("BearerTokenAuth", func(t *testing.T) { testAntctlObserveBearerTokenAuth(t, data) })
	t.Run("NoCredential", func(t *testing.T) { testAntctlObserveNoCredential(t, data, antreaImage) })
	t.Run("MultiInstanceDiscovery", func(t *testing.T) { testAntctlObserveMultiInstance(t, data) })
	t.Run("ConnectionModeDirectFailsWithoutTunnel", func(t *testing.T) { testAntctlObserveConnectionModeDirect(t, data) })
	t.Run("ConnectionFallbackUnderNetworkDenial", func(t *testing.T) { testAntctlObserveConnectionFallback(t, data) })
	t.Run("ExitsOnDisconnect", func(t *testing.T) { testAntctlObserveExitsOnDisconnect(t, data) })
}

// perftestListenPort is the port createPerftestPods' Pods listen on (iperf3 -s); generateOneFlow
// only needs a listener to complete a TCP handshake against, not an actual iperf3 session.
const perftestListenPort = iperfPort

// generateOneFlow opens and immediately closes a single TCP connection from srcPodName to
// dstIP:dstPort ("nc -z": zero-I/O, connect-then-close), rather than running a multi-second
// iperf3 transfer. This was iperf3 originally, and it caused two distinct problems under this
// file's aggressively short flow-export timeouts (ci/kind/values-flow-exporter.yml: 1s poll, 2s
// active, 1s idle — tuned for fast CI, not for a single clean record per call): first, a 5-second
// transfer routinely produced *multiple* ring-buffer snapshots for the same logical connection
// (the eager-export-on-correlation snapshot, plus periodic updates), which silently broke every
// test in this file that counted records expecting one-generated-flow-per-record. Second, under
// the same tuning, a single iperf3 invocation could be seen as more than one distinct connection
// (different ephemeral source ports across snapshots), which broke exact-port assertions. A quick
// connect-and-close finishes fast enough, and produces little enough traffic, to reliably become
// exactly one ring-buffer record.
func generateOneFlow(t *testing.T, data *TestData, srcPodName, dstIP string, dstPort int32) {
	cmdStr := fmt.Sprintf("nc -z -w 2 %s %d", dstIP, dstPort)
	_, stderr, err := data.RunCommandFromPod(data.testNamespace, srcPodName, "iperf", []string{"bash", "-c", cmdStr})
	require.NoErrorf(t, err, "Error when connecting from %s to %s:%d: %s", srcPodName, dstIP, dstPort, stderr)
}

// observeUntilNonEmpty polls "antctl observe <extraArgs>" (no --follow, i.e. the default: exit
// once historical flows are drained) until it returns at least one record or the default timeout
// elapses.
func observeUntilNonEmpty(t *testing.T, data *TestData, format string, extraArgs ...string) []observeRecord {
	args := append([]string{"-o", format}, extraArgs...)
	var records []observeRecord
	require.NoError(t, wait.PollUntilContextTimeout(context.Background(), defaultInterval, defaultTimeout, false, func(ctx context.Context) (bool, error) {
		stdout, stderr, err := runObserve(data, args...)
		if err != nil {
			t.Logf("antctl observe not ready yet: %v (stderr: %s)", err, stderr)
			return false, nil
		}
		if format == "json" {
			records = parseObserveJSON(t, stdout)
		} else {
			records = parseObserveText(t, stdout)
		}
		return len(records) > 0, nil
	}), "antctl observe %v never returned any matching record", args)
	return records
}

// observeEmpty runs "antctl observe <extraArgs>" (no --follow) once and asserts it returns no
// records at all — used for the "filter correctly excludes a non-matching flow" half of every
// filter test below. Unlike observeUntilNonEmpty, this does not poll: a filter that is broken in
// the "matches too much" direction would otherwise never be caught by retrying.
func observeEmpty(t *testing.T, data *TestData, format string, extraArgs ...string) {
	args := append([]string{"-o", format}, extraArgs...)
	stdout, stderr, err := runObserve(data, args...)
	require.NoErrorf(t, err, "antctl observe %v failed: %s", args, stderr)
	var records []observeRecord
	if format == "json" {
		records = parseObserveJSON(t, stdout)
	} else {
		records = parseObserveText(t, stdout)
	}
	assert.Emptyf(t, records, "antctl observe %v matched a flow it should have excluded", args)
}

// testAntctlObserveCapturesFlow verifies that a live intra-Node or inter-Node flow must show up
// through "antctl observe" with every relevant field correct.
// Does not assert on the exact source port: with this file's aggressively short
// flow-export timeouts (see generateOneFlow), the ring buffer can hold more than one snapshot per
// logical connection, and this only needs to confirm the record's identity (endpoints,
// Namespaces, flow type), not its transport-level exactness.
func testAntctlObserveCapturesFlow(t *testing.T, data *TestData, interNode bool) {
	label := randSeq(8)
	dstPodName, dstIP := "perftest-b", podBIPs.IPv4.String()
	if interNode {
		dstPodName, dstIP = "perftest-c", podCIPs.IPv4.String()
	}
	addLabelToTestPods(t, data, label, []string{"perftest-a", dstPodName})

	generateOneFlow(t, data, "perftest-a", dstIP, perftestListenPort)

	// text for one of the two (intra/inter) cases and json for the other, so both output formats
	// are covered across this file rather than a dedicated, redundant format test.
	format := "json"
	if interNode {
		format = "text"
	}
	records := observeUntilNonEmpty(t, data, format, "--selector", "targetLabel="+label)
	r := records[len(records)-1]

	assert.Equal(t, "perftest-a", r.SourcePodName)
	assert.Equal(t, data.testNamespace, r.SourcePodNamespace)
	assert.Equal(t, dstPodName, r.DestinationPodName)
	assert.Equal(t, data.testNamespace, r.DestinationPodNamespace)
	assert.EqualValues(t, perftestListenPort, r.DestinationPort)
	if interNode {
		assert.Equal(t, "FLOW_TYPE_INTER_NODE", r.FlowType)
	} else {
		assert.Equal(t, "FLOW_TYPE_INTRA_NODE", r.FlowType)
	}
}

// testAntctlObserveCapturesExternalFlow covers observe for Pod->External External->Pod flows.
func testAntctlObserveCapturesExternalFlow(t *testing.T, data *TestData, toExternal bool) {
	if toExternal {
		serverIPs := createToExternalTestServer(t, data)
		label := randSeq(8)
		addLabelToTestPods(t, data, label, []string{"perftest-a"})

		generateOneFlow(t, data, "perftest-a", serverIPs.IPv4.String(), serverPodPort)

		records := observeUntilNonEmpty(t, data, "json", "--selector", "targetLabel="+label, "--flow-type", "to-external")
		r := records[len(records)-1]
		assert.Equal(t, "FLOW_TYPE_TO_EXTERNAL", r.FlowType)
		assert.Equal(t, "perftest-a", r.SourcePodName)
		return
	}

	nginxPodName, _, cleanupFunc := createAndWaitForPod(t, data, data.createNginxPodOnNode, "observe-ext-to-pod-", workerNodeName(1), data.testNamespace, false)
	defer cleanupFunc()
	label := randSeq(8)
	addLabelToTestPods(t, data, label, []string{nginxPodName})

	svcIPFamily := corev1.IPv4Protocol
	service, err := data.CreateServiceWithAnnotations("observe-ext-to-pod-svc", data.testNamespace, 80, containerPort, corev1.ProtocolTCP,
		map[string]string{"antrea-e2e": nginxPodName}, false, false, corev1.ServiceTypeNodePort, &svcIPFamily, nil)
	require.NoError(t, err, "failed to create NodePort Service for external-to-Pod test")
	t.Cleanup(func() { assert.NoError(t, data.deleteService(data.testNamespace, service.Name)) })

	createExternalToPodConnection(t, data, service, 0, false)

	records := observeUntilNonEmpty(t, data, "json", "--selector", "targetLabel="+label, "--flow-type", "from-external")
	r := records[len(records)-1]
	assert.Equal(t, "FLOW_TYPE_FROM_EXTERNAL", r.FlowType)
	assert.Equal(t, nginxPodName, r.DestinationPodName)
}

// testAntctlObserveFilters: namespaces, pod_names, pod_label_selector and ips, each tested with
// a matching and a non-matching case.
func testAntctlObserveFilters(t *testing.T, data *TestData) {
	label := randSeq(8)
	addLabelToTestPods(t, data, label, []string{"perftest-a", "perftest-b"})
	generateOneFlow(t, data, "perftest-a", podBIPs.IPv4.String(), perftestListenPort)
	labelSelector := "--selector=targetLabel=" + label

	t.Run("Namespace", func(t *testing.T) {
		records := observeUntilNonEmpty(t, data, "json", labelSelector, "-n", data.testNamespace)
		assert.Equal(t, "perftest-a", records[len(records)-1].SourcePodName)
		observeEmpty(t, data, "json", labelSelector, "-n", "kube-system")
	})

	t.Run("PodName", func(t *testing.T) {
		records := observeUntilNonEmpty(t, data, "json", labelSelector, "--pod", "perftest-a")
		assert.Equal(t, "perftest-a", records[len(records)-1].SourcePodName)
		observeEmpty(t, data, "json", labelSelector, "--pod", "some-other-pod-name")
	})

	t.Run("PodLabelSelector", func(t *testing.T) {
		records := observeUntilNonEmpty(t, data, "json", "-l", "targetLabel="+label)
		assert.Equal(t, "perftest-a", records[len(records)-1].SourcePodName)
		observeEmpty(t, data, "json", "-l", "targetLabel=some-other-value-"+label)
	})

	t.Run("IP", func(t *testing.T) {
		records := observeUntilNonEmpty(t, data, "json", labelSelector, "--ip", podAIPs.IPv4.String())
		assert.Equal(t, "perftest-a", records[len(records)-1].SourcePodName)
		observeEmpty(t, data, "json", labelSelector, "--ip", "203.0.113.1/32")
	})
}

// testAntctlObserveDirectionFilter: a single flow and a single filter value, toggling
// only --direction, isolates exactly what --direction changes (which side is checked) rather than
// whether matching works at all.
func testAntctlObserveDirectionFilter(t *testing.T, data *TestData) {
	label := randSeq(8)
	addLabelToTestPods(t, data, label, []string{"perftest-a", "perftest-b"})
	generateOneFlow(t, data, "perftest-a", podBIPs.IPv4.String(), perftestListenPort)
	labelSelector := "--selector=targetLabel=" + label

	// perftest-a is genuinely the source: --direction=from must match on its Namespace, and
	// --direction=to must not, even though perftest-a's Namespace is also perftest-b's Namespace
	// (they are in the same test Namespace), so a filter that ignored --direction entirely would
	// pass this by accident.
	records := observeUntilNonEmpty(t, data, "json", labelSelector, "-n", data.testNamespace, "--direction", "from")
	assert.Equal(t, "perftest-a", records[len(records)-1].SourcePodName)

	observeEmpty(t, data, "json", labelSelector, "--pod", "perftest-a", "--direction", "to")
}

// countDistinctFlows deduplicates records by 5-tuple. Under aggressively short
// flow-export timeouts (ci/kind/values-flow-exporter.yml: 1s poll, 2s active, 1s idle,
// the ring buffer can hold more than one snapshot for the same logical connection.
// Counting raw records might therefore overcount "how many connections happened".
func countDistinctFlows(records []observeRecord) int {
	seen := make(map[string]struct{})
	for _, r := range records {
		seen[fmt.Sprintf("%s:%d-%s:%d", r.SourceIP, r.SourcePort, r.DestinationIP, r.DestinationPort)] = struct{}{}
	}
	return len(seen)
}

// testAntctlObserveSince: X flows at T1, X more at T2, three cutoffs. Counts distinct
// flows (see countDistinctFlows), not raw records: --since's job is to filter by time, and
// whether a given connection happens to appear as one ring-buffer record or several is an
// unrelated, timing-dependent implementation detail this test should not depend on.
func testAntctlObserveSince(t *testing.T, data *TestData) {
	label := randSeq(8)
	addLabelToTestPods(t, data, label, []string{"perftest-a", "perftest-b"})
	labelSelector := "--selector=targetLabel=" + label
	const batchSize = 2

	for i := 0; i < batchSize; i++ {
		generateOneFlow(t, data, "perftest-a", podBIPs.IPv4.String(), perftestListenPort)
	}
	// Let batch 1 fully settle before capturing the "between batches" cutoff: a flow's recorded
	// end_ts lags behind generateOneFlow returning by however long the Agent's own poll/export
	// cycle takes (up to ~2s under this file's aggressively short flowExporter timeouts — see
	// ci/kind/values-flow-exporter.yml), so a cutoff captured too soon after batch 1 can still
	// land before some of batch 1's flows get their end_ts recorded, making them appear to be
	// "after" the cutoff and leak into what should be a batch-2-only query.
	time.Sleep(3 * time.Second)
	tBetween := time.Now()
	time.Sleep(1 * time.Second)
	for i := 0; i < batchSize; i++ {
		generateOneFlow(t, data, "perftest-a", podBIPs.IPv4.String(), perftestListenPort)
	}
	t2 := time.Now()

	// The ring buffer only gains an entry for a flow once correlation completes (eager export),
	// which lags slightly behind generateOneFlow returning; give it a moment before querying so
	// "since > t2" below is not observing a false negative caused by that lag rather than by
	// --since actually working.
	var records []observeRecord
	require.Eventually(t, func() bool {
		records = parseObserveJSON(t, mustRunObserve(t, data, labelSelector, "--since", tBetween.Add(-time.Hour).Format(time.RFC3339)))
		return countDistinctFlows(records) >= 2*batchSize
	}, defaultTimeout, defaultInterval, "since before both batches should eventually return all of them")

	records = parseObserveJSON(t, mustRunObserve(t, data, labelSelector, "--since", tBetween.Format(time.RFC3339)))
	assert.Equal(t, batchSize, countDistinctFlows(records), "since between the two batches should return only the second one")

	records = parseObserveJSON(t, mustRunObserve(t, data, labelSelector, "--since", t2.Add(time.Minute).Format(time.RFC3339)))
	assert.Empty(t, records, "since after both batches should return nothing")
}

func mustRunObserve(t *testing.T, data *TestData, args ...string) string {
	stdout, stderr, err := runObserve(data, append([]string{"-o", "json"}, args...)...)
	require.NoErrorf(t, err, "antctl observe %v failed: %s", args, stderr)
	return stdout
}

// testAntctlObserveMaxCount: --max-count for K in {0,<total,=total,>total}. Unlike
// testAntctlObserveSince, this deliberately measures the actual available record count ("total")
// rather than assuming it equals the number of generateOneFlow calls: --max-count's real contract
// is a cap on raw ring-buffer records returned, not on distinct logical connections (see
// countDistinctFlows), and under this aggressive short flow-export timeouts a handful of
// connections routinely produce more raw records than connections generated. Measuring total
// directly, and deriving every K from it, keeps the assertions correct regardless of exactly how
// many records each connection happens to produce.
func testAntctlObserveMaxCount(t *testing.T, data *TestData) {
	label := randSeq(8)
	addLabelToTestPods(t, data, label, []string{"perftest-a", "perftest-b"})
	labelSelector := "--selector=targetLabel=" + label
	const n = 3
	for i := 0; i < n; i++ {
		generateOneFlow(t, data, "perftest-a", podBIPs.IPv4.String(), perftestListenPort)
	}

	// Wait for all n distinct connections to be visible at least once, then let the aggressive
	// 1s/2s export timeouts settle so "total" (measured next) is not still climbing.
	require.Eventually(t, func() bool {
		return countDistinctFlows(parseObserveJSON(t, mustRunObserve(t, data, labelSelector))) >= n
	}, defaultTimeout, defaultInterval, "not all %d generated flows became visible", n)
	time.Sleep(3 * time.Second)
	total := len(parseObserveJSON(t, mustRunObserve(t, data, labelSelector)))
	require.Greaterf(t, total, 1, "need at least a couple of available records to meaningfully exercise --max-count, got %d", total)

	for _, tc := range []struct {
		name     string
		maxCount int
	}{
		{"Unlimited", 0},
		{"LessThanTotal", total - 1},
		{"EqualToTotal", total},
		{"GreaterThanTotal", total + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			records := parseObserveJSON(t, mustRunObserve(t, data, labelSelector, "--max-count", strconv.Itoa(tc.maxCount)))
			expect := tc.maxCount
			if expect == 0 || expect > total {
				expect = total
			}
			assert.Len(t, records, expect)
		})
	}
}

// testAntctlObserveFollow: without --follow (the default, matching "kubectl logs"),
// observe must terminate on its own once historical flows are exhausted; --follow must show
// historical flows first and then flows generated after the stream opened, proving it streams
// live data rather than only replaying history.
func testAntctlObserveFollow(t *testing.T, data *TestData) {
	t.Run("DefaultTerminatesOnItsOwn", func(t *testing.T) {
		done := make(chan error, 1)
		go func() {
			_, _, err := runObserve(data, "-n", "a-namespace-with-no-flows-at-all")
			done <- err
		}()
		select {
		case err := <-done:
			assert.NoError(t, err)
		case <-time.After(30 * time.Second):
			t.Fatal("antctl observe (default, no --follow) did not terminate on its own within 30s")
		}
	})

	t.Run("FollowShowsHistoricalThenLiveFlows", func(t *testing.T) {
		label := randSeq(8)
		addLabelToTestPods(t, data, label, []string{"perftest-a", "perftest-b", "perftest-c"})

		// Historical: generated before the stream opens.
		generateOneFlow(t, data, "perftest-a", podBIPs.IPv4.String(), perftestListenPort)
		require.Eventually(t, func() bool {
			return len(parseObserveJSON(t, mustRunObserve(t, data, "--selector=targetLabel="+label))) >= 1
		}, defaultTimeout, defaultInterval, "the historical flow never became visible before starting the follow Pod")

		podName := "antctl-observe-follow-" + randSeq(6)
		cleanup := startObservePod(t, data, podName, true, nil, true,
			"--selector", "targetLabel="+label, "-o", "json", "--follow")
		defer cleanup()

		// Live: generated after the stream opened.
		generateOneFlow(t, data, "perftest-a", podCIPs.IPv4.String(), perftestListenPort)

		require.Eventually(t, func() bool {
			logs, err := data.GetPodLogs(context.TODO(), data.testNamespace, podName, antctlObserveContainerName)
			if err != nil {
				return false
			}
			records := parseObserveJSON(t, logs)
			sawHistorical, sawLive := false, false
			for _, r := range records {
				if r.DestinationPodName == "perftest-b" {
					sawHistorical = true
				}
				if r.DestinationPodName == "perftest-c" {
					sawLive = true
				}
			}
			return sawHistorical && sawLive
		}, defaultTimeout, defaultInterval, "--follow did not show both the historical and the live-generated flow")
	})
}

// testAntctlObserveCombinedParameters: verifies --since, --max-count and --follow used
// together. The server closes the stream once max_count is reached even with follow=true (see
// FlowStreamService.GetFlows), so this terminates deterministically without needing to time out
// or kill the process.
func testAntctlObserveCombinedParameters(t *testing.T, data *TestData) {
	label := randSeq(8)
	addLabelToTestPods(t, data, label, []string{"perftest-a", "perftest-b"})
	since := time.Now()
	generateOneFlow(t, data, "perftest-a", podBIPs.IPv4.String(), perftestListenPort)

	// The combined --follow invocation below must not be the first check for the flow's presence:
	// with --follow, the server deliberately keeps the stream open waiting for more data until
	// max_count hasn't been reached yet, so a single missed/late delivery here would hang forever
	// rather than fail fast. Confirm the flow is already visible through a quick, retryable,
	// non-follow poll using the same filters first, mirroring FollowShowsHistoricalThenLiveFlows above.
	require.Eventually(t, func() bool {
		return len(parseObserveJSON(t, mustRunObserve(t, data, "--selector", "targetLabel="+label, "--since", since.Format(time.RFC3339)))) >= 1
	}, defaultTimeout, defaultInterval, "the flow never became visible before the combined --follow invocation")

	stdout, stderr, err := runObserve(data, "--selector", "targetLabel="+label, "--since", since.Format(time.RFC3339),
		"--max-count", "1", "--follow", "-o", "json")
	require.NoErrorf(t, err, "combined --since/--max-count/--follow invocation failed: %s", stderr)
	records := parseObserveJSON(t, stdout)
	assert.Len(t, records, 1)
}

// testAntctlObserveBearerTokenAuth: The shared stand-in Pod (setupAntctlObserveStandinPod)
// has no kubeconfig file mounted, so runtime.ResolveKubeconfig falls through to
// rest.InClusterConfig(), which is a bearer-token credential (the Pod's own ServiceAccount token)
// — meaning every other test in this file already exercises the TokenReview path as a side
// effect of simply succeeding at all. This test exists to make that assertion explicit rather
// than leaving it implicit, in case the default credential source ever changes.
func testAntctlObserveBearerTokenAuth(t *testing.T, data *TestData) {
	label := randSeq(8)
	addLabelToTestPods(t, data, label, []string{"perftest-a", "perftest-b"})
	generateOneFlow(t, data, "perftest-a", podBIPs.IPv4.String(), perftestListenPort)
	records := observeUntilNonEmpty(t, data, "json", "--selector", "targetLabel="+label)
	assert.NotEmpty(t, records, "the bearer-token (ServiceAccount) credential path should have authenticated successfully")
}

// testAntctlObserveNoCredential: rather than constructing a kubeconfig with a syntactically-present
// but invalid credential  this runs "antctl observe" from a Pod with a ServiceAccount that is bound
// to no ClusterRole at all, so it can't even reach the Kubernetes API server.
// This test does not verify rejected credentials from FlowStreamService, it simply verifies the observe
// command gracefully fails when there is a permission-related failure.
func testAntctlObserveNoCredential(t *testing.T, data *TestData, antreaImage string) {
	const saName = "antctl-observe-no-rbac"
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: data.testNamespace, Name: saName}}
	_, err := data.clientset.CoreV1().ServiceAccounts(data.testNamespace).Create(context.TODO(), sa, metav1.CreateOptions{})
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, data.clientset.CoreV1().ServiceAccounts(data.testNamespace).Delete(context.TODO(), saName, metav1.DeleteOptions{}))
	})

	podName := "antctl-observe-no-rbac"
	require.NoError(t, NewPodBuilder(podName, data.testNamespace, antreaImage).
		WithServiceAccountName(saName).WithContainerName(antctlObserveContainerName).
		WithCommand([]string{"sleep", "3600"}).OnNode(controlPlaneNodeName()).InHostNetwork().Create(data))
	t.Cleanup(func() { assert.NoError(t, data.DeletePodAndWait(defaultTimeout, podName, data.testNamespace)) })
	require.NoError(t, data.podWaitForRunning(defaultTimeout, podName, data.testNamespace))

	_, stderr, err := runAntctlCommandFromPod(data, podName, []string{"antctl", "observe"})
	require.Error(t, err, "antctl observe should fail for a ServiceAccount with no RBAC at all")
	assert.Contains(t, strings.ToLower(stderr), "forbidden")
}

// testAntctlObserveMultiInstance: with two Flow Aggregator instances deployed, discovery
// must fail with a disambiguation error, while --server and --flow-aggregator both succeed. Reuses
// exactly the two-instance deployment mechanism from setupFlowExporterDestinationTest.
func testAntctlObserveMultiInstance(t *testing.T, data *TestData) {
	// This exercises three instances at once: the default one TestAntctlObserve's own setup
	// deployed (Namespace flow-aggregator, release name "flow-aggregator"), plus this subtest's
	// own instance 1 (Namespace flow-aggregator-1). ci/kind/test-e2e-kind.sh's manifest generation
	// now gives every instance a distinct --release-name (not just --namespace), matching what a
	// real multi-instance deployment would do.

	opts := flowVisibilityTestOptions{flowAggregator: flowAggregatorTestOptions{selectedAggregator: 1}}
	require.NoError(t, data.deployFlowAggregator("", nil, nil, nil, opts), "failed to deploy second Flow Aggregator instance")
	t.Cleanup(func() {
		// Not teardownFlowAggregator: that deletes every flowAggregator* Namespace,
		// including the default instance TestAntctlObserve's own setup deployed and every other
		// subtest in this file depends on. This subtest only owns instance 1.
		if err := data.DeleteNamespace(flowAggregatorNamespace1, defaultTimeout); err != nil {
			t.Logf("Error when deleting %s Namespace: %v", flowAggregatorNamespace1, err)
		}
	})
	enableFlowStreamService(t, data, flowAggregatorNamespace1)

	_, stderr, err := runObserve(data, "--max-count", "1")
	require.Error(t, err, "discovery must fail when more than one Flow Aggregator instance exists")
	assert.Contains(t, stderr, "multiple Namespaces")

	pods, err := data.getFlowAggregators(flowAggregatorNamespace1)
	require.NoError(t, err)
	require.NotEmpty(t, pods)
	addr := fmt.Sprintf("%s:14740", pods[0].Status.PodIP)
	// --flow-aggregator-namespace must match the instance being dialed: with --flow-aggregator-address
	// there is no discovered Pod to read a Namespace from, so the CA/serverName lookup would
	// otherwise default to defaultFlowAggregatorNamespace ("flow-aggregator") and fail to verify
	// instance 1's certificate (whose SAN is namespace-specific, see connect.go/discovery.go).
	_, stderr, err = runObserve(data, "--max-count", "1", "--flow-aggregator-address", addr, "--flow-aggregator-namespace", flowAggregatorNamespace1)
	assert.NoErrorf(t, err, "explicit --flow-aggregator-address should bypass discovery: %s", stderr)

	// The Deployment's own name is release-name-derived (distinct per instance), so it is looked up
	// rather than assumed, the same way the e2e framework's own helpers do.
	deployment, err := data.getFlowAggregatorDeployment(flowAggregatorNamespace1)
	require.NoError(t, err)
	_, stderr, err = runObserve(data, "--max-count", "1", "--flow-aggregator", flowAggregatorNamespace1+"/"+deployment.Name)
	assert.NoErrorf(t, err, "explicit --flow-aggregator should bypass discovery: %s", stderr)
}

// testAntctlObserveConnectionModeDirect: confirms --connection-mode=direct fails outright, rather than
// silently tunneling when the caller has no direct route to the Flow
// Aggregator's Pod IP, which is expected inside this Pod network for the shared, host-network
// stand-in Pod. However, that Pod, being host-network, *does* have a direct route. So this test
// runs from a plain (non-host-network) Pod instead, which shares the fallback test's premise: see
// testAntctlObserveConnectionFallback for why host networking is avoided there.
func testAntctlObserveConnectionModeDirect(t *testing.T, data *TestData) {
	podName := "antctl-observe-direct-" + randSeq(6)
	cleanup := startObservePod(t, data, podName, false, nil, false, "--max-count", "1", "--connection-mode", "direct")
	defer cleanup()
	// A Pod's own network namespace can always reach any other Pod's IP over Antrea's own Pod
	// network so --connection-mode=direct is expected to succeed here, not fail: this asserts
	// the "always tunnels" and "never silently tunnels" halves of the mode matrix are both true,
	// using the one mode (direct) that has no fallback to hide a bug behind.
	require.NoError(t, wait.PollUntilContextTimeout(context.Background(), defaultInterval, defaultTimeout, false, func(ctx context.Context) (bool, error) {
		pod, err := data.clientset.CoreV1().Pods(data.testNamespace).Get(context.TODO(), podName, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		return pod.Status.Phase == corev1.PodSucceeded, nil
	}), "antctl observe --connection-mode=direct did not exit successfully")
}

// testAntctlObserveConnectionFallback9: verifies the automatic fallback to a tunnel is triggered
// in response to a genuine network denial, not just forced via --connection-mode=tunnel.
// Uses a Pod without host networking, deliberately: a host-network Pod's traffic is sourced from
// the Node's IP, so an ACNP scoped to "this one Pod" would actually block the whole Node.
// This could be a source of flakiness for tests.
func testAntctlObserveConnectionFallback(t *testing.T, data *TestData) {
	faPods, err := data.getFlowAggregators(flowAggregatorNamespace)
	require.NoError(t, err)
	require.NotEmpty(t, faPods)
	faPodIP := faPods[0].Status.PodIP

	podName := "antctl-observe-fallback-" + randSeq(6)
	blockLabel := map[string]string{"antrea-e2e": podName}

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

	cleanup := startObservePod(t, data, podName, false, blockLabel, false, "--max-count", "1")
	defer cleanup()

	// connectionModeAuto's direct attempt is expected to time out against the blocked port
	// (directDialTimeout, 2s) before falling back; give it comfortably more than that before
	// concluding it never completed.
	require.NoError(t, wait.PollUntilContextTimeout(context.Background(), defaultInterval, defaultTimeout, false, func(ctx context.Context) (bool, error) {
		pod, err := data.clientset.CoreV1().Pods(data.testNamespace).Get(context.TODO(), podName, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		return pod.Status.Phase == corev1.PodSucceeded, nil
	}), "antctl observe (auto mode) did not fall back to a tunnel and succeed despite the direct path being blocked")
}

// testAntctlObserveExitsOnDisconnect: observe must exit promptly with a clear error
// when the Flow Aggregator connection drops mid-stream, not hang waiting for it to come back (see
// the design doc's decision: retry policy, if any, belongs to the caller, not to observe itself).
func testAntctlObserveExitsOnDisconnect(t *testing.T, data *TestData) {
	podName := "antctl-observe-disconnect-" + randSeq(6)
	cleanup := startObservePod(t, data, podName, true, nil, false, "--follow")
	defer cleanup()

	// Give the stream a moment to actually connect before pulling the rug out from under it —
	// otherwise a Pod that failed to connect at all for an unrelated reason could be
	// misattributed to this test's own disconnect.
	require.Eventually(t, func() bool {
		logs, err := data.GetPodLogs(context.TODO(), data.testNamespace, podName, antctlObserveContainerName)
		return err == nil && !strings.Contains(logs, "Error:")
	}, 30*time.Second, defaultInterval, "antctl observe did not start cleanly before the Flow Aggregator was restarted")

	require.NoError(t, data.restartFlowAggregator(flowAggregatorNamespace), "failed to restart the Flow Aggregator to sever the connection")

	require.Eventually(t, func() bool {
		pod, err := data.clientset.CoreV1().Pods(data.testNamespace).Get(context.TODO(), podName, metav1.GetOptions{})
		if err != nil {
			return false
		}
		// PodBuilder.Create (framework.go) hardcodes RestartPolicy: Never for every Pod it
		// creates, this one included: a container that exits simply stays exited (Pod phase
		// Succeeded/Failed), it is never restarted. So the signal to look for is the container's
		// own Terminated state, not RestartCount, which can never leave 0 here regardless of
		// whether antctl observe exited promptly or not.
		for _, cs := range pod.Status.ContainerStatuses {
			if cs.State.Terminated != nil {
				return true
			}
		}
		return false
	}, 30*time.Second, defaultInterval, "antctl observe did not exit promptly when the Flow Aggregator connection was severed")
}
