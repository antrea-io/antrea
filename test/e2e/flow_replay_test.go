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

package e2e

import (
	"context"
	"errors"
	"fmt"
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
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	utilexec "k8s.io/client-go/util/exec"

	crdv1beta1 "antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
)

// replayRetryTimeout is the maximum delay between two flow replay attempts in the Agent
// (replayFlowsMaxRetryDelay).
const replayRetryTimeout = 30 * time.Second

// klogHeaderRegex matches the header which starts every klog entry, e.g.
// "E1117 18:50:43.070068      15 agent.go:654] ".
var klogHeaderRegex = regexp.MustCompile(`^[IWEF]\d{4} \d{2}:\d{2}:\d{2}\.\d{6}\s`)

// splitKlogEntries splits logs written by klog into entries. An entry can span multiple lines, as
// klog writes a value containing line breaks, e.g. an error joining several errors, on separate
// lines, followed by the remaining key/value pairs of the entry.
func splitKlogEntries(logs string) []string {
	var entries []string
	for line := range strings.Lines(logs) {
		if len(entries) == 0 || klogHeaderRegex.MatchString(line) {
			entries = append(entries, line)
		} else {
			entries[len(entries)-1] += line
		}
	}
	return entries
}

// containsAll tells whether s contains all of the given substrings.
func containsAll(s string, substrings ...string) bool {
	return !slices.ContainsFunc(substrings, func(substring string) bool { return !strings.Contains(s, substring) })
}

// TestFlowReplayRetry verifies that the Agent recovers when replaying flows after a reconnection
// to OVS fails. Every replay starts by deleting all OVS groups, so a replay that fails before
// reinstalling the NetworkPolicy logging groups leaves the Drop rules with logging enabled
// unenforced, and prevents any such new rule from being installed, until the replay succeeds.
//
// To make the replay fail deterministically, the test limits the number of flows in table 0 so
// that OVS rejects the bundle of default flows, and then forces a reconnection to OVS. When the
// limit is removed, the Agent is expected to recover by retrying the replay, without any further
// reconnection.
func TestFlowReplayRetry(t *testing.T) {
	skipIfHasWindowsNodes(t)
	skipIfAntreaPolicyDisabled(t)
	skipIfNumNodesLessThan(t, 2)

	data, err := setupTest(t)
	if err != nil {
		t.Fatalf("Error when setting up test: %v", err)
	}
	defer teardownTest(t, data)

	nodeName := workerNodeName(1)
	namespace := data.testNamespace
	serverLabels := map[string]string{"app": "flow-replay-server"}
	clientLabels := map[string]string{"app": "flow-replay-client"}
	serverName := randName("flow-replay-server-")
	clientName := randName("flow-replay-client-")
	require.NoError(t, NewPodBuilder(serverName, namespace, nginxImage).OnNode(nodeName).WithLabels(serverLabels).Create(data))
	defer deletePodWrapper(t, data, namespace, serverName)
	require.NoError(t, NewPodBuilder(clientName, namespace, ToolboxImage).OnNode(nodeName).WithLabels(clientLabels).Create(data))
	defer deletePodWrapper(t, data, namespace, clientName)
	serverIPs, err := data.podWaitForIPs(defaultTimeout, serverName, namespace)
	require.NoError(t, err)
	_, err = data.podWaitForIPs(defaultTimeout, clientName, namespace)
	require.NoError(t, err)
	serverIP := serverIPs.IPv4
	if serverIP == nil {
		serverIP = serverIPs.IPv6
	}

	antreaPodName, err := data.getAntreaPodOnNode(nodeName)
	require.NoError(t, err)
	runOVSCommand := func(cmd ...string) string {
		stdout, stderr, err := data.RunCommandFromPod(antreaNamespace, antreaPodName, ovsContainerName, cmd)
		require.NoError(t, err, "Error when running %v: stdout: %s, stderr: %s", cmd, stdout, stderr)
		return strings.TrimSpace(stdout)
	}
	// countLoggingGroups counts the NetworkPolicy logging groups. Multicast groups also have type
	// "all", and are replayed even when initialize fails, but every one of their buckets starts
	// by loading a register (or they have no bucket at all), whereas the first bucket of a
	// logging group only resubmits the packet to the next table.
	countLoggingGroups := func() int {
		groups := runOVSCommand("ovs-ofctl", "-O", "OpenFlow15", "dump-groups", defaultBridgeName)
		count := 0
		for line := range strings.Lines(groups) {
			if !strings.Contains(line, "type=all") {
				continue
			}
			if _, actions, found := strings.Cut(line, "actions="); found && strings.HasPrefix(actions, "resubmit(") {
				count++
			}
		}
		return count
	}
	// isConnectionDropped tells whether a TCP connection to the server is dropped, i.e. it times
	// out, as opposed to succeeding or being refused by the server. Any other failure, e.g. an
	// error executing nc or a DNS or routing error, does not tell anything about the policy
	// enforcement, and is returned as an error.
	isConnectionDropped := func(port int32) (bool, error) {
		cmd := []string{"nc", "-vz", "-w", "3", serverIP.String(), strconv.Itoa(int(port))}
		_, stderr, err := data.RunCommandFromPod(namespace, clientName, toolboxContainerName, cmd)
		if err == nil {
			return false, nil
		}
		var exitErr utilexec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitStatus() != 1 {
			return false, err
		}
		// The nc in the toolbox image is Ncat, which reports "Ncat: TIMEOUT." when the connection
		// times out and "Ncat: Connection refused." when it is refused. "timed out" is how other
		// implementations report a timeout.
		switch lowerStderr := strings.ToLower(stderr); {
		case strings.Contains(lowerStderr, "timeout"), strings.Contains(lowerStderr, "timed out"):
			return true, nil
		case strings.Contains(lowerStderr, "refused"):
			return false, nil
		}
		return false, fmt.Errorf("unexpected failure of nc: %w, stderr: %s", err, stderr)
	}
	// waitForConnection waits until the connection to the server is dropped or not, as
	// expected. Errors when probing the connection are retried.
	waitForConnection := func(port int32, expectedDropped bool, timeout time.Duration) error {
		return wait.PollUntilContextTimeout(context.Background(), time.Second, timeout, true, func(ctx context.Context) (bool, error) {
			dropped, err := isConnectionDropped(port)
			if err != nil {
				t.Logf("Failed to probe the connection to port %d, will retry: %v", port, err)
				return false, nil
			}
			return dropped == expectedDropped, nil
		})
	}
	getAgentLogEntries := func(ctx context.Context) ([]string, error) {
		logs, err := data.clientset.CoreV1().Pods(antreaNamespace).GetLogs(antreaPodName, &corev1.PodLogOptions{
			Container: agentContainerName,
		}).DoRaw(ctx)
		if err != nil {
			return nil, err
		}
		return splitKlogEntries(string(logs)), nil
	}
	// countAgentLogEntries counts the entries of the Agent log containing all of the given strings.
	countAgentLogEntries := func(ctx context.Context, substrings ...string) (int, error) {
		entries, err := getAgentLogEntries(ctx)
		if err != nil {
			return 0, err
		}
		count := 0
		for _, entry := range entries {
			if containsAll(entry, substrings...) {
				count++
			}
		}
		return count, nil
	}
	newDropRuleWithLogging := func(name string, port int32) *crdv1beta1.NetworkPolicy {
		return &crdv1beta1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
			Spec: crdv1beta1.NetworkPolicySpec{
				Tier:      defaultTierName,
				Priority:  5,
				AppliedTo: []crdv1beta1.AppliedTo{{PodSelector: &metav1.LabelSelector{MatchLabels: serverLabels}}},
				Ingress: []crdv1beta1.Rule{{
					Action:        new(crdv1beta1.RuleActionDrop),
					EnableLogging: true,
					From:          []crdv1beta1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{MatchLabels: clientLabels}}},
					Ports: []crdv1beta1.NetworkPolicyPort{{
						Protocol: new(corev1.ProtocolTCP),
						Port:     new(intstr.FromInt32(port)),
					}},
				}},
			},
		}
	}

	// Verify that the server is reachable before testing policy enforcement.
	require.NoError(t, waitForConnection(80, false, defaultTimeout), "Connection should succeed before installing the ANNP")

	t.Logf("Creating an ANNP with a Drop rule with logging enabled")
	annp, err := data.CreateOrUpdateANNP(newDropRuleWithLogging(randName("drop-logged-"), 80))
	require.NoError(t, err)
	defer data.DeleteANNP(namespace, annp.Name)
	require.NoError(t, data.waitForANNPRealized(t, namespace, annp.Name, policyRealizedTimeout))
	require.NoError(t, waitForConnection(80, true, defaultTimeout), "Connection should be dropped by the ANNP")
	numLoggingGroups := countLoggingGroups()
	require.NotZero(t, numLoggingGroups, "NetworkPolicy logging groups should be installed")

	// The Agent logs are not filtered by time, as the precision of the log timestamp filter is
	// one second and entries logged just before the fault could be selected. Instead, count the
	// entries logged before the reconnection, and wait for new ones.
	// See restoreOVSOnReconnection in pkg/agent/agent.go for these messages.
	const (
		reconnectedLog   = "Replaying OF flows to OVS bridge"
		stepFailedLog    = "Step failed after OVS reconnection"
		stepCompletedLog = "Step completed after OVS reconnection"
		replayStep       = `step="Replay OF flows"`
	)
	// waitForReplayAfterReconnection waits until the Agent has reconnected to OVS more than
	// numReconnections times, and has replayed flows successfully after the last reconnection.
	waitForReplayAfterReconnection := func(numReconnections int) error {
		return wait.PollUntilContextTimeout(context.Background(), time.Second, 2*replayRetryTimeout, true, func(ctx context.Context) (bool, error) {
			entries, err := getAgentLogEntries(ctx)
			if err != nil {
				return false, err
			}
			reconnections, replayed := 0, false
			for _, entry := range entries {
				if containsAll(entry, reconnectedLog) {
					reconnections++
					replayed = false
				} else if containsAll(entry, stepCompletedLog, replayStep) {
					replayed = true
				}
			}
			return reconnections > numReconnections && replayed, nil
		})
	}

	// Changing the OpenFlow versions allowed by the bridge makes OVS close the OpenFlow
	// connections, after which the Agent reconnects and replays flows. Toggle OpenFlow13, which
	// is used neither by the Agent, which uses OpenFlow15, nor by the ovs-ofctl commands it runs
	// after a reconnection to restore port configs, which use OpenFlow10.
	protocols := runOVSCommand("ovs-vsctl", "get", "Bridge", defaultBridgeName, "protocols")
	origProtocols := strings.Split(strings.NewReplacer("[", "", "]", "", `"`, "", " ", "").Replace(protocols), ",")
	require.Contains(t, origProtocols, "OpenFlow15")
	newProtocols := append(slices.Clone(origProtocols), "OpenFlow13")
	if slices.Contains(origProtocols, "OpenFlow13") {
		newProtocols = slices.DeleteFunc(slices.Clone(origProtocols), func(p string) bool { return p == "OpenFlow13" })
	}
	setProtocols := func(protocols []string) {
		runOVSCommand("ovs-vsctl", "set", "Bridge", defaultBridgeName, "protocols="+strings.Join(protocols, ","))
	}

	t.Logf("Making OVS reject new flows in table 0 on Node '%s'", nodeName)
	// The default flows are already installed, and OVS replaces an existing flow instead of
	// adding a new one, so delete one of them to make the bundle of default flows fail.
	runOVSCommand("ovs-ofctl", "-O", "OpenFlow15", "--strict", "del-flows", defaultBridgeName, "table=0,priority=0")
	runOVSCommand("ovs-vsctl", "--", "--id=@ft", "create", "Flow_Table", "flow_limit=0", "overflow_policy=refuse",
		"--", "set", "Bridge", defaultBridgeName, "flow_tables:0=@ft")
	removeFlowLimit := func() {
		runOVSCommand("ovs-vsctl", "--if-exists", "remove", "Bridge", defaultBridgeName, "flow_tables", "0")
	}
	protocolsChanged := false
	defer func() {
		// Remove the flow limit first, so that the replay after restoring the protocols can
		// succeed.
		removeFlowLimit()
		if !protocolsChanged {
			return
		}
		numReconnections, err := countAgentLogEntries(context.Background(), reconnectedLog)
		setProtocols(origProtocols)
		if !assert.NoError(t, err, "Failed to get the Agent logs") {
			return
		}
		// Wait for the replay, so that the Agent is not disconnected from OVS while the test
		// resources are deleted, nor when the next test starts.
		assert.NoError(t, waitForReplayAfterReconnection(numReconnections), "The Agent should replay flows after the bridge protocols are restored")
	}()

	t.Logf("Forcing the Agent to reconnect to OVS by changing the bridge protocols from %v to %v", origProtocols, newProtocols)
	numReconnections, err := countAgentLogEntries(context.Background(), reconnectedLog)
	require.NoError(t, err)
	numReplayFailures, err := countAgentLogEntries(context.Background(), stepFailedLog, replayStep)
	require.NoError(t, err)
	setProtocols(newProtocols)
	protocolsChanged = true

	// Changing the protocols may not close the OpenFlow connection with some OVS versions. Check
	// that the Agent reconnected first, so that the cause is clear if it did not.
	t.Logf("Waiting for the Agent to reconnect to OVS")
	err = wait.PollUntilContextTimeout(context.Background(), time.Second, 30*time.Second, true, func(ctx context.Context) (bool, error) {
		count, err := countAgentLogEntries(ctx, reconnectedLog)
		return count > numReconnections, err
	})
	require.NoError(t, err, "The Agent should reconnect to OVS after the bridge protocols are changed")

	t.Logf("Waiting for the flow replay to fail and leave OVS without NetworkPolicy logging groups")
	err = wait.PollUntilContextTimeout(context.Background(), time.Second, 30*time.Second, true, func(ctx context.Context) (bool, error) {
		// Groups disappear during every replay. Wait for the attempt to fail before
		// removing the fault, so recovery must come from a subsequent retry. The failure
		// is logged as a multi-line entry when several errors are joined.
		count, err := countAgentLogEntries(ctx, stepFailedLog, replayStep)
		return count > numReplayFailures, err
	})
	require.NoError(t, err, "The Agent should report a failed flow replay")
	require.Zero(t, countLoggingGroups(), "NetworkPolicy logging groups should be deleted by the failed flow replay")

	t.Logf("Removing the flow limit, the Agent should recover without reconnecting to OVS")
	removeFlowLimit()
	err = wait.PollUntilContextTimeout(context.Background(), time.Second, 2*replayRetryTimeout, true, func(ctx context.Context) (bool, error) {
		if countLoggingGroups() != numLoggingGroups {
			return false, nil
		}
		// initialize restores groups before the cached policy action flows are replayed.
		dropped, err := isConnectionDropped(80)
		if err != nil {
			t.Logf("Failed to probe the connection to port 80, will retry: %v", err)
			return false, nil
		}
		return dropped, nil
	})
	require.NoError(t, err, "A flow replay retry should restore logging groups and ANNP Drop enforcement")

	t.Logf("Creating another ANNP with a Drop rule with logging enabled")
	// Nothing listens on this port, so the server refuses connections until the rule is enforced.
	const anotherPort = 8080
	require.NoError(t, waitForConnection(anotherPort, false, defaultTimeout), "Connection should be refused before installing the second ANNP")
	annp2, err := data.CreateOrUpdateANNP(newDropRuleWithLogging(randName("drop-logged-"), anotherPort))
	require.NoError(t, err)
	defer data.DeleteANNP(namespace, annp2.Name)
	require.NoError(t, data.waitForANNPRealized(t, namespace, annp2.Name, policyRealizedTimeout))
	// The logging groups are shared by all the rules (there is one per table), so installing a
	// rule must not add any. What proves that the new rule works is that its Drop action, which
	// refers to a logging group, is enforced.
	assert.NoError(t, waitForConnection(anotherPort, true, defaultTimeout), "Connection should be dropped by the second ANNP")
	assert.Equal(t, numLoggingGroups, countLoggingGroups(), "NetworkPolicy logging groups should not change")
}
