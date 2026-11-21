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
	"fmt"
	"net"
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

	crdv1beta1 "antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
)

// replayRetryTimeout is the maximum delay between two flow replay attempts in the Agent
// (ovsRestoreMaxRetryDelay).
const replayRetryTimeout = 30 * time.Second

// TestFlowReplayRetry verifies that the Agent recovers when replaying flows after a reconnection
// to OVS fails. Every replay starts by deleting all OVS groups, so a replay that fails before
// reinstalling the NetworkPolicy logging groups leaves the Drop rules with logging enabled
// unenforced, and prevents any such new rule from being installed, until the replay succeeds.
//
// To make the replay fail deterministically, the test limits the number of flows in table 0 so
// that OVS rejects the bundle of default flows, and then makes ovs-vswitchd drop its OpenFlow
// connections, so that the Agent reconnects. When the limit is removed, the Agent is expected to
// recover by retrying the replay, without any further reconnection.
func TestFlowReplayRetry(t *testing.T) {
	skipIfHasWindowsNodes(t)
	skipIfNotRequired(t, "mode-irrelevant")
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
	require.NoError(t, NewPodBuilder(clientName, namespace, agnhostImage).OnNode(nodeName).WithLabels(clientLabels).Create(data))
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
	runOVSCommand := func(cmd ...string) (string, error) {
		stdout, stderr, err := data.RunCommandFromPod(antreaNamespace, antreaPodName, ovsContainerName, cmd)
		if err != nil {
			return "", fmt.Errorf("error when running %v: %w, stdout: %s, stderr: %s", cmd, err, stdout, stderr)
		}
		return strings.TrimSpace(stdout), nil
	}
	// forceReconnection makes ovs-vswitchd drop the OpenFlow connections of the bridge, including
	// the Agent's, after which the Agent reconnects and replays flows.
	forceReconnection := func() error {
		_, err := runOVSCommand("ovs-appctl", "bridge/reconnect", defaultBridgeName)
		return err
	}
	removeFlowLimit := func() error {
		_, err := runOVSCommand("ovs-vsctl", "--if-exists", "remove", "Bridge", defaultBridgeName, "flow_tables", "0")
		return err
	}
	// countLoggingGroups counts the NetworkPolicy logging groups. Multicast groups also have type
	// "all", and are replayed even when initialize fails, but every one of their buckets starts
	// by loading a register (or they have no bucket at all), whereas the first bucket of a
	// logging group only resubmits the packet to the next table.
	countLoggingGroups := func() (int, error) {
		groups, err := runOVSCommand("ovs-ofctl", "-O", "OpenFlow15", "dump-groups", defaultBridgeName)
		if err != nil {
			return 0, err
		}
		count := 0
		for line := range strings.Lines(groups) {
			if !strings.Contains(line, "type=all") {
				continue
			}
			if _, actions, found := strings.Cut(line, "actions="); found && strings.HasPrefix(actions, "resubmit(") {
				count++
			}
		}
		return count, nil
	}
	// probe probes a TCP connection from the client to the server.
	probe := func(port int32) PodConnectivityMark {
		url := net.JoinHostPort(serverIP.String(), strconv.Itoa(int(port)))
		return data.RunProbeCommand(namespace, clientName, agnhostContainerName, "", url, ProbeCommand(url, "tcp", ""), nil)
	}
	// waitForConnectivity waits until probing a TCP connection from the client to the server gives
	// the expected result.
	waitForConnectivity := func(port int32, expected PodConnectivityMark, timeout time.Duration) error {
		var result PodConnectivityMark
		err := wait.PollUntilContextTimeout(context.Background(), time.Second, timeout, true, func(ctx context.Context) (bool, error) {
			result = probe(port)
			return result == expected, nil
		})
		if err != nil {
			return fmt.Errorf("expected %s for port %d, last probe result: %s: %w", expected, port, result, err)
		}
		return nil
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

	// See restoreOVSOnReconnection in pkg/agent/agent.go for these messages.
	const (
		reconnectedLog     = "Reconnected to OVS, restoring OVS state"
		replayFailedLog    = "Failed to replay OF flows"
		replayCompletedLog = "Flow replay completed"
	)
	type replayStatus struct {
		// reconnections is the number of times the Agent has reconnected to OVS.
		reconnections int
		// failures is the number of failed flow replays.
		failures int
		// replayed tells whether flows were replayed successfully after the last reconnection.
		replayed bool
	}
	// getReplayStatus gets the replay status from the Agent logs. The logs are not filtered by
	// time, as the precision of the log timestamp filter is one second and entries logged just
	// before the fault could be selected. Instead, the test compares the number of entries with
	// the number logged before the fault.
	getReplayStatus := func(ctx context.Context) (replayStatus, error) {
		logs, err := data.GetPodLogs(ctx, antreaNamespace, antreaPodName, agentContainerName)
		if err != nil {
			return replayStatus{}, err
		}
		var status replayStatus
		for line := range strings.Lines(logs) {
			switch {
			case strings.Contains(line, reconnectedLog):
				status.reconnections++
				status.replayed = false
			case strings.Contains(line, replayFailedLog):
				status.failures++
			case strings.Contains(line, replayCompletedLog):
				status.replayed = true
			}
		}
		return status, nil
	}

	// Verify that the server is reachable before testing policy enforcement.
	require.NoError(t, waitForConnectivity(80, Connected, defaultTimeout), "Connection should succeed before installing the ANNP")

	t.Logf("Creating an ANNP with a Drop rule with logging enabled")
	annp, err := data.CreateOrUpdateANNP(newDropRuleWithLogging(randName("drop-logged-"), 80))
	require.NoError(t, err)
	defer data.DeleteANNP(namespace, annp.Name)
	require.NoError(t, data.waitForANNPRealized(t, namespace, annp.Name, policyRealizedTimeout))
	require.NoError(t, waitForConnectivity(80, Dropped, defaultTimeout), "Connection should be dropped by the ANNP")
	numLoggingGroups, err := countLoggingGroups()
	require.NoError(t, err)
	require.NotZero(t, numLoggingGroups, "NetworkPolicy logging groups should be installed")

	initialStatus, err := getReplayStatus(context.Background())
	require.NoError(t, err)
	// Set once the test has seen the Agent replay flows successfully after the fault.
	recovered := false
	// Restore the Node whichever step below fails, so that the following tests are not affected.
	defer func() {
		// The flow limit is stored in the OVSDB database, which persists across antrea-ovs
		// restarts and Antrea redeployments. If it was left in place, the Agent could not install
		// its default flows the next time ovs-vswitchd starts on this Node.
		limitRemoved := assert.NoError(t, wait.PollUntilContextTimeout(context.Background(), time.Second, 10*time.Second, true, func(ctx context.Context) (bool, error) {
			if err := removeFlowLimit(); err != nil {
				t.Logf("Failed to remove the flow limit, will retry: %v", err)
				return false, nil
			}
			return true, nil
		}), "Failed to remove the flow limit of table 0")
		if recovered {
			return
		}
		// Only a replay restores the flow deleted below, and the Agent may be waiting to retry a
		// failed replay, or may not have reconnected to OVS yet. Force a reconnection, so that
		// the Agent replays flows right away.
		status, err := getReplayStatus(context.Background())
		if !assert.NoError(t, err, "Failed to get the Agent logs") {
			return
		}
		if !assert.NoError(t, forceReconnection(), "Failed to force a reconnection to OVS") {
			return
		}
		if !limitRemoved {
			// The replay cannot succeed while the flow limit is in place.
			return
		}
		assert.NoError(t, wait.PollUntilContextTimeout(context.Background(), time.Second, replayRetryTimeout, true, func(ctx context.Context) (bool, error) {
			s, err := getReplayStatus(ctx)
			return s.reconnections > status.reconnections && s.replayed, err
		}), "The Agent should replay flows after reconnecting to OVS")
	}()

	t.Logf("Making OVS reject new flows in table 0 on Node '%s'", nodeName)
	// The default flows are already installed, and OVS replaces an existing flow instead of
	// adding a new one, so delete one of them to make the bundle of default flows fail.
	_, err = runOVSCommand("ovs-ofctl", "-O", "OpenFlow15", "--strict", "del-flows", defaultBridgeName, "table=0,priority=0")
	require.NoError(t, err)
	_, err = runOVSCommand("ovs-vsctl", "--", "--id=@ft", "create", "Flow_Table", "flow_limit=0", "overflow_policy=refuse",
		"--", "set", "Bridge", defaultBridgeName, "flow_tables:0=@ft")
	require.NoError(t, err)

	t.Logf("Forcing the Agent to reconnect to OVS")
	require.NoError(t, forceReconnection())
	var faultStatus replayStatus
	err = wait.PollUntilContextTimeout(context.Background(), time.Second, 30*time.Second, true, func(ctx context.Context) (bool, error) {
		status, err := getReplayStatus(ctx)
		faultStatus = status
		return status.reconnections > initialStatus.reconnections, err
	})
	require.NoError(t, err, "The Agent should reconnect to OVS")

	t.Logf("Waiting for the flow replay to fail and leave OVS without NetworkPolicy logging groups")
	err = wait.PollUntilContextTimeout(context.Background(), time.Second, 30*time.Second, true, func(ctx context.Context) (bool, error) {
		// Groups disappear during every replay. Wait for the attempt to fail before
		// removing the fault, so recovery must come from a subsequent retry.
		status, err := getReplayStatus(ctx)
		return status.failures > initialStatus.failures, err
	})
	require.NoError(t, err, "The Agent should report a failed flow replay")
	n, err := countLoggingGroups()
	require.NoError(t, err)
	require.Zero(t, n, "NetworkPolicy logging groups should be deleted by the failed flow replay")

	t.Logf("Removing the flow limit, the Agent should recover without reconnecting to OVS")
	require.NoError(t, removeFlowLimit())
	var recoveredStatus replayStatus
	err = wait.PollUntilContextTimeout(context.Background(), time.Second, 2*replayRetryTimeout, true, func(ctx context.Context) (bool, error) {
		if n, err := countLoggingGroups(); err != nil || n != numLoggingGroups {
			return false, err
		}
		// initialize restores groups before the cached policy action flows are replayed.
		if probe(80) != Dropped {
			return false, nil
		}
		status, err := getReplayStatus(ctx)
		recoveredStatus = status
		return status.replayed, err
	})
	require.NoError(t, err, "A flow replay retry should restore logging groups and ANNP Drop enforcement")
	recovered = true
	// If the Agent reconnected to OVS again in the meantime, the replay after that reconnection
	// may be what restored the flows, and the retry would not have been tested.
	require.Equal(t, faultStatus.reconnections, recoveredStatus.reconnections, "The Agent should recover without reconnecting to OVS")

	t.Logf("Creating another ANNP with a Drop rule with logging enabled")
	// Nothing listens on this port, so the server refuses connections until the rule is enforced.
	const anotherPort = 8080
	require.NoError(t, waitForConnectivity(anotherPort, Rejected, defaultTimeout), "Connection should be refused before installing the second ANNP")
	annp2, err := data.CreateOrUpdateANNP(newDropRuleWithLogging(randName("drop-logged-"), anotherPort))
	require.NoError(t, err)
	defer data.DeleteANNP(namespace, annp2.Name)
	require.NoError(t, data.waitForANNPRealized(t, namespace, annp2.Name, policyRealizedTimeout))
	// The logging groups are shared by all the rules (there is one per table), so installing a
	// rule must not add any. What proves that the new rule works is that its Drop action, which
	// refers to a logging group, is enforced.
	assert.NoError(t, waitForConnectivity(anotherPort, Dropped, defaultTimeout), "Connection should be dropped by the second ANNP")
	n, err = countLoggingGroups()
	if assert.NoError(t, err) {
		assert.Equal(t, numLoggingGroups, n, "NetworkPolicy logging groups should not change")
	}
}
