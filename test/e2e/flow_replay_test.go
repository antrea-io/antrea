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
	// The NetworkPolicy logging groups are the only groups of type "all" when multicast is not
	// used.
	countAllGroups := func() int {
		groups := runOVSCommand("ovs-ofctl", "-O", "OpenFlow15", "dump-groups", defaultBridgeName)
		return strings.Count(groups, "type=all")
	}
	// isConnectionDropped distinguishes a failed connection from an error executing nc.
	isConnectionDropped := func() (bool, error) {
		cmd := []string{"nc", "-vz", "-w", "3", serverIP.String(), "80"}
		_, _, err := data.RunCommandFromPod(namespace, clientName, toolboxContainerName, cmd)
		var exitErr utilexec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitStatus() == 1 {
			return true, nil
		}
		return false, err
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
	err = wait.PollUntilContextTimeout(context.Background(), time.Second, defaultTimeout, true, func(ctx context.Context) (bool, error) {
		dropped, err := isConnectionDropped()
		return !dropped, err
	})
	require.NoError(t, err, "Connection should succeed before installing the ANNP")

	t.Logf("Creating an ANNP with a Drop rule with logging enabled")
	annp, err := data.CreateOrUpdateANNP(newDropRuleWithLogging(randName("drop-logged-"), 80))
	require.NoError(t, err)
	defer data.DeleteANNP(namespace, annp.Name)
	require.NoError(t, data.waitForANNPRealized(t, namespace, annp.Name, policyRealizedTimeout))
	dropped, err := isConnectionDropped()
	require.NoError(t, err)
	require.True(t, dropped, "Connection should be dropped by the ANNP")
	numAllGroups := countAllGroups()
	require.NotZero(t, numAllGroups, "NetworkPolicy logging groups should be installed")

	t.Logf("Making OVS reject new flows in table 0 on Node '%s'", nodeName)
	// The default flows are already installed, and OVS replaces an existing flow instead of
	// adding a new one, so delete one of them to make the bundle of default flows fail.
	runOVSCommand("ovs-ofctl", "-O", "OpenFlow15", "--strict", "del-flows", defaultBridgeName, "table=0,priority=0")
	runOVSCommand("ovs-vsctl", "--", "--id=@ft", "create", "Flow_Table", "flow_limit=0", "overflow_policy=refuse",
		"--", "set", "Bridge", defaultBridgeName, "flow_tables:0=@ft")
	removeFlowLimit := func() {
		runOVSCommand("ovs-vsctl", "--if-exists", "remove", "Bridge", defaultBridgeName, "flow_tables", "0")
	}
	defer removeFlowLimit()

	// Changing the OpenFlow versions allowed by the bridge makes OVS close the OpenFlow
	// connections, after which the Agent reconnects and replays flows.
	protocols := runOVSCommand("ovs-vsctl", "get", "Bridge", defaultBridgeName, "protocols")
	t.Logf("Forcing the Agent to reconnect to OVS by changing the bridge protocols from %s", protocols)
	newProtocols := "OpenFlow15"
	if protocols == `["OpenFlow15"]` || protocols == "[OpenFlow15]" {
		newProtocols = "OpenFlow10,OpenFlow15"
	}
	replayStart := metav1.Now()
	runOVSCommand("ovs-vsctl", "set", "Bridge", defaultBridgeName, "protocols="+newProtocols)
	defer func() {
		restoredProtocols := strings.Trim(protocols, "[]")
		restoredProtocols = strings.ReplaceAll(strings.ReplaceAll(restoredProtocols, `"`, ""), " ", "")
		runOVSCommand("ovs-vsctl", "set", "Bridge", defaultBridgeName, "protocols="+restoredProtocols)
	}()

	t.Logf("Waiting for the flow replay to fail and leave OVS without NetworkPolicy logging groups")
	err = wait.PollUntilContextTimeout(context.Background(), time.Second, 30*time.Second, true, func(ctx context.Context) (bool, error) {
		// Groups disappear during every replay. Wait for the attempt to fail before
		// removing the fault, so recovery must come from a subsequent retry.
		logs, err := data.clientset.CoreV1().Pods(antreaNamespace).GetLogs(antreaPodName, &corev1.PodLogOptions{
			Container: agentContainerName,
			SinceTime: &replayStart,
		}).DoRaw(ctx)
		if err != nil {
			return false, err
		}
		return strings.Contains(string(logs), "Flow replay failed, will retry"), nil
	})
	require.NoError(t, err, "The Agent should report a failed flow replay")
	require.Zero(t, countAllGroups(), "NetworkPolicy logging groups should be deleted by the failed flow replay")

	t.Logf("Removing the flow limit, the Agent should recover without reconnecting to OVS")
	removeFlowLimit()
	err = wait.PollUntilContextTimeout(context.Background(), time.Second, 2*replayRetryTimeout, true, func(ctx context.Context) (bool, error) {
		if countAllGroups() != numAllGroups {
			return false, nil
		}
		// initialize restores groups before the cached policy action flows are replayed.
		return isConnectionDropped()
	})
	require.NoError(t, err, "A flow replay retry should restore logging groups and ANNP Drop enforcement")

	t.Logf("Creating another ANNP with a Drop rule with logging enabled")
	annp2, err := data.CreateOrUpdateANNP(newDropRuleWithLogging(randName("drop-logged-"), 8080))
	require.NoError(t, err)
	defer data.DeleteANNP(namespace, annp2.Name)
	assert.NoError(t, data.waitForANNPRealized(t, namespace, annp2.Name, policyRealizedTimeout))
}
