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
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
)

func testAntctlObserveColumns(t *testing.T, data *TestData) {
	label := randSeq(8)
	addLabelToTestPods(t, data, label, []string{"perftest-a", "perftest-c"})
	deployAntreaNetworkPolicies(t, data, "perftest-a", "perftest-c", controlPlaneNodeName(), workerNodeName(1))
	for i := 0; i < 2; i++ {
		generateOneFlow(t, data, "perftest-a", podCIPs.IPv4.String(), perftestListenPort)
	}
	args := []string{"--flow-aggregator-namespace", flowAggregatorNamespace, "--selector", "targetLabel=" + label}
	// Wait for both connections so that a broken --max-count cannot pass just because the
	// Flow Aggregator happened to have only one matching record when the command ran.
	require.NoError(t, wait.PollUntilContextTimeout(context.Background(), defaultInterval, defaultTimeout, false, func(ctx context.Context) (bool, error) {
		stdout, stderr, err := runObserve(data, append(append([]string{}, args...), "-o", "json")...)
		if err != nil {
			return false, fmt.Errorf("failed to read generated flows: %w: %s", err, stderr)
		}
		return countDistinctFlows(parseObserveJSON(t, stdout)) >= 2, nil
	}), "Flow Aggregator did not report both generated connections")
	args = append(args, "--max-count", "1")

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

	t.Run("JSON", func(t *testing.T) {
		stdout, stderr, err := runObserve(data, append(append([]string{}, args...), "-o", "json")...)
		require.NoErrorf(t, err, "antctl observe -o json failed: %s", stderr)
		lines := strings.Split(strings.TrimSpace(stdout), "\n")
		require.Len(t, lines, 1, "--max-count 1 must emit exactly one JSON record")
		var fields map[string]json.RawMessage
		require.NoError(t, json.Unmarshal([]byte(lines[0]), &fields))
		assert.Len(t, fields, 48, "JSON must include the full record, including fields outside the default table")
		for name, value := range want {
			require.Contains(t, fields, name)
			expected, err := json.Marshal(value)
			require.NoError(t, err)
			assert.JSONEq(t, string(expected), string(fields[name]), name)
		}
		for _, name := range []string{
			"endTime", "startTime", "endReason", "tcpState", "sourcePort", "destinationServiceName",
			"destinationServiceIP", "destinationServicePort", "packetTotalCount", "reversePacketTotalCount",
			"octetTotalCount", "reverseOctetTotalCount", "packetDeltaCount", "reversePacketDeltaCount",
			"octetDeltaCount", "reverseOctetDeltaCount", "egressName", "egressIP", "egressNodeName",
			"proxySnatIP", "proxySnatPort", "throughput", "reverseThroughput",
		} {
			assert.Contains(t, fields, name)
		}
	})

	for _, tc := range []struct {
		name    string
		columns []string
	}{
		{"SingleColumn", []string{"sourcePodName"}},
		{"Endpoints", []string{"destinationIP", "sourceIP", "destinationPodName", "sourcePodName", "destinationPort", "protocol"}},
		{"LabelsAndPlacement", []string{"sourceNodeName", "sourcePodLabels", "destinationNodeName", "destinationPodLabels"}},
		{"IngressPolicy", []string{"ingressNetworkPolicyRuleAction", "ingressNetworkPolicyNamespace", "ingressNetworkPolicyName", "ingressNetworkPolicyType", "ingressNetworkPolicyRuleName"}},
		{"EgressPolicy", []string{"egressNetworkPolicyName", "egressNetworkPolicyNamespace", "egressNetworkPolicyType", "egressNetworkPolicyRuleName", "egressNetworkPolicyRuleAction"}},
	} {
		t.Run("Text/"+tc.name, func(t *testing.T) {
			stdout, stderr, err := runObserve(data, append(append([]string{}, args...), "-o", "text", "-c", strings.Join(tc.columns, ","))...)
			require.NoErrorf(t, err, "antctl observe -c failed: %s", stderr)
			lines := strings.Split(strings.TrimSpace(stdout), "\n")
			require.Len(t, lines, 2, "--max-count 1 must emit one header and exactly one record")
			assert.Equal(t, tc.columns, strings.Fields(lines[0]), "column headers must follow the requested order")
			values := strings.Fields(lines[1])
			require.Len(t, values, len(tc.columns), "unselected columns must not be printed")
			for i, name := range tc.columns {
				value := want[name]
				if podLabels, ok := value.(map[string]string); ok {
					value = labels.Set(podLabels).String()
				}
				// The shared fixture's policy names exceed the text column width. Their
				// complete, distinct names are checked in JSON above; text keeps their prefix.
				if name == "ingressNetworkPolicyName" || name == "egressNetworkPolicyName" {
					value = "test-flow-aggregator-antrea-networkpolic..."
				}
				assert.Equal(t, fmt.Sprint(value), values[i], name)
			}
		})
	}

	t.Run("Text/CountersAndTime", func(t *testing.T) {
		columns := []string{"startTime", "endTime", "packetTotalCount", "reversePacketTotalCount", "octetDeltaCount", "reverseOctetDeltaCount", "throughput", "reverseThroughput"}
		stdout, stderr, err := runObserve(data, append(append([]string{}, args...), "-c", strings.Join(columns, ","))...)
		require.NoErrorf(t, err, "antctl observe -c failed: %s", stderr)
		lines := strings.Split(strings.TrimSpace(stdout), "\n")
		require.Len(t, lines, 2)
		assert.Equal(t, columns, strings.Fields(lines[0]))
		values := strings.Fields(lines[1])
		require.Len(t, values, len(columns))
		start, err := time.Parse(time.RFC3339, values[0])
		require.NoError(t, err)
		end, err := time.Parse(time.RFC3339, values[1])
		require.NoError(t, err)
		assert.False(t, end.Before(start), "a flow cannot end before it starts")
		for i := 2; i < len(values); i++ {
			_, err := strconv.ParseUint(values[i], 10, 64)
			assert.NoError(t, err, columns[i]+" must be an unsigned integer")
		}
	})

	t.Run("JSONRejectsColumns", func(t *testing.T) {
		stdout, stderr, err := runObserve(data, append(append([]string{}, args...), "-o", "json", "-c", "sourcePodName,sourcePodLabels")...)
		require.Error(t, err, "--columns is only supported for text output")
		assert.Empty(t, stdout, "an invalid invocation must not emit partial flow records")
		assert.Contains(t, stderr, "--columns can only be used with text output")
	})
}
