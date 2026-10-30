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

package observe

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	flowpb "antrea.io/antrea/v2/pkg/apis/flow/v1alpha1"
)

func TestParseColumns(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []string
		want []string
		err  string
	}{
		{name: "default"},
		{name: "requested order", in: []string{"tcpState", "source", " sourcePodLabels "}, want: []string{"tcpState", "source", "sourcePodLabels"}},
		{name: "empty selection", in: []string{}, err: "requires at least one column"},
		{name: "unknown", in: []string{"source", "sorce"}, err: `unknown column "sorce"`},
		{name: "empty entry", in: []string{"source", ""}, err: `unknown column ""`},
		{name: "duplicate", in: []string{"source", " source "}, err: `duplicate column "source"`},
		{name: "case sensitive", in: []string{"SourceIP"}, err: `unknown column "SourceIP"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			columns, err := parseColumns(tc.in)
			if tc.err != "" {
				require.ErrorContains(t, err, tc.err)
				return
			}
			require.NoError(t, err)
			var names []string
			for _, c := range columns {
				names = append(names, c.name)
			}
			assert.Equal(t, tc.want, names)
		})
	}
}

func TestColumnsMatchJSONFields(t *testing.T) {
	// All JSON fields must be selectable under the same name and read the same value. In
	// particular, forward/reverse counters and ingress/egress policies must not get swapped.
	r := toRecord(enrichedFlow())
	data, err := json.Marshal(r)
	require.NoError(t, err)
	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(data, &fields))
	for name, want := range fields {
		columns, err := parseColumns([]string{name})
		require.NoError(t, err, name)
		got, err := json.Marshal(columns[0].value(r))
		require.NoError(t, err)
		assert.JSONEq(t, string(want), string(got), name)
	}
	assert.Len(t, availableColumns, len(fields)+3, "only source, destination and totalBytes are combined columns")
	_, err = parseColumns(columnNames())
	require.NoError(t, err, "the supported column list must have no duplicate names")

	flag := Command.Flags().Lookup("columns")
	require.NotNil(t, flag)
	assert.Equal(t, "c", flag.Shorthand)
	assert.Equal(t, "f", Command.Flags().Lookup("follow").Shorthand)
	for _, name := range columnNames() {
		assert.Contains(t, flag.Usage, name, "--columns help must list every supported column")
	}
}

func TestTextRenderer_SelectedColumns(t *testing.T) {
	t.Run("requested order, labels and one header across batches", func(t *testing.T) {
		columns, err := parseColumns([]string{"tcpState", "sourcePodLabels", "ingressNetworkPolicyName", "packetTotalCount"})
		require.NoError(t, err)
		var out bytes.Buffer
		r := &textRenderer{out: &out, columns: columns}
		require.NoError(t, r.render(nil, 0))
		assert.Empty(t, out.String())
		require.NoError(t, r.render([]*flowpb.Flow{enrichedFlow()}, 0))
		require.NoError(t, r.render([]*flowpb.Flow{enrichedFlow()}, 0))
		lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
		require.Len(t, lines, 3)
		assert.Equal(t, []string{"tcpState", "sourcePodLabels", "ingressNetworkPolicyName", "packetTotalCount"}, strings.Fields(lines[0]))
		assert.Equal(t, []string{"ESTABLISHED", "app=web,tier=frontend", "allow-web", "100"}, strings.Fields(lines[1]))
		assert.Equal(t, lines[1], lines[2])
		assert.NotContains(t, out.String(), "default/perftest-b", "unselected columns must not appear")
	})

	t.Run("long labels stay aligned and empty labels differ from missing", func(t *testing.T) {
		columns, err := parseColumns([]string{"sourcePodLabels", "destinationPodLabels", "sourcePort"})
		require.NoError(t, err)
		f := testFlow()
		f.K8S.SourcePodLabels = &flowpb.Labels{Labels: map[string]string{
			"app": strings.Repeat("a", 63), "tier": strings.Repeat("b", 63),
		}}
		f.K8S.DestinationPodLabels = &flowpb.Labels{}
		var out bytes.Buffer
		r := &textRenderer{out: &out, columns: columns}
		require.NoError(t, r.render([]*flowpb.Flow{f}, 0))
		require.NoError(t, r.render([]*flowpb.Flow{testFlow()}, 0))
		lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
		require.Len(t, lines, 3)
		assert.Contains(t, lines[1], "...")
		assert.Contains(t, lines[1], "{}")
		assert.Equal(t, []string{"-", "-", "12345"}, strings.Fields(lines[2]))
		assert.Equal(t, strings.Index(lines[0], "sourcePort"), strings.Index(lines[1], "12345"))
		assert.Equal(t, strings.Index(lines[0], "sourcePort"), strings.Index(lines[2], "12345"))
	})

	t.Run("byte formatting does not change packets, ports or throughput", func(t *testing.T) {
		columns, err := parseColumns([]string{"octetDeltaCount", "reverseOctetDeltaCount", "totalBytes", "packetTotalCount", "throughput", "proxySnatPort"})
		require.NoError(t, err)
		var out bytes.Buffer
		r := &textRenderer{out: &out, columns: columns, humanReadableBytes: true}
		require.NoError(t, r.render([]*flowpb.Flow{enrichedFlow()}, 0))
		lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
		assert.Equal(t, []string{"1.0KB", "2.0KB", "1.5KB", "100", "8192", "54321"}, strings.Fields(lines[1]))
	})

	t.Run("withheld identity leaves policy actions and disclosure visible", func(t *testing.T) {
		f := redactedFlow(flowpb.FlowType_FLOW_TYPE_INTER_NODE)
		f.K8S.IngressNetworkPolicyType = flowpb.NetworkPolicyType_NETWORK_POLICY_TYPE_ACNP
		f.K8S.IngressNetworkPolicyRuleAction = flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_DROP
		columns, err := parseColumns([]string{
			"destination", "destinationPodLabels", "ingressNetworkPolicyName",
			"ingressNetworkPolicyRuleAction", "destinationDisclosure",
		})
		require.NoError(t, err)
		var out bytes.Buffer
		require.NoError(t, (&textRenderer{out: &out, columns: columns}).render([]*flowpb.Flow{f}, 0))
		lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
		assert.Equal(t, []string{
			"default/<redacted>(10.0.0.6)", "-", "-", "NETWORK_POLICY_RULE_ACTION_DROP", "flow",
		}, strings.Fields(lines[1]))
	})

	t.Run("write failures are returned", func(t *testing.T) {
		columns, err := parseColumns([]string{"source", "tcpState"})
		require.NoError(t, err)
		r := &textRenderer{out: &erroringWriter{}, columns: columns}
		require.ErrorContains(t, r.render([]*flowpb.Flow{enrichedFlow()}, 0), "write failed")
	})
}
