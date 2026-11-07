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
	"google.golang.org/protobuf/proto"

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

func TestColumnCell_Truncation(t *testing.T) {
	podName := "a-deployment-with-a-rather-long-generated-name-5d8f7c9b6-x7k2p"
	require.Greater(t, len(podName), 43)
	ingress := "test-flow-aggregator-antrea-networkpolicy-ingress"
	egress := "test-flow-aggregator-antrea-networkpolicy-egress"
	require.Greater(t, len(ingress), 43)
	require.Greater(t, len(egress), 43)

	for _, tc := range []struct {
		column string
		r      record
		want   string
	}{
		// Names whose distinguishing part is at the end keep the end.
		{column: "sourcePodName", r: record{SourcePodName: podName}, want: "..." + podName[len(podName)-40:]},
		{column: "destinationPodName", r: record{DestinationPodName: podName}, want: "..." + podName[len(podName)-40:]},
		{column: "ingressNetworkPolicyName", r: record{IngressNetworkPolicyName: ingress}, want: "..." + ingress[len(ingress)-40:]},
		{column: "egressNetworkPolicyName", r: record{EgressNetworkPolicyName: egress}, want: "..." + egress[len(egress)-40:]},
		{column: "ingressNetworkPolicyRuleName", r: record{IngressNetworkPolicyName: "p", IngressNetworkPolicyRuleName: ingress}, want: "..." + ingress[len(ingress)-40:]},
		{column: "egressNetworkPolicyRuleName", r: record{EgressNetworkPolicyName: "p", EgressNetworkPolicyRuleName: egress}, want: "..." + egress[len(egress)-40:]},
		{column: "sourceNodeName", r: record{SourceNodeName: podName}, want: "..." + podName[len(podName)-40:]},
		{column: "destinationNodeName", r: record{DestinationNodeName: podName}, want: "..." + podName[len(podName)-40:]},
		{column: "egressNodeName", r: record{EgressNodeName: podName}, want: "..." + podName[len(podName)-40:]},
		// Any other column keeps the start.
		{column: "egressName", r: record{EgressName: ingress}, want: ingress[:40] + "..."},
		// A value that fits is left alone.
		{column: "sourcePodName", r: record{SourcePodName: "short-5d8f7c9b6-x7k2p"}, want: "short-5d8f7c9b6-x7k2p"},
	} {
		t.Run(tc.column+"/"+tc.want, func(t *testing.T) {
			columns, err := parseColumns([]string{tc.column})
			require.NoError(t, err)
			got := columns[0].cell(tc.r, false)
			assert.Equal(t, tc.want, got)
			assert.LessOrEqual(t, len(got), columns[0].width)
		})
	}

	t.Run("two Pods of a Deployment and the two policy directions stay distinguishable", func(t *testing.T) {
		columns, err := parseColumns([]string{"sourcePodName", "ingressNetworkPolicyName", "egressNetworkPolicyName"})
		require.NoError(t, err)
		first := record{SourcePodName: podName, IngressNetworkPolicyName: ingress, EgressNetworkPolicyName: egress}
		second := record{SourcePodName: strings.TrimSuffix(podName, "x7k2p") + "q9m4z"}
		assert.NotEqual(t, columns[0].cell(first, false), columns[0].cell(second, false))
		assert.NotEqual(t, columns[1].cell(first, false), columns[2].cell(first, false))
	})
}

// selectedCells returns what the text output shows in each of the named columns for f.
func selectedCells(t *testing.T, f *flowpb.Flow, names ...string) map[string]string {
	t.Helper()
	columns, err := parseColumns(names)
	require.NoError(t, err)
	r := toRecord(f)
	cells := make(map[string]string, len(columns))
	for _, c := range columns {
		cells[c.name] = c.cell(r, false)
	}
	return cells
}

// TestColumnCell_Withheld checks that a column shows redactedMarker for exactly what the Flow
// Aggregator withholds, and not for a value that is empty because it does not exist. Each flow is
// what redactFlow (pkg/flowaggregator/flowstreamservice/redaction.go) produces from enrichedFlow
// for the tiers in question.
func TestColumnCell_Withheld(t *testing.T) {
	const (
		podName      = "perftest-a"
		dstPodName   = "perftest-b"
		noValue      = "-"
		redacted     = redactedMarker
		serviceName  = "default/frontend:http"
		ingressAllow = "allow-web"
	)
	allColumns := []string{
		"sourcePodNamespace", "sourcePodName", "sourcePodLabels", "sourceNodeName",
		"destinationPodNamespace", "destinationPodName", "destinationPodLabels", "destinationNodeName",
		"destinationServiceName", "destinationServiceIP", "destinationServicePort",
		"egressName", "egressIP", "egressNodeName",
		"ingressNetworkPolicyNamespace", "ingressNetworkPolicyName", "ingressNetworkPolicyRuleName",
		"egressNetworkPolicyNamespace", "egressNetworkPolicyName", "egressNetworkPolicyRuleName",
	}

	// Source tier: flow. The Pod and its placement are withheld, but not its Namespace.
	sourceFlowTier := enrichedFlow()
	sourceFlowTier.K8S.SourceDisclosure = flowpb.EndpointDisclosure_ENDPOINT_DISCLOSURE_FLOW
	sourceFlowTier.K8S.SourcePodName, sourceFlowTier.K8S.SourcePodLabels = "", nil
	sourceFlowTier.K8S.SourceNodeName = ""
	sourceFlowTier.K8S.EgressName, sourceFlowTier.K8S.EgressIp, sourceFlowTier.K8S.EgressNodeName = "", nil, ""

	// Source tier: identity. The Pod is disclosed, but not where it is placed.
	sourceIdentityTier := enrichedFlow()
	sourceIdentityTier.K8S.SourceDisclosure = flowpb.EndpointDisclosure_ENDPOINT_DISCLOSURE_IDENTITY
	sourceIdentityTier.K8S.SourceNodeName = ""
	sourceIdentityTier.K8S.EgressName, sourceIdentityTier.K8S.EgressIp, sourceIdentityTier.K8S.EgressNodeName = "", nil, ""

	// Destination tier: flow, for an allowed connection. Besides the Pod and its Node, the identity of
	// the ingress policy, which is namespaced and so follows the destination, is withheld. The Service
	// is not: it is disclosed at the tier of its own Namespace, here one the client may see.
	destinationFlowTier := enrichedFlow()
	destinationFlowTier.K8S.DestinationDisclosure = flowpb.EndpointDisclosure_ENDPOINT_DISCLOSURE_FLOW
	destinationFlowTier.K8S.DestinationPodName, destinationFlowTier.K8S.DestinationPodLabels = "", nil
	destinationFlowTier.K8S.DestinationNodeName = ""
	destinationFlowTier.K8S.IngressNetworkPolicyNamespace = ""
	destinationFlowTier.K8S.IngressNetworkPolicyName = ""
	destinationFlowTier.K8S.IngressNetworkPolicyRuleName = ""

	// The Service withheld next to a destination that is disclosed in full, as when the Service is in
	// a Namespace the client may not see.
	serviceWithheld := enrichedFlow()
	serviceWithheld.K8S.DestinationServiceDisclosure = flowpb.EndpointDisclosure_ENDPOINT_DISCLOSURE_FLOW
	serviceWithheld.K8S.DestinationServicePortName, serviceWithheld.K8S.DestinationServiceIp = "", nil
	serviceWithheld.K8S.DestinationServicePort = 0

	// The same destination and Service withheld together, for a denied connection, whose destination
	// Namespace is withheld too, and the Service with it.
	destinationDenied := proto.Clone(destinationFlowTier).(*flowpb.Flow)
	destinationDenied.K8S.DestinationPodNamespace = ""
	destinationDenied.K8S.DestinationServiceDisclosure = flowpb.EndpointDisclosure_ENDPOINT_DISCLOSURE_FLOW
	destinationDenied.K8S.DestinationServicePortName, destinationDenied.K8S.DestinationServiceIp = "", nil
	destinationDenied.K8S.DestinationServicePort = 0

	// A namespaced egress policy follows the source, as an ingress one follows the destination.
	sourceFlowTierPolicy := proto.Clone(sourceFlowTier).(*flowpb.Flow)
	sourceFlowTierPolicy.K8S.EgressNetworkPolicyType = flowpb.NetworkPolicyType_NETWORK_POLICY_TYPE_ANP
	sourceFlowTierPolicy.K8S.EgressNetworkPolicyNamespace = ""
	sourceFlowTierPolicy.K8S.EgressNetworkPolicyName = ""
	sourceFlowTierPolicy.K8S.EgressNetworkPolicyRuleName = ""

	// The implicit isolation drop of a Kubernetes NetworkPolicy is reported with a type and an action
	// but no Namespace or name, even when nothing is redacted, as on a cluster-wide stream.
	isolationDrop := enrichedFlow()
	isolationDrop.K8S.IngressNetworkPolicyType = flowpb.NetworkPolicyType_NETWORK_POLICY_TYPE_K8S
	isolationDrop.K8S.IngressNetworkPolicyNamespace = ""
	isolationDrop.K8S.IngressNetworkPolicyName = ""
	isolationDrop.K8S.IngressNetworkPolicyRuleName = ""
	isolationDrop.K8S.IngressNetworkPolicyRuleAction = flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_DROP

	// A cluster-scoped policy follows the cluster tier, which the record does not carry. Its Namespace
	// is empty whether or not it is withheld.
	clusterPolicyWithheld := enrichedFlow()
	clusterPolicyWithheld.K8S.EgressNetworkPolicyName = ""
	clusterPolicyWithheld.K8S.EgressNetworkPolicyRuleName = ""

	// An external destination is reported at the lowest tier, but nothing was held back from it.
	externalDestination := testFlow()
	externalDestination.K8S.FlowType = flowpb.FlowType_FLOW_TYPE_TO_EXTERNAL
	externalDestination.K8S.DestinationDisclosure = flowpb.EndpointDisclosure_ENDPOINT_DISCLOSURE_FLOW
	externalDestination.K8S.DestinationPodNamespace, externalDestination.K8S.DestinationPodName = "", ""
	externalDestination.K8S.DestinationServicePortName = ""

	for _, tc := range []struct {
		name string
		flow *flowpb.Flow
		// want holds the columns that must show something other than their value; every other column
		// among allColumns must not show redactedMarker.
		want map[string]string
	}{
		{
			name: "source at the flow tier",
			flow: sourceFlowTier,
			want: map[string]string{
				"sourcePodName": redacted, "sourcePodLabels": redacted, "sourceNodeName": redacted,
				"egressName": redacted, "egressIP": redacted, "egressNodeName": redacted,
			},
		},
		{
			name: "namespaced egress policy is withheld with the source",
			flow: sourceFlowTierPolicy,
			want: map[string]string{
				"sourcePodName": redacted, "sourcePodLabels": redacted, "sourceNodeName": redacted,
				"egressName": redacted, "egressIP": redacted, "egressNodeName": redacted,
				"egressNetworkPolicyNamespace": redacted, "egressNetworkPolicyName": redacted, "egressNetworkPolicyRuleName": redacted,
			},
		},
		{
			name: "source at the identity tier withholds placement only",
			flow: sourceIdentityTier,
			want: map[string]string{
				"sourceNodeName": redacted, "egressName": redacted, "egressIP": redacted, "egressNodeName": redacted,
			},
		},
		{
			name: "destination at the flow tier keeps a Service of its own tier",
			flow: destinationFlowTier,
			want: map[string]string{
				"destinationPodName": redacted, "destinationPodLabels": redacted, "destinationNodeName": redacted,
				"ingressNetworkPolicyNamespace": redacted, "ingressNetworkPolicyName": redacted, "ingressNetworkPolicyRuleName": redacted,
				"destinationServiceName": serviceName, "destinationServiceIP": "fd00::100", "destinationServicePort": "8080",
			},
		},
		{
			name: "Service withheld next to a destination that is disclosed",
			flow: serviceWithheld,
			want: map[string]string{
				"destinationServiceName": redacted, "destinationServiceIP": redacted, "destinationServicePort": redacted,
				"destinationPodName": dstPodName,
			},
		},
		{
			name: "destination at the flow tier of a denied connection also withholds its Namespace",
			flow: destinationDenied,
			want: map[string]string{
				"destinationPodNamespace": redacted,
				"destinationPodName":      redacted, "destinationPodLabels": redacted, "destinationNodeName": redacted,
				"destinationServiceName": redacted, "destinationServiceIP": redacted, "destinationServicePort": redacted,
				"ingressNetworkPolicyNamespace": redacted, "ingressNetworkPolicyName": redacted, "ingressNetworkPolicyRuleName": redacted,
			},
		},
		{
			name: "isolation drop of a Kubernetes NetworkPolicy has no name that was withheld",
			flow: isolationDrop,
			want: map[string]string{
				"ingressNetworkPolicyNamespace": noValue, "ingressNetworkPolicyName": noValue, "ingressNetworkPolicyRuleName": noValue,
			},
		},
		{
			name: "cluster-scoped policy whose identity is withheld has no Namespace to withhold",
			flow: clusterPolicyWithheld,
			want: map[string]string{
				"egressNetworkPolicyName": redacted, "egressNetworkPolicyRuleName": redacted,
				"egressNetworkPolicyNamespace": noValue,
			},
		},
		{
			name: "external destination has nothing to withhold",
			flow: externalDestination,
			want: map[string]string{
				"destinationPodNamespace": noValue, "destinationPodName": noValue, "destinationPodLabels": noValue,
				"destinationNodeName": noValue, "destinationServiceName": noValue, "destinationServiceIP": noValue,
			},
		},
		{
			name: "nothing withheld",
			flow: enrichedFlow(),
			want: map[string]string{
				"sourcePodName": podName, "destinationPodName": dstPodName, "destinationServiceName": serviceName,
				"ingressNetworkPolicyName": ingressAllow, "sourceNodeName": "worker-1", "egressName": "outbound",
				"egressNetworkPolicyNamespace": noValue,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := selectedCells(t, tc.flow, allColumns...)
			for _, name := range allColumns {
				if want, ok := tc.want[name]; ok {
					assert.Equal(t, want, got[name], name)
				} else {
					assert.NotEqual(t, redacted, got[name], "%s is not withheld here", name)
				}
			}
		})
	}

	t.Run("the type and action of a withheld policy stay visible", func(t *testing.T) {
		got := selectedCells(t, destinationFlowTier, "ingressNetworkPolicyType", "ingressNetworkPolicyRuleAction", "destinationDisclosure")
		assert.Equal(t, map[string]string{
			"ingressNetworkPolicyType":       "NETWORK_POLICY_TYPE_ANP",
			"ingressNetworkPolicyRuleAction": "NETWORK_POLICY_RULE_ACTION_ALLOW",
			"destinationDisclosure":          "flow",
		}, got)
	})

	t.Run("a column that can show the marker is wide enough for it", func(t *testing.T) {
		for _, c := range availableColumns {
			if c.withheld != nil {
				assert.GreaterOrEqual(t, c.width, len(redactedMarker), c.name)
			}
		}
	})
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
			"default/<redacted>(10.0.0.6)", redactedMarker, redactedMarker, "NETWORK_POLICY_RULE_ACTION_DROP", "flow",
		}, strings.Fields(lines[1]))
	})

	t.Run("write failures are returned", func(t *testing.T) {
		columns, err := parseColumns([]string{"source", "tcpState"})
		require.NoError(t, err)
		r := &textRenderer{out: &erroringWriter{}, columns: columns}
		require.ErrorContains(t, r.render([]*flowpb.Flow{enrichedFlow()}, 0), "write failed")
	})
}
