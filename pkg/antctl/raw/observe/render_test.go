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
	"errors"
	"io"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	flowpb "antrea.io/antrea/v2/pkg/apis/flow/v1alpha1"
)

func TestFormatBytes(t *testing.T) {
	cases := []struct {
		n    uint64
		want string
	}{
		{0, "0B"},
		{1, "1B"},
		{1023, "1023B"},
		{1024, "1.0KB"},
		{1536, "1.5KB"},
		{1048576, "1.0MB"},
		{5 * 1048576, "5.0MB"},
		{1073741824, "1.0GB"},
		{1099511627776, "1.0TB"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, formatBytes(c.n), "formatBytes(%d)", c.n)
	}
}

func TestRecordEndpoint(t *testing.T) {
	t.Run("short Namespace and Pod name are shown in full", func(t *testing.T) {
		r := record{SourcePodNamespace: "default", SourcePodName: "perftest-a"}
		assert.Equal(t, "default/perftest-a", r.endpoint(true))
	})

	t.Run("a long Namespace and Pod name are shown whole", func(t *testing.T) {
		namespace := "superlongnamespacenametomakeyoucry-and-then-some-more"
		podName := "iamveryevilandIchoseeaverylongnameformyreplicasetjusttodriveyoucrazy-668d6bf9bc-hhs4"
		r := record{DestinationPodNamespace: namespace, DestinationPodName: podName}
		assert.Equal(t, namespace+"/"+podName, r.endpoint(false))
	})

	t.Run("falls back to the IP when there is no Pod name", func(t *testing.T) {
		r := record{SourceIP: "10.0.0.5"}
		assert.Equal(t, "10.0.0.5", r.endpoint(true))
	})

	t.Run("falls back to the placeholder when neither a Pod name nor an IP is set", func(t *testing.T) {
		r := record{}
		assert.Equal(t, "-", r.endpoint(true))
	})
}

func TestIPString(t *testing.T) {
	assert.Equal(t, "10.0.0.5", ipString(netip.MustParseAddr("10.0.0.5").AsSlice()))
	assert.Equal(t, "fd00::1", ipString(netip.MustParseAddr("fd00::1").AsSlice()))
	assert.Equal(t, "", ipString(nil))
	assert.Equal(t, "", ipString([]byte{1, 2, 3}))
}

func testFlow() *flowpb.Flow {
	return &flowpb.Flow{
		Id:    "flow-1",
		EndTs: timestamppb.New(time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC)),
		Ip: &flowpb.IP{
			Source:      netip.MustParseAddr("10.0.0.5").AsSlice(),
			Destination: netip.MustParseAddr("10.0.0.6").AsSlice(),
		},
		Transport: &flowpb.Transport{ProtocolNumber: 6, SourcePort: 12345, DestinationPort: 80},
		K8S: &flowpb.Kubernetes{
			SourcePodNamespace:         "default",
			SourcePodName:              "perftest-a",
			DestinationPodNamespace:    "default",
			DestinationPodName:         "perftest-b",
			DestinationServicePortName: "default/frontend:http",
			FlowType:                   flowpb.FlowType_FLOW_TYPE_INTRA_NODE,
		},
		Stats:        &flowpb.Stats{OctetTotalCount: 1000},
		ReverseStats: &flowpb.Stats{OctetTotalCount: 500},
	}
}

func enrichedFlow() *flowpb.Flow {
	f := testFlow()
	f.StartTs = timestamppb.New(time.Date(2026, 1, 2, 15, 0, 0, 0, time.UTC))
	f.EndReason = flowpb.FlowEndReason_FLOW_END_REASON_ACTIVE_TIMEOUT
	f.Transport.Protocol = &flowpb.Transport_TCP{TCP: &flowpb.TCP{StateName: "ESTABLISHED"}}
	f.K8S.SourcePodLabels = &flowpb.Labels{Labels: map[string]string{"tier": "frontend", "app": "web"}}
	f.K8S.DestinationPodLabels = &flowpb.Labels{Labels: map[string]string{"app": "backend"}}
	f.K8S.SourceNodeName = "worker-1"
	f.K8S.DestinationNodeName = "worker-2"
	f.K8S.DestinationServiceIp = netip.MustParseAddr("fd00::100").AsSlice()
	f.K8S.DestinationServicePort = 8080
	f.K8S.IngressNetworkPolicyNamespace = "backend"
	f.K8S.IngressNetworkPolicyName = "allow-web"
	f.K8S.IngressNetworkPolicyType = flowpb.NetworkPolicyType_NETWORK_POLICY_TYPE_ANP
	f.K8S.IngressNetworkPolicyRuleName = "http"
	f.K8S.IngressNetworkPolicyRuleAction = flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_ALLOW
	f.K8S.EgressNetworkPolicyNamespace = ""
	f.K8S.EgressNetworkPolicyName = "restrict-outbound"
	f.K8S.EgressNetworkPolicyType = flowpb.NetworkPolicyType_NETWORK_POLICY_TYPE_ACNP
	f.K8S.EgressNetworkPolicyRuleName = "deny-external"
	f.K8S.EgressNetworkPolicyRuleAction = flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_DROP
	f.K8S.EgressName = "outbound"
	f.K8S.EgressIp = netip.MustParseAddr("192.0.2.10").AsSlice()
	f.K8S.EgressNodeName = "worker-3"
	f.ProxySnatIp = netip.MustParseAddr("2001:db8::1").AsSlice()
	f.ProxySnatPort = 54321
	f.Stats.PacketTotalCount = 100
	f.Stats.PacketDeltaCount = 10
	f.Stats.OctetDeltaCount = 1024
	f.ReverseStats.PacketTotalCount = 50
	f.ReverseStats.PacketDeltaCount = 5
	f.ReverseStats.OctetDeltaCount = 2048
	f.Aggregation = &flowpb.Aggregation{Throughput: 8192, ReverseThroughput: 16384}
	return f
}

func TestToRecord(t *testing.T) {
	t.Run("fully populated flow", func(t *testing.T) {
		r := toRecord(testFlow())
		assert.Equal(t, "2026-01-02T15:04:05Z", r.EndTime)
		assert.Equal(t, "10.0.0.5", r.SourceIP)
		assert.Equal(t, "10.0.0.6", r.DestinationIP)
		assert.EqualValues(t, 6, r.Protocol)
		assert.EqualValues(t, 12345, r.SourcePort)
		assert.EqualValues(t, 80, r.DestinationPort)
		assert.Equal(t, "default", r.SourcePodNamespace)
		assert.Equal(t, "perftest-a", r.SourcePodName)
		assert.Equal(t, "default", r.DestinationPodNamespace)
		assert.Equal(t, "perftest-b", r.DestinationPodName)
		assert.Equal(t, "default/frontend:http", r.DestinationServiceName)
		assert.Equal(t, "FLOW_TYPE_INTRA_NODE", r.FlowType)
		assert.EqualValues(t, 1000, r.OctetTotalCount)
		assert.EqualValues(t, 500, r.ReverseOctetTotalCount)
	})

	t.Run("minimal flow with nil optional fields", func(t *testing.T) {
		r := toRecord(&flowpb.Flow{})
		// A record no stage redacted reads as fully disclosed: that is the zero value of the protocol's
		// disclosure marker, and what every record on a cluster-wide stream looks like.
		assert.Equal(t, record{
			SourceDisclosure: disclosureFull, DestinationDisclosure: disclosureFull, DestinationServiceDisclosure: disclosureFull,
			EndReason: "FLOW_END_REASON_UNSPECIFIED",
		}, r)
	})

	t.Run("disclosure markers", func(t *testing.T) {
		f := testFlow()
		f.K8S.SourceDisclosure = flowpb.EndpointDisclosure_ENDPOINT_DISCLOSURE_IDENTITY
		f.K8S.DestinationDisclosure = flowpb.EndpointDisclosure_ENDPOINT_DISCLOSURE_FLOW
		r := toRecord(f)
		assert.Equal(t, disclosureIdentity, r.SourceDisclosure)
		assert.Equal(t, disclosureFlow, r.DestinationDisclosure)
	})
}

// redactedFlow is what FlowStreamService sends a client that may only see the flow tier of the
// destination: the destination's Pod identity is withheld, its address is not. The Service is not
// part of it, as it is disclosed at the tier of its own Namespace: see serviceWithheldFlow.
func redactedFlow(flowType flowpb.FlowType) *flowpb.Flow {
	f := testFlow()
	f.K8S.FlowType = flowType
	f.K8S.DestinationPodName = ""
	f.K8S.DestinationDisclosure = flowpb.EndpointDisclosure_ENDPOINT_DISCLOSURE_FLOW
	return f
}

// serviceWithheldFlow is what FlowStreamService sends a client that may see the destination in full
// but not the Namespace of the destination Service.
func serviceWithheldFlow() *flowpb.Flow {
	f := testFlow()
	f.K8S.DestinationServicePortName = ""
	f.K8S.DestinationServiceDisclosure = flowpb.EndpointDisclosure_ENDPOINT_DISCLOSURE_FLOW
	return f
}

func TestRecordEndpoint_Redacted(t *testing.T) {
	t.Run("withheld Pod in a disclosed Namespace keeps the Namespace and the address", func(t *testing.T) {
		r := toRecord(redactedFlow(flowpb.FlowType_FLOW_TYPE_INTER_NODE))
		assert.Equal(t, "default/<redacted>(10.0.0.6)", r.endpoint(false))
		assert.Equal(t, "default/perftest-a", r.endpoint(true), "the other endpoint was disclosed in full")
	})

	t.Run("withheld Namespace as well, as for a denied connection", func(t *testing.T) {
		f := redactedFlow(flowpb.FlowType_FLOW_TYPE_INTER_NODE)
		f.K8S.DestinationPodNamespace = ""
		assert.Equal(t, "<redacted>(10.0.0.6)", toRecord(f).endpoint(false))
	})

	t.Run("an external endpoint is not redacted although it is reported at the lowest tier", func(t *testing.T) {
		f := redactedFlow(flowpb.FlowType_FLOW_TYPE_TO_EXTERNAL)
		f.K8S.DestinationPodNamespace = ""
		f.K8S.DestinationServicePortName = ""
		r := toRecord(f)
		assert.Equal(t, "10.0.0.6", r.endpoint(false))
		assert.Equal(t, "-", r.service(), "no Service was withheld, there is none to show")
	})

	t.Run("the same holds for an external source", func(t *testing.T) {
		f := testFlow()
		f.K8S.FlowType = flowpb.FlowType_FLOW_TYPE_FROM_EXTERNAL
		f.K8S.SourcePodNamespace, f.K8S.SourcePodName = "", ""
		f.K8S.SourceDisclosure = flowpb.EndpointDisclosure_ENDPOINT_DISCLOSURE_FLOW
		assert.Equal(t, "10.0.0.5", toRecord(f).endpoint(true))
	})

	t.Run("identity tier shows the identity, only placement is withheld", func(t *testing.T) {
		f := testFlow()
		f.K8S.DestinationDisclosure = flowpb.EndpointDisclosure_ENDPOINT_DISCLOSURE_IDENTITY
		r := toRecord(f)
		assert.Equal(t, "default/perftest-b", r.endpoint(false))
		assert.Equal(t, "default/frontend:http", r.service())
	})

	t.Run("a withheld Service marks the Service column", func(t *testing.T) {
		r := toRecord(serviceWithheldFlow())
		assert.Equal(t, redactedMarker, r.service())
		assert.Equal(t, "default/perftest-b", r.endpoint(false), "the destination was disclosed in full")
	})

	t.Run("a withheld destination does not mark a Service that was disclosed", func(t *testing.T) {
		r := toRecord(redactedFlow(flowpb.FlowType_FLOW_TYPE_INTER_NODE))
		assert.Equal(t, "default/frontend:http", r.service())
	})

	t.Run("a flow that never went through a Service is not marked", func(t *testing.T) {
		f := testFlow()
		f.K8S.DestinationServicePortName = ""
		assert.Equal(t, "-", toRecord(f).service())
	})
}

func TestRenderers_Redacted(t *testing.T) {
	f := redactedFlow(flowpb.FlowType_FLOW_TYPE_INTER_NODE)

	t.Run("text line keeps the Namespace and the address of a withheld Pod", func(t *testing.T) {
		var buf bytes.Buffer
		require.NoError(t, (&textRenderer{out: &buf}).render([]*flowpb.Flow{f}, 0))
		assert.Contains(t, buf.String(), "-> default/<redacted>(10.0.0.6):80  ")
	})

	t.Run("table row is still one cell per column", func(t *testing.T) {
		columns, err := parseColumns(nil)
		require.NoError(t, err)
		var buf bytes.Buffer
		require.NoError(t, (&tableRenderer{out: &buf, columns: columns}).render([]*flowpb.Flow{f}, 0))
		rows := tableRows(buf.String())
		require.Len(t, rows, 2)
		assert.Len(t, rows[1], len(rows[0]))
		assert.Contains(t, rows[1], "default/<redacted>(10.0.0.6)")
	})

	t.Run("JSON carries the disclosure markers so a script can tell withheld from absent", func(t *testing.T) {
		var buf bytes.Buffer
		require.NoError(t, (&jsonRenderer{out: &buf}).render([]*flowpb.Flow{f}, 0))
		var got map[string]any
		require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
		assert.Equal(t, disclosureFull, got["sourceDisclosure"])
		assert.Equal(t, disclosureFlow, got["destinationDisclosure"])
		assert.Equal(t, disclosureFull, got["destinationServiceDisclosure"])
		assert.Equal(t, "", got["destinationPodName"])
	})

	t.Run("JSON carries the Service marker apart from the destination's", func(t *testing.T) {
		var buf bytes.Buffer
		require.NoError(t, (&jsonRenderer{out: &buf}).render([]*flowpb.Flow{serviceWithheldFlow()}, 0))
		var got map[string]any
		require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
		assert.Equal(t, disclosureFull, got["destinationDisclosure"])
		assert.Equal(t, disclosureFlow, got["destinationServiceDisclosure"])
		assert.Equal(t, "", got["destinationServiceName"])
	})
}

func TestNewRenderer(t *testing.T) {
	assert.IsType(t, &jsonRenderer{}, newRenderer(outputJSON, io.Discard, io.Discard, false, nil, false))
	assert.IsType(t, &textRenderer{}, newRenderer(outputText, io.Discard, io.Discard, false, nil, false))
	assert.IsType(t, &tableRenderer{}, newRenderer(outputTable, io.Discard, io.Discard, false, nil, false))
	// Any other/unrecognized value falls back to text, matching runE's own validation, which
	// rejects anything but "text", "table" and "json" before newRenderer is ever called.
	assert.IsType(t, &textRenderer{}, newRenderer(outputFormat("bogus"), io.Discard, io.Discard, false, nil, false))
}

func TestJSONRenderer_Render(t *testing.T) {
	t.Run("one line of JSON per flow", func(t *testing.T) {
		var buf bytes.Buffer
		r := &jsonRenderer{out: &buf}
		require.NoError(t, r.render([]*flowpb.Flow{testFlow(), testFlow()}, 0))

		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		require.Len(t, lines, 2)
		var decoded record
		require.NoError(t, json.Unmarshal([]byte(lines[0]), &decoded))
		assert.Equal(t, "perftest-a", decoded.SourcePodName)
	})

	t.Run("every line is a record, with the documented field names", func(t *testing.T) {
		var buf bytes.Buffer
		r := &jsonRenderer{out: &buf}
		require.NoError(t, r.render([]*flowpb.Flow{testFlow()}, 0))

		var got map[string]any
		require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
		assert.ElementsMatch(t, []string{
			"endTime", "sourceIP", "destinationIP", "protocol", "sourcePort", "destinationPort",
			"sourcePodNamespace", "sourcePodName", "destinationPodNamespace", "destinationPodName",
			"destinationServiceName", "flowType", "octetTotalCount", "reverseOctetTotalCount",
			"sourceDisclosure", "destinationDisclosure", "destinationServiceDisclosure",
			"sourcePodLabels", "destinationPodLabels",
			"ingressNetworkPolicyNamespace", "ingressNetworkPolicyName", "ingressNetworkPolicyType",
			"ingressNetworkPolicyRuleName", "ingressNetworkPolicyRuleAction",
			"egressNetworkPolicyNamespace", "egressNetworkPolicyName", "egressNetworkPolicyType",
			"egressNetworkPolicyRuleName", "egressNetworkPolicyRuleAction",
			"tcpState", "sourceNodeName", "destinationNodeName", "packetTotalCount", "reversePacketTotalCount",
			"startTime", "endReason", "destinationServiceIP", "destinationServicePort",
			"packetDeltaCount", "reversePacketDeltaCount", "octetDeltaCount", "reverseOctetDeltaCount",
			"egressName", "egressIP", "egressNodeName", "proxySnatIP", "proxySnatPort",
			"throughput", "reverseThroughput",
		}, slices.Collect(maps.Keys(got)))
	})

	t.Run("additional fields preserve addresses, enum names, labels and both statistics directions", func(t *testing.T) {
		var buf bytes.Buffer
		require.NoError(t, (&jsonRenderer{out: &buf}).render([]*flowpb.Flow{enrichedFlow()}, 0))
		assert.JSONEq(t, `{
			"endTime":"2026-01-02T15:04:05Z", "sourceIP":"10.0.0.5", "destinationIP":"10.0.0.6",
			"protocol":6, "sourcePort":12345, "destinationPort":80,
			"sourcePodNamespace":"default", "sourcePodName":"perftest-a",
			"destinationPodNamespace":"default", "destinationPodName":"perftest-b",
			"destinationServiceName":"default/frontend:http", "flowType":"FLOW_TYPE_INTRA_NODE",
			"octetTotalCount":1000, "reverseOctetTotalCount":500,
			"sourceDisclosure":"full", "destinationDisclosure":"full", "destinationServiceDisclosure":"full",
			"sourcePodLabels":{"app":"web","tier":"frontend"}, "destinationPodLabels":{"app":"backend"},
			"ingressNetworkPolicyNamespace":"backend", "ingressNetworkPolicyName":"allow-web",
			"ingressNetworkPolicyType":"NETWORK_POLICY_TYPE_ANP", "ingressNetworkPolicyRuleName":"http",
			"ingressNetworkPolicyRuleAction":"NETWORK_POLICY_RULE_ACTION_ALLOW",
			"egressNetworkPolicyNamespace":"", "egressNetworkPolicyName":"restrict-outbound",
			"egressNetworkPolicyType":"NETWORK_POLICY_TYPE_ACNP", "egressNetworkPolicyRuleName":"deny-external",
			"egressNetworkPolicyRuleAction":"NETWORK_POLICY_RULE_ACTION_DROP",
			"tcpState":"ESTABLISHED", "sourceNodeName":"worker-1", "destinationNodeName":"worker-2",
			"packetTotalCount":100, "reversePacketTotalCount":50,
			"startTime":"2026-01-02T15:00:00Z", "endReason":"FLOW_END_REASON_ACTIVE_TIMEOUT",
			"destinationServiceIP":"fd00::100", "destinationServicePort":8080,
			"packetDeltaCount":10, "reversePacketDeltaCount":5, "octetDeltaCount":1024, "reverseOctetDeltaCount":2048,
			"egressName":"outbound", "egressIP":"192.0.2.10", "egressNodeName":"worker-3",
			"proxySnatIP":"2001:db8::1", "proxySnatPort":54321, "throughput":8192, "reverseThroughput":16384
		}`, buf.String())
	})

	t.Run("missing and explicitly empty labels remain distinct", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			labels *flowpb.Labels
			want   string
		}{
			{name: "missing", want: "null"},
			{name: "empty message", labels: &flowpb.Labels{}, want: "{}"},
			{name: "empty map", labels: &flowpb.Labels{Labels: map[string]string{}}, want: "{}"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f := testFlow()
				f.K8S.SourcePodLabels, f.K8S.DestinationPodLabels = tc.labels, tc.labels
				var buf bytes.Buffer
				require.NoError(t, (&jsonRenderer{out: &buf}).render([]*flowpb.Flow{f}, 0))
				var got map[string]json.RawMessage
				require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
				assert.JSONEq(t, tc.want, string(got["sourcePodLabels"]))
				assert.JSONEq(t, tc.want, string(got["destinationPodLabels"]))
			})
		}
	})

	t.Run("dropped count is warned about on stderr, not added to the stream", func(t *testing.T) {
		var out, errOut bytes.Buffer
		r := &jsonRenderer{out: &out, dropped: droppedWarner{errOut: &errOut}}
		require.NoError(t, r.render([]*flowpb.Flow{testFlow()}, 3))

		lines := strings.Split(strings.TrimSpace(out.String()), "\n")
		require.Len(t, lines, 1, "stdout must only carry records")
		assert.Contains(t, errOut.String(), "warning: 3 flow(s) dropped")
	})

	t.Run("no flows and no drops writes nothing", func(t *testing.T) {
		var buf bytes.Buffer
		r := &jsonRenderer{out: &buf}
		require.NoError(t, r.render(nil, 0))
		assert.Empty(t, buf.String())
	})
}

// localTime is how the text output shows a time: in the time zone of the user.
func localTime(t time.Time) string { return t.Local().Format("Jan _2 15:04:05") }

func TestTextRenderer_Render(t *testing.T) {
	endTime := localTime(time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC))

	t.Run("one line per flow, with no header", func(t *testing.T) {
		var buf bytes.Buffer
		tr := &textRenderer{out: &buf}
		require.NoError(t, tr.render(nil, 0))
		assert.Empty(t, buf.String())
		require.NoError(t, tr.render([]*flowpb.Flow{testFlow()}, 0))
		require.NoError(t, tr.render([]*flowpb.Flow{testFlow(), testFlow()}, 0))
		lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
		require.Len(t, lines, 3)
		want := endTime + "  default/perftest-a(10.0.0.5):12345 -> default/perftest-b(10.0.0.6):80  TCP  intra-node" +
			"  svc=default/frontend:http  bytes=1000/500  Policy verdict: N/A"
		for _, line := range lines {
			assert.Equal(t, want, line)
		}
	})

	t.Run("human-readable bytes formats each count instead of the raw one", func(t *testing.T) {
		f := testFlow()
		f.Stats.OctetTotalCount, f.ReverseStats.OctetTotalCount = 1536, 3*1024*1024
		var raw, human bytes.Buffer
		require.NoError(t, (&textRenderer{out: &raw}).render([]*flowpb.Flow{f}, 0))
		require.NoError(t, (&textRenderer{out: &human, humanReadableBytes: true}).render([]*flowpb.Flow{f}, 0))
		assert.Contains(t, raw.String(), "  bytes=1536/3145728  ")
		assert.Contains(t, human.String(), "  bytes=1.5KB/3.0MB  ")
	})

	t.Run("additional record fields do not change the line, except for the verdict", func(t *testing.T) {
		before := func(f *flowpb.Flow) string {
			var buf bytes.Buffer
			require.NoError(t, (&textRenderer{out: &buf}).render([]*flowpb.Flow{f}, 0))
			line, _, _ := strings.Cut(buf.String(), "  Policy verdict: ")
			return line
		}
		assert.Equal(t, before(testFlow()), before(enrichedFlow()))
	})

	t.Run("an empty flow has a placeholder where a field is not optional", func(t *testing.T) {
		var buf bytes.Buffer
		require.NoError(t, (&textRenderer{out: &buf}).render([]*flowpb.Flow{{}}, 0))
		assert.Equal(t, "-  -:0 -> -:0  0  -  bytes=0/0  Policy verdict: N/A\n", buf.String())
	})

	t.Run("dropped count is warned about on stderr, not on stdout", func(t *testing.T) {
		var out, errOut bytes.Buffer
		tr := &textRenderer{out: &out, dropped: droppedWarner{errOut: &errOut}}
		require.NoError(t, tr.render([]*flowpb.Flow{testFlow()}, 7))
		assert.NotContains(t, out.String(), "dropped")
		assert.Contains(t, errOut.String(), "warning: 7 flow(s) dropped")
	})
}

func TestRecord_TextLine(t *testing.T) {
	line := func(f *flowpb.Flow) string { return toRecord(f).textLine(false) }

	t.Run("IPv6", func(t *testing.T) {
		f := testFlow()
		f.Ip.Source = netip.MustParseAddr("fd00:10:244::5").AsSlice()
		f.Ip.Destination = netip.MustParseAddr("2606:4700:4700::1111").AsSlice()
		f.K8S.FlowType = flowpb.FlowType_FLOW_TYPE_TO_EXTERNAL
		f.K8S.DestinationPodNamespace, f.K8S.DestinationPodName, f.K8S.DestinationServicePortName = "", "", ""
		f.Transport.DestinationPort = 443
		got := line(f)
		assert.Contains(t, got, "default/perftest-a(fd00:10:244::5):12345 -> [2606:4700:4700::1111]:443  TCP  to-external  ")
	})

	t.Run("an endpoint with no address is a placeholder", func(t *testing.T) {
		f := testFlow()
		f.Ip = nil
		assert.Contains(t, line(f), "default/perftest-a:12345 -> default/perftest-b:80")
	})

	t.Run("protocols", func(t *testing.T) {
		for number, want := range map[uint32]string{1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6", 132: "SCTP", 47: "47"} {
			f := testFlow()
			f.Transport.ProtocolNumber = number
			assert.Contains(t, line(f), "  "+want+"  ", "protocol %d", number)
		}
		for _, number := range []uint32{1, 58} {
			f := testFlow()
			f.Transport.ProtocolNumber = number
			f.Transport.SourcePort, f.Transport.DestinationPort = 0, 0
			assert.Contains(t, line(f), "(10.0.0.5) -> default/perftest-b(10.0.0.6)  ", "an ICMP flow has no ports")
		}
	})

	t.Run("flow types are named as --flow-type names them", func(t *testing.T) {
		for flowType, want := range map[flowpb.FlowType]string{
			flowpb.FlowType_FLOW_TYPE_INTRA_NODE:    "intra-node",
			flowpb.FlowType_FLOW_TYPE_INTER_NODE:    "inter-node",
			flowpb.FlowType_FLOW_TYPE_TO_EXTERNAL:   "to-external",
			flowpb.FlowType_FLOW_TYPE_FROM_EXTERNAL: "from-external",
		} {
			f := testFlow()
			f.K8S.FlowType = flowType
			assert.Contains(t, line(f), "  "+want+"  ")
		}
		assert.Equal(t, "-", flowTypeText(""))
	})

	t.Run("a flow that did not go through a Service has no svc field", func(t *testing.T) {
		f := testFlow()
		f.K8S.DestinationServicePortName = ""
		assert.NotContains(t, line(f), "svc=")
		assert.Contains(t, line(f), "  intra-node  bytes=1000/500  ")
	})

	t.Run("a time that cannot be read is shown as it is", func(t *testing.T) {
		assert.Equal(t, "-", record{}.textTime())
		assert.Equal(t, "yesterday", record{EndTime: "yesterday"}.textTime())
	})
}

func TestRecord_PolicyVerdict(t *testing.T) {
	const (
		allow  = flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_ALLOW
		drop   = flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_DROP
		reject = flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_REJECT
	)
	// enrichedFlow has an ingress ANP rule that allows and an egress ACNP rule that drops.
	flow := func(ingress, egress flowpb.NetworkPolicyRuleAction) *flowpb.Flow {
		f := enrichedFlow()
		f.K8S.IngressNetworkPolicyRuleAction, f.K8S.EgressNetworkPolicyRuleAction = ingress, egress
		return f
	}
	const (
		egressText  = "egress ACNP restrict-outbound (rule deny-external)"
		ingressText = "ingress ANP backend/allow-web (rule http)"
	)
	for _, tc := range []struct {
		name string
		flow *flowpb.Flow
		want string
	}{
		{name: "no policy applied", flow: testFlow(), want: "N/A"},
		{name: "ingress allows", flow: flow(allow, 0), want: "ALLOWED " + ingressText},
		{name: "egress allows", flow: flow(0, allow), want: "ALLOWED " + egressText},
		{name: "both allow, and both are named", flow: flow(allow, allow), want: "ALLOWED " + egressText + ", " + ingressText},
		{name: "a drop is the verdict over an allow, and only the policy that drops is named", flow: flow(allow, drop), want: "DROPPED " + egressText},
		{name: "ingress drops, egress allows", flow: flow(drop, allow), want: "DROPPED " + ingressText},
		{name: "both drop", flow: flow(drop, drop), want: "DROPPED " + egressText + ", " + ingressText},
		{name: "a reject is the verdict over a drop", flow: flow(reject, drop), want: "REJECTED " + ingressText},
		{name: "egress rejects, ingress allows", flow: flow(allow, reject), want: "REJECTED " + egressText},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, toRecord(tc.flow).policyVerdict())
			assert.True(t, strings.HasSuffix(toRecord(tc.flow).textLine(false), "  Policy verdict: "+tc.want), "the verdict is the last field")
		})
	}

	t.Run("a policy has what is known of it", func(t *testing.T) {
		f := flow(allow, 0)
		f.K8S.IngressNetworkPolicyRuleName = ""
		assert.Equal(t, "ALLOWED ingress ANP backend/allow-web", toRecord(f).policyVerdict(), "no rule name")
		f.K8S.IngressNetworkPolicyNamespace = ""
		assert.Equal(t, "ALLOWED ingress ANP allow-web", toRecord(f).policyVerdict(), "no Namespace")
		f.K8S.IngressNetworkPolicyType = flowpb.NetworkPolicyType_NETWORK_POLICY_TYPE_UNSPECIFIED
		f.K8S.IngressNetworkPolicyName = ""
		assert.Equal(t, "ALLOWED ingress", toRecord(f).policyVerdict(), "no type: the action is all there is")
	})

	t.Run("the isolation drop of a Kubernetes NetworkPolicy is the direction and the type", func(t *testing.T) {
		f := testFlow()
		f.K8S.IngressNetworkPolicyType = flowpb.NetworkPolicyType_NETWORK_POLICY_TYPE_K8S
		f.K8S.IngressNetworkPolicyRuleAction = drop
		assert.Equal(t, "DROPPED ingress K8S", toRecord(f).policyVerdict())
	})
}

// TestTextLine_WithheldIsNotMissing checks that the text line marks what the Flow Aggregator withheld,
// and does not mark what a flow has not got, for every field that redaction can empty.
func TestTextLine_WithheldIsNotMissing(t *testing.T) {
	line := func(f *flowpb.Flow) string { return toRecord(f).textLine(false) }

	t.Run("the Pod of an endpoint", func(t *testing.T) {
		withheld := redactedFlow(flowpb.FlowType_FLOW_TYPE_INTER_NODE)
		assert.Contains(t, line(withheld), "-> default/<redacted>(10.0.0.6):80")

		withheld.K8S.DestinationPodNamespace = ""
		assert.Contains(t, line(withheld), "-> <redacted>(10.0.0.6):80", "a denied connection withholds the Namespace too")

		source := testFlow()
		source.K8S.SourcePodName = ""
		source.K8S.SourceDisclosure = flowpb.EndpointDisclosure_ENDPOINT_DISCLOSURE_FLOW
		assert.True(t, strings.Contains(line(source), "  default/<redacted>(10.0.0.5):12345 -> "), line(source))

		external := redactedFlow(flowpb.FlowType_FLOW_TYPE_TO_EXTERNAL)
		external.K8S.DestinationPodNamespace, external.K8S.DestinationServicePortName = "", ""
		assert.Contains(t, line(external), "-> 10.0.0.6:80", "an external endpoint has no Pod, and none was withheld")
		assert.NotContains(t, line(external), redactedMarker)
	})

	t.Run("the Service", func(t *testing.T) {
		assert.Contains(t, line(serviceWithheldFlow()), "  svc=<redacted>  ")

		none := testFlow()
		none.K8S.DestinationServicePortName = ""
		assert.NotContains(t, line(none), "svc=")
		assert.NotContains(t, line(none), redactedMarker)

		disclosed := redactedFlow(flowpb.FlowType_FLOW_TYPE_INTER_NODE)
		assert.Contains(t, line(disclosed), "  svc=default/frontend:http  ", "a withheld destination does not withhold a Service of another tier")
	})

	t.Run("the policy of the verdict", func(t *testing.T) {
		allow := flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_ALLOW

		// An ingress policy that is namespaced follows the destination.
		namespaced := redactedFlow(flowpb.FlowType_FLOW_TYPE_INTER_NODE)
		namespaced.K8S.IngressNetworkPolicyType = flowpb.NetworkPolicyType_NETWORK_POLICY_TYPE_ANP
		namespaced.K8S.IngressNetworkPolicyRuleAction = allow
		assert.True(t, strings.HasSuffix(line(namespaced), "  Policy verdict: ALLOWED ingress ANP <redacted>"), line(namespaced))

		// A cluster-scoped one that has no name was withheld.
		cluster := testFlow()
		cluster.K8S.EgressNetworkPolicyType = flowpb.NetworkPolicyType_NETWORK_POLICY_TYPE_ACNP
		cluster.K8S.EgressNetworkPolicyRuleAction = allow
		assert.True(t, strings.HasSuffix(line(cluster), "  Policy verdict: ALLOWED egress ACNP <redacted>"), line(cluster))

		// The isolation drop of a Kubernetes NetworkPolicy has no name either, and nothing was withheld.
		isolation := testFlow()
		isolation.K8S.IngressNetworkPolicyType = flowpb.NetworkPolicyType_NETWORK_POLICY_TYPE_K8S
		isolation.K8S.IngressNetworkPolicyRuleAction = flowpb.NetworkPolicyRuleAction_NETWORK_POLICY_RULE_ACTION_DROP
		assert.True(t, strings.HasSuffix(line(isolation), "  Policy verdict: DROPPED ingress K8S"), line(isolation))
		assert.NotContains(t, line(isolation), redactedMarker)

		// No policy at all: the verdict is known, and it is that.
		assert.True(t, strings.HasSuffix(line(redactedFlow(flowpb.FlowType_FLOW_TYPE_INTER_NODE)), "  Policy verdict: N/A"))
	})
}

// erroringWriter fails every Write after the first n bytes it has already accepted, so tests can
// exercise a renderer's otherwise-untested "the output stream itself failed" error paths.
type erroringWriter struct {
	failAfter int
	written   int
}

func (w *erroringWriter) Write(p []byte) (int, error) {
	if w.written >= w.failAfter {
		return 0, errors.New("write failed")
	}
	w.written += len(p)
	return len(p), nil
}

func TestJSONRenderer_Render_WriteError(t *testing.T) {
	r := &jsonRenderer{out: &erroringWriter{failAfter: 0}}
	err := r.render([]*flowpb.Flow{testFlow()}, 0)
	require.Error(t, err)
}

func TestTextRenderer_Render_WriteError(t *testing.T) {
	t.Run("a line write fails", func(t *testing.T) {
		tr := &textRenderer{out: &erroringWriter{failAfter: 0}}
		require.Error(t, tr.render([]*flowpb.Flow{testFlow()}, 0))
	})

	t.Run("dropped-count warning write fails", func(t *testing.T) {
		tr := &textRenderer{out: io.Discard, dropped: droppedWarner{errOut: &erroringWriter{failAfter: 0}}}
		require.Error(t, tr.render(nil, 5))
	})
}

func TestTableRenderer_Render_WriteError(t *testing.T) {
	columns, err := parseColumns(nil)
	require.NoError(t, err)
	header := len(strings.Join(defaultColumns, "\t")) + 1

	t.Run("header write fails", func(t *testing.T) {
		tr := &tableRenderer{out: &erroringWriter{failAfter: 0}, columns: columns}
		require.Error(t, tr.render([]*flowpb.Flow{testFlow()}, 0))
	})

	t.Run("row write fails after earlier batches were written", func(t *testing.T) {
		tr := &tableRenderer{out: &erroringWriter{failAfter: header + 1}, columns: columns}
		require.NoError(t, tr.render([]*flowpb.Flow{testFlow()}, 0))
		require.Error(t, tr.render([]*flowpb.Flow{testFlow()}, 0))
	})

	t.Run("dropped-count warning write fails", func(t *testing.T) {
		tr := &tableRenderer{out: io.Discard, columns: columns, dropped: droppedWarner{errOut: &erroringWriter{failAfter: 0}}, wroteHeader: true}
		require.Error(t, tr.render(nil, 5))
	})
}

func TestWriteBatch_ReturnsTheErrorOfTheBatch(t *testing.T) {
	wantErr := errors.New("cannot render")
	var out bytes.Buffer
	err := writeBatch(&out, func(w io.Writer) error {
		_, _ = io.WriteString(w, "partial")
		return wantErr
	})
	assert.ErrorIs(t, err, wantErr)
}

// A batch that is larger than the buffer in front of the output reaches the output in parts, so the
// output can fail before the batch is over, and not only when the batch is flushed.
func TestRenderers_OutputFailsInTheMiddleOfABatch(t *testing.T) {
	flows := make([]*flowpb.Flow, 60)
	for i := range flows {
		flows[i] = testFlow()
	}
	columns, err := parseColumns(nil)
	require.NoError(t, err)
	renderers := map[string]renderer{
		"json":  &jsonRenderer{out: &erroringWriter{}},
		"text":  &textRenderer{out: &erroringWriter{}},
		"table": &tableRenderer{out: &erroringWriter{}, columns: columns},
	}
	for name, r := range renderers {
		t.Run(name, func(t *testing.T) {
			err := r.render(flows, 0)
			require.Error(t, err)
			assert.ErrorContains(t, err, "write failed")
		})
	}
}

// countingWriter counts the Write calls it receives, to tell how many writes a batch costs.
type countingWriter struct {
	bytes.Buffer
	writes int
}

func (w *countingWriter) Write(p []byte) (int, error) {
	w.writes++
	return w.Buffer.Write(p)
}

func TestRenderers_WriteOncePerBatch(t *testing.T) {
	// Two expanded JSON records still fit in writeBatch's buffer.
	flows := make([]*flowpb.Flow, 2)
	for i := range flows {
		flows[i] = testFlow()
	}
	columns, err := parseColumns(nil)
	require.NoError(t, err)
	for name, newOut := range map[string]func(out io.Writer) renderer{
		"text":  func(out io.Writer) renderer { return &textRenderer{out: out} },
		"table": func(out io.Writer) renderer { return &tableRenderer{out: out, columns: columns} },
		"json":  func(out io.Writer) renderer { return &jsonRenderer{out: out} },
	} {
		t.Run(name, func(t *testing.T) {
			var out countingWriter
			r := newOut(&out)
			require.NoError(t, r.render(flows, 0))
			assert.Equal(t, 1, out.writes, "a batch that fits the buffer is one write, not one per record")
			assert.Positive(t, out.Len())

			require.NoError(t, r.render(flows[:1], 0))
			assert.Equal(t, 2, out.writes, "every batch is flushed at its end, so --follow is not delayed")
		})
	}
}

func TestRenderers_RecordsPrecedeTheDroppedWarning(t *testing.T) {
	columns, err := parseColumns(nil)
	require.NoError(t, err)
	for name, newR := range map[string]func(out io.Writer) renderer{
		"text": func(out io.Writer) renderer { return &textRenderer{out: out, dropped: droppedWarner{errOut: out}} },
		"table": func(out io.Writer) renderer {
			return &tableRenderer{out: out, columns: columns, dropped: droppedWarner{errOut: out}}
		},
		"json": func(out io.Writer) renderer { return &jsonRenderer{out: out, dropped: droppedWarner{errOut: out}} },
	} {
		t.Run(name, func(t *testing.T) {
			// The same writer for both, as when stdout and stderr are the same terminal.
			var both bytes.Buffer
			require.NoError(t, newR(&both).render([]*flowpb.Flow{testFlow()}, 3))
			assert.Less(t, strings.Index(both.String(), "perftest-a"), strings.Index(both.String(), "warning:"))
		})
	}
}

func TestDroppedWarner(t *testing.T) {
	t.Run("the count is cumulative, so it is only reported when it goes up", func(t *testing.T) {
		var buf bytes.Buffer
		w := droppedWarner{errOut: &buf}
		require.NoError(t, w.warn(0))
		assert.Empty(t, buf.String(), "nothing dropped, nothing to say")

		require.NoError(t, w.warn(4))
		require.NoError(t, w.warn(4))
		require.NoError(t, w.warn(4))
		assert.Equal(t, 1, strings.Count(buf.String(), "warning:"), "an unchanged count must not be repeated")

		require.NoError(t, w.warn(9))
		assert.Equal(t, 2, strings.Count(buf.String(), "warning:"))
		assert.Contains(t, buf.String(), "warning: 9 flow(s) dropped")
	})

	t.Run("without a writer there is nowhere to warn", func(t *testing.T) {
		w := droppedWarner{}
		assert.NoError(t, w.warn(5))
	})
}
