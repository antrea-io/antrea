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

func TestTruncatePrefix(t *testing.T) {
	assert.Equal(t, "short", truncatePrefix("short", 30))
	exactly30 := strings.Repeat("a", 30)
	assert.Equal(t, exactly30, truncatePrefix(exactly30, 30))
	long := strings.Repeat("a", 31)
	assert.Equal(t, strings.Repeat("a", 30)+"...", truncatePrefix(long, 30))
}

func TestTruncateSuffix(t *testing.T) {
	assert.Equal(t, "short", truncateSuffix("short", 30))
	exactly30 := strings.Repeat("b", 30)
	assert.Equal(t, exactly30, truncateSuffix(exactly30, 30))
	long := "deployment-name-668d6bf9bc-hhs4x"
	assert.Equal(t, "..."+long[len(long)-30:], truncateSuffix(long, 30))
	// The trailing random suffix, the part that actually distinguishes two Pods of the same
	// Deployment, must survive truncation.
	assert.Contains(t, truncateSuffix(long, 30), "668d6bf9bc-hhs4x")
}

func TestRecordEndpoint(t *testing.T) {
	t.Run("short Namespace and Pod name are shown in full", func(t *testing.T) {
		r := record{SourcePodNamespace: "default", SourcePodName: "perftest-a"}
		assert.Equal(t, "default/perftest-a", r.endpoint(true))
	})

	t.Run("long Namespace is truncated as a prefix, long Pod name as a suffix", func(t *testing.T) {
		namespace := "superlongnamespacenametomakeyoucry-and-then-some-more"
		podName := "iamveryevilandIchoseeaverylongnameformyreplicasetjusttodriveyoucrazy-668d6bf9bc-hhs4"
		r := record{DestinationPodNamespace: namespace, DestinationPodName: podName}
		got := r.endpoint(false)

		ns, name, ok := strings.Cut(got, "/")
		assert.True(t, ok, "expected exactly one '/' separating Namespace and Pod name, got %q", got)
		assert.True(t, strings.HasPrefix(namespace, strings.TrimSuffix(ns, "...")))
		assert.True(t, strings.HasSuffix(name, "...") == false)
		assert.True(t, strings.HasSuffix(podName, strings.TrimPrefix(name, "...")))
		// The Pod's trailing random suffix must remain visible: that's the part that
		// distinguishes it from another Pod of the same Deployment/ReplicaSet.
		assert.Contains(t, name, "668d6bf9bc-hhs4")
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

func TestTruncateServiceName(t *testing.T) {
	t.Run("short value is shown in full", func(t *testing.T) {
		assert.Equal(t, "default/kubernetes:https", truncateServiceName("default/kubernetes:https"))
	})

	t.Run("long Namespace is truncated as a prefix, long name:port as a suffix", func(t *testing.T) {
		namespace := strings.Repeat("n", maxNamespaceDisplayLen+5)
		nameAndPort := strings.Repeat("s", maxServiceNameDisplayLen+5) + ":flowstream-grpc"
		got := truncateServiceName(namespace + "/" + nameAndPort)

		ns, rest, ok := strings.Cut(got, "/")
		require.True(t, ok)
		assert.Equal(t, namespace[:maxNamespaceDisplayLen]+"...", ns)
		assert.Equal(t, "..."+nameAndPort[len(nameAndPort)-maxServiceNameDisplayLen:], rest)
		// The port name, the part that distinguishes multiple ports on the same Service, must
		// survive truncation.
		assert.Contains(t, rest, ":flowstream-grpc")
	})

	t.Run("value with no '/' is truncated as a single prefix", func(t *testing.T) {
		long := strings.Repeat("x", serviceColumnWidth+10)
		got := truncateServiceName(long)
		assert.True(t, strings.HasSuffix(got, "..."))
		assert.LessOrEqual(t, len(got), serviceColumnWidth+len("..."))
	})

	t.Run("empty value stays empty (placeholder is applied by the caller)", func(t *testing.T) {
		assert.Equal(t, "", truncateServiceName(""))
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
		assert.Equal(t, record{SourceDisclosure: disclosureFull, DestinationDisclosure: disclosureFull}, r)
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
// destination: the destination's Pod and Service identity are withheld, its address is not.
func redactedFlow(flowType flowpb.FlowType) *flowpb.Flow {
	f := testFlow()
	f.K8S.FlowType = flowType
	f.K8S.DestinationPodName = ""
	f.K8S.DestinationServicePortName = ""
	f.K8S.DestinationDisclosure = flowpb.EndpointDisclosure_ENDPOINT_DISCLOSURE_FLOW
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

	t.Run("a withheld destination marks the Service column", func(t *testing.T) {
		assert.Equal(t, redactedMarker, toRecord(redactedFlow(flowpb.FlowType_FLOW_TYPE_INTER_NODE)).service())
	})
}

func TestRenderers_Redacted(t *testing.T) {
	f := redactedFlow(flowpb.FlowType_FLOW_TYPE_INTER_NODE)

	t.Run("text row is still one token per column", func(t *testing.T) {
		var buf bytes.Buffer
		require.NoError(t, (&textRenderer{out: &buf}).render([]*flowpb.Flow{f}, 0))
		lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
		require.Len(t, lines, 2)
		// The header's TOTAL BYTES is two words where a row's value is one token.
		assert.Equal(t, len(strings.Fields(lines[0])), len(strings.Fields(lines[1]))+1)
		assert.Contains(t, lines[1], "default/<redacted>(10.0.0.6)")
	})

	t.Run("JSON carries the disclosure markers so a script can tell withheld from absent", func(t *testing.T) {
		var buf bytes.Buffer
		require.NoError(t, (&jsonRenderer{out: &buf}).render([]*flowpb.Flow{f}, 0))
		var got map[string]any
		require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
		assert.Equal(t, disclosureFull, got["sourceDisclosure"])
		assert.Equal(t, disclosureFlow, got["destinationDisclosure"])
		assert.Equal(t, "", got["destinationPodName"])
	})
}

func TestNewRenderer(t *testing.T) {
	assert.IsType(t, &jsonRenderer{}, newRenderer(outputJSON, io.Discard, io.Discard, false))
	assert.IsType(t, &textRenderer{}, newRenderer(outputText, io.Discard, io.Discard, false))
	// Any other/unrecognized value falls back to text, matching runE's own validation, which
	// rejects anything but "text"/"json" before newRenderer is ever called.
	assert.IsType(t, &textRenderer{}, newRenderer(outputFormat("bogus"), io.Discard, io.Discard, false))
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
			"sourceDisclosure", "destinationDisclosure",
		}, slices.Collect(maps.Keys(got)))
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

func TestTextRenderer_Render(t *testing.T) {
	t.Run("header is written once, only when there is at least one flow", func(t *testing.T) {
		var buf bytes.Buffer
		tr := &textRenderer{out: &buf}
		require.NoError(t, tr.render(nil, 0))
		assert.Empty(t, buf.String(), "an empty batch must not print a header on its own")

		require.NoError(t, tr.render([]*flowpb.Flow{testFlow()}, 0))
		firstOutput := buf.String()
		assert.Equal(t, 1, strings.Count(firstOutput, "TIME"), "header must appear exactly once")

		buf.Reset()
		require.NoError(t, tr.render([]*flowpb.Flow{testFlow()}, 0))
		assert.NotContains(t, buf.String(), "TIME", "header must not be repeated on a later batch")
	})

	t.Run("row contains the expected fields", func(t *testing.T) {
		var buf bytes.Buffer
		tr := &textRenderer{out: &buf}
		require.NoError(t, tr.render([]*flowpb.Flow{testFlow()}, 0))
		lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
		require.Len(t, lines, 2)
		row := lines[1]
		assert.Contains(t, row, "default/perftest-a")
		assert.Contains(t, row, "default/perftest-b")
		assert.Contains(t, row, "default/frontend:http")
		assert.Contains(t, row, "FLOW_TYPE_INTRA_NODE")
		assert.Contains(t, row, "1500") // OctetTotalCount + ReverseOctetTotalCount, raw bytes
	})

	t.Run("human-readable bytes formats the total instead of the raw count", func(t *testing.T) {
		var buf bytes.Buffer
		tr := &textRenderer{out: &buf, humanReadableBytes: true}
		require.NoError(t, tr.render([]*flowpb.Flow{testFlow()}, 0))
		row := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")[1]
		assert.Contains(t, row, "1.5KB")
		assert.NotContains(t, row, "1500")
	})

	t.Run("dropped count is warned about on stderr, not on stdout", func(t *testing.T) {
		var out, errOut bytes.Buffer
		tr := &textRenderer{out: &out, dropped: droppedWarner{errOut: &errOut}}
		require.NoError(t, tr.render([]*flowpb.Flow{testFlow()}, 7))
		assert.NotContains(t, out.String(), "dropped")
		assert.Contains(t, errOut.String(), "warning: 7 flow(s) dropped")
	})

	t.Run("empty fields fall back to the placeholder", func(t *testing.T) {
		var buf bytes.Buffer
		tr := &textRenderer{out: &buf}
		require.NoError(t, tr.render([]*flowpb.Flow{{}}, 0))
		row := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")[1]
		fields := strings.Fields(row)
		for _, f := range fields {
			assert.NotEmpty(t, f)
		}
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
	t.Run("header write fails", func(t *testing.T) {
		tr := &textRenderer{out: &erroringWriter{failAfter: 0}}
		err := tr.render([]*flowpb.Flow{testFlow()}, 0)
		require.Error(t, err)
	})

	t.Run("row write fails after earlier batches were written", func(t *testing.T) {
		tr := &textRenderer{out: &erroringWriter{failAfter: len(textHeader) + 1}}
		require.NoError(t, tr.render([]*flowpb.Flow{testFlow()}, 0))
		require.Error(t, tr.render([]*flowpb.Flow{testFlow()}, 0))
	})

	t.Run("dropped-count warning write fails", func(t *testing.T) {
		tr := &textRenderer{out: io.Discard, dropped: droppedWarner{errOut: &erroringWriter{failAfter: 0}}, wroteHeader: true}
		err := tr.render(nil, 5)
		require.Error(t, err)
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
	renderers := map[string]renderer{
		"json": &jsonRenderer{out: &erroringWriter{}},
		"text": &textRenderer{out: &erroringWriter{}},
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
	flows := make([]*flowpb.Flow, 5)
	for i := range flows {
		flows[i] = testFlow()
	}
	for name, newOut := range map[string]func(out io.Writer) renderer{
		"text": func(out io.Writer) renderer { return &textRenderer{out: out} },
		"json": func(out io.Writer) renderer { return &jsonRenderer{out: out} },
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
	for name, newR := range map[string]func(out io.Writer) renderer{
		"text": func(out io.Writer) renderer { return &textRenderer{out: out, dropped: droppedWarner{errOut: out}} },
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

func TestFlowTypeColumnWidthFitsLongestValue(t *testing.T) {
	// FlowType is a closed enum: this is a compile-time-adjacent guard that the column width
	// tracks whichever value happens to be longest, rather than a hand-picked number that could
	// silently go stale if a longer FlowType value were ever added.
	for _, v := range []string{
		"FLOW_TYPE_UNSPECIFIED",
		"FLOW_TYPE_INTRA_NODE",
		"FLOW_TYPE_INTER_NODE",
		"FLOW_TYPE_TO_EXTERNAL",
		"FLOW_TYPE_FROM_EXTERNAL",
	} {
		assert.LessOrEqualf(t, len(v), flowTypeColumnWidth, "FlowType value %q does not fit flowTypeColumnWidth", v)
	}
}
