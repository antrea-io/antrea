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

package flowstreamservice

import (
	"context"
	"fmt"
	"math"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/encoding"
	grpcproto "google.golang.org/grpc/encoding/proto"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	flowpb "antrea.io/antrea/v2/pkg/apis/flow/v1alpha1"
)

// selectRecordsBeforeSizeLimit provides a benchmark baseline without response size checks.
func selectRecordsBeforeSizeLimit(ctx context.Context, streamAuth *StreamAuthorization, batch []*flowpb.Flow, filters []flowFilter, since time.Time, limit int) ([]*flowpb.Flow, int) {
	records := slices.All(batch)
	if streamAuth != nil {
		records = streamAuth.Authorized(ctx, batch)
	}
	selected := batch[:0]
	examined := len(batch)
	for i, f := range records {
		if !matchFlow(f, filters, since) {
			continue
		}
		selected = append(selected, f)
		if limit > 0 && len(selected) >= limit {
			examined = i + 1
			break
		}
	}
	return selected, examined
}

func newCodecTestFlows(numLabels, valueLength int) []*flowpb.Flow {
	labels := func(prefix string) *flowpb.Labels {
		m := make(map[string]string, numLabels)
		for i := range numLabels {
			m[fmt.Sprintf("app.kubernetes.io/%s-%02d", prefix, i)] = strings.Repeat("v", valueLength)
		}
		return &flowpb.Labels{Labels: m}
	}
	flows := make([]*flowpb.Flow, internalBatchSize)
	for i := range flows {
		flows[i] = newFlow(fmt.Sprintf("flow-%d", i), &flowpb.Kubernetes{
			SourcePodNamespace:      "frontend",
			SourcePodName:           "frontend-7d9f8c6b5d-x2k9p",
			SourcePodLabels:         labels("src"),
			DestinationPodNamespace: "backend",
			DestinationPodName:      "backend-5c4b3a2918-q7w8e",
			DestinationPodLabels:    labels("dst"),
		})
	}
	return flows
}

// BenchmarkSelectAndMarshal compares selection and serialization before size limiting,
// with size limiting and the standard codec, and with flowStreamCodec. The latter still calls
// ordinary proto.Size for each selected flow on every iteration: it cannot benefit
// from warming the flow caches in an earlier iteration or a different stream.
func BenchmarkSelectAndMarshal(b *testing.B) {
	defaultCodec := encoding.GetCodecV2(grpcproto.Name)
	for _, fixture := range []struct {
		labels, valueLength int
	}{
		{6, 11},
		{40, 11},
		{6, 300},
	} {
		b.Run(fmt.Sprintf("labels=%d/value=%d", fixture.labels, fixture.valueLength), func(b *testing.B) {
			for _, redacted := range []bool{false, true} {
				b.Run(fmt.Sprintf("redacted=%t", redacted), func(b *testing.B) {
					for _, variant := range []string{"before", "standard_codec", "cached_codec"} {
						b.Run(variant, func(b *testing.B) {
							flows := newCodecTestFlows(fixture.labels, fixture.valueLength)
							batch := make([]*flowpb.Flow, len(flows))
							codec := defaultCodec
							if variant == "cached_codec" {
								codec = newFlowStreamCodec()
							}
							b.ReportAllocs()
							for b.Loop() {
								copy(batch, flows)
								if redacted {
									for i, f := range batch {
										batch[i] = redactFlow(f, tierFull, tierFlow, tierFull)
									}
								}
								var selected []*flowpb.Flow
								if variant == "before" {
									selected, _ = selectRecordsBeforeSizeLimit(context.Background(), nil, batch, nil, time.Time{}, 0)
								} else {
									selected, _, _ = selectRecords(context.Background(), nil, batch, nil, time.Time{}, 0, maxEncodedFlowsSize)
								}
								data, err := codec.Marshal(&flowpb.GetFlowsResponse{
									Flows: selected,
									ResumeToken: &flowpb.ResumeToken{
										StreamEpoch: "ed7b6aee-22d1-44d7-94be-4668df46d289", SequenceNumber: 99,
									},
								})
								if err != nil {
									b.Fatal(err)
								}
								data.Free()
							}
						})
					}
				})
			}
		})
	}
}

func requireStandardProtoEncoding(t *testing.T, codec *flowStreamCodec, response *flowpb.GetFlowsResponse) {
	t.Helper()
	// Use the service codec first, before proto.Marshal can populate response caches.
	data, err := codec.Marshal(response)
	require.NoError(t, err)
	defer data.Free()
	got := data.Materialize()
	want, err := proto.Marshal(response)
	require.NoError(t, err)
	require.Len(t, got, len(want))
	decoded := &flowpb.GetFlowsResponse{}
	require.NoError(t, proto.Unmarshal(got, decoded))
	// Map iteration order may differ, so compare decoded messages rather than encoded bytes.
	require.True(t, proto.Equal(response, decoded))
}

func TestFlowStreamCodec(t *testing.T) {
	codec := newFlowStreamCodec()
	for _, tc := range []struct {
		numFlows, labels int
	}{{0, 0}, {1, 0}, {1, 40}, {internalBatchSize, 40}} {
		for _, redacted := range []bool{false, true} {
			t.Run(fmt.Sprintf("flows=%d/labels=%d/redacted=%t", tc.numFlows, tc.labels, redacted), func(t *testing.T) {
				flows := newCodecTestFlows(tc.labels, 11)[:tc.numFlows]
				for i, f := range flows {
					// Exercise redaction after another stream already populated all caches.
					proto.Size(f)
					if redacted {
						flows[i] = redactFlow(f, tierFull, tierFlow, tierFull)
					}
				}
				selected, _, _ := selectRecords(t.Context(), nil, flows, nil, time.Time{}, 0, maxEncodedFlowsSize)
				response := &flowpb.GetFlowsResponse{
					Flows: selected, DroppedCount: math.MaxUint64,
					ResumeToken: &flowpb.ResumeToken{
						StreamEpoch: "ed7b6aee-22d1-44d7-94be-4668df46d289", SequenceNumber: -1,
					},
				}
				requireStandardProtoEncoding(t, codec, response)
			})
		}
	}
}

func TestFlowStreamCodecSharedFlows(t *testing.T) {
	flows := newCodecTestFlows(40, 11)
	codec := newFlowStreamCodec()
	for i := range 4 {
		t.Run(fmt.Sprintf("stream=%d", i), func(t *testing.T) {
			t.Parallel()
			batch := append([]*flowpb.Flow(nil), flows...)
			selected, _, _ := selectRecords(t.Context(), nil, batch, nil, time.Time{}, 0, maxEncodedFlowsSize)
			for _, seq := range []int64{-1, 0, 127, 128, math.MaxInt64} {
				// Sharing immutable flows is safe, while each response and token must be fresh.
				requireStandardProtoEncoding(t, codec, &flowpb.GetFlowsResponse{
					Flows: selected, DroppedCount: uint64(i),
					ResumeToken: &flowpb.ResumeToken{StreamEpoch: "epoch", SequenceNumber: seq},
				})
			}
		})
	}
}

func TestFlowStreamCodecUnknownFields(t *testing.T) {
	unknown := protowire.AppendVarint(protowire.AppendTag(nil, 500, protowire.VarintType), 12345)
	flow := newFlow("unknown-fields", newPodK8S("source", "pod", "destination", "peer"))
	flow.ProtoReflect().SetUnknown(unknown)
	flow.K8S.ProtoReflect().SetUnknown(unknown)
	selected, _, _ := selectRecords(t.Context(), nil, []*flowpb.Flow{flow}, nil, time.Time{}, 0, maxEncodedFlowsSize)
	response := &flowpb.GetFlowsResponse{Flows: selected}
	response.ProtoReflect().SetUnknown(unknown)
	requireStandardProtoEncoding(t, newFlowStreamCodec(), response)
}

func TestFlowStreamCodecDefaultCodecDelegation(t *testing.T) {
	codec := newFlowStreamCodec()
	require.Equal(t, grpcproto.Name, codec.Name())
	req := &flowpb.GetFlowsRequest{Namespaces: []string{"ns-a"}, Follow: true, MaxCount: 100}
	data, err := codec.Marshal(req)
	require.NoError(t, err)
	defer data.Free()
	want, err := proto.Marshal(req)
	require.NoError(t, err)
	require.Equal(t, want, data.Materialize())
	decoded := &flowpb.GetFlowsRequest{}
	require.NoError(t, codec.Unmarshal(data, decoded))
	require.True(t, proto.Equal(req, decoded))
	_, err = codec.Marshal(struct{}{})
	require.Error(t, err)
}

func TestFlowStreamCodecInvalidUTF8(t *testing.T) {
	for _, length := range []int{0, 4096} {
		t.Run(fmt.Sprintf("length=%d", length), func(t *testing.T) {
			flow := &flowpb.Flow{Id: strings.Repeat("x", length) + "\xff"}
			selected, _, _ := selectRecords(t.Context(), nil, []*flowpb.Flow{flow}, nil, time.Time{}, 0, maxEncodedFlowsSize)
			response := &flowpb.GetFlowsResponse{Flows: selected}
			data, err := newFlowStreamCodec().Marshal(response)
			require.Error(t, err)
			require.Empty(t, data)
			_, err = proto.Marshal(response)
			require.Error(t, err)
		})
	}
}
