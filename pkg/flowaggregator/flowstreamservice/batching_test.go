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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"
	"k8s.io/apiserver/pkg/endpoints/request"

	flowpb "antrea.io/antrea/v2/pkg/apis/flow/v1alpha1"
	"antrea.io/antrea/v2/pkg/flowaggregator/ringbuffer"
)

const (
	grpcDefaultReceiveLimit = 4 * 1024 * 1024
	maxEncodedFlowsSize     = grpcDefaultReceiveLimit - 62
)

func requireResponseWithinLimit(t *testing.T, resp *flowpb.GetFlowsResponse) {
	t.Helper()
	data, err := proto.Marshal(resp)
	require.NoError(t, err)
	require.LessOrEqual(t, len(data), grpcDefaultReceiveLimit)
	require.LessOrEqual(t, len(resp.GetFlows()), internalBatchSize)
}

// padResponseToSize uses a synthetic flow ID to exercise exact wire-size boundaries,
// including the response's counters, resume token, and nested length prefixes.
func padResponseToSize(t *testing.T, resp *flowpb.GetFlowsResponse, size int) {
	t.Helper()
	f := resp.Flows[len(resp.Flows)-1]
	f.Id = strings.Repeat("x", size)
	f.Id = f.Id[:size-(proto.Size(resp)-size)]
	data, err := proto.Marshal(resp)
	require.NoError(t, err)
	require.Len(t, data, size)
}

func newLabelRichFlows(n int) []*flowpb.Flow {
	labels := &flowpb.Labels{Labels: make(map[string]string, 300)}
	for i := range 300 {
		labels.Labels[fmt.Sprintf("label-%03d", i)] = strings.Repeat("v", 63)
	}
	flows := make([]*flowpb.Flow, n)
	for i := range flows {
		flows[i] = newFlow(fmt.Sprintf("flow-%03d", i), &flowpb.Kubernetes{
			SourcePodLabels:      labels,
			DestinationPodLabels: labels,
		})
	}
	return flows
}

func TestSelectRecords_Limits(t *testing.T) {
	newMatchingFlow := func(id string) *flowpb.Flow {
		return &flowpb.Flow{Id: id, K8S: &flowpb.Kubernetes{SourcePodName: "match"}}
	}
	first, second, third := newMatchingFlow("first"), newMatchingFlow("other"), newMatchingFlow("third")
	oversized := newMatchingFlow(strings.Repeat("x", 100))
	filtered := newMatchingFlow(strings.Repeat("y", 100))
	filtered.K8S.SourcePodName = "other"
	batch := []*flowpb.Flow{filtered, first, oversized, second, filtered, third}
	flowSize := proto.Size(&flowpb.GetFlowsResponse{Flows: []*flowpb.Flow{first}})
	filters := mustParseFilters(&flowpb.FlowFilter{PodNames: []string{"match"}})
	for _, tc := range []struct {
		name         string
		batch        []*flowpb.Flow
		limit        int
		sizeLimit    int
		want         []*flowpb.Flow
		wantConsumed int
		wantDropped  uint64
	}{
		{name: "count", batch: batch, limit: 1, sizeLimit: 3 * flowSize, want: []*flowpb.Flow{first}, wantConsumed: 2},
		{name: "bytes", batch: batch, sizeLimit: flowSize, want: []*flowpb.Flow{first}, wantConsumed: 3, wantDropped: 1},
		{name: "count_excludes_drops", batch: batch, limit: 2, sizeLimit: 2 * flowSize, want: []*flowpb.Flow{first, second}, wantConsumed: 4, wantDropped: 1},
		{name: "whole_batch", batch: batch, sizeLimit: 3 * flowSize, want: []*flowpb.Flow{first, second, third}, wantConsumed: 6, wantDropped: 1},
		{name: "all_oversized", batch: []*flowpb.Flow{oversized, oversized}, limit: 1, sizeLimit: flowSize, wantConsumed: 2, wantDropped: 2},
		{name: "filtered_oversized", batch: []*flowpb.Flow{filtered}, sizeLimit: flowSize, wantConsumed: 1},
		{name: "empty", sizeLimit: flowSize},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := append([]*flowpb.Flow(nil), tc.batch...)
			got, consumed, dropped := selectRecords(t.Context(), nil, input, filters, time.Time{}, tc.limit, tc.sizeLimit)
			require.Equal(t, tc.wantConsumed, consumed)
			assert.Equal(t, tc.wantDropped, dropped)
			require.Equal(t, len(tc.want), len(got))
			for i := range got {
				assert.True(t, proto.Equal(tc.want[i], got[i]), "selected flow %d", i)
			}
			for i := consumed; i < len(input); i++ {
				assert.Same(t, tc.batch[i], input[i], "the unconsumed tail must be left unchanged")
			}
		})
	}
}

func TestGetFlows_ResponseSizeDefaultGRPCClient(t *testing.T) {
	buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](128)
	want := newLabelRichFlows(100)
	buf.ProduceMultiple(want)
	buf.Shutdown()
	svc := newTestService(buf)
	require.Greater(t, proto.Size(&flowpb.GetFlowsResponse{Flows: want}), grpcDefaultReceiveLimit,
		"the original count-only batch must exceed the default client receive limit")

	certPEM, keyPEM := newTestCert(t)
	require.NoError(t, svc.UpdateCertificate(certPEM, keyPEM))
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(certPEM))
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	stopCh := make(chan struct{})
	errCh := make(chan error, 1)
	go func() { errCh <- svc.Run(lis, stopCh, func(State) {}) }()
	t.Cleanup(func() {
		close(stopCh)
		select {
		case err := <-errCh:
			assert.NoError(t, err)
		case <-time.After(10 * time.Second):
			t.Error("Run did not return after stopCh was closed")
		}
	})

	// Use the default receive limit, with no MaxCallRecvMsgSize override.
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		RootCAs:    roots,
		ServerName: "127.0.0.1",
	})))
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, conn.Close()) })
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	stream, err := flowpb.NewFlowStreamServiceClient(conn).GetFlows(ctx, &flowpb.GetFlowsRequest{})
	require.NoError(t, err)

	var got []*flowpb.Flow
	responses := 0
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		requireResponseWithinLimit(t, resp)
		got = append(got, resp.GetFlows()...)
		assert.EqualValues(t, len(got)-1, resp.GetResumeToken().GetSequenceNumber())
		assert.Zero(t, resp.GetDroppedCount())
		responses++
	}
	require.GreaterOrEqual(t, responses, 3, "handshake followed by at least two data responses")
	require.Len(t, got, len(want))
	for i := range want {
		assert.True(t, proto.Equal(want[i], got[i]), "flow %d and its labels must be preserved in order", i)
	}
}

func TestGetFlows_ResponseSizeBoundaries(t *testing.T) {
	for _, dropped := range []int{0, 128} {
		for _, extra := range []int{-1, 0, 1} {
			t.Run(fmt.Sprintf("dropped=%d/limit%+d", dropped, extra), func(t *testing.T) {
				buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](2)
				svc := newTestService(buf)
				flows := []*flowpb.Flow{{Id: "first"}, {}}
				padResponseToSize(t, &flowpb.GetFlowsResponse{Flows: flows}, maxEncodedFlowsSize+extra)
				for range dropped {
					buf.Produce(&flowpb.Flow{Id: "evicted"})
				}
				buf.ProduceMultiple(flows)
				buf.Shutdown()
				stream := newFakeStream(t.Context())
				require.NoError(t, svc.GetFlows(&flowpb.GetFlowsRequest{
					Resume: &flowpb.ResumeToken{StreamEpoch: svc.streamEpoch, SequenceNumber: -1},
				}, stream))
				wantResponses := 2
				if extra > 0 {
					wantResponses++
				}
				require.Equal(t, wantResponses, len(stream.responses))
				seen := dropped
				for _, r := range stream.responses[1:] {
					requireResponseWithinLimit(t, r)
					seen += len(r.GetFlows())
					assert.EqualValues(t, seen-1, r.GetResumeToken().GetSequenceNumber())
					assert.EqualValues(t, dropped, r.GetDroppedCount())
				}
				got := collectFlows(stream.responses)
				require.Len(t, got, len(flows))
				for i := range flows {
					assert.True(t, proto.Equal(flows[i], got[i]), "flow %d changed", i)
				}
			})
		}
	}
}

func TestGetFlows_ResponseSizeMetadataHeadroom(t *testing.T) {
	buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](2)
	svc := newTestService(buf)
	resp := &flowpb.GetFlowsResponse{
		Flows: []*flowpb.Flow{{K8S: &flowpb.Kubernetes{SourcePodName: "match"}}},
	}
	padResponseToSize(t, resp, maxEncodedFlowsSize)
	for range 127 {
		buf.Produce(&flowpb.Flow{})
	}
	buf.Produce(resp.Flows[0])
	buf.Produce(&flowpb.Flow{K8S: &flowpb.Kubernetes{SourcePodName: "other"}})
	buf.Shutdown()
	stream := newFakeStream(t.Context())
	require.NoError(t, svc.GetFlows(&flowpb.GetFlowsRequest{
		Filters: []*flowpb.FlowFilter{{PodNames: []string{"match"}}},
	}, stream))

	// The flow fills the byte budget. The reserved metadata space also covers advancing
	// the token from 127 to 128, so the trailing filtered record needs no extra response.
	require.Equal(t, 2, len(stream.responses))
	for _, r := range stream.responses {
		requireResponseWithinLimit(t, r)
		assert.Zero(t, r.GetDroppedCount())
	}
	resp.ResumeToken = &flowpb.ResumeToken{StreamEpoch: svc.streamEpoch, SequenceNumber: 128}
	assert.True(t, proto.Equal(resp, stream.responses[1]))
}

func TestGetFlows_ResponseSizeCumulativeDrops(t *testing.T) {
	buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](128)
	initial := newLabelRichFlows(200)
	buf.ProduceMultiple(initial)
	svc := newTestService(buf)
	stream := newFakeStream(t.Context())
	producedMore := false
	t.Cleanup(func() {
		if !producedMore {
			buf.Shutdown()
		}
	})
	var following []*flowpb.Flow
	stream.onSend = func(resp *flowpb.GetFlowsResponse) {
		if len(resp.GetFlows()) == 0 || producedMore {
			return
		}
		producedMore = true
		// The current read holds positions 72-171, including unsent split responses.
		// Overwrite the buffer while those responses are being sent. The next read
		// starts at 328 and reports another 156 drops, for a cumulative total of 228.
		for i := range 256 {
			following = append(following, &flowpb.Flow{Id: fmt.Sprintf("later-%d", i)})
		}
		buf.ProduceMultiple(following)
		buf.Shutdown()
	}
	require.NoError(t, svc.GetFlows(&flowpb.GetFlowsRequest{
		Resume: &flowpb.ResumeToken{StreamEpoch: svc.streamEpoch, SequenceNumber: -1},
	}, stream))
	require.True(t, producedMore)
	require.GreaterOrEqual(t, len(stream.responses), 5, "handshake, split first batch, and two later batches")
	for _, resp := range stream.responses[1:] {
		requireResponseWithinLimit(t, resp)
		wantDrops := 72
		if resp.GetResumeToken().GetSequenceNumber() >= 328 {
			wantDrops = 228
		}
		assert.EqualValues(t, wantDrops, resp.GetDroppedCount())
	}
	want := append(append([]*flowpb.Flow(nil), initial[72:172]...), following[128:]...)
	got := collectFlows(stream.responses)
	require.Equal(t, len(want), len(got))
	for i := range want {
		assert.True(t, proto.Equal(want[i], got[i]), "flow %d must be delivered once, in order", i)
	}
	assert.EqualValues(t, 455, stream.responses[len(stream.responses)-1].GetResumeToken().GetSequenceNumber())
}

func TestGetFlows_ResponseSizeOversizedFlowIsDropped(t *testing.T) {
	for _, tc := range []struct {
		name       string
		preceding  int
		oversized  int
		following  int
		maxCount   uint32
		wantSent   int
		wantDrops  uint64
		wantResume int64
		headroom   bool
	}{
		{name: "first", oversized: 1, following: 1, wantSent: 1, wantDrops: 1, wantResume: 1},
		{name: "middle", preceding: 1, oversized: 1, following: 1, wantSent: 2, wantDrops: 1, wantResume: 2},
		{name: "last", preceding: 1, oversized: 1, wantSent: 1, wantDrops: 1, wantResume: 1},
		{name: "all_oversized", oversized: 2, wantDrops: 2, wantResume: 1},
		{name: "max_count_excludes_drops", preceding: 1, oversized: 1, following: 2, maxCount: 2, wantSent: 2, wantDrops: 1, wantResume: 2},
		{name: "max_count_before_oversized", preceding: 1, oversized: 1, following: 1, maxCount: 1, wantSent: 1, wantResume: 0},
		{name: "reserved_headroom", oversized: 1, following: 1, wantSent: 1, wantDrops: 1, wantResume: 1, headroom: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](8)
			svc := newTestService(buf)
			var flows []*flowpb.Flow
			if tc.preceding > 0 {
				flows = append(flows, &flowpb.Flow{Id: "first"})
			}
			want := append([]*flowpb.Flow(nil), flows...)
			oversized := &flowpb.GetFlowsResponse{
				Flows: []*flowpb.Flow{{}},
				ResumeToken: &flowpb.ResumeToken{
					StreamEpoch: svc.streamEpoch, SequenceNumber: int64(len(flows)),
				},
			}
			padResponseToSize(t, oversized, grpcDefaultReceiveLimit+1)
			if tc.headroom {
				// The conservative budget rejects this entry even though a response with
				// smaller actual metadata could fit it. Pin down that intentional tradeoff.
				padResponseToSize(t, &flowpb.GetFlowsResponse{Flows: oversized.Flows}, maxEncodedFlowsSize+1)
				require.Less(t, proto.Size(oversized), grpcDefaultReceiveLimit)
			}
			for range tc.oversized {
				flows = append(flows, oversized.Flows[0])
			}
			for i := range tc.following {
				f := &flowpb.Flow{Id: fmt.Sprintf("following-%d", i)}
				flows = append(flows, f)
				want = append(want, f)
			}
			buf.ProduceMultiple(flows)
			buf.Shutdown()
			stream := newFakeStream(t.Context())
			require.NoError(t, svc.GetFlows(&flowpb.GetFlowsRequest{MaxCount: tc.maxCount}, stream))
			got := collectFlows(stream.responses)
			require.Equal(t, tc.wantSent, len(got))
			for _, resp := range stream.responses {
				requireResponseWithinLimit(t, resp)
				if resp.GetResumeToken().GetSequenceNumber() < int64(tc.preceding) {
					assert.Zero(t, resp.GetDroppedCount(), "do not report a drop before the token accounts for it")
				}
			}
			last := stream.responses[len(stream.responses)-1]
			assert.Equal(t, tc.wantResume, last.GetResumeToken().GetSequenceNumber())
			assert.Equal(t, tc.wantDrops, last.GetDroppedCount())
			resumed := newFakeStream(t.Context())
			require.NoError(t, svc.GetFlows(&flowpb.GetFlowsRequest{Resume: last.GetResumeToken()}, resumed))
			got = append(got, collectFlows(resumed.responses)...)
			require.Equal(t, len(want), len(got))
			for i := range want {
				assert.True(t, proto.Equal(want[i], got[i]), "flow %d must be delivered once, in order", i)
			}
		})
	}
}

func TestGetFlows_ResponseSizeResumeWithAuthorizationAndFilters(t *testing.T) {
	for _, tc := range []struct {
		name      string
		maxCount  uint32
		stopAfter int
		follow    bool
	}{
		{name: "all"},
		{name: "max_count", maxCount: 2},
		{name: "disconnect_after_first", stopAfter: 1},
		{name: "disconnect_after_second", stopAfter: 2},
		{name: "follow_shutdown", follow: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](16)
			verb := listVerb
			if tc.follow {
				verb = watchVerb
			}
			svc, _ := newAuthorizedTestService(buf, flowsGrant(verb, "ns-a"))
			largeFlow := func(id string) *flowpb.Flow {
				f := newFlow(id, newPodK8S("ns-a", "match", "ns-b", "peer"))
				// Synthetic label values make the raw flow too large, but the authorized form
				// fits on its own once the peer's labels have been redacted.
				f.K8S.SourcePodLabels = &flowpb.Labels{Labels: map[string]string{"payload": strings.Repeat("s", 2*1024*1024)}}
				f.K8S.DestinationPodLabels = &flowpb.Labels{Labels: map[string]string{"secret": strings.Repeat("d", 4*1024*1024)}}
				return f
			}
			first, second, third := largeFlow("first"), largeFlow("second"), largeFlow("third")
			withheld := newFlow("withheld", newPodK8S("ns-c", "match", "ns-d", "peer"))
			filtered := newFlow("filtered", newPodK8S("ns-a", "other", "ns-b", "match"))
			for range 16 {
				buf.Produce(withheld)
			}
			// Positions 0-7 have been evicted. Selected positions are 17, 20, and 22;
			// everything between them is removed by authorization or by the filter.
			buf.ProduceMultiple([]*flowpb.Flow{withheld, first, filtered, withheld, second, filtered, third, withheld})
			buf.Shutdown()
			req := &flowpb.GetFlowsRequest{
				Namespaces: []string{"ns-a"},
				Filters:    []*flowpb.FlowFilter{{PodNames: []string{"match"}}},
				MaxCount:   tc.maxCount,
				Follow:     tc.follow,
				Resume:     &flowpb.ResumeToken{StreamEpoch: svc.streamEpoch, SequenceNumber: -1},
			}
			ctx := request.WithUser(t.Context(), testUserInfo)
			stream := newFakeStream(ctx)
			sendErr := errors.New("client disconnected")
			if tc.stopAfter > 0 {
				stream.onSend = func(resp *flowpb.GetFlowsResponse) {
					if len(stream.responses) == tc.stopAfter+1 {
						stream.sendErr = sendErr
					}
				}
			}
			err := svc.GetFlows(req, stream)
			if tc.stopAfter > 0 {
				require.ErrorIs(t, err, sendErr)
			} else {
				require.NoError(t, err)
			}
			wantPositions := []int64{19, 21, 23}
			if tc.maxCount > 0 {
				wantPositions = []int64{19, 20}
			} else if tc.stopAfter > 0 {
				wantPositions = wantPositions[:tc.stopAfter]
			}
			require.Len(t, stream.responses, len(wantPositions)+1)
			for i, resp := range stream.responses[1:] {
				requireResponseWithinLimit(t, resp)
				assert.Equal(t, wantPositions[i], resp.GetResumeToken().GetSequenceNumber())
				assert.EqualValues(t, 8, resp.GetDroppedCount(), "drops are cumulative across split responses")
			}
			got := collectFlows(stream.responses)
			resumed := newFakeStream(ctx)
			req.Resume = stream.responses[len(stream.responses)-1].GetResumeToken()
			req.MaxCount = 0
			require.NoError(t, svc.GetFlows(req, resumed))
			for _, resp := range resumed.responses {
				requireResponseWithinLimit(t, resp)
				assert.Zero(t, resp.GetDroppedCount(), "already reported drops must not be counted again on resume")
			}
			got = append(got, collectFlows(resumed.responses)...)
			require.Len(t, got, 3)
			for i, original := range []*flowpb.Flow{first, second, third} {
				assert.Equal(t, original.GetId(), got[i].GetId())
				assert.True(t, proto.Equal(original.K8S.SourcePodLabels, got[i].K8S.SourcePodLabels))
				assert.Nil(t, got[i].K8S.DestinationPodLabels)
				assert.Empty(t, got[i].K8S.DestinationPodName)
				assert.Equal(t, flowpb.EndpointDisclosure_ENDPOINT_DISCLOSURE_FLOW, got[i].K8S.DestinationDisclosure)
				require.Greater(t, proto.Size(original), grpcDefaultReceiveLimit, "the buffered record must remain unmodified")
			}
		})
	}
}

func TestGetFlows_SplitBatchSharesAuthorizationTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](4)
		svc, fake := newAuthorizedTestService(buf, flowsGrant(listVerb, "ns-a"), flowsGrant(listVerb, "ready"))
		fake.hang(identityGrant("peer-1"))
		fake.hang(identityGrant("peer-2"))
		for _, peer := range []string{"ready", "peer-1", "peer-2"} {
			// Each flow fits individually, but any pair needs separate responses.
			flow := newFlow(peer+strings.Repeat("x", 2*1024*1024), newPodK8S("ns-a", "source", peer, "destination"))
			buf.Produce(flow)
		}
		buf.Shutdown()
		stream := newFakeStream(request.WithUser(t.Context(), testUserInfo))
		start := time.Now()
		require.NoError(t, svc.GetFlows(&flowpb.GetFlowsRequest{Namespaces: []string{"ns-a"}}, stream))
		require.Equal(t, authorizationCheckTimeout, time.Since(start), "split responses must share the batch's authorization deadline")
		require.Len(t, stream.responses, 4, "handshake followed by one response per flow")
		for i, response := range stream.responses[1:] {
			requireResponseWithinLimit(t, response)
			require.Len(t, response.Flows, 1)
			assert.EqualValues(t, i, response.ResumeToken.SequenceNumber)
			if i > 0 {
				assert.Equal(t, flowpb.EndpointDisclosure_ENDPOINT_DISCLOSURE_FLOW, response.Flows[0].K8S.DestinationDisclosure)
			}
		}
	})
}
