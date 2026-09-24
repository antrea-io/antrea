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
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"k8s.io/apiserver/pkg/endpoints/request"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	flowpb "antrea.io/antrea/v2/pkg/apis/flow/v1alpha1"
	flowaggregatorconfig "antrea.io/antrea/v2/pkg/config/flowaggregator"
	"antrea.io/antrea/v2/pkg/flowaggregator/exporter"
	"antrea.io/antrea/v2/pkg/flowaggregator/ringbuffer"
)

// fakeStream implements flowpb.FlowStreamService_GetFlowsServer.
type fakeStream struct {
	ctx       context.Context
	responses []*flowpb.GetFlowsResponse
	// onSend, if set, runs synchronously from within Send, letting a test inject work (e.g.
	// producing more items) at an exact point in GetFlows' execution, such as right as the
	// handshake response goes out.
	onSend func(*flowpb.GetFlowsResponse)
}

func newFakeStream(ctx context.Context) *fakeStream { return &fakeStream{ctx: ctx} }

func (f *fakeStream) Send(r *flowpb.GetFlowsResponse) error {
	f.responses = append(f.responses, r)
	if onSend := f.onSend; onSend != nil {
		onSend(r)
	}
	return nil
}
func (f *fakeStream) Context() context.Context     { return f.ctx }
func (f *fakeStream) SetHeader(metadata.MD) error  { return nil }
func (f *fakeStream) SendHeader(metadata.MD) error { return nil }
func (f *fakeStream) SetTrailer(metadata.MD)       {}
func (f *fakeStream) SendMsg(any) error            { return nil }
func (f *fakeStream) RecvMsg(any) error            { return nil }

func newTestService(buf ringbuffer.BroadcastBuffer[*flowpb.Flow]) *FlowStreamService {
	// These tests exercise GetFlows itself, with no API server to validate credentials against;
	// authentication is covered separately in authenticator_test.go, and authorization by the tests
	// that build a service with newAuthorizedTestService.
	return newFlowStreamServiceWithoutAuthentication(buf, nil)
}

func collectFlows(responses []*flowpb.GetFlowsResponse) []*flowpb.Flow {
	var out []*flowpb.Flow
	for _, r := range responses {
		out = append(out, r.GetFlows()...)
	}
	return out
}

func newFlow(id string, k8s *flowpb.Kubernetes) *flowpb.Flow {
	return &flowpb.Flow{Id: id, EndTs: timestamppb.New(time.Now()), K8S: k8s}
}

func newFlowEndTs(id string, endTs time.Time, k8s *flowpb.Kubernetes) *flowpb.Flow {
	return &flowpb.Flow{Id: id, EndTs: timestamppb.New(endTs), K8S: k8s}
}

func newFlowWithIPs(srcIP, dstIP string) *flowpb.Flow {
	return &flowpb.Flow{
		EndTs: timestamppb.New(time.Now()),
		K8S:   &flowpb.Kubernetes{},
		Ip: &flowpb.IP{
			Source:      netip.MustParseAddr(srcIP).AsSlice(),
			Destination: netip.MustParseAddr(dstIP).AsSlice(),
		},
	}
}

func newPodK8S(srcNS, srcName, dstNS, dstName string) *flowpb.Kubernetes {
	return &flowpb.Kubernetes{
		SourcePodNamespace:      srcNS,
		SourcePodName:           srcName,
		DestinationPodNamespace: dstNS,
		DestinationPodName:      dstName,
	}
}

func TestDestinationServiceName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "", want: ""},
		{input: "default/frontend", want: "frontend"},
		{input: "default/frontend:http", want: "frontend"},
		{input: "production/api-gateway:grpc", want: "api-gateway"},
		{input: "ns/svc:", want: "svc"},
		{input: "bareword", want: ""},
		{input: "a/b:c:d", want: "b"},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("%q", tc.input), func(t *testing.T) {
			assert.Equal(t, tc.want, destinationServiceName(tc.input))
		})
	}
}

// mustParseFilters parses proto FlowFilters into flowFilters, panicking on error.
func mustParseFilters(protos ...*flowpb.FlowFilter) []flowFilter {
	out := make([]flowFilter, len(protos))
	for i, p := range protos {
		f, err := parseFlowFilter(p)
		if err != nil {
			panic(err)
		}
		out[i] = f
	}
	return out
}

func TestApplyFilter_Since(t *testing.T) {
	now := time.Now()
	since := now.Add(-30 * time.Second)

	oldFlow := newFlowEndTs("old", now.Add(-1*time.Minute), &flowpb.Kubernetes{})
	recentFlow := newFlowEndTs("recent", now.Add(-5*time.Second), &flowpb.Kubernetes{})

	got := applyFilters([]*flowpb.Flow{oldFlow, recentFlow}, nil, since)
	require.Len(t, got, 1)
	assert.Equal(t, "recent", got[0].GetId())
}

func TestApplyFilter_SinceExcludesNilEndTs(t *testing.T) {
	// A flow with no EndTs should be treated as having end_ts == zero time,
	// which is before any non-zero since value, so it must be excluded.
	since := time.Now().Add(-30 * time.Second)
	nilEndTsFlow := &flowpb.Flow{Id: "nil-ts", K8S: &flowpb.Kubernetes{}}
	got := applyFilters([]*flowpb.Flow{nilEndTsFlow}, nil, since)
	assert.Empty(t, got)
}

func TestApplyFilter_ZeroSincePassesAll(t *testing.T) {
	flows := []*flowpb.Flow{newFlow("a", &flowpb.Kubernetes{}), newFlow("b", &flowpb.Kubernetes{})}
	got := applyFilters(flows, nil, time.Time{})
	assert.Len(t, got, 2)
}

func TestApplyFilter_NilFilterPassesAll(t *testing.T) {
	flows := []*flowpb.Flow{newFlow("a", &flowpb.Kubernetes{}), newFlow("b", &flowpb.Kubernetes{})}
	got := applyFilters(flows, nil, time.Time{})
	assert.Len(t, got, 2)
}

func TestMatchFilter_Namespaces(t *testing.T) {
	tests := []struct {
		name      string
		srcNS     string
		dstNS     string
		filter    []string
		direction flowpb.FlowFilterDirection
		want      bool
	}{
		{
			name:  "BOTH: src matches",
			srcNS: "default", dstNS: "prod",
			filter: []string{"default"}, direction: flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_BOTH,
			want: true,
		},
		{
			name:  "BOTH: dst matches",
			srcNS: "other", dstNS: "default",
			filter: []string{"default"}, direction: flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_BOTH,
			want: true,
		},
		{
			name:  "BOTH: neither matches",
			srcNS: "other", dstNS: "prod",
			filter: []string{"default"}, direction: flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_BOTH,
			want: false,
		},
		{
			name:  "FROM: src matches",
			srcNS: "default", dstNS: "prod",
			filter: []string{"default"}, direction: flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_FROM,
			want: true,
		},
		{
			name:  "FROM: only dst matches",
			srcNS: "other", dstNS: "default",
			filter: []string{"default"}, direction: flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_FROM,
			want: false,
		},
		{
			name:  "TO: dst matches",
			srcNS: "other", dstNS: "default",
			filter: []string{"default"}, direction: flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_TO,
			want: true,
		},
		{
			name:  "TO: only src matches",
			srcNS: "default", dstNS: "other",
			filter: []string{"default"}, direction: flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_TO,
			want: false,
		},
		{
			name:  "BOTH: multiple namespaces in filter, one matches",
			srcNS: "monitoring", dstNS: "prod",
			filter: []string{"default", "monitoring"}, direction: flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_BOTH,
			want: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFlow("f", newPodK8S(tc.srcNS, "src-pod", tc.dstNS, "dst-pod"))
			filter := &flowpb.FlowFilter{Namespaces: tc.filter, Direction: tc.direction}
			got := applyFilters([]*flowpb.Flow{f}, mustParseFilters(filter), time.Time{})
			if tc.want {
				assert.Len(t, got, 1)
			} else {
				assert.Empty(t, got)
			}
		})
	}
}

func TestMatchFilter_PodNames(t *testing.T) {
	tests := []struct {
		name      string
		srcPod    string
		dstPod    string
		filter    []string
		direction flowpb.FlowFilterDirection
		want      bool
	}{
		{
			name:   "BOTH: src matches",
			srcPod: "frontend", dstPod: "backend",
			filter: []string{"frontend"}, direction: flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_BOTH,
			want: true,
		},
		{
			name:   "BOTH: dst matches",
			srcPod: "other", dstPod: "frontend",
			filter: []string{"frontend"}, direction: flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_BOTH,
			want: true,
		},
		{
			name:   "BOTH: neither matches",
			srcPod: "other", dstPod: "another",
			filter: []string{"frontend"}, direction: flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_BOTH,
			want: false,
		},
		{
			name:   "FROM: src matches",
			srcPod: "frontend", dstPod: "backend",
			filter: []string{"frontend"}, direction: flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_FROM,
			want: true,
		},
		{
			name:   "FROM: only dst matches",
			srcPod: "other", dstPod: "frontend",
			filter: []string{"frontend"}, direction: flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_FROM,
			want: false,
		},
		{
			name:   "TO: dst matches",
			srcPod: "other", dstPod: "frontend",
			filter: []string{"frontend"}, direction: flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_TO,
			want: true,
		},
		{
			name:   "TO: only src matches",
			srcPod: "frontend", dstPod: "other",
			filter: []string{"frontend"}, direction: flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_TO,
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFlow("f", newPodK8S("ns", tc.srcPod, "ns", tc.dstPod))
			filter := &flowpb.FlowFilter{PodNames: tc.filter, Direction: tc.direction}
			got := applyFilters([]*flowpb.Flow{f}, mustParseFilters(filter), time.Time{})
			if tc.want {
				assert.Len(t, got, 1)
			} else {
				assert.Empty(t, got)
			}
		})
	}
}

func TestMatchFilter_FlowTypes(t *testing.T) {
	intra := newFlow("intra", &flowpb.Kubernetes{FlowType: flowpb.FlowType_FLOW_TYPE_INTRA_NODE})
	inter := newFlow("inter", &flowpb.Kubernetes{FlowType: flowpb.FlowType_FLOW_TYPE_INTER_NODE})

	filter := &flowpb.FlowFilter{FlowTypes: []flowpb.FlowType{flowpb.FlowType_FLOW_TYPE_INTRA_NODE}}
	got := applyFilters([]*flowpb.Flow{intra, inter}, mustParseFilters(filter), time.Time{})
	require.Len(t, got, 1)
	assert.Equal(t, "intra", got[0].GetId())
}

func TestMatchFilter_ServiceNames(t *testing.T) {
	tests := []struct {
		name        string
		svcPortName string
		filter      []string
		wantMatch   bool
	}{
		{
			name:        "plain name matches namespace/name:port",
			svcPortName: "default/frontend:http",
			filter:      []string{"frontend"},
			wantMatch:   true,
		},
		{
			name:        "same name in different namespace still matches",
			svcPortName: "production/frontend:http",
			filter:      []string{"frontend"},
			wantMatch:   true,
		},
		{
			name:        "different service name does not match",
			svcPortName: "default/backend:http",
			filter:      []string{"frontend"},
			wantMatch:   false,
		},
		{
			name:        "partial prefix of name does not match (no HasPrefix bug)",
			svcPortName: "default/frontendXYZ:http",
			filter:      []string{"frontend"},
			wantMatch:   false,
		},
		{
			name:        "empty DestinationServicePortName does not match",
			svcPortName: "",
			filter:      []string{"frontend"},
			wantMatch:   false,
		},
		{
			name:        "multiple entries in filter: one matches",
			svcPortName: "default/backend:http",
			filter:      []string{"frontend", "backend"},
			wantMatch:   true,
		},
		{
			name:        "no port suffix (namespace/name only) still matches",
			svcPortName: "default/frontend",
			filter:      []string{"frontend"},
			wantMatch:   true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFlow("f", &flowpb.Kubernetes{DestinationServicePortName: tc.svcPortName})
			filter := &flowpb.FlowFilter{ServiceNames: tc.filter}
			got := applyFilters([]*flowpb.Flow{f}, mustParseFilters(filter), time.Time{})
			if tc.wantMatch {
				assert.Len(t, got, 1)
			} else {
				assert.Empty(t, got)
			}
		})
	}
}

func TestMatchFilter_IPs(t *testing.T) {
	f := newFlowWithIPs("10.0.0.1", "192.168.1.5")
	tests := []struct {
		name      string
		ips       []string
		direction flowpb.FlowFilterDirection
		wantMatch bool
	}{
		{
			name: "BOTH: exact src matches",
			ips:  []string{"10.0.0.1"}, direction: flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_BOTH,
			wantMatch: true,
		},
		{
			name: "BOTH: exact dst matches",
			ips:  []string{"192.168.1.5"}, direction: flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_BOTH,
			wantMatch: true,
		},
		{
			name: "BOTH: no match",
			ips:  []string{"1.1.1.1"}, direction: flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_BOTH,
			wantMatch: false,
		},
		{
			name: "BOTH: CIDR matches src",
			ips:  []string{"10.0.0.0/8"}, direction: flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_BOTH,
			wantMatch: true,
		},
		{
			name: "BOTH: CIDR matches dst",
			ips:  []string{"192.168.0.0/16"}, direction: flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_BOTH,
			wantMatch: true,
		},
		{
			name: "BOTH: CIDR no match",
			ips:  []string{"172.16.0.0/12"}, direction: flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_BOTH,
			wantMatch: false,
		},
		{
			name: "FROM: src matches",
			ips:  []string{"10.0.0.1"}, direction: flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_FROM,
			wantMatch: true,
		},
		{
			name: "FROM: dst address is ignored",
			ips:  []string{"192.168.1.5"}, direction: flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_FROM,
			wantMatch: false,
		},
		{
			name: "TO: dst matches",
			ips:  []string{"192.168.1.5"}, direction: flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_TO,
			wantMatch: true,
		},
		{
			name: "TO: src address is ignored",
			ips:  []string{"10.0.0.1"}, direction: flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_TO,
			wantMatch: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			filter := &flowpb.FlowFilter{Ips: tc.ips, Direction: tc.direction}
			got := applyFilters([]*flowpb.Flow{f}, mustParseFilters(filter), time.Time{})
			if tc.wantMatch {
				assert.Len(t, got, 1)
			} else {
				assert.Empty(t, got)
			}
		})
	}
}

func TestMatchFilter_LabelSelector(t *testing.T) {
	srcMatch := &flowpb.Labels{Labels: map[string]string{"app": "frontend"}}
	noMatch := &flowpb.Labels{Labels: map[string]string{"app": "backend"}}

	tests := []struct {
		name      string
		k8s       *flowpb.Kubernetes
		direction flowpb.FlowFilterDirection
		wantMatch bool
	}{
		{
			name:      "BOTH: src labels match",
			k8s:       &flowpb.Kubernetes{SourcePodLabels: srcMatch, DestinationPodLabels: noMatch},
			direction: flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_BOTH,
			wantMatch: true,
		},
		{
			name:      "BOTH: dst labels match",
			k8s:       &flowpb.Kubernetes{SourcePodLabels: noMatch, DestinationPodLabels: srcMatch},
			direction: flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_BOTH,
			wantMatch: true,
		},
		{
			name:      "BOTH: neither matches",
			k8s:       &flowpb.Kubernetes{SourcePodLabels: noMatch, DestinationPodLabels: noMatch},
			direction: flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_BOTH,
			wantMatch: false,
		},
		{
			name:      "FROM: src matches",
			k8s:       &flowpb.Kubernetes{SourcePodLabels: srcMatch, DestinationPodLabels: noMatch},
			direction: flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_FROM,
			wantMatch: true,
		},
		{
			name:      "FROM: only dst matches, src does not",
			k8s:       &flowpb.Kubernetes{SourcePodLabels: noMatch, DestinationPodLabels: srcMatch},
			direction: flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_FROM,
			wantMatch: false,
		},
		{
			name:      "TO: dst matches",
			k8s:       &flowpb.Kubernetes{SourcePodLabels: noMatch, DestinationPodLabels: srcMatch},
			direction: flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_TO,
			wantMatch: true,
		},
		{
			name:      "TO: only src matches, dst does not",
			k8s:       &flowpb.Kubernetes{SourcePodLabels: srcMatch, DestinationPodLabels: noMatch},
			direction: flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_TO,
			wantMatch: false,
		},
		{
			name:      "nil k8s field",
			k8s:       nil,
			direction: flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_BOTH,
			wantMatch: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := applyFilters(
				[]*flowpb.Flow{newFlow("f", tc.k8s)},
				mustParseFilters(&flowpb.FlowFilter{Direction: tc.direction, PodLabelSelector: "app=frontend"}),
				time.Time{},
			)
			if tc.wantMatch {
				assert.Len(t, got, 1)
			} else {
				assert.Empty(t, got)
			}
		})
	}
}

func TestGetFlows_ReceivesAllFlows(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](64)
		t.Cleanup(func() { buf.Shutdown() })

		const n = 5
		wantIDs := make([]string, n)
		for i := range n {
			id := fmt.Sprintf("flow-%d", i)
			wantIDs[i] = id
			buf.Produce(newFlow(id, &flowpb.Kubernetes{}))
		}

		svc := newTestService(buf)
		stream := newFakeStream(t.Context())

		errCh := make(chan error, 1)
		go func() { errCh <- svc.GetFlows(&flowpb.GetFlowsRequest{Follow: false}, stream) }()

		// Advance fake time past ConsumeDeadline so that after all buffered flows
		// are consumed, ConsumeMultiple returns n==0 and the non-follow stream exits.
		time.Sleep(2 * exporter.ConsumeDeadline)
		synctest.Wait()

		require.NoError(t, <-errCh)
		got := collectFlows(stream.responses)
		gotIDs := make([]string, len(got))
		for i, f := range got {
			gotIDs[i] = f.GetId()
		}
		assert.ElementsMatch(t, wantIDs, gotIDs)
	})
}

func TestGetFlows_MaxCount(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](64)
		t.Cleanup(func() { buf.Shutdown() })

		for i := range 10 {
			buf.Produce(newFlow(fmt.Sprintf("flow-%d", i), &flowpb.Kubernetes{}))
		}

		svc := newTestService(buf)
		stream := newFakeStream(t.Context())
		req := &flowpb.GetFlowsRequest{Follow: false, MaxCount: 3}

		errCh := make(chan error, 1)
		go func() { errCh <- svc.GetFlows(req, stream) }()
		synctest.Wait()

		require.NoError(t, <-errCh)
		got := collectFlows(stream.responses)
		assert.Len(t, got, 3)
		assert.Equal(t, "flow-0", got[0].GetId())
		assert.Equal(t, "flow-1", got[1].GetId())
		assert.Equal(t, "flow-2", got[2].GetId())
	})
}

func TestGetFlows_FilterByServiceName(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](64)
		t.Cleanup(func() { buf.Shutdown() })

		for i := range 3 {
			buf.Produce(newFlow(fmt.Sprintf("fe-%d", i), &flowpb.Kubernetes{
				DestinationServicePortName: "default/frontend:http",
			}))
			buf.Produce(newFlow(fmt.Sprintf("be-%d", i), &flowpb.Kubernetes{
				DestinationServicePortName: "default/backend:http",
			}))
		}

		svc := newTestService(buf)
		stream := newFakeStream(t.Context())
		req := &flowpb.GetFlowsRequest{
			Follow:  false,
			Filters: []*flowpb.FlowFilter{{ServiceNames: []string{"frontend"}}},
		}

		errCh := make(chan error, 1)
		go func() { errCh <- svc.GetFlows(req, stream) }()
		time.Sleep(2 * exporter.ConsumeDeadline)
		synctest.Wait()

		require.NoError(t, <-errCh)
		got := collectFlows(stream.responses)
		assert.Len(t, got, 3)
		for _, f := range got {
			assert.Equal(t, "default/frontend:http", f.GetK8S().GetDestinationServicePortName())
		}
	})
}

func TestGetFlows_FilterByNamespace(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](64)
		t.Cleanup(func() { buf.Shutdown() })

		for i := range 4 {
			buf.Produce(newFlow(fmt.Sprintf("def-%d", i), newPodK8S("default", "pod", "other", "pod")))
		}
		for i := range 2 {
			buf.Produce(newFlow(fmt.Sprintf("mon-%d", i), newPodK8S("monitoring", "pod", "other", "pod")))
		}

		svc := newTestService(buf)
		stream := newFakeStream(t.Context())
		req := &flowpb.GetFlowsRequest{
			Follow: false,
			Filters: []*flowpb.FlowFilter{{
				Namespaces: []string{"monitoring"},
				Direction:  flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_FROM,
			}},
		}

		errCh := make(chan error, 1)
		go func() { errCh <- svc.GetFlows(req, stream) }()
		time.Sleep(2 * exporter.ConsumeDeadline)
		synctest.Wait()

		require.NoError(t, <-errCh)
		got := collectFlows(stream.responses)
		assert.Len(t, got, 2)
		for _, f := range got {
			assert.Equal(t, "monitoring", f.GetK8S().GetSourcePodNamespace())
		}
	})
}

func TestGetFlows_MultipleFilters(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](64)
		t.Cleanup(func() { buf.Shutdown() })

		// flows from "frontend" ns to "backend" ns
		buf.Produce(newFlow("fe-to-backend", newPodK8S("frontend", "pod", "backend", "pod")))
		// flows from "frontend" ns to "other" ns - should NOT match
		buf.Produce(newFlow("fe-to-other", newPodK8S("frontend", "pod", "other", "pod")))
		// flows from "other" ns to "backend" ns - should NOT match
		buf.Produce(newFlow("other-to-backend", newPodK8S("other", "pod", "backend", "pod")))

		svc := newTestService(buf)
		stream := newFakeStream(t.Context())
		req := &flowpb.GetFlowsRequest{
			Follow: false,
			Filters: []*flowpb.FlowFilter{
				{Namespaces: []string{"frontend"}, Direction: flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_FROM},
				{Namespaces: []string{"backend"}, Direction: flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_TO},
			},
		}

		errCh := make(chan error, 1)
		go func() { errCh <- svc.GetFlows(req, stream) }()
		time.Sleep(2 * exporter.ConsumeDeadline)
		synctest.Wait()

		require.NoError(t, <-errCh)
		got := collectFlows(stream.responses)
		require.Len(t, got, 1)
		assert.Equal(t, "fe-to-backend", got[0].GetId())
	})
}

func TestGetFlows_SinceFilter(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](64)
		t.Cleanup(func() { buf.Shutdown() })

		// Use a fixed reference time relative to the synctest fake clock epoch.
		now := time.Now()
		since := now.Add(-30 * time.Second)

		buf.Produce(newFlowEndTs("old-1", now.Add(-2*time.Minute), &flowpb.Kubernetes{}))
		buf.Produce(newFlowEndTs("old-2", now.Add(-45*time.Second), &flowpb.Kubernetes{}))
		buf.Produce(newFlowEndTs("recent-1", now.Add(-10*time.Second), &flowpb.Kubernetes{}))
		buf.Produce(newFlowEndTs("recent-2", now.Add(-1*time.Second), &flowpb.Kubernetes{}))

		svc := newTestService(buf)
		stream := newFakeStream(t.Context())
		req := &flowpb.GetFlowsRequest{
			Follow: false,
			Since:  timestamppb.New(since),
		}

		errCh := make(chan error, 1)
		go func() { errCh <- svc.GetFlows(req, stream) }()
		time.Sleep(2 * exporter.ConsumeDeadline)
		synctest.Wait()

		require.NoError(t, <-errCh)
		got := collectFlows(stream.responses)
		require.Len(t, got, 2)
		gotIDs := []string{got[0].GetId(), got[1].GetId()}
		assert.ElementsMatch(t, []string{"recent-1", "recent-2"}, gotIDs)
	})
}

func TestGetFlows_InvalidLabelSelector(t *testing.T) {
	buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](64)
	t.Cleanup(func() { buf.Shutdown() }) // only needed for cleanup, GetFlows returns before consuming

	svc := newTestService(buf)
	stream := newFakeStream(context.Background())
	req := &flowpb.GetFlowsRequest{
		Filters: []*flowpb.FlowFilter{{PodLabelSelector: "!!!not-valid"}},
	}

	err := svc.GetFlows(req, stream)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Empty(t, stream.responses)
}

func TestGetFlows_InvalidIP(t *testing.T) {
	buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](64)
	t.Cleanup(func() { buf.Shutdown() })

	svc := newTestService(buf)
	stream := newFakeStream(context.Background())
	req := &flowpb.GetFlowsRequest{
		Filters: []*flowpb.FlowFilter{{Ips: []string{"not-an-ip"}}},
	}

	err := svc.GetFlows(req, stream)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Empty(t, stream.responses)
}

func TestGetFlows_ServiceNamesWithFromDirection(t *testing.T) {
	buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](64)
	t.Cleanup(func() { buf.Shutdown() })

	svc := newTestService(buf)
	stream := newFakeStream(context.Background())
	req := &flowpb.GetFlowsRequest{
		Filters: []*flowpb.FlowFilter{{
			ServiceNames: []string{"frontend"},
			Direction:    flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_FROM,
		}},
	}

	err := svc.GetFlows(req, stream)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestGetFlows_FollowContextCancelled(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](64)
		t.Cleanup(func() { buf.Shutdown() })

		ctx, cancel := context.WithCancel(t.Context())
		svc := newTestService(buf)
		stream := newFakeStream(ctx)

		errCh := make(chan error, 1)
		go func() { errCh <- svc.GetFlows(&flowpb.GetFlowsRequest{Follow: true}, stream) }()

		// Cancel the context and advance fake time past ConsumeDeadline so the
		// consumer wakes up and checks ctx.Err() on the next iteration.
		cancel()
		time.Sleep(2 * exporter.ConsumeDeadline)
		synctest.Wait()

		select {
		case err := <-errCh:
			st, ok := status.FromError(err)
			require.True(t, ok)
			assert.Equal(t, codes.Canceled, st.Code())
		default:
			t.Fatal("GetFlows did not return after context cancellation")
		}
	})
}

// TestNewFlowStreamService_RequiresAuthenticatorAndAuthorizer pins down that neither authentication
// nor authorization is the zero value: a caller that omits either gets an error rather than an open
// server that streams every record to every peer with nothing in the code to flag it.
func TestNewFlowStreamService_RequiresAuthenticatorAndAuthorizer(t *testing.T) {
	buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](4)
	s, err := NewFlowStreamService(buf, nil, newAuthorizer(newFakeAuthorizer()))
	require.Error(t, err)
	assert.Nil(t, s)

	// An authenticator without an authorizer is refused too: that combination would authenticate
	// every client and then stream every record to it unredacted.
	s, err = NewFlowStreamService(buf, &StreamServerAuthenticator{}, nil)
	require.Error(t, err)
	assert.Nil(t, s)

	// Serving clients without authentication has to be asked for by name, and the only constructor
	// that does it is unexported, so no caller outside this package can reach it at all.
	assert.NotNil(t, newFlowStreamServiceWithoutAuthentication(buf, nil))
}

// newAuthorizedTestService builds a service that authorizes clients from a fixed set of grants,
// and a stream context carrying the identity those grants are written for. The real clock is used
// deliberately: inside a synctest bubble it reads the bubble's virtual time, so a test can advance
// past revalidationInterval with time.Sleep.
func newAuthorizedTestService(buf ringbuffer.BroadcastBuffer[*flowpb.Flow], grants ...string) (*FlowStreamService, *fakeAuthorizer) {
	fake := newFakeAuthorizer(grants...)
	return newFlowStreamServiceWithoutAuthentication(buf, newAuthorizer(fake)), fake
}

func TestGetFlows_ScopeIsAuthorized(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](64)
		t.Cleanup(func() { buf.Shutdown() })

		buf.Produce(podFlow("ns-a", "ns-b"))
		buf.Produce(podFlow("ns-c", "ns-d"))

		svc, _ := newAuthorizedTestService(buf, flowsGrant(listVerb, "ns-a"))
		stream := newFakeStream(request.WithUser(t.Context(), testUserInfo))

		errCh := make(chan error, 1)
		go func() {
			errCh <- svc.GetFlows(&flowpb.GetFlowsRequest{Namespaces: []string{"ns-a"}}, stream)
		}()
		time.Sleep(2 * exporter.ConsumeDeadline)
		synctest.Wait()
		require.NoError(t, <-errCh)

		// The first response is always the empty post-auth ack; every response after it carries flows.
		require.Len(t, stream.responses, 2)
		assert.Empty(t, stream.responses[0].GetFlows())
		assert.NotEmpty(t, stream.responses[1].GetFlows())

		// Only the record involving ns-a is streamed, with its peer left unidentified.
		got := collectFlows(stream.responses)
		require.Len(t, got, 1)
		assert.Equal(t, "ns-a->ns-b", got[0].GetId())
		assert.Equal(t, "source-pod", got[0].GetK8S().GetSourcePodName())
		assert.Empty(t, got[0].GetK8S().GetDestinationPodName())
		assert.Equal(t, flowpb.EndpointDisclosure_ENDPOINT_DISCLOSURE_FLOW, got[0].GetK8S().GetDestinationDisclosure())
	})
}

func TestGetFlows_ScopeDenied(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](64)
		t.Cleanup(func() { buf.Shutdown() })
		buf.Produce(podFlow("ns-a", "ns-b"))

		svc, _ := newAuthorizedTestService(buf)
		stream := newFakeStream(request.WithUser(t.Context(), testUserInfo))

		err := svc.GetFlows(&flowpb.GetFlowsRequest{Namespaces: []string{"ns-a"}}, stream)

		assert.Equal(t, codes.PermissionDenied, status.Code(err))
		// Nothing at all is sent to a client whose request was denied.
		assert.Empty(t, stream.responses)
	})
}

func TestGetFlows_NoAuthenticatedUser(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](64)
		t.Cleanup(func() { buf.Shutdown() })

		svc, _ := newAuthorizedTestService(buf, flowsGrant(listVerb, "ns-a"))
		stream := newFakeStream(t.Context())

		err := svc.GetFlows(&flowpb.GetFlowsRequest{Namespaces: []string{"ns-a"}}, stream)

		assert.Equal(t, codes.Unauthenticated, status.Code(err))
	})
}

func TestGetFlows_RevokedMidStream(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](64)
		t.Cleanup(func() { buf.Shutdown() })

		svc, fake := newAuthorizedTestService(buf, flowsGrant(watchVerb, "ns-a"))
		stream := newFakeStream(request.WithUser(t.Context(), testUserInfo))

		errCh := make(chan error, 1)
		go func() {
			errCh <- svc.GetFlows(&flowpb.GetFlowsRequest{Namespaces: []string{"ns-a"}, Follow: true}, stream)
		}()
		time.Sleep(2 * exporter.ConsumeDeadline)
		synctest.Wait()
		// The stream is established and stays open while the grant holds.
		select {
		case err := <-errCh:
			t.Fatalf("GetFlows returned early: %v", err)
		default:
		}

		fake.revoke(flowsGrant(watchVerb, "ns-a"))
		time.Sleep(revalidationInterval + exporter.ConsumeDeadline)
		synctest.Wait()

		select {
		case err := <-errCh:
			assert.Equal(t, codes.PermissionDenied, status.Code(err))
			assert.Contains(t, status.Convert(err).Message(), "was revoked")
		default:
			t.Fatal("GetFlows did not return after the grant was revoked")
		}
	})
}

func TestGetFlows_HandshakeAndSequenceNumbers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](64)
		t.Cleanup(func() { buf.Shutdown() })

		buf.Produce(newFlow("flow-0", &flowpb.Kubernetes{}))
		buf.Produce(newFlow("flow-1", &flowpb.Kubernetes{}))

		svc := newTestService(buf)
		stream := newFakeStream(t.Context())

		errCh := make(chan error, 1)
		go func() { errCh <- svc.GetFlows(&flowpb.GetFlowsRequest{Follow: false}, stream) }()
		time.Sleep(2 * exporter.ConsumeDeadline)
		synctest.Wait()
		require.NoError(t, <-errCh)

		require.Len(t, stream.responses, 2)
		handshake, data := stream.responses[0], stream.responses[1]

		assert.Empty(t, handshake.GetFlows())
		assert.Zero(t, handshake.GetDroppedCount())
		assert.NotEmpty(t, handshake.GetResumeToken().GetStreamEpoch())
		assert.EqualValues(t, -1, handshake.GetResumeToken().GetSequenceNumber(), "nothing accounted for before the first flow")

		assert.Equal(t, handshake.GetResumeToken().GetStreamEpoch(), data.GetResumeToken().GetStreamEpoch(), "epoch is stable across a stream's lifetime")
		require.Len(t, data.GetFlows(), 2)
		assert.EqualValues(t, 1, data.GetResumeToken().GetSequenceNumber(), "positions 0 and 1 both accounted for")
	})
}

func TestGetFlows_ResumeContinuesWithoutGap(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](64)
		t.Cleanup(func() { buf.Shutdown() })

		buf.Produce(newFlow("flow-0", &flowpb.Kubernetes{}))
		buf.Produce(newFlow("flow-1", &flowpb.Kubernetes{}))

		svc := newTestService(buf)
		first := newFakeStream(t.Context())
		errCh := make(chan error, 1)
		go func() { errCh <- svc.GetFlows(&flowpb.GetFlowsRequest{Follow: false}, first) }()
		time.Sleep(2 * exporter.ConsumeDeadline)
		synctest.Wait()
		require.NoError(t, <-errCh)

		last := first.responses[len(first.responses)-1]
		token := last.GetResumeToken()

		buf.Produce(newFlow("flow-2", &flowpb.Kubernetes{}))

		second := newFakeStream(t.Context())
		go func() {
			errCh <- svc.GetFlows(&flowpb.GetFlowsRequest{Follow: false, Resume: token}, second)
		}()
		time.Sleep(2 * exporter.ConsumeDeadline)
		synctest.Wait()
		require.NoError(t, <-errCh)

		assert.Zero(t, second.responses[0].GetDroppedCount(), "nothing fell out of the buffer between the two streams")
		assert.Equal(t, token.GetStreamEpoch(), second.responses[0].GetResumeToken().GetStreamEpoch(),
			"the epoch came back unchanged, which is how a client learns its resume was honored and that this 0 is a measurement")
		got := collectFlows(second.responses)
		require.Len(t, got, 1)
		assert.Equal(t, "flow-2", got[0].GetId(), "flow-0 and flow-1 were already seen and must not be re-sent")
	})
}

func TestGetFlows_ResumePastEvictedGapReportsExactDrop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const bufSize = 4
		buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](bufSize)
		t.Cleanup(func() { buf.Shutdown() })

		buf.Produce(newFlow("flow-0", &flowpb.Kubernetes{}))

		svc := newTestService(buf)
		first := newFakeStream(t.Context())
		errCh := make(chan error, 1)
		go func() { errCh <- svc.GetFlows(&flowpb.GetFlowsRequest{Follow: false}, first) }()
		time.Sleep(2 * exporter.ConsumeDeadline)
		synctest.Wait()
		require.NoError(t, <-errCh)

		last := first.responses[len(first.responses)-1]
		token := last.GetResumeToken()

		// Produce past flow-0 by more than a full buffer's worth, so its position (0) is gone by
		// the time the second stream reconnects: only flow-5 through flow-8 (positions 5-8) remain.
		for i := 1; i <= bufSize*2; i++ {
			buf.Produce(newFlow(fmt.Sprintf("flow-%d", i), &flowpb.Kubernetes{}))
		}

		second := newFakeStream(t.Context())
		go func() {
			errCh <- svc.GetFlows(&flowpb.GetFlowsRequest{Follow: false, Resume: token}, second)
		}()
		time.Sleep(2 * exporter.ConsumeDeadline)
		synctest.Wait()
		require.NoError(t, <-errCh)

		// Positions 1-4 are an unrecoverable gap: already unseen by the client, and now also gone
		// from the buffer. flow-0 (position 0) was already seen, so it is not part of the gap.
		//
		// The gap surfaces on the first data response rather than the handshake: the resuming
		// consumer is positioned behind the buffer at flow-0's successor, so the eviction is
		// reported as lost by its first read, the same way being lapped mid-stream would be. The
		// handshake goes out before anything is read, so its own 0 is not a measurement.
		require.Len(t, second.responses, 2)
		assert.Zero(t, second.responses[0].GetDroppedCount(), "nothing has been read at handshake time")
		assert.EqualValues(t, 4, second.responses[1].GetDroppedCount())
		assert.EqualValues(t, 8, second.responses[1].GetResumeToken().GetSequenceNumber(),
			"position 8 is the last one accounted for, by delivery")

		got := collectFlows(second.responses)
		gotIDs := make([]string, len(got))
		for i, f := range got {
			gotIDs[i] = f.GetId()
		}
		assert.ElementsMatch(t, []string{"flow-5", "flow-6", "flow-7", "flow-8"}, gotIDs)
	})
}

// TestGetFlows_HandshakeResumeTokenReflectsResumePosition covers a client that disconnects
// immediately after the handshake response of a resumed stream, before any data response: the
// handshake's own resume token is then the only one it ever sees, so it must itself carry the
// resume position forward rather than the oldest position the ring buffer still holds, which would
// go backwards whenever the client resumes from a position still in the buffer and cause the flows
// between the two to be replayed.
func TestGetFlows_HandshakeResumeTokenReflectsResumePosition(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](64)
		t.Cleanup(func() { buf.Shutdown() })

		buf.Produce(newFlow("flow-0", &flowpb.Kubernetes{}))
		buf.Produce(newFlow("flow-1", &flowpb.Kubernetes{}))
		buf.Produce(newFlow("flow-2", &flowpb.Kubernetes{}))

		svc := newTestService(buf)

		first := newFakeStream(t.Context())
		errCh := make(chan error, 1)
		go func() { errCh <- svc.GetFlows(&flowpb.GetFlowsRequest{Follow: false}, first) }()
		time.Sleep(2 * exporter.ConsumeDeadline)
		synctest.Wait()
		require.NoError(t, <-errCh)
		token := first.responses[len(first.responses)-1].GetResumeToken()
		require.EqualValues(t, 2, token.GetSequenceNumber())

		// Nothing new is produced before the second stream connects: the buffer's oldest position
		// is still 0, well behind the resume position (2).
		second := newFakeStream(t.Context())
		go func() {
			errCh <- svc.GetFlows(&flowpb.GetFlowsRequest{Follow: false, Resume: token}, second)
		}()
		time.Sleep(2 * exporter.ConsumeDeadline)
		synctest.Wait()
		require.NoError(t, <-errCh)

		handshake := second.responses[0]
		assert.Empty(t, handshake.GetFlows())
		assert.EqualValues(t, 2, handshake.GetResumeToken().GetSequenceNumber(),
			"handshake must echo the resume position, or a client resuming from it alone would replay flow-0 through flow-2")
	})
}

// TestGetFlows_ResumeDoesNotDoubleCountAlreadySeenDrops covers the window between a resuming
// consumer being created and its first read of the ring buffer (a window that includes the
// handshake Send): if the producer advances far enough in that window to evict positions the client
// already received before the resume, those positions must not also be reported as newly dropped.
//
// The consumer is positioned past everything the client has already seen, so this is structural
// rather than something the handler has to subtract back out: a drop can only ever be reported for
// a position at or after where the consumer starts.
func TestGetFlows_ResumeDoesNotDoubleCountAlreadySeenDrops(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const bufSize = 4
		buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](bufSize)
		t.Cleanup(func() { buf.Shutdown() })

		buf.Produce(newFlow("flow-0", &flowpb.Kubernetes{}))
		buf.Produce(newFlow("flow-1", &flowpb.Kubernetes{}))

		svc := newTestService(buf)
		first := newFakeStream(t.Context())
		errCh := make(chan error, 1)
		go func() { errCh <- svc.GetFlows(&flowpb.GetFlowsRequest{Follow: false}, first) }()
		time.Sleep(2 * exporter.ConsumeDeadline)
		synctest.Wait()
		require.NoError(t, <-errCh)
		token := first.responses[len(first.responses)-1].GetResumeToken()
		require.EqualValues(t, 1, token.GetSequenceNumber())

		// Simulate the race: right as the resuming stream's handshake response goes out, the
		// producer advances by a full buffer's worth, evicting flow-0 and flow-1 — exactly the
		// range this stream's client already has from the first stream — before the resuming
		// consumer gets to read anything.
		second := newFakeStream(t.Context())
		second.onSend = func(*flowpb.GetFlowsResponse) {
			second.onSend = nil // only once, on the handshake
			for i := 2; i < 2+bufSize; i++ {
				buf.Produce(newFlow(fmt.Sprintf("flow-%d", i), &flowpb.Kubernetes{}))
			}
		}
		go func() {
			errCh <- svc.GetFlows(&flowpb.GetFlowsRequest{Follow: false, Resume: token}, second)
		}()
		time.Sleep(2 * exporter.ConsumeDeadline)
		synctest.Wait()
		require.NoError(t, <-errCh)

		data := second.responses[len(second.responses)-1]
		assert.Zero(t, data.GetDroppedCount(),
			"flow-0 and flow-1 were overwritten before this consumer could read them, but the client already has them from the first stream")
		var gotIDs []string
		for _, f := range collectFlows(second.responses) {
			gotIDs = append(gotIDs, f.GetId())
		}
		assert.ElementsMatch(t, []string{"flow-2", "flow-3", "flow-4", "flow-5"}, gotIDs)
	})
}

func TestGetFlows_ResumeEpochMismatchFallsBackToFullReplay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](64)
		t.Cleanup(func() { buf.Shutdown() })

		buf.Produce(newFlow("flow-0", &flowpb.Kubernetes{}))
		buf.Produce(newFlow("flow-1", &flowpb.Kubernetes{}))

		svc := newTestService(buf)
		stream := newFakeStream(t.Context())
		req := &flowpb.GetFlowsRequest{
			Follow: false,
			Resume: &flowpb.ResumeToken{StreamEpoch: "stale-epoch-from-a-restarted-process", SequenceNumber: 1},
		}
		errCh := make(chan error, 1)
		go func() { errCh <- svc.GetFlows(req, stream) }()
		time.Sleep(2 * exporter.ConsumeDeadline)
		synctest.Wait()
		require.NoError(t, <-errCh)

		// A stale epoch is not an error and not honored: the stream replays everything, exactly as
		// if no resume token had been sent. The client learns its resume was not honored by
		// comparing the epoch it sent against the one that comes back, which is always this
		// server's own. That matters because dropped_count is 0 here and must not be read as a
		// confirmed zero: the previous epoch's buffer is gone, so there is no way to know whether
		// the client missed anything produced after its last-seen position and before the restart.
		handshake := stream.responses[0]
		assert.Equal(t, svc.streamEpoch, handshake.GetResumeToken().GetStreamEpoch())
		assert.NotEqual(t, req.GetResume().GetStreamEpoch(), handshake.GetResumeToken().GetStreamEpoch())
		assert.EqualValues(t, -1, handshake.GetResumeToken().GetSequenceNumber(),
			"a resume that was not honored reports nothing accounted for, not the position it was asked to resume from")
		assert.Zero(t, handshake.GetDroppedCount())
		got := collectFlows(stream.responses)
		require.Len(t, got, 2)
	})
}

// TestGetFlows_ResumeAheadOfCurrentPositionRejected covers the boundary the epoch check alone does
// not: a token that matches this process's epoch but names a sequence_number this server could
// never have issued (at or beyond its own current position). Unlike a Kubernetes watch resuming
// from a future ResourceVersion — which can be legitimate skew from a different apiserver replica,
// and so gets a bounded wait before failing — there is exactly one Flow Aggregator process behind
// one epoch, so a same-epoch token this far out of range can only be malformed, and is rejected
// immediately rather than waited out.
func TestGetFlows_ResumeAheadOfCurrentPositionRejected(t *testing.T) {
	buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](64)
	t.Cleanup(func() { buf.Shutdown() })

	buf.Produce(newFlow("flow-0", &flowpb.Kubernetes{})) // position 0; tip is now 1

	svc := newTestService(buf)
	stream := newFakeStream(context.Background())
	req := &flowpb.GetFlowsRequest{
		// sequence_number 1 == the tip: one past the only position ever produced, so this server
		// could never have handed this value back to a client.
		Resume: &flowpb.ResumeToken{StreamEpoch: svc.streamEpoch, SequenceNumber: 1},
	}

	err := svc.GetFlows(req, stream)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Empty(t, stream.responses, "a rejected resume token must not get even the handshake response")
}

// TestGetFlows_ResumeBelowMinimumRejected covers the lower boundary of a resume token's
// sequence_number. -1 ("nothing accounted for yet") is the smallest value a server ever issues;
// anything below that is invalid input, not just unusual. The ring buffer absorbs it safely rather
// than wrapping its own position arithmetic around (see WithReadFromSequenceNumber), so what this
// pins down is that a client holding a corrupted or fabricated token is told so, rather than served
// a stream that silently starts somewhere it did not ask for.
func TestGetFlows_ResumeBelowMinimumRejected(t *testing.T) {
	buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](64)
	t.Cleanup(func() { buf.Shutdown() })

	buf.Produce(newFlow("flow-0", &flowpb.Kubernetes{}))

	svc := newTestService(buf)
	stream := newFakeStream(context.Background())
	req := &flowpb.GetFlowsRequest{
		Resume: &flowpb.ResumeToken{StreamEpoch: svc.streamEpoch, SequenceNumber: math.MinInt64},
	}

	err := svc.GetFlows(req, stream)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Empty(t, stream.responses, "a rejected resume token must not get even the handshake response")
}

// TestGetFlows_ResumeTokenTracksRawPositionNotVisibility pins down that a resume token names a raw
// ring-buffer position, unaffected by how much of the batch authorization then withheld, rather
// than a count of what this particular client was actually sent: a flow withheld from a client
// entirely still occupies a position, and resuming from a token must account for it exactly once.
func TestGetFlows_ResumeTokenTracksRawPositionNotVisibility(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](64)
		t.Cleanup(func() { buf.Shutdown() })

		buf.Produce(podFlow("ns-a", "ns-b")) // position 0: visible under the ns-a grant below
		buf.Produce(podFlow("ns-c", "ns-d")) // position 1: withheld entirely; neither end is ns-a

		svc, _ := newAuthorizedTestService(buf, flowsGrant(listVerb, "ns-a"))
		first := newFakeStream(request.WithUser(t.Context(), testUserInfo))
		errCh := make(chan error, 1)
		go func() {
			errCh <- svc.GetFlows(&flowpb.GetFlowsRequest{Namespaces: []string{"ns-a"}}, first)
		}()
		time.Sleep(2 * exporter.ConsumeDeadline)
		synctest.Wait()
		require.NoError(t, <-errCh)

		got := collectFlows(first.responses)
		require.Len(t, got, 1, "the ns-c->ns-d flow is withheld entirely")
		assert.Equal(t, "ns-a->ns-b", got[0].GetId())
		last := first.responses[len(first.responses)-1]
		assert.EqualValues(t, 1, last.GetResumeToken().GetSequenceNumber(), "position 1 was read and withheld, and is accounted for either way")

		token := last.GetResumeToken()
		buf.Produce(podFlow("ns-a", "ns-b")) // position 2

		second := newFakeStream(request.WithUser(t.Context(), testUserInfo))
		go func() {
			errCh <- svc.GetFlows(&flowpb.GetFlowsRequest{Namespaces: []string{"ns-a"}, Resume: token}, second)
		}()
		time.Sleep(2 * exporter.ConsumeDeadline)
		synctest.Wait()
		require.NoError(t, <-errCh)

		// Resuming from position 1 must not report the withheld flow at that position as a gap, nor
		// re-deliver anything: only the new flow at position 2 is new to this client.
		assert.Zero(t, second.responses[0].GetDroppedCount())
		got2 := collectFlows(second.responses)
		require.Len(t, got2, 1)
		assert.Equal(t, "ns-a->ns-b", got2[0].GetId())
	})
}

// TestGetFlows_HandshakeTokenOverWrappedBuffer covers a client that disconnects right after the
// handshake of a stream that did not resume, over a buffer that has already wrapped: resuming from
// the handshake's token must not report the records evicted before that first stream even opened
// as dropped. The token names the position just before the oldest record held when it started.
func TestGetFlows_HandshakeTokenOverWrappedBuffer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const bufSize = 4
		buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](bufSize)
		t.Cleanup(func() { buf.Shutdown() })

		for i := range 100 {
			buf.Produce(newFlow(fmt.Sprintf("flow-%d", i), &flowpb.Kubernetes{}))
		}

		svc := newTestService(buf)
		first := newFakeStream(t.Context())
		errCh := make(chan error, 1)
		go func() { errCh <- svc.GetFlows(&flowpb.GetFlowsRequest{Follow: false}, first) }()
		time.Sleep(2 * exporter.ConsumeDeadline)
		synctest.Wait()
		require.NoError(t, <-errCh)

		token := first.responses[0].GetResumeToken()
		assert.EqualValues(t, 95, token.GetSequenceNumber(), "position 96 is the oldest record held when the stream started")

		second := newFakeStream(t.Context())
		go func() {
			errCh <- svc.GetFlows(&flowpb.GetFlowsRequest{Follow: false, Resume: token}, second)
		}()
		time.Sleep(2 * exporter.ConsumeDeadline)
		synctest.Wait()
		require.NoError(t, <-errCh)

		require.Len(t, second.responses, 2)
		assert.Zero(t, second.responses[1].GetDroppedCount(),
			"positions 0-95 were evicted before the first stream opened, and were never owed to this client")
		var gotIDs []string
		for _, f := range collectFlows(second.responses) {
			gotIDs = append(gotIDs, f.GetId())
		}
		assert.Equal(t, []string{"flow-96", "flow-97", "flow-98", "flow-99"}, gotIDs)
	})
}

// TestGetFlows_MaxCountTokenCoversOnlyExaminedRecords covers a batch cut short by max_count: the
// last token must not cover the records past the last one delivered, or a client paging through
// flows with max_count and resume would silently skip them.
func TestGetFlows_MaxCountTokenCoversOnlyExaminedRecords(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](64)
		t.Cleanup(func() { buf.Shutdown() })

		// Even positions match the filter below, odd ones do not.
		for i := range 10 {
			ns := "default"
			if i%2 == 0 {
				ns = "monitoring"
			}
			buf.Produce(newFlow(fmt.Sprintf("flow-%d", i), newPodK8S(ns, "pod", "other", "pod")))
		}
		filters := []*flowpb.FlowFilter{{
			Namespaces: []string{"monitoring"},
			Direction:  flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_FROM,
		}}

		svc := newTestService(buf)
		var gotIDs []string
		var token *flowpb.ResumeToken
		var pageTokens []int64
		errCh := make(chan error, 1)
		for range 3 {
			stream := newFakeStream(t.Context())
			req := &flowpb.GetFlowsRequest{Follow: false, MaxCount: 2, Filters: filters, Resume: token}
			go func() { errCh <- svc.GetFlows(req, stream) }()
			time.Sleep(2 * exporter.ConsumeDeadline)
			synctest.Wait()
			require.NoError(t, <-errCh)
			for _, f := range collectFlows(stream.responses) {
				gotIDs = append(gotIDs, f.GetId())
			}
			token = stream.responses[len(stream.responses)-1].GetResumeToken()
			pageTokens = append(pageTokens, token.GetSequenceNumber())
		}
		assert.Equal(t, []string{"flow-0", "flow-2", "flow-4", "flow-6", "flow-8"}, gotIDs)
		// The first two pages end at the last record they delivered (flow-2, flow-6), not at the
		// end of the batch they read; the last page is not cut short, so it covers everything.
		assert.Equal(t, []int64{2, 6, 9}, pageTokens)
	})
}

// TestGetFlows_TokenRefreshWhenEverythingFilteredOut covers a selective client whose filters remove
// every record: it must still receive a token that moves forward as the buffer does, or resuming
// from its handshake token after the buffer wrapped would report records it would have filtered
// out anyway as dropped.
func TestGetFlows_TokenRefreshWhenEverythingFilteredOut(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const bufSize = 4
		buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](bufSize)
		t.Cleanup(func() { buf.Shutdown() })

		svc := newTestService(buf)
		req := &flowpb.GetFlowsRequest{
			Follow: true,
			Filters: []*flowpb.FlowFilter{{
				Namespaces: []string{"monitoring"},
				Direction:  flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_FROM,
			}},
		}
		ctx, cancel := context.WithCancel(t.Context())
		first := newFakeStream(ctx)
		errCh := make(chan error, 1)
		go func() { errCh <- svc.GetFlows(req, first) }()
		synctest.Wait()

		for i := range 3 * bufSize {
			buf.Produce(newFlow(fmt.Sprintf("flow-%d", i), newPodK8S("default", "pod", "other", "pod")))
			time.Sleep(2 * exporter.ConsumeDeadline)
			synctest.Wait()
		}
		cancel()
		time.Sleep(2 * exporter.ConsumeDeadline)
		synctest.Wait()
		require.Error(t, <-errCh)

		assert.Empty(t, collectFlows(first.responses))
		require.Greater(t, len(first.responses), 1, "the token must be refreshed even though nothing matched")
		assert.Less(t, len(first.responses), 3*bufSize, "token-only responses must be rate-limited, not sent per batch")
		token := first.responses[len(first.responses)-1].GetResumeToken()
		assert.GreaterOrEqual(t, token.GetSequenceNumber(), int64(3*bufSize-1-bufSize/2),
			"the token lags the last position read by less than the refresh span")

		second := newFakeStream(t.Context())
		resumeReq := &flowpb.GetFlowsRequest{Follow: false, Filters: req.Filters, Resume: token}
		go func() { errCh <- svc.GetFlows(resumeReq, second) }()
		time.Sleep(2 * exporter.ConsumeDeadline)
		synctest.Wait()
		require.NoError(t, <-errCh)
		for _, r := range second.responses {
			assert.Zero(t, r.GetDroppedCount(), "the refreshed token is still in the buffer")
		}
	})
}

// TestGetFlows_NonFollowTailSendsFinalTokenWhenFilteredOut covers a non-follow, selective stream
// that reaches the tail without ever crossing tokenRefreshSpan: every record it read was filtered
// out, so the per-batch send condition never fires, and the client would otherwise be left with
// only its handshake token. The stream must still send that position once, right before closing.
func TestGetFlows_NonFollowTailSendsFinalTokenWhenFilteredOut(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const bufSize = 64
		buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](bufSize)
		t.Cleanup(func() { buf.Shutdown() })

		const produced = 20 // well under bufSize/2 (tokenRefreshSpan), so no mid-stream refresh fires
		for i := range produced {
			buf.Produce(newFlow(fmt.Sprintf("flow-%d", i), newPodK8S("default", "pod", "other", "pod")))
		}

		svc := newTestService(buf)
		stream := newFakeStream(t.Context())
		req := &flowpb.GetFlowsRequest{
			Follow: false,
			Filters: []*flowpb.FlowFilter{{
				Namespaces: []string{"monitoring"},
				Direction:  flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_FROM,
			}},
		}
		errCh := make(chan error, 1)
		go func() { errCh <- svc.GetFlows(req, stream) }()
		time.Sleep(2 * exporter.ConsumeDeadline)
		synctest.Wait()

		require.NoError(t, <-errCh)
		assert.Empty(t, collectFlows(stream.responses))
		require.Len(t, stream.responses, 2, "handshake plus one final token-only response")
		assert.EqualValues(t, produced-1, stream.responses[len(stream.responses)-1].GetResumeToken().GetSequenceNumber(),
			"the final response must report the position this stream actually reached")
	})
}

// TestGetFlows_FinalBatchDeliveredOnShutdown covers records produced right before the ring buffer
// shuts down: ConsumeMultiple hands them out together with shutdown, and they must still be sent.
func TestGetFlows_FinalBatchDeliveredOnShutdown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](64)

		svc := newTestService(buf)
		stream := newFakeStream(t.Context())
		errCh := make(chan error, 1)
		go func() { errCh <- svc.GetFlows(&flowpb.GetFlowsRequest{Follow: true}, stream) }()
		synctest.Wait()

		buf.Produce(newFlow("flow-0", &flowpb.Kubernetes{}))
		buf.Produce(newFlow("flow-1", &flowpb.Kubernetes{}))
		buf.Shutdown()
		time.Sleep(2 * exporter.ConsumeDeadline)
		synctest.Wait()
		require.NoError(t, <-errCh)

		var gotIDs []string
		for _, f := range collectFlows(stream.responses) {
			gotIDs = append(gotIDs, f.GetId())
		}
		assert.Equal(t, []string{"flow-0", "flow-1"}, gotIDs)
		assert.EqualValues(t, 1, stream.responses[len(stream.responses)-1].GetResumeToken().GetSequenceNumber())
	})
}

// TestNewFlowStreamService_MaxStreamsPerConn covers that the number of concurrent streams the server
// advertises per connection tracks the configured service-wide cap, and so stays above the
// per-client-IP cap whatever an operator sets. If it did not, a client on a single connection would
// reach the transport limit first and grpc-go would park its call in checkForStreamQuota rather than
// let the interceptor answer ResourceExhausted.
func TestNewFlowStreamService_MaxStreamsPerConn(t *testing.T) {
	buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](4)
	limits := StreamLimits{MaxStreamsPerClientIP: 3, MaxTotalStreams: 9}
	a, err := newStreamServerAuthenticator(k8sfake.NewSimpleClientset(), newTokenReviewClient(t, nil), limits)
	require.NoError(t, err)

	s, err := NewFlowStreamService(buf, a, newAuthorizer(newFakeAuthorizer()))
	require.NoError(t, err)
	assert.Equal(t, uint32(limits.MaxTotalStreams), s.maxStreamsPerConn)
	assert.Greater(t, s.maxStreamsPerConn, uint32(limits.MaxStreamsPerClientIP),
		"the advertised per-connection limit must not preempt the per-client-IP cap")

	// The test-only constructor has no authenticator to take limits from, so it falls back to the
	// shipped default rather than to grpc-go's math.MaxUint32.
	assert.Equal(t, uint32(flowaggregatorconfig.DefaultFlowStreamMaxTotalStreams),
		newFlowStreamServiceWithoutAuthentication(buf, nil).maxStreamsPerConn)
}
