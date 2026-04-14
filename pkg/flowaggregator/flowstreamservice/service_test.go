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
	"k8s.io/apimachinery/pkg/labels"

	flowpb "antrea.io/antrea/v2/pkg/apis/flow/v1alpha1"
	"antrea.io/antrea/v2/pkg/flowaggregator/ringbuffer"
)

// fakeStream implements flowpb.FlowStreamService_GetFlowsServer.
type fakeStream struct {
	ctx       context.Context
	responses []*flowpb.GetFlowsResponse
}

func newFakeStream(ctx context.Context) *fakeStream { return &fakeStream{ctx: ctx} }

func (f *fakeStream) Send(r *flowpb.GetFlowsResponse) error {
	f.responses = append(f.responses, r)
	return nil
}
func (f *fakeStream) Context() context.Context     { return f.ctx }
func (f *fakeStream) SetHeader(metadata.MD) error  { return nil }
func (f *fakeStream) SendHeader(metadata.MD) error { return nil }
func (f *fakeStream) SetTrailer(metadata.MD)       {}
func (f *fakeStream) SendMsg(any) error            { return nil }
func (f *fakeStream) RecvMsg(any) error            { return nil }

func newTestService(buf ringbuffer.BroadcastBuffer[*flowpb.Flow]) *FlowStreamService {
	svc := NewFlowStreamService(buf)
	svc.consumerDeadline = 5 * time.Millisecond
	return svc
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

func TestApplyFilter_Since(t *testing.T) {
	now := time.Now()
	since := now.Add(-30 * time.Second)

	oldFlow := newFlowEndTs("old", now.Add(-1*time.Minute), &flowpb.Kubernetes{})
	recentFlow := newFlowEndTs("recent", now.Add(-5*time.Second), &flowpb.Kubernetes{})

	got := applyFilter([]*flowpb.Flow{oldFlow, recentFlow}, nil, nil, since)
	require.Len(t, got, 1)
	assert.Equal(t, "recent", got[0].GetId())
}

func TestApplyFilter_ZeroSincePassesAll(t *testing.T) {
	flows := []*flowpb.Flow{newFlow("a", &flowpb.Kubernetes{}), newFlow("b", &flowpb.Kubernetes{})}
	got := applyFilter(flows, nil, nil, time.Time{})
	assert.Len(t, got, 2)
}

func TestApplyFilter_NilFilterPassesAll(t *testing.T) {
	flows := []*flowpb.Flow{newFlow("a", &flowpb.Kubernetes{}), newFlow("b", &flowpb.Kubernetes{})}
	got := applyFilter(flows, nil, nil, time.Time{})
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
			got := applyFilter([]*flowpb.Flow{f}, filter, nil, time.Time{})
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
			got := applyFilter([]*flowpb.Flow{f}, filter, nil, time.Time{})
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
	got := applyFilter([]*flowpb.Flow{intra, inter}, filter, nil, time.Time{})
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
			got := applyFilter([]*flowpb.Flow{f}, filter, nil, time.Time{})
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
			got := applyFilter([]*flowpb.Flow{f}, filter, nil, time.Time{})
			if tc.wantMatch {
				assert.Len(t, got, 1)
			} else {
				assert.Empty(t, got)
			}
		})
	}
}

func TestMatchFilter_LabelSelector(t *testing.T) {
	sel, err := labels.Parse("app=frontend")
	require.NoError(t, err)

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
			got := applyFilter(
				[]*flowpb.Flow{newFlow("f", tc.k8s)},
				&flowpb.FlowFilter{Direction: tc.direction},
				sel,
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
	stream := newFakeStream(context.Background())
	require.NoError(t, svc.GetFlows(&flowpb.GetFlowsRequest{Follow: false}, stream))

	got := collectFlows(stream.responses)
	gotIDs := make([]string, len(got))
	for i, f := range got {
		gotIDs[i] = f.GetId()
	}
	assert.ElementsMatch(t, wantIDs, gotIDs)
}

func TestGetFlows_MaxCount(t *testing.T) {
	buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](64)
	t.Cleanup(func() { buf.Shutdown() })

	for i := range 10 {
		buf.Produce(newFlow(fmt.Sprintf("flow-%d", i), &flowpb.Kubernetes{}))
	}

	svc := newTestService(buf)
	stream := newFakeStream(context.Background())
	req := &flowpb.GetFlowsRequest{Follow: false, MaxCount: 3}
	require.NoError(t, svc.GetFlows(req, stream))

	got := collectFlows(stream.responses)
	assert.Len(t, got, 3)
	assert.Equal(t, "flow-0", got[0].GetId())
	assert.Equal(t, "flow-1", got[1].GetId())
	assert.Equal(t, "flow-2", got[2].GetId())
}

func TestGetFlows_FilterByServiceName(t *testing.T) {
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
	stream := newFakeStream(context.Background())
	req := &flowpb.GetFlowsRequest{
		Follow: false,
		Filter: &flowpb.FlowFilter{ServiceNames: []string{"frontend"}},
	}
	require.NoError(t, svc.GetFlows(req, stream))

	got := collectFlows(stream.responses)
	assert.Len(t, got, 3)
	for _, f := range got {
		assert.Equal(t, "default/frontend:http", f.GetK8S().GetDestinationServicePortName())
	}
}

func TestGetFlows_FilterByNamespace(t *testing.T) {
	buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](64)
	t.Cleanup(func() { buf.Shutdown() })

	for i := range 4 {
		buf.Produce(newFlow(fmt.Sprintf("def-%d", i), newPodK8S("default", "pod", "other", "pod")))
	}
	for i := range 2 {
		buf.Produce(newFlow(fmt.Sprintf("mon-%d", i), newPodK8S("monitoring", "pod", "other", "pod")))
	}

	svc := newTestService(buf)
	stream := newFakeStream(context.Background())
	req := &flowpb.GetFlowsRequest{
		Follow: false,
		Filter: &flowpb.FlowFilter{
			Namespaces: []string{"monitoring"},
			Direction:  flowpb.FlowFilterDirection_FLOW_FILTER_DIRECTION_FROM,
		},
	}
	require.NoError(t, svc.GetFlows(req, stream))

	got := collectFlows(stream.responses)
	assert.Len(t, got, 2)
	for _, f := range got {
		assert.Equal(t, "monitoring", f.GetK8S().GetSourcePodNamespace())
	}
}

// TestGetFlows_FilterCombinedNamespacesAndPodNames verifies AND semantics across
// filter fields: a flow must satisfy namespaces (per direction) and pod_names
// together. Values inside each repeated field are OR-ed (see FlowFilter comment
// in service.proto).
func TestGetFlows_FilterCombinedNamespacesAndPodNames(t *testing.T) {
	buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](64)
	t.Cleanup(func() { buf.Shutdown() })

	// Matches: namespace default on source, pod name app on source.
	buf.Produce(newFlow("match-src", newPodK8S("default", "app", "kube-system", "db")))
	// Matches: namespace default on destination, pod name app on destination.
	buf.Produce(newFlow("match-dst", newPodK8S("kube-system", "x", "default", "app")))
	// Namespace matches but pod name does not.
	buf.Produce(newFlow("wrong-pod", newPodK8S("default", "nginx", "default", "nginx")))
	// Pod name matches but neither side is in default namespace.
	buf.Produce(newFlow("wrong-ns", newPodK8S("kube-system", "app", "kube-system", "app")))

	svc := newTestService(buf)
	stream := newFakeStream(context.Background())
	req := &flowpb.GetFlowsRequest{
		Follow: false,
		Filter: &flowpb.FlowFilter{
			Namespaces: []string{"default"},
			PodNames:   []string{"app"},
		},
	}
	require.NoError(t, svc.GetFlows(req, stream))

	got := collectFlows(stream.responses)
	require.Len(t, got, 2)
	gotIDs := []string{got[0].GetId(), got[1].GetId()}
	assert.ElementsMatch(t, []string{"match-src", "match-dst"}, gotIDs)
}

func TestGetFlows_SinceFilter(t *testing.T) {
	buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](64)
	t.Cleanup(func() { buf.Shutdown() })

	now := time.Now()
	since := now.Add(-30 * time.Second)

	buf.Produce(newFlowEndTs("old-1", now.Add(-2*time.Minute), &flowpb.Kubernetes{}))
	buf.Produce(newFlowEndTs("old-2", now.Add(-45*time.Second), &flowpb.Kubernetes{}))
	buf.Produce(newFlowEndTs("recent-1", now.Add(-10*time.Second), &flowpb.Kubernetes{}))
	buf.Produce(newFlowEndTs("recent-2", now.Add(-1*time.Second), &flowpb.Kubernetes{}))

	svc := newTestService(buf)
	stream := newFakeStream(context.Background())
	req := &flowpb.GetFlowsRequest{
		Follow: false,
		Since:  timestamppb.New(since),
	}
	require.NoError(t, svc.GetFlows(req, stream))

	got := collectFlows(stream.responses)
	require.Len(t, got, 2)
	gotIDs := []string{got[0].GetId(), got[1].GetId()}
	assert.ElementsMatch(t, []string{"recent-1", "recent-2"}, gotIDs)
}

func TestGetFlows_InvalidLabelSelector(t *testing.T) {
	buf := ringbuffer.NewBroadcastBuffer[*flowpb.Flow](64)
	t.Cleanup(func() { buf.Shutdown() })

	svc := newTestService(buf)
	stream := newFakeStream(context.Background())
	req := &flowpb.GetFlowsRequest{
		Filter: &flowpb.FlowFilter{PodLabelSelector: "!!!not-valid"},
	}

	err := svc.GetFlows(req, stream)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Empty(t, stream.responses)
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

		// Wait until GetFlows is blocked in the consumer (e.g. ConsumeMultiple).
		synctest.Wait()
		cancel()
		// Wait until GetFlows observes cancellation and returns.
		synctest.Wait()

		select {
		case err := <-errCh:
			st, ok := status.FromError(err)
			require.True(t, ok)
			assert.Equal(t, codes.Canceled, st.Code())
		case <-time.After(2 * time.Second):
			t.Fatal("GetFlows did not return after context cancellation")
		}
	})
}
