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

package collector

import (
	"context"
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"
	"k8s.io/apimachinery/pkg/util/sets"

	flowpb "antrea.io/antrea/v2/pkg/apis/flow/v1alpha1"
)

func newValidFlow() *flowpb.Flow {
	return &flowpb.Flow{
		Ipfix:        &flowpb.IPFIX{},
		StartTs:      timestamppb.Now(),
		EndTs:        timestamppb.Now(),
		Ip:           &flowpb.IP{},
		Transport:    &flowpb.Transport{},
		K8S:          &flowpb.Kubernetes{},
		Stats:        &flowpb.Stats{},
		ReverseStats: &flowpb.Stats{},
	}
}

func TestValidateFlow(t *testing.T) {
	tests := []struct {
		name        string
		mutate      func(f *flowpb.Flow)
		expectedErr string
	}{
		{
			name:   "valid",
			mutate: func(f *flowpb.Flow) {},
		},
		{
			name:        "missing ipfix",
			mutate:      func(f *flowpb.Flow) { f.Ipfix = nil },
			expectedErr: `missing field "ipfix"`,
		},
		{
			name:        "missing start_ts",
			mutate:      func(f *flowpb.Flow) { f.StartTs = nil },
			expectedErr: `missing field "start_ts"`,
		},
		{
			name:        "missing end_ts",
			mutate:      func(f *flowpb.Flow) { f.EndTs = nil },
			expectedErr: `missing field "end_ts"`,
		},
		{
			name:        "missing ip",
			mutate:      func(f *flowpb.Flow) { f.Ip = nil },
			expectedErr: `missing field "ip"`,
		},
		{
			name:        "missing transport",
			mutate:      func(f *flowpb.Flow) { f.Transport = nil },
			expectedErr: `missing field "transport"`,
		},
		{
			name:        "missing k8s",
			mutate:      func(f *flowpb.Flow) { f.K8S = nil },
			expectedErr: `missing field "k8s"`,
		},
		{
			name:        "missing stats",
			mutate:      func(f *flowpb.Flow) { f.Stats = nil },
			expectedErr: `missing field "stats"`,
		},
		{
			name:        "missing reverse_stats",
			mutate:      func(f *flowpb.Flow) { f.ReverseStats = nil },
			expectedErr: `missing field "reverse_stats"`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newValidFlow()
			tc.mutate(f)
			err := validateFlow(f)
			if tc.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.expectedErr)
			}
		})
	}
	t.Run("nil flow", func(t *testing.T) {
		assert.EqualError(t, validateFlow(nil), "flow is nil")
	})
	t.Run("empty flow", func(t *testing.T) {
		assert.Error(t, validateFlow(&flowpb.Flow{}))
	})
}

// optionalFlowFields are the Flow sub-messages which validateFlow does not require. See the
// validateFlow doc comment for the rule to follow when adding a sub-message to Flow.
var optionalFlowFields = sets.New("aggregation", "app")

// TestValidateFlowCoversAllSubMessages ensures that every Flow sub-message is either required by
// validateFlow or explicitly listed in optionalFlowFields, so that adding a sub-message to Flow
// requires deciding which one applies.
func TestValidateFlowCoversAllSubMessages(t *testing.T) {
	fields := (&flowpb.Flow{}).ProtoReflect().Descriptor().Fields()
	var messageFields []protoreflect.FieldDescriptor
	for i := range fields.Len() {
		if fd := fields.Get(i); fd.Kind() == protoreflect.MessageKind {
			messageFields = append(messageFields, fd)
		}
	}

	// newFullFlow returns a Flow with all its sub-messages set, so that clearing any of them,
	// including optional ones, changes the Flow.
	newFullFlow := func() *flowpb.Flow {
		f := &flowpb.Flow{}
		for _, fd := range messageFields {
			f.ProtoReflect().Mutable(fd)
		}
		return f
	}
	require.NoError(t, validateFlow(newFullFlow()))

	names := sets.New[string]()
	for _, fd := range messageFields {
		name := string(fd.Name())
		names.Insert(name)
		t.Run(name, func(t *testing.T) {
			f := newFullFlow()
			f.ProtoReflect().Clear(fd)
			if optionalFlowFields.Has(name) {
				assert.NoError(t, validateFlow(f), "Flow sub-message %q is in optionalFlowFields but is required by validateFlow", name)
			} else {
				assert.Error(t, validateFlow(f), "Flow sub-message %q must be required by validateFlow or added to optionalFlowFields", name)
			}
		})
	}
	assert.Empty(t, sets.List(optionalFlowFields.Difference(names)), "optionalFlowFields contains names which are not Flow sub-messages")
}

// fakeExportStream is a flowpb.FlowExportService_ExportServer which returns the configured
// requests from Recv, then io.EOF.
type fakeExportStream struct {
	grpc.ServerStream
	ctx      context.Context
	requests []*flowpb.ExportRequest
	closed   bool
}

func (s *fakeExportStream) Context() context.Context {
	return s.ctx
}

func (s *fakeExportStream) Recv() (*flowpb.ExportRequest, error) {
	if len(s.requests) == 0 {
		return nil, io.EOF
	}
	req := s.requests[0]
	s.requests = s.requests[1:]
	return req, nil
}

func (s *fakeExportStream) SendAndClose(*flowpb.ExportResponse) error {
	s.closed = true
	return nil
}

func TestGRPCServiceExport(t *testing.T) {
	const exporterIP = "10.10.0.1"
	peerCtx := peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP(exporterIP), Port: 43210},
	})

	flowWithout := func(mutate func(f *flowpb.Flow)) *flowpb.Flow {
		f := newValidFlow()
		mutate(f)
		return f
	}

	tests := []struct {
		name string
		// each element is the content of one ExportRequest
		requests            [][]*flowpb.Flow
		expectedCode        codes.Code
		expectedForwarded   int
		expectedStreamClose bool
	}{
		{
			name:                "valid records",
			requests:            [][]*flowpb.Flow{{newValidFlow(), newValidFlow()}, {newValidFlow()}},
			expectedCode:        codes.OK,
			expectedForwarded:   3,
			expectedStreamClose: true,
		},
		{
			name:         "missing ipfix",
			requests:     [][]*flowpb.Flow{{flowWithout(func(f *flowpb.Flow) { f.Ipfix = nil })}},
			expectedCode: codes.InvalidArgument,
		},
		{
			name:         "missing ip",
			requests:     [][]*flowpb.Flow{{flowWithout(func(f *flowpb.Flow) { f.Ip = nil })}},
			expectedCode: codes.InvalidArgument,
		},
		{
			name:         "empty flow",
			requests:     [][]*flowpb.Flow{{{}}},
			expectedCode: codes.InvalidArgument,
		},
		{
			// A request is rejected as a unit: none of its records are forwarded.
			name: "invalid record after valid record in same request",
			requests: [][]*flowpb.Flow{{
				newValidFlow(),
				flowWithout(func(f *flowpb.Flow) { f.K8S = nil }),
			}},
			expectedCode: codes.InvalidArgument,
		},
		{
			// Records from earlier valid requests were already forwarded.
			name: "invalid request after valid request",
			requests: [][]*flowpb.Flow{
				{newValidFlow()},
				{flowWithout(func(f *flowpb.Flow) { f.Stats = nil })},
			},
			expectedCode:      codes.InvalidArgument,
			expectedForwarded: 1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			recordCh := make(chan *flowpb.Flow, 16)
			service := &grpcService{recordCh: recordCh}
			stream := &fakeExportStream{ctx: peerCtx}
			for _, flows := range tc.requests {
				stream.requests = append(stream.requests, &flowpb.ExportRequest{Flows: flows})
			}

			// Export must never panic, whatever the content of the records.
			var err error
			require.NotPanics(t, func() { err = service.Export(stream) })

			assert.Equal(t, tc.expectedCode, status.Code(err))
			assert.Equal(t, tc.expectedStreamClose, stream.closed)
			require.Len(t, recordCh, tc.expectedForwarded)
			assert.EqualValues(t, tc.expectedForwarded, service.numRecordsReceived.Load())
			assert.EqualValues(t, 0, service.numConns.Load())
			for range tc.expectedForwarded {
				assert.Equal(t, exporterIP, (<-recordCh).Ipfix.ExporterIp)
			}
		})
	}
}
