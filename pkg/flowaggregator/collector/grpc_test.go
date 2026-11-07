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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"

	flowpb "antrea.io/antrea/v2/pkg/apis/flow/v1alpha1"
)

// fakeExportServer is a minimal implementation of flowpb.FlowExportService_ExportServer
// that replays a fixed list of ExportRequests, used to exercise grpcService.Export
// without needing a real TLS-secured gRPC connection.
type fakeExportServer struct {
	reqs []*flowpb.ExportRequest
	idx  int
	resp *flowpb.ExportResponse
}

func (f *fakeExportServer) Recv() (*flowpb.ExportRequest, error) {
	if f.idx >= len(f.reqs) {
		return nil, io.EOF
	}
	req := f.reqs[f.idx]
	f.idx++
	return req, nil
}

func (f *fakeExportServer) SendAndClose(resp *flowpb.ExportResponse) error {
	f.resp = resp
	return nil
}

func (f *fakeExportServer) SetHeader(metadata.MD) error  { return nil }
func (f *fakeExportServer) SendHeader(metadata.MD) error { return nil }
func (f *fakeExportServer) SetTrailer(metadata.MD)       {}
func (f *fakeExportServer) Context() context.Context     { return context.Background() }
func (f *fakeExportServer) SendMsg(m any) error          { return nil }
func (f *fakeExportServer) RecvMsg(m any) error          { return nil }

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

// TestExportDropsInvalidFlowWithoutPanicking reproduces the crash reported in the
// issue: a client-supplied Flow record with a nil sub-message (e.g. Ipfix) used to
// cause grpcService.Export to panic with a nil pointer dereference at
// "record.Ipfix.ExporterIp = exportAddress", crashing the whole flow-aggregator
// process. It also covers a Flow missing each of the other sub-messages that
// downstream flow-aggregator code unconditionally dereferences.
func TestExportDropsInvalidFlowWithoutPanicking(t *testing.T) {
	validRecord := newValidFlow()

	testCases := []struct {
		name          string
		invalidRecord *flowpb.Flow
	}{
		{"nilIpfix", func() *flowpb.Flow { f := newValidFlow(); f.Ipfix = nil; return f }()},
		{"nilStartTs", func() *flowpb.Flow { f := newValidFlow(); f.StartTs = nil; return f }()},
		{"nilEndTs", func() *flowpb.Flow { f := newValidFlow(); f.EndTs = nil; return f }()},
		{"nilIp", func() *flowpb.Flow { f := newValidFlow(); f.Ip = nil; return f }()},
		{"nilTransport", func() *flowpb.Flow { f := newValidFlow(); f.Transport = nil; return f }()},
		{"nilK8S", func() *flowpb.Flow { f := newValidFlow(); f.K8S = nil; return f }()},
		{"nilStats", func() *flowpb.Flow { f := newValidFlow(); f.Stats = nil; return f }()},
		{"nilReverseStats", func() *flowpb.Flow { f := newValidFlow(); f.ReverseStats = nil; return f }()},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			recordCh := make(chan *flowpb.Flow, 2)
			service := &grpcService{recordCh: recordCh}
			stream := &fakeExportServer{reqs: []*flowpb.ExportRequest{
				{Flows: []*flowpb.Flow{tc.invalidRecord, validRecord}},
			}}

			var err error
			require.NotPanics(t, func() {
				err = service.Export(stream)
			})
			require.NoError(t, err)

			close(recordCh)
			var got []*flowpb.Flow
			for r := range recordCh {
				got = append(got, r)
			}
			// Only the valid record should have made it to recordCh; the invalid
			// one is dropped instead of crashing the process.
			require.Len(t, got, 1)
			assert.Same(t, validRecord, got[0])
			assert.EqualValues(t, 2, service.numRecordsReceived.Load())
		})
	}
}
