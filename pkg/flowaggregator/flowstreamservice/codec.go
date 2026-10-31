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
	"google.golang.org/grpc/encoding"
	grpcproto "google.golang.org/grpc/encoding/proto"
	"google.golang.org/grpc/mem"
	"google.golang.org/protobuf/proto"

	flowpb "antrea.io/antrea/v2/pkg/apis/flow/v1alpha1"
)

// flowStreamCodec reuses the flow sizes computed by selectRecords instead of walking every
// flow again in gRPC's standard proto codec. It is installed only on this service's server.
// Requests and other message types use the standard codec.
type flowStreamCodec struct {
	encoding.CodecV2
}

func newFlowStreamCodec() *flowStreamCodec {
	return &flowStreamCodec{CodecV2: encoding.GetCodecV2(grpcproto.Name)}
}

func (c *flowStreamCodec) Marshal(v any) (mem.BufferSlice, error) {
	response, ok := v.(*flowpb.GetFlowsResponse)
	if !ok {
		return c.CodecV2.Marshal(v)
	}

	// GetFlows constructs a fresh response for each Send. Its flows were sized by selectRecords
	// after redaction, and neither those flows nor their shared sub-messages may change before
	// serialization completes. Ring-buffer records are immutable, and redaction creates fresh
	// messages. Size therefore computes the new envelope while reusing the per-flow caches.
	// Reusing a response after modifying it, or changing a selected flow, would invalidate those
	// caches and could corrupt the encoded message. Metadata-only responses have no flow caches.
	options := proto.MarshalOptions{UseCachedSize: true}
	size := options.Size(response)
	if mem.IsBelowBufferPoolingThreshold(size) {
		data, err := options.Marshal(response)
		if err != nil {
			return nil, err
		}
		return mem.BufferSlice{mem.SliceBuffer(data)}, nil
	}

	// Match the standard codec's pooling so large responses do not allocate a new buffer for
	// every Send. The returned BufferSlice owns the buffer until gRPC releases it.
	pool := mem.DefaultBufferPool()
	buf := pool.Get(size)
	data, err := options.MarshalAppend((*buf)[:0], response)
	if err != nil {
		pool.Put(buf)
		return nil, err
	}
	*buf = data
	return mem.BufferSlice{mem.NewBuffer(buf, pool)}, nil
}
