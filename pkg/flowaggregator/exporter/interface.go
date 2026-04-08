// Copyright 2022 Antrea Authors
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

package exporter

import (
	"context"
	"time"

	flowpb "antrea.io/antrea/v2/pkg/apis/flow/v1alpha1"
	"antrea.io/antrea/v2/pkg/flowaggregator/ringbuffer"
)

const (
	// consumeDeadline is the maximum time ConsumeMultiple will block before
	// returning with n==0, giving the Run loop a chance to check ctx
	// cancellation. Keeping this at 1s bounds shutdown latency for all
	// exporters regardless of their internal commit/upload intervals.
	consumeDeadline = 1 * time.Second

	// consumeMultipleBatchSize is the maximum number of records fetched in a
	// single ConsumeMultiple call. The slice is pre-allocated and reused.
	consumeMultipleBatchSize = 100
)

// Runner is the interface that all supported exporters must implement.
// Run blocks, consuming records from the ring buffer until ctx is cancelled
// or the buffer signals shutdown. The exporter is responsible for creating
// its own consumer from the buffer. All resource setup happens at the start
// of Run; all teardown (flush, close) happens before Run returns.
type Runner interface {
	Run(ctx context.Context, buf ringbuffer.BroadcastBuffer[*flowpb.Flow])
}
