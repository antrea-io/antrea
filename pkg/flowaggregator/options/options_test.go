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

package options

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	flowaggregatorconfig "antrea.io/antrea/v2/pkg/config/flowaggregator"
)

// TestLoadConfigFlowStreamService covers the stream concurrency limits, which are the two
// flowStreamService settings an operator can get wrong in a way the server cannot report at runtime:
// at maxStreamsPerClientIP >= maxTotalStreams, a client on a single connection reaches the number of
// concurrent streams the server advertises before the per-client-IP limit, and its own gRPC transport
// parks the call rather than surfacing the retryable ResourceExhausted the limit is there to return.
func TestLoadConfigFlowStreamService(t *testing.T) {
	tests := []struct {
		name             string
		config           string
		wantErr          string
		wantPerClientIP  int32
		wantTotalStreams int32
	}{
		{
			// Not the empty string: LoadConfig leaves opt.Config nil for an empty document, which is
			// pre-existing behavior and never what the ConfigMap contains.
			name:             "defaults applied when the service is not configured at all",
			config:           "mode: Aggregate\n",
			wantPerClientIP:  flowaggregatorconfig.DefaultFlowStreamMaxStreamsPerClientIP,
			wantTotalStreams: flowaggregatorconfig.DefaultFlowStreamMaxTotalStreams,
		},
		{
			name: "defaults applied when only enable is set",
			config: `
flowStreamService:
  enable: true
`,
			wantPerClientIP:  flowaggregatorconfig.DefaultFlowStreamMaxStreamsPerClientIP,
			wantTotalStreams: flowaggregatorconfig.DefaultFlowStreamMaxTotalStreams,
		},
		{
			name: "operator-provided limits are kept",
			config: `
flowStreamService:
  enable: true
  maxStreamsPerClientIP: 8
  maxTotalStreams: 32
`,
			wantPerClientIP:  8,
			wantTotalStreams: 32,
		},
		{
			name: "equal limits are refused",
			config: `
flowStreamService:
  enable: true
  maxStreamsPerClientIP: 64
  maxTotalStreams: 64
`,
			wantErr: "maxStreamsPerClientIP (64) must be smaller than maxTotalStreams (64)",
		},
		{
			name: "a per-client-IP limit above the total is refused",
			config: `
flowStreamService:
  enable: true
  maxStreamsPerClientIP: 300
  maxTotalStreams: 256
`,
			wantErr: "maxStreamsPerClientIP (300) must be smaller than maxTotalStreams (256)",
		},
		{
			name: "negative limits are refused",
			config: `
flowStreamService:
  enable: true
  maxStreamsPerClientIP: -1
`,
			wantErr: "maxStreamsPerClientIP cannot be negative",
		},
		{
			// The limits are only reachable when the server runs, so a stale value left behind by an
			// operator who disabled the service does not keep the Flow Aggregator from starting.
			name: "limits are not validated while the service is disabled",
			config: `
flowStreamService:
  enable: false
  maxStreamsPerClientIP: 64
  maxTotalStreams: 64
`,
			wantPerClientIP:  64,
			wantTotalStreams: 64,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opt, err := LoadConfig([]byte(tc.config))
			if tc.wantErr != "" {
				assert.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantPerClientIP, opt.Config.FlowStreamService.MaxStreamsPerClientIP)
			assert.Equal(t, tc.wantTotalStreams, opt.Config.FlowStreamService.MaxTotalStreams)
		})
	}
}
