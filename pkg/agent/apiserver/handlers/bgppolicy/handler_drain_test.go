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

package bgppolicy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"antrea.io/antrea/v2/pkg/agent/controller/bgp"
	queriertest "antrea.io/antrea/v2/pkg/querier/testing"
)

func TestBGPPolicyQueryDraining(t *testing.T) {
	tests := []struct {
		name     string
		draining bool
	}{
		{
			name:     "draining Node",
			draining: true,
		},
		{
			name:     "Node that is not draining",
			draining: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			q := queriertest.NewMockAgentBGPPolicyInfoQuerier(ctrl)
			q.EXPECT().GetBGPPolicyInfo().Return(&bgp.BGPPolicyInfo{
				BGPPolicyName: "policy-1",
				Draining:      tt.draining,
				RouterID:      "192.168.1.2",
				LocalASN:      64512,
				ListenPort:    179,
			})

			handler := HandleFunc(q)

			req, err := http.NewRequest(http.MethodGet, "", nil)
			require.NoError(t, err)

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			require.Equal(t, http.StatusOK, recorder.Code)

			if tt.draining {
				assert.Contains(t, recorder.Body.String(), `"draining":true`)
			} else {
				// The field is tagged omitempty, so the output of a Node that is not draining is unchanged.
				assert.NotContains(t, recorder.Body.String(), "draining")
			}
		})
	}
}
