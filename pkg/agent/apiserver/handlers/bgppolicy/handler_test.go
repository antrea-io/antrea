// Copyright 2024 Antrea Authors
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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"antrea.io/antrea/v2/pkg/agent/apis"
	"antrea.io/antrea/v2/pkg/agent/controller/bgp"
	queriertest "antrea.io/antrea/v2/pkg/querier/testing"
)

func TestBGPPolicyQuery(t *testing.T) {
	tests := []struct {
		name             string
		expectedStatus   int
		expectedResponse *apis.BGPPolicyResponse
	}{
		{
			name:           "bgpPolicyState exists",
			expectedStatus: http.StatusOK,
			expectedResponse: &apis.BGPPolicyResponse{
				BGPPolicyName: "policy-1",
				RouterID:      "192.168.1.2",
				LocalASN:      64512,
				ListenPort:    179,
			},
		},
		{
			name:           "bgpPolicyState exists with confederation",
			expectedStatus: http.StatusOK,
			expectedResponse: &apis.BGPPolicyResponse{
				BGPPolicyName:           "policy-1",
				RouterID:                "192.168.1.2",
				LocalASN:                64512,
				ListenPort:              179,
				ConfederationIdentifier: 65000,
				MemberASNs:              []uint32{64513, 64514},
			},
		},
		{
			name:           "bgpPolicyState does not exist",
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			q := queriertest.NewMockAgentBGPPolicyInfoQuerier(ctrl)
			if tt.expectedResponse != nil {
				q.EXPECT().GetBGPPolicyInfo().Return(&bgp.BGPPolicyInfo{
					BGPPolicyName:           tt.expectedResponse.BGPPolicyName,
					RouterID:                tt.expectedResponse.RouterID,
					LocalASN:                tt.expectedResponse.LocalASN,
					ListenPort:              tt.expectedResponse.ListenPort,
					ConfederationIdentifier: tt.expectedResponse.ConfederationIdentifier,
					MemberASNs:              tt.expectedResponse.MemberASNs,
				})
			} else {
				q.EXPECT().GetBGPPolicyInfo().Return(nil)
			}

			handler := HandleFunc(q)

			req, err := http.NewRequest(http.MethodGet, "", nil)
			require.NoError(t, err)

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			assert.Equal(t, tt.expectedStatus, recorder.Code)

			if tt.expectedStatus == http.StatusOK {
				received := &apis.BGPPolicyResponse{}
				err = json.Unmarshal(recorder.Body.Bytes(), received)
				require.NoError(t, err)
				assert.Equal(t, tt.expectedResponse, received)
			}
		})
	}
}
