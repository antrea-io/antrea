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

package bgproute

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"antrea.io/antrea/pkg/agent/apis"
	"antrea.io/antrea/pkg/agent/controller/bgp"
	queriertest "antrea.io/antrea/pkg/querier/testing"
)

func TestBGPRouteQuery(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name             string
		url              string
		expectedCalls    func(mockBGPServer *queriertest.MockAgentBGPPolicyInfoQuerier)
		expectedStatus   int
		expectedResponse []apis.BGPRouteResponse
	}{
		{
			name: "bgpPolicyState does not exist",
			expectedCalls: func(mockBGPServer *queriertest.MockAgentBGPPolicyInfoQuerier) {
				mockBGPServer.EXPECT().GetBGPRoutes(context.Background(), true, true).Return(nil, bgp.ErrBGPPolicyNotFound)
			},
			expectedStatus: http.StatusNotFound,
		},
		{
			name: "get all advertised routes",
			expectedCalls: func(mockBGPServer *queriertest.MockAgentBGPPolicyInfoQuerier) {
				mockBGPServer.EXPECT().GetBGPRoutes(ctx, true, true).Return(
					[]string{"192.168.1.0/24", "192.168.2.0/24", "fec0::10:96:10:10/128"}, nil)
			},
			expectedStatus: http.StatusOK,
			expectedResponse: []apis.BGPRouteResponse{
				{
					Route: "192.168.1.0/24",
				},
				{
					Route: "192.168.2.0/24",
				},
				{
					Route: "fec0::10:96:10:10/128",
				},
			},
		},
		{
			name: "get advertised ipv4 routes only",
			url:  "?ipv4-only",
			expectedCalls: func(mockBGPServer *queriertest.MockAgentBGPPolicyInfoQuerier) {
				mockBGPServer.EXPECT().GetBGPRoutes(ctx, true, false).Return(
					[]string{"192.168.1.0/24", "192.168.2.0/24"}, nil)
			},
			expectedStatus: http.StatusOK,
			expectedResponse: []apis.BGPRouteResponse{
				{
					Route: "192.168.1.0/24",
				},
				{
					Route: "192.168.2.0/24",
				},
			},
		},
		{
			name: "get advertised ipv6 routes only",
			url:  "?ipv6-only=",
			expectedCalls: func(mockBGPServer *queriertest.MockAgentBGPPolicyInfoQuerier) {
				mockBGPServer.EXPECT().GetBGPRoutes(ctx, false, true).Return(
					[]string{"fec0::192:168:77:150/128", "fec0::10:10:0:10/128"}, nil)
			},
			expectedStatus: http.StatusOK,
			expectedResponse: []apis.BGPRouteResponse{
				{
					Route: "fec0::192:168:77:150/128",
				},
				{
					Route: "fec0::10:10:0:10/128",
				},
			},
		},
		{
			name:           "flag with value",
			url:            "?ipv4-only=true",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "both flags are passed",
			url:            "?ipv4-only&ipv6-only",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			q := queriertest.NewMockAgentBGPPolicyInfoQuerier(ctrl)
			if tt.expectedCalls != nil {
				tt.expectedCalls(q)
			}
			handler := HandleFunc(q)

			req, err := http.NewRequest(http.MethodGet, tt.url, nil)
			require.NoError(t, err)

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			assert.Equal(t, tt.expectedStatus, recorder.Code)

			if tt.expectedStatus == http.StatusOK {
				var received []apis.BGPRouteResponse
				err = json.Unmarshal(recorder.Body.Bytes(), &received)
				require.NoError(t, err)
				assert.Equal(t, tt.expectedResponse, received)
			}
		})
	}
}
