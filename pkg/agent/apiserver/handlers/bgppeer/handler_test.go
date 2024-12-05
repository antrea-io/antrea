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

package bgppeer

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
	"antrea.io/antrea/pkg/agent/bgp"
	bgpcontroller "antrea.io/antrea/pkg/agent/controller/bgp"
	queriertest "antrea.io/antrea/pkg/querier/testing"
)

var (
	bgpPeerStatus = []bgp.PeerStatus{
		{
			Address:      "192.168.77.201",
			Port:         179,
			ASN:          65002,
			SessionState: bgp.SessionActive,
		},
		{
			Address:      "fec0::196:168:77:252",
			Port:         179,
			ASN:          65002,
			SessionState: bgp.SessionActive,
		},
		{
			Address:      "192.168.77.200",
			Port:         179,
			ASN:          65001,
			SessionState: bgp.SessionEstablished,
		},
		{
			Address:      "fec0::196:168:77:251",
			Port:         179,
			ASN:          65001,
			SessionState: bgp.SessionEstablished,
		},
	}
)

func TestBGPPeerQuery(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name             string
		url              string
		expectedCalls    func(mockBGPServer *queriertest.MockAgentBGPPolicyInfoQuerier)
		expectedStatus   int
		expectedResponse []apis.BGPPeerResponse
	}{
		{
			name: "get ipv4 bgp peers only",
			url:  "?ipv4-only",
			expectedCalls: func(mockBGPServer *queriertest.MockAgentBGPPolicyInfoQuerier) {
				mockBGPServer.EXPECT().GetBGPPeerStatus(ctx).Return(bgpPeerStatus, nil)
			},
			expectedStatus: http.StatusOK,
			expectedResponse: []apis.BGPPeerResponse{
				{
					Peer:  "192.168.77.200:179",
					ASN:   65001,
					State: "Established",
				},
				{
					Peer:  "192.168.77.201:179",
					ASN:   65002,
					State: "Active",
				},
			},
		},
		{
			name: "get ipv6 bgp peers only",
			url:  "?ipv6-only=",
			expectedCalls: func(mockBGPServer *queriertest.MockAgentBGPPolicyInfoQuerier) {
				mockBGPServer.EXPECT().GetBGPPeerStatus(ctx).Return(bgpPeerStatus, nil)
			},
			expectedStatus: http.StatusOK,
			expectedResponse: []apis.BGPPeerResponse{
				{
					Peer:  "[fec0::196:168:77:251]:179",
					ASN:   65001,
					State: "Established",
				},
				{
					Peer:  "[fec0::196:168:77:252]:179",
					ASN:   65002,
					State: "Active",
				},
			},
		},
		{
			name: "get all bgp peers",
			expectedCalls: func(mockBGPServer *queriertest.MockAgentBGPPolicyInfoQuerier) {
				mockBGPServer.EXPECT().GetBGPPeerStatus(ctx).Return(bgpPeerStatus, nil)
			},
			expectedStatus: http.StatusOK,
			expectedResponse: []apis.BGPPeerResponse{
				{
					Peer:  "192.168.77.200:179",
					ASN:   65001,
					State: "Established",
				},
				{
					Peer:  "192.168.77.201:179",
					ASN:   65002,
					State: "Active",
				},
				{
					Peer:  "[fec0::196:168:77:251]:179",
					ASN:   65001,
					State: "Established",
				},
				{
					Peer:  "[fec0::196:168:77:252]:179",
					ASN:   65002,
					State: "Active",
				},
			},
		},
		{
			name: "bgpPolicyState does not exist",
			expectedCalls: func(mockBGPServer *queriertest.MockAgentBGPPolicyInfoQuerier) {
				mockBGPServer.EXPECT().GetBGPPeerStatus(ctx).Return(nil, bgpcontroller.ErrBGPPolicyNotFound)
			},
			expectedStatus: http.StatusNotFound,
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
				var received []apis.BGPPeerResponse
				err = json.Unmarshal(recorder.Body.Bytes(), &received)
				require.NoError(t, err)
				assert.Equal(t, tt.expectedResponse, received)
			}
		})
	}
}
