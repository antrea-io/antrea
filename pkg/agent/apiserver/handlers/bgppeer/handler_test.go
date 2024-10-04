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

func TestBGPPeerQuery(t *testing.T) {
	tests := []struct {
		name              string
		fakeBGPPeerStatus []bgp.PeerStatus
		expectedStatus    int
		expectedResponse  []apis.BGPPeerResponse
		fakeErr           error
	}{
		{
			name: "bgpPolicyState exists",
			fakeBGPPeerStatus: []bgp.PeerStatus{
				{
					Address:      "192.168.77.200",
					Port:         179,
					ASN:          65001,
					SessionState: bgp.SessionEstablished,
				},
				{
					Address:      "192.168.77.201",
					Port:         179,
					ASN:          65002,
					SessionState: bgp.SessionActive,
				},
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
			name:              "bgpPolicyState does not exist",
			fakeBGPPeerStatus: nil,
			expectedStatus:    http.StatusNotFound,
			fakeErr:           bgpcontroller.ErrBGPPolicyNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			q := queriertest.NewMockAgentBGPPolicyInfoQuerier(ctrl)
			q.EXPECT().GetBGPPeerStatus(context.Background()).Return(tt.fakeBGPPeerStatus, tt.fakeErr)
			handler := HandleFunc(q)

			req, err := http.NewRequest(http.MethodGet, "", nil)
			require.NoError(t, err)

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			assert.Equal(t, tt.expectedStatus, recorder.Code)

			if tt.expectedStatus == http.StatusOK {
				var received []apis.BGPPeerResponse
				err = json.Unmarshal(recorder.Body.Bytes(), &received)
				require.NoError(t, err)
				assert.ElementsMatch(t, tt.expectedResponse, received)
			}
		})
	}
}
