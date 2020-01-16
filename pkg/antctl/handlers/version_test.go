// Copyright 2019 Antrea Authors
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

package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	mockmonitor "github.com/vmware-tanzu/antrea/pkg/monitor/testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestVersion(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	testcases := map[string]struct {
		version               string
		expectedOutput        string
		expectedStatusCode    int
		isAgent, isController bool
	}{
		"AgentVersion": {
			version:            "v0.0.1",
			expectedOutput:     "{\"agentVersion\":\"v0.0.1\"}\n",
			expectedStatusCode: http.StatusOK,
			isAgent:            true,
		},
		"ControllerVersion": {
			version:            "v0.0.1",
			expectedOutput:     "{\"controllerVersion\":\"v0.0.1\"}\n",
			expectedStatusCode: http.StatusOK,
			isController:       true,
		},
	}
	for k, tc := range testcases {
		t.Run(k, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/", nil)
			assert.Nil(t, err)
			recorder := httptest.NewRecorder()
			if tc.isAgent {
				aq := mockmonitor.NewMockAgentQuerier(ctrl)
				aq.EXPECT().GetVersion().Return(tc.version)
				new(Version).Handler(aq, nil).ServeHTTP(recorder, req)
			} else if tc.isController {
				cq := mockmonitor.NewMockControllerQuerier(ctrl)
				cq.EXPECT().GetVersion().Return(tc.version)
				new(Version).Handler(nil, cq).ServeHTTP(recorder, req)
			}
			assert.Equal(t, tc.expectedStatusCode, recorder.Code, k)
			assert.Equal(t, tc.expectedOutput, recorder.Body.String(), k)
		})
	}
}
