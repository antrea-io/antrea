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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	monitor "github.com/vmware-tanzu/antrea/pkg/monitor/testing"
)

func TestFlowTableQuery(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	testTables := map[string]int32{
		"10": 10,
		"20": 20,
	}

	testcases := map[string]struct {
		query           string
		expectedStatus  int
		expectedContent FlowTableResponse
	}{
		"hit table query": {
			query:           "?tableID=10",
			expectedStatus:  http.StatusOK,
			expectedContent: FlowTableResponse{TableID: "10", FlowCount: 10},
		},
		"miss table query": {
			query:           "?tableID=30",
			expectedStatus:  http.StatusNotFound,
			expectedContent: FlowTableResponse{},
		},
		"multiple table query key": {
			query:           "?tableID=30&tableID=10",
			expectedStatus:  http.StatusBadRequest,
			expectedContent: FlowTableResponse{},
		},
		"empty table query": {
			query:           "?tableID=",
			expectedStatus:  http.StatusBadRequest,
			expectedContent: FlowTableResponse{},
		},
	}

	for k, tc := range testcases {
		q := monitor.NewMockAgentQuerier(ctrl)
		q.EXPECT().GetOVSFlowTable().Return(testTables).AnyTimes()
		s := new(FlowTable)
		recorder := httptest.NewRecorder()
		req, err := http.NewRequest(http.MethodGet, tc.query, nil)
		assert.Nil(t, err)
		handler := s.Handler(q, nil)
		handler.ServeHTTP(recorder, req)
		assert.Equal(t, tc.expectedStatus, recorder.Code, k)

		if tc.expectedStatus == http.StatusOK {
			var received FlowTableResponse
			err = json.Unmarshal(recorder.Body.Bytes(), &received)
			assert.Nil(t, err)
			assert.Equal(t, tc.expectedContent, received)
		}
	}

}

func TestFlowTableList(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	testcases := map[string]struct {
		testTables      map[string]int32
		expectedStatus  int
		expectedContent []FlowTableResponse
	}{
		"flow table list": {
			testTables: map[string]int32{
				"10": 10,
				"20": 20,
			},
			expectedStatus: http.StatusOK,
			expectedContent: []FlowTableResponse{
				{TableID: "10", FlowCount: 10},
				{TableID: "20", FlowCount: 20},
			},
		},
		"empty table list": {
			testTables:      map[string]int32{},
			expectedStatus:  http.StatusOK,
			expectedContent: []FlowTableResponse{},
		},
		"nil table list": {
			testTables:      nil,
			expectedStatus:  http.StatusOK,
			expectedContent: []FlowTableResponse{},
		},
	}

	for k, tc := range testcases {
		q := monitor.NewMockAgentQuerier(ctrl)
		q.EXPECT().GetOVSFlowTable().Return(tc.testTables).AnyTimes()
		s := new(FlowTable)
		recorder := httptest.NewRecorder()
		req, err := http.NewRequest(http.MethodGet, "", nil)
		assert.Nil(t, err)
		handler := s.Handler(q, nil)
		handler.ServeHTTP(recorder, req)
		assert.Equal(t, tc.expectedStatus, recorder.Code, k)

		if tc.expectedStatus == http.StatusOK {
			var received []FlowTableResponse
			err = json.Unmarshal(recorder.Body.Bytes(), &received)
			assert.Nil(t, err)

			for _, flowTable := range tc.expectedContent {
				assert.Contains(t, received, flowTable)
			}
		}
	}
}
