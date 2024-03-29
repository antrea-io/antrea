// Copyright 2022 Antrea Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package flowrecords

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vmware/go-ipfix/pkg/intermediate"
	"go.uber.org/mock/gomock"

	"antrea.io/antrea/pkg/flowaggregator/apis"
	queriertest "antrea.io/antrea/pkg/flowaggregator/querier/testing"
)

var (
	record1 = map[string]interface{}{
		"sourceIPv4Address":          "10.0.0.1",
		"destinationIPv4Address":     "10.0.0.2",
		"sourceTransportPort":        float64(8080),
		"destinationTransportPort":   float64(3700),
		"protocolIdentifier":         float64(6),
		"sourcePodName":              "test-pod-a",
		"destinationPodName":         "test-pod-b",
		"sourcePodNamespace":         "test-namespace-a",
		"destinationPodNamespace":    "test-namespace-b",
		"destinationServicePortName": "",
	}
	recordTableRows1 = []string{
		"10.0.0.1", "10.0.0.2", "8080", "3700", "6", "test-pod-a", "test-pod-b", "test-namespace-a", "test-namespace-b", "",
	}
	record2 = map[string]interface{}{
		"sourceIPv4Address":          "10.0.0.2",
		"destinationIPv4Address":     "10.0.0.1",
		"sourceTransportPort":        float64(3701),
		"destinationTransportPort":   float64(8080),
		"protocolIdentifier":         float64(6),
		"sourcePodName":              "test-pod-b",
		"destinationPodName":         "test-pod-a",
		"sourcePodNamespace":         "test-namespace-b",
		"destinationPodNamespace":    "test-namespace-a",
		"destinationServicePortName": "",
	}
	recordTableRows2 = []string{
		"10.0.0.2", "10.0.0.1", "3701", "8080", "6", "test-pod-b", "test-pod-a", "test-namespace-b", "test-namespace-a", "",
	}
	record3 = map[string]interface{}{
		"sourceIPv6Address":          "2001:ce18:4d:1c5::3ac:2d1",
		"destinationIPv6Address":     "2001:ce18:4d:1c5::3ac:2d2",
		"sourceTransportPort":        float64(8080),
		"destinationTransportPort":   float64(3700),
		"protocolIdentifier":         float64(6),
		"sourcePodName":              "test-pod-c",
		"destinationPodName":         "test-pod-d",
		"sourcePodNamespace":         "test-namespace-c",
		"destinationPodNamespace":    "test-namespace-d",
		"destinationServicePortName": "",
	}
	recordTableRows3 = []string{
		"2001:ce18:4d:1c5::3ac:2d1", "2001:ce18:4d:1c5::3ac:2d2", "8080", "3700", "6", "test-pod-c", "test-pod-d", "test-namespace-c", "test-namespace-d", "",
	}
)

type testCase struct {
	name              string
	records           []map[string]interface{}
	query             string
	flowKey           *intermediate.FlowKey
	expectedStatus    int
	expectedResponse  []apis.FlowRecordsResponse
	expectedTableRows [][]string
}

func TestGetFlowRecordsQuery(t *testing.T) {
	testCases := []testCase{
		{
			name:              "Get all records",
			records:           []map[string]interface{}{record1, record2, record3},
			query:             "",
			flowKey:           nil,
			expectedStatus:    http.StatusOK,
			expectedResponse:  []apis.FlowRecordsResponse{record1, record2, record3},
			expectedTableRows: [][]string{recordTableRows1, recordTableRows2, recordTableRows3},
		},
		{
			name:    "Get records by IP address",
			records: []map[string]interface{}{record2},
			query:   "?srcip=10.0.0.2&&dstip=10.0.0.1",
			flowKey: &intermediate.FlowKey{
				SourceAddress:      "10.0.0.2",
				DestinationAddress: "10.0.0.1",
			},
			expectedStatus:    http.StatusOK,
			expectedResponse:  []apis.FlowRecordsResponse{record2},
			expectedTableRows: [][]string{recordTableRows2},
		},
		{
			name:    "Get records by ports",
			records: []map[string]interface{}{record1, record3},
			query:   "?srcport=8080",
			flowKey: &intermediate.FlowKey{
				SourcePort: 8080,
			},
			expectedStatus:    http.StatusOK,
			expectedResponse:  []apis.FlowRecordsResponse{record1, record3},
			expectedTableRows: [][]string{recordTableRows1, recordTableRows3},
		},
		{
			name:  "Records not found",
			query: "?srcip=10.0.0.10",
			flowKey: &intermediate.FlowKey{
				SourceAddress: "10.0.0.10",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Illegal protocol",
			query:          "?proto=tcp",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "Illegal source port",
			query:          "?srcport=tcp-port",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "Illegal destination port",
			query:          "?dstport=tcp-port",
			expectedStatus: http.StatusNotFound,
		},
	}

	ctrl := gomock.NewController(t)
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			faq := queriertest.NewMockFlowAggregatorQuerier(ctrl)
			faq.EXPECT().GetFlowRecords(tc.flowKey).Return(tc.records).AnyTimes()

			handler := HandleFunc(faq)
			req, err := http.NewRequest(http.MethodGet, tc.query, nil)
			assert.Nil(t, err)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			assert.Equal(t, tc.expectedStatus, recorder.Code)

			if tc.expectedStatus == http.StatusOK {
				var received []apis.FlowRecordsResponse
				err = json.Unmarshal(recorder.Body.Bytes(), &received)
				assert.Nil(t, err)
				assert.ElementsMatch(t, tc.expectedResponse, received)
				var receivedTableRows [][]string
				for _, r := range received {
					receivedTableRows = append(receivedTableRows, r.GetTableRow(0))
				}
				assert.ElementsMatch(t, tc.expectedTableRows, receivedTableRows)
			}
		})

	}

}
