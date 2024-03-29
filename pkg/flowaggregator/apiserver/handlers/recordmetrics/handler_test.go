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

package recordmetrics

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"antrea.io/antrea/pkg/flowaggregator/apis"
	"antrea.io/antrea/pkg/flowaggregator/querier"
	queriertest "antrea.io/antrea/pkg/flowaggregator/querier/testing"
)

func TestRecordMetricsQuery(t *testing.T) {
	ctrl := gomock.NewController(t)
	faq := queriertest.NewMockFlowAggregatorQuerier(ctrl)
	faq.EXPECT().GetRecordMetrics().Return(querier.Metrics{
		NumRecordsExported:     20,
		NumRecordsReceived:     15,
		NumFlows:               30,
		NumConnToCollector:     1,
		WithClickHouseExporter: true,
		WithS3Exporter:         true,
		WithLogExporter:        true,
		WithIPFIXExporter:      true,
	})

	handler := HandleFunc(faq)
	req, err := http.NewRequest(http.MethodGet, "", nil)
	assert.Nil(t, err)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code)

	var received apis.RecordMetricsResponse
	err = json.Unmarshal(recorder.Body.Bytes(), &received)
	assert.Nil(t, err)
	assert.Equal(t, apis.RecordMetricsResponse{
		NumRecordsExported:     20,
		NumRecordsReceived:     15,
		NumFlows:               30,
		NumConnToCollector:     1,
		WithClickHouseExporter: true,
		WithS3Exporter:         true,
		WithLogExporter:        true,
		WithIPFIXExporter:      true,
	}, received)

	assert.Equal(t, received.GetTableRow(0), []string{"20", "15", "30", "1", "true", "true", "true", "true"})

}
