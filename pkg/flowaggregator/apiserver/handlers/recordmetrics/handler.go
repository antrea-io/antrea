// Copyright 2020 Antrea Authors
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

package recordmetrics

import (
	"encoding/json"
	"net/http"

	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/antctl/transform/common"
	"antrea.io/antrea/pkg/flowaggregator/querier"
)

// Response is the response struct of recordmetrics command.
type Response struct {
	NumRecordsExported     int64 `json:"numRecordsExported,omitempty"`
	NumRecordsReceived     int64 `json:"numRecordsReceived,omitempty"`
	NumFlows               int64 `json:"numFlows,omitempty"`
	NumConnToCollector     int64 `json:"numConnToCollector,omitempty"`
	WithClickHouseExporter bool  `json:"withClickHouseExporter,omitempty"`
	WithS3Exporter         bool  `json:"withS3Exporter,omitempty"`
	WithLogExporter        bool  `json:"withLogExporter,omitempty"`
	WithIPFIXExporter      bool  `json:"withIPFIXExporter,omitempty"`
}

// HandleFunc returns the function which can handle the /recordmetrics API request.
func HandleFunc(faq querier.FlowAggregatorQuerier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		metrics := faq.GetRecordMetrics()
		metricsResponse := Response{
			NumRecordsExported:     metrics.NumRecordsExported,
			NumRecordsReceived:     metrics.NumRecordsReceived,
			NumFlows:               metrics.NumFlows,
			NumConnToCollector:     metrics.NumConnToCollector,
			WithClickHouseExporter: metrics.WithClickHouseExporter,
			WithS3Exporter:         metrics.WithS3Exporter,
			WithLogExporter:        metrics.WithLogExporter,
			WithIPFIXExporter:      metrics.WithIPFIXExporter,
		}
		err := json.NewEncoder(w).Encode(metricsResponse)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			klog.Errorf("Error when encoding record metrics to json: %v", err)
		}
	}
}

func (r Response) GetTableHeader() []string {
	return []string{"RECORDS-EXPORTED", "RECORDS-RECEIVED", "FLOWS", "EXPORTERS-CONNECTED", "CLICKHOUSE-EXPORTER", "S3-EXPORTER", "LOG-EXPORTER", "IPFIX-EXPORTER"}
}

func (r Response) GetTableRow(maxColumnLength int) []string {
	return []string{
		common.Int64ToString(r.NumRecordsExported),
		common.Int64ToString(r.NumRecordsReceived),
		common.Int64ToString(r.NumFlows),
		common.Int64ToString(r.NumConnToCollector),
		common.BoolToString(r.WithClickHouseExporter),
		common.BoolToString(r.WithS3Exporter),
		common.BoolToString(r.WithLogExporter),
		common.BoolToString(r.WithIPFIXExporter),
	}
}

func (r Response) SortRows() bool {
	return true
}
