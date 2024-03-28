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

	"antrea.io/antrea/pkg/flowaggregator/apis"
	"antrea.io/antrea/pkg/flowaggregator/querier"
)

// HandleFunc returns the function which can handle the /recordmetrics API request.
func HandleFunc(faq querier.FlowAggregatorQuerier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		metrics := faq.GetRecordMetrics()
		metricsResponse := apis.RecordMetricsResponse{
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
