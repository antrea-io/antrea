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

package apis

import (
	"fmt"
	"strconv"
)

// FlowRecordsResponse is the response struct of flowrecords command.
type FlowRecordsResponse map[string]interface{}

func (r FlowRecordsResponse) GetTableHeader() []string {
	return []string{"SRC_IP", "DST_IP", "SPORT", "DPORT", "PROTO", "SRC_POD", "DST_POD", "SRC_NS", "DST_NS", "SERVICE"}
}

func (r FlowRecordsResponse) GetTableRow(maxColumnLength int) []string {
	var sourceAddress, destinationAddress interface{}
	if r["sourceIPv4Address"] != nil {
		sourceAddress = r["sourceIPv4Address"]
		destinationAddress = r["destinationIPv4Address"]
	} else {
		sourceAddress = r["sourceIPv6Address"]
		destinationAddress = r["destinationIPv6Address"]
	}
	return []string{
		fmt.Sprintf("%v", sourceAddress),
		fmt.Sprintf("%v", destinationAddress),
		fmt.Sprintf("%v", r["sourceTransportPort"]),
		fmt.Sprintf("%v", r["destinationTransportPort"]),
		fmt.Sprintf("%v", r["protocolIdentifier"]),
		fmt.Sprintf("%v", r["sourcePodName"]),
		fmt.Sprintf("%v", r["destinationPodName"]),
		fmt.Sprintf("%v", r["sourcePodNamespace"]),
		fmt.Sprintf("%v", r["destinationPodNamespace"]),
		fmt.Sprintf("%v", r["destinationServicePortName"]),
	}
}

func (r FlowRecordsResponse) SortRows() bool {
	return false
}

// RecordMetricsResponse is the response struct of recordmetrics command.
type RecordMetricsResponse struct {
	NumRecordsExported     int64 `json:"numRecordsExported,omitempty"`
	NumRecordsReceived     int64 `json:"numRecordsReceived,omitempty"`
	NumFlows               int64 `json:"numFlows,omitempty"`
	NumConnToCollector     int64 `json:"numConnToCollector,omitempty"`
	WithClickHouseExporter bool  `json:"withClickHouseExporter,omitempty"`
	WithS3Exporter         bool  `json:"withS3Exporter,omitempty"`
	WithLogExporter        bool  `json:"withLogExporter,omitempty"`
	WithIPFIXExporter      bool  `json:"withIPFIXExporter,omitempty"`
}

func (r RecordMetricsResponse) GetTableHeader() []string {
	return []string{"RECORDS-EXPORTED", "RECORDS-RECEIVED", "FLOWS", "EXPORTERS-CONNECTED", "CLICKHOUSE-EXPORTER", "S3-EXPORTER", "LOG-EXPORTER", "IPFIX-EXPORTER"}
}

func (r RecordMetricsResponse) GetTableRow(maxColumnLength int) []string {
	return []string{
		strconv.Itoa(int(r.NumRecordsExported)),
		strconv.Itoa(int(r.NumRecordsReceived)),
		strconv.Itoa(int(r.NumFlows)),
		strconv.Itoa(int(r.NumConnToCollector)),
		strconv.FormatBool(r.WithClickHouseExporter),
		strconv.FormatBool(r.WithS3Exporter),
		strconv.FormatBool(r.WithLogExporter),
		strconv.FormatBool(r.WithIPFIXExporter),
	}
}

func (r RecordMetricsResponse) SortRows() bool {
	return true
}
