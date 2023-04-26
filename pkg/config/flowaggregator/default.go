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

package flowaggregator

import (
	"os"
	"path/filepath"
	"time"

	"antrea.io/antrea/pkg/apis"
)

const (
	DefaultExternalFlowCollectorTransport = "tcp"
	DefaultExternalFlowCollectorPort      = "4739"
	DefaultActiveFlowRecordTimeout        = "60s"
	DefaultInactiveFlowRecordTimeout      = "90s"
	DefaultAggregatorTransportProtocol    = "TLS"
	DefaultRecordFormat                   = "IPFIX"

	DefaultClickHouseDatabase       = "default"
	DefaultClickHouseCommitInterval = "8s"
	MinClickHouseCommitInterval     = 1 * time.Second
	DefaultClickHouseDatabaseUrl    = "tcp://clickhouse-clickhouse.flow-visibility.svc:9000"

	DefaultS3Region            = "us-west-2"
	DefaultS3RecordFormat      = "CSV"
	DefaultS3MaxRecordsPerFile = 1000000
	DefaultS3UploadInterval    = "60s"
	MinS3CommitInterval        = 1 * time.Second

	DefaultLoggerMaxSize      = 100
	DefaultLoggerMaxBackups   = 3
	DefaultLoggerRecordFormat = "CSV"
)

func SetConfigDefaults(flowAggregatorConf *FlowAggregatorConfig) {
	if flowAggregatorConf.ActiveFlowRecordTimeout == "" {
		flowAggregatorConf.ActiveFlowRecordTimeout = DefaultActiveFlowRecordTimeout
	}
	if flowAggregatorConf.InactiveFlowRecordTimeout == "" {
		flowAggregatorConf.InactiveFlowRecordTimeout = DefaultInactiveFlowRecordTimeout
	}
	if flowAggregatorConf.AggregatorTransportProtocol == "" {
		flowAggregatorConf.AggregatorTransportProtocol = DefaultAggregatorTransportProtocol
	}
	if flowAggregatorConf.APIServer.APIPort == 0 {
		flowAggregatorConf.APIServer.APIPort = apis.FlowAggregatorAPIPort
	}
	if flowAggregatorConf.FlowCollector.RecordFormat == "" {
		flowAggregatorConf.FlowCollector.RecordFormat = DefaultRecordFormat
	}
	if flowAggregatorConf.ClickHouse.Database == "" {
		flowAggregatorConf.ClickHouse.Database = DefaultClickHouseDatabase
	}
	if flowAggregatorConf.ClickHouse.DatabaseURL == "" {
		flowAggregatorConf.ClickHouse.DatabaseURL = DefaultClickHouseDatabaseUrl
	}
	if flowAggregatorConf.ClickHouse.Compress == nil {
		flowAggregatorConf.ClickHouse.Compress = new(bool)
		*flowAggregatorConf.ClickHouse.Compress = true
	}
	if flowAggregatorConf.ClickHouse.CommitInterval == "" {
		flowAggregatorConf.ClickHouse.CommitInterval = DefaultClickHouseCommitInterval
	}
	if flowAggregatorConf.S3Uploader.Compress == nil {
		flowAggregatorConf.S3Uploader.Compress = new(bool)
		*flowAggregatorConf.S3Uploader.Compress = true
	}
	if flowAggregatorConf.S3Uploader.MaxRecordsPerFile == 0 {
		flowAggregatorConf.S3Uploader.MaxRecordsPerFile = DefaultS3MaxRecordsPerFile
	}
	if flowAggregatorConf.S3Uploader.RecordFormat == "" {
		flowAggregatorConf.S3Uploader.RecordFormat = DefaultS3RecordFormat
	}
	if flowAggregatorConf.S3Uploader.UploadInterval == "" {
		flowAggregatorConf.S3Uploader.UploadInterval = DefaultS3UploadInterval
	}
	if flowAggregatorConf.FlowLogger.Path == "" {
		flowAggregatorConf.FlowLogger.Path = filepath.Join(os.TempDir(), "antrea-flows.log")
	}
	if flowAggregatorConf.FlowLogger.MaxSize == 0 {
		flowAggregatorConf.FlowLogger.MaxSize = DefaultLoggerMaxSize
	}
	if flowAggregatorConf.FlowLogger.MaxBackups == 0 {
		flowAggregatorConf.FlowLogger.MaxBackups = DefaultLoggerMaxBackups
	}
	if flowAggregatorConf.FlowLogger.Compress == nil {
		flowAggregatorConf.FlowLogger.Compress = new(bool)
		*flowAggregatorConf.FlowLogger.Compress = true
	}
	if flowAggregatorConf.FlowLogger.RecordFormat == "" {
		flowAggregatorConf.FlowLogger.RecordFormat = DefaultLoggerRecordFormat
	}
	if flowAggregatorConf.FlowLogger.PrettyPrint == nil {
		flowAggregatorConf.FlowLogger.PrettyPrint = new(bool)
		*flowAggregatorConf.FlowLogger.PrettyPrint = true
	}
}
