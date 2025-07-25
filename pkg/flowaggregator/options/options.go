// Copyright 2022 Antrea Authors
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

package options

import (
	"fmt"
	"net"
	"time"

	"k8s.io/klog/v2"

	flowaggregatorconfig "antrea.io/antrea/pkg/config/flowaggregator"
	"antrea.io/antrea/pkg/util/flowexport"
	"antrea.io/antrea/pkg/util/yaml"
)

type Options struct {
	// The configuration object
	Config *flowaggregatorconfig.FlowAggregatorConfig
	// Mode is the mode in which to run the flow aggregator (with aggregation or just as a proxy)
	AggregatorMode flowaggregatorconfig.AggregatorMode
	// Expiration timeout for active flow records in the flow aggregator
	ActiveFlowRecordTimeout time.Duration
	// Expiration timeout for inactive flow records in the flow aggregator
	InactiveFlowRecordTimeout time.Duration
	// Transport protocol over which the aggregator collects IPFIX records from all Agents
	AggregatorTransportProtocol flowaggregatorconfig.AggregatorTransportProtocol
	// IPFIX flow collector address
	ExternalFlowCollectorAddr string
	// IPFIX flow collector transport protocol
	ExternalFlowCollectorProto string
	//  Template retransmission interval when using the UDP protocol to export records.
	TemplateRefreshTimeout time.Duration
	// clickHouseCommitInterval flow records batch commit interval to clickhouse in the flow aggregator
	ClickHouseCommitInterval time.Duration
	// Flow records batch upload interval from flow aggregator to S3 bucket
	S3UploadInterval time.Duration
}

func LoadConfig(configBytes []byte) (*Options, error) {
	var opt Options
	if err := yaml.UnmarshalLenient(configBytes, &opt.Config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal FlowAggregator config from ConfigMap: %v", err)
	}
	flowaggregatorconfig.SetConfigDefaults(opt.Config)
	// Validate all the required options.
	if opt.Config.FlowCollector.Enable && opt.Config.FlowCollector.Address == "" {
		return nil, fmt.Errorf("external flow collector enabled without providing address")
	}
	if opt.Config.S3Uploader.Enable && opt.Config.S3Uploader.BucketName == "" {
		return nil, fmt.Errorf("s3Uploader enabled without specifying bucket name")
	}
	if !opt.Config.FlowCollector.Enable && !opt.Config.ClickHouse.Enable && !opt.Config.S3Uploader.Enable && !opt.Config.FlowLogger.Enable {
		klog.InfoS("No collector / sink has been configured, so no flow data will be exported")
	}
	// Validate common parameters
	if opt.Config.Mode != flowaggregatorconfig.AggregatorModeAggregate && opt.Config.Mode != flowaggregatorconfig.AggregatorModeProxy {
		return nil, fmt.Errorf("unsupported FlowAggregator mode %s", opt.Config.Mode)
	}
	opt.AggregatorMode = opt.Config.Mode
	if opt.AggregatorMode == flowaggregatorconfig.AggregatorModeProxy {
		if opt.Config.ClickHouse.Enable || opt.Config.S3Uploader.Enable || opt.Config.FlowLogger.Enable {
			return nil, fmt.Errorf("only flow collector is supported in Proxy mode")
		}
	}
	var err error
	opt.ActiveFlowRecordTimeout, err = time.ParseDuration(opt.Config.ActiveFlowRecordTimeout)
	if err != nil {
		return nil, err
	}
	opt.InactiveFlowRecordTimeout, err = time.ParseDuration(opt.Config.InactiveFlowRecordTimeout)
	if err != nil {
		return nil, err
	}
	opt.AggregatorTransportProtocol, err = flowexport.ParseTransportProtocol(opt.Config.AggregatorTransportProtocol)
	if err != nil {
		return nil, err
	}
	// Validate flow collector specific parameters
	if opt.Config.FlowCollector.Enable {
		host, port, proto, err := flowexport.ParseFlowCollectorAddr(
			opt.Config.FlowCollector.Address, flowaggregatorconfig.DefaultExternalFlowCollectorPort,
			flowaggregatorconfig.DefaultExternalFlowCollectorTransport)
		if err != nil {
			return nil, err
		}
		opt.ExternalFlowCollectorAddr = net.JoinHostPort(host, port)
		opt.ExternalFlowCollectorProto = proto

		if opt.Config.FlowCollector.RecordFormat != "IPFIX" && opt.Config.FlowCollector.RecordFormat != "JSON" {
			return nil, fmt.Errorf("record format %s is not supported", opt.Config.FlowCollector.RecordFormat)
		}

		opt.TemplateRefreshTimeout, err = time.ParseDuration(opt.Config.FlowCollector.TemplateRefreshTimeout)
		if err != nil {
			return nil, fmt.Errorf("templateRefreshTimeout is not a valid duration: %w", err)
		}
		if opt.TemplateRefreshTimeout < 0 {
			return nil, fmt.Errorf("templateRefreshTimeout cannot be a negative duration")
		}

		if opt.Config.FlowCollector.MaxIPFIXMsgSize < 0 {
			return nil, fmt.Errorf("maxIPFIXMsgSize cannot be negative")
		}
		if opt.Config.FlowCollector.MaxIPFIXMsgSize > 0 {
			if opt.Config.FlowCollector.MaxIPFIXMsgSize < flowaggregatorconfig.MinValidIPFIXMsgSize {
				return nil, fmt.Errorf("maxIPFIXMsgSize cannot be smaller than the minimum valid IPFIX mesage size %d", flowaggregatorconfig.MinValidIPFIXMsgSize)
			}
			if opt.Config.FlowCollector.MaxIPFIXMsgSize > flowaggregatorconfig.MaxValidIPFIXMsgSize {
				return nil, fmt.Errorf("maxIPFIXMsgSize cannot be greater than the maximum valid IPFIX mesage size %d", flowaggregatorconfig.MaxValidIPFIXMsgSize)
			}
		}
		if opt.Config.FlowCollector.TLS.Enable {
			if _, err := TLSVersion(opt.Config.FlowCollector.TLS.MinVersion); err != nil {
				return nil, err
			}
		}
	}
	// Validate clickhouse specific parameters
	if opt.Config.ClickHouse.Enable {
		opt.ClickHouseCommitInterval, err = time.ParseDuration(opt.Config.ClickHouse.CommitInterval)
		if err != nil {
			return nil, err
		}
		if opt.ClickHouseCommitInterval < flowaggregatorconfig.MinClickHouseCommitInterval {
			return nil, fmt.Errorf("commitInterval %s is too small: shortest supported interval is %v",
				opt.Config.ClickHouse.CommitInterval, flowaggregatorconfig.MinClickHouseCommitInterval)
		}
	}
	// Validate S3Uploader specific parameters
	if opt.Config.S3Uploader.Enable {
		if opt.Config.S3Uploader.RecordFormat != "CSV" {
			return nil, fmt.Errorf("record format %s is not supported", opt.Config.S3Uploader.RecordFormat)
		}
		opt.S3UploadInterval, err = time.ParseDuration(opt.Config.S3Uploader.UploadInterval)
		if err != nil {
			return nil, err
		}
		if opt.S3UploadInterval < flowaggregatorconfig.MinS3CommitInterval {
			return nil, fmt.Errorf("uploadInterval %s is too small: shortest supported interval is %v",
				opt.Config.S3Uploader.UploadInterval, flowaggregatorconfig.MinS3CommitInterval)
		}
	}
	// Validate FlowLogger specific parameters
	if opt.Config.FlowLogger.Enable {
		if opt.Config.FlowLogger.RecordFormat != "CSV" {
			return nil, fmt.Errorf("record format %s is not supported", opt.Config.FlowLogger.RecordFormat)
		}
	}
	return &opt, nil
}
