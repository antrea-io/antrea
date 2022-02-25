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

package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"time"

	"github.com/spf13/pflag"
	"gopkg.in/yaml.v2"

	"antrea.io/antrea/pkg/apis"
	flowaggregatorconfig "antrea.io/antrea/pkg/config/flowaggregator"
	"antrea.io/antrea/pkg/flowaggregator"
	"antrea.io/antrea/pkg/util/flowexport"
)

const (
	defaultExternalFlowCollectorTransport = "tcp"
	defaultExternalFlowCollectorPort      = "4739"
	defaultActiveFlowRecordTimeout        = "60s"
	defaultInactiveFlowRecordTimeout      = "90s"
	defaultAggregatorTransportProtocol    = "TLS"
	defaultFlowAggregatorAddress          = "flow-aggregator.flow-aggregator.svc"
	defaultRecordFormat                   = "IPFIX"
	defaultClickHouseDatabase             = "default"
	defaultClickHouseCommitInterval       = "8s"
	minClickHouseCommitInterval           = 1 * time.Second
	defaultClickHouseDatabaseUrl          = "tcp://clickhouse-clickhouse.flow-visibility.svc:9000"
)

type Options struct {
	// The path of configuration file.
	configFile string
	// The configuration object
	config *flowaggregatorconfig.FlowAggregatorConfig
	// Expiration timeout for active flow records in the flow aggregator
	activeFlowRecordTimeout time.Duration
	// Expiration timeout for inactive flow records in the flow aggregator
	inactiveFlowRecordTimeout time.Duration
	// Transport protocol over which the aggregator collects IPFIX records from all Agents
	aggregatorTransportProtocol flowaggregator.AggregatorTransportProtocol
	// DNS name or IP address of flow aggregator for generating TLS certificate
	flowAggregatorAddress string
	// includePodLabels indicates whether source and destination Pod labels are included or not
	includePodLabels bool
	// IPFIX flow collector address
	externalFlowCollectorAddr string
	// IPFIX flow collector transport protocol
	externalFlowCollectorProto string
	// Format for record sent to the configured flow collector
	format string
	// clickHouseCommitInterval flow records batch commit interval to clickhouse in the flow aggregator
	clickHouseCommitInterval time.Duration
}

func newOptions() *Options {
	return &Options{
		config: &flowaggregatorconfig.FlowAggregatorConfig{},
	}
}

// addFlags adds flags to fs and binds them to options.
func (o *Options) addFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.configFile, "config", o.configFile, "The path to the configuration file")
}

// complete completes all the required options.
func (o *Options) complete(args []string) error {
	if len(o.configFile) > 0 {
		c, err := o.loadConfigFromFile(o.configFile)
		if err != nil {
			return err
		}
		o.config = c
		o.setDefaults()
	}
	return nil
}

// validate validates all the required options.
func (o *Options) validate(args []string) error {
	var err error
	if len(args) != 0 {
		return errors.New("no positional arguments are supported")
	}
	if o.config.FlowCollector.Enable && o.config.FlowCollector.Address == "" {
		return fmt.Errorf("external flow collector enabled without providing address")
	}
	if !o.isFlowCollectorSet() && !o.isClickHouseSet() {
		return fmt.Errorf("external flow collector or ClickHouse should be configured")
	}

	// Validate common parameters
	o.activeFlowRecordTimeout, err = time.ParseDuration(o.config.ActiveFlowRecordTimeout)
	if err != nil {
		return err
	}
	o.inactiveFlowRecordTimeout, err = time.ParseDuration(o.config.ActiveFlowRecordTimeout)
	if err != nil {
		return err
	}
	transportProtocol, err := flowexport.ParseTransportProtocol(o.config.AggregatorTransportProtocol)
	if err != nil {
		return err
	}
	o.aggregatorTransportProtocol = transportProtocol
	o.flowAggregatorAddress = o.config.FlowAggregatorAddress
	o.includePodLabels = o.config.RecordContents.PodLabels

	// Validate flow collector specific parameters
	if o.isFlowCollectorSet() {
		host, port, proto, err := flowexport.ParseFlowCollectorAddr(
			o.config.FlowCollector.Address, defaultExternalFlowCollectorPort,
			defaultExternalFlowCollectorTransport)
		if err != nil {
			return err
		}
		o.externalFlowCollectorAddr = net.JoinHostPort(host, port)
		o.externalFlowCollectorProto = proto

		if o.config.FlowCollector.RecordFormat != "IPFIX" &&
			o.config.FlowCollector.RecordFormat != "JSON" {
			return fmt.Errorf("record format %s is not supported", o.config.FlowCollector.RecordFormat)
		} else {
			o.format = o.config.FlowCollector.RecordFormat
		}
	}

	// Validate clickhouse specific parameters
	if o.isClickHouseSet() {
		o.clickHouseCommitInterval, err = time.ParseDuration(o.config.ClickHouse.CommitInterval)
		if err != nil {
			return err
		}
		if o.clickHouseCommitInterval < minClickHouseCommitInterval {
			return fmt.Errorf("commitInterval %s is too small: shortest supported interval is %s",
				o.config.ClickHouse.CommitInterval, minClickHouseCommitInterval)
		}
	}
	return nil
}

func (o *Options) loadConfigFromFile(file string) (*flowaggregatorconfig.FlowAggregatorConfig, error) {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	c := flowaggregatorconfig.FlowAggregatorConfig{}
	err = yaml.UnmarshalStrict(data, &c)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (o *Options) isFlowCollectorSet() bool {
	return o.config.FlowCollector.Enable && len(o.config.FlowCollector.Address) > 0
}

func (o *Options) isClickHouseSet() bool {
	return o.config.ClickHouse.Enable
}

func (o *Options) setDefaults() {
	if o.config.ActiveFlowRecordTimeout == "" {
		o.config.ActiveFlowRecordTimeout = defaultActiveFlowRecordTimeout
	}
	if o.config.InactiveFlowRecordTimeout == "" {
		o.config.InactiveFlowRecordTimeout = defaultInactiveFlowRecordTimeout
	}
	if o.config.AggregatorTransportProtocol == "" {
		o.config.AggregatorTransportProtocol = defaultAggregatorTransportProtocol
	}
	if o.config.FlowAggregatorAddress == "" {
		o.config.FlowAggregatorAddress = defaultFlowAggregatorAddress
	}
	if o.config.APIServer.APIPort == 0 {
		o.config.APIServer.APIPort = apis.FlowAggregatorAPIPort
	}
	if o.isFlowCollectorSet() {
		if o.config.FlowCollector.RecordFormat == "" {
			o.config.FlowCollector.RecordFormat = defaultRecordFormat
		}
	}
	if o.isClickHouseSet() {
		if o.config.ClickHouse.Database == "" {
			o.config.ClickHouse.Database = defaultClickHouseDatabase
		}
		if o.config.ClickHouse.DatabaseURL == "" {
			o.config.ClickHouse.DatabaseURL = defaultClickHouseDatabaseUrl
		}
		if o.config.ClickHouse.Compress == nil {
			o.config.ClickHouse.Compress = new(bool)
			*o.config.ClickHouse.Compress = true
		}
		if o.config.ClickHouse.CommitInterval == "" {
			o.config.ClickHouse.CommitInterval = defaultClickHouseCommitInterval
		}
	}
}
