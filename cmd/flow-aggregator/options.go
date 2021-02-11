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

	"github.com/vmware-tanzu/antrea/pkg/flowaggregator"
	"github.com/vmware-tanzu/antrea/pkg/util/flowexport"
)

const (
	defaultExternalFlowCollectorTransport = "tcp"
	defaultExternalFlowCollectorPort      = "4739"
	defaultFlowExportInterval             = 60 * time.Second
	defaultAggregatorTransportProtocol    = flowaggregator.AggregatorTransportProtocolTLS
	defaultFlowAggregatorAddress          = "flow-aggregator.flow-aggregator.svc"
)

type Options struct {
	// The path of configuration file.
	configFile string
	// The configuration object
	config *FlowAggregatorConfig
	// IPFIX flow collector address
	externalFlowCollectorAddr string
	// IPFIX flow collector transport protocol
	externalFlowCollectorProto string
	// Flow export interval of the flow aggregator
	exportInterval time.Duration
	// Transport protocol over which the aggregator collects IPFIX records from all Agents
	aggregatorTransportProtocol flowaggregator.AggregatorTransportProtocol
	// DNS name or IP address of flow aggregator for generating TLS certificate
	flowAggregatorAddress string
}

func newOptions() *Options {
	return &Options{
		config: new(FlowAggregatorConfig),
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
	}
	return nil
}

// validate validates all the required options.
func (o *Options) validate(args []string) error {
	if len(args) != 0 {
		return errors.New("no positional arguments are supported")
	}
	if o.config.ExternalFlowCollectorAddr == "" {
		return fmt.Errorf("IPFIX flow collector address should be provided")
	}
	host, port, proto, err := flowexport.ParseFlowCollectorAddr(o.config.ExternalFlowCollectorAddr, defaultExternalFlowCollectorPort, defaultExternalFlowCollectorTransport)
	if err != nil {
		return err
	}
	o.externalFlowCollectorAddr = net.JoinHostPort(host, port)
	o.externalFlowCollectorProto = proto
	if o.config.FlowExportInterval == "" {
		o.exportInterval = defaultFlowExportInterval
	} else {
		flowExportInterval, err := flowexport.ParseFlowIntervalString(o.config.FlowExportInterval)
		if err != nil {
			return err
		}
		o.exportInterval = flowExportInterval
	}
	if o.config.AggregatorTransportProtocol == "" {
		o.aggregatorTransportProtocol = defaultAggregatorTransportProtocol
	} else {
		transportProtocol, err := flowexport.ParseTransportProtocol(o.config.AggregatorTransportProtocol)
		if err != nil {
			return err
		}
		o.aggregatorTransportProtocol = transportProtocol
	}
	if o.config.flowAggregatorAddress == "" {
		o.flowAggregatorAddress = defaultFlowAggregatorAddress
	} else {
		o.flowAggregatorAddress = o.config.flowAggregatorAddress
	}
	return nil
}

func (o *Options) loadConfigFromFile(file string) (*FlowAggregatorConfig, error) {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	c := FlowAggregatorConfig{}
	err = yaml.UnmarshalStrict(data, &c)
	if err != nil {
		return nil, err
	}
	return &c, nil
}
