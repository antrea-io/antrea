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
	"strings"
	"time"

	"github.com/spf13/pflag"
	"gopkg.in/yaml.v2"

	"github.com/vmware-tanzu/antrea/pkg/flowaggregator"
)

const (
	defaultFlowExportInterval          = 60 * time.Second
	defaultAggregatorTransportProtocol = flowaggregator.AggregatorTransportProtocolTCP
)

type Options struct {
	// The path of configuration file.
	configFile string
	// The configuration object
	config *FlowAggregatorConfig
	// IPFIX flow collector address
	externalFlowCollectorAddr net.Addr
	// Flow export interval of the flow aggregator
	exportInterval time.Duration
	// Transport protocol over which the aggregator collects IPFIX records from all Agents
	aggregatorTransportProtocol flowaggregator.AggregatorTransportProtocol
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
	if o.config.ExternalFlowCollectorProtocol == "" {
		return fmt.Errorf("IPFIX flow collector address should be provided")
	} else {
		// Check if it is TCP or UDP
		strSlice := strings.Split(o.config.ExternalFlowCollectorProtocol, ":")
		var proto string
		if len(strSlice) == 2 {
			// If no separator ":" and proto is given, then default to TCP.
			proto = "tcp"
		} else if len(strSlice) > 2 {
			if (strSlice[2] != "udp") && (strSlice[2] != "tcp") {
				return fmt.Errorf("IPFIX flow collector over %s proto is not supported", strSlice[2])
			}
			proto = strSlice[2]
		} else {
			return fmt.Errorf("IPFIX flow collector is given in invalid format")
		}

		// Convert the string input in net.Addr format
		hostPortAddr := strSlice[0] + ":" + strSlice[1]
		_, _, err := net.SplitHostPort(hostPortAddr)
		if err != nil {
			return fmt.Errorf("IPFIX flow collector is given in invalid format: %v", err)
		}
		if proto == "udp" {
			o.externalFlowCollectorAddr, err = net.ResolveUDPAddr("udp", hostPortAddr)
			if err != nil {
				return fmt.Errorf("IPFIX flow collector over UDP proto cannot be resolved: %v", err)
			}
		} else {
			o.externalFlowCollectorAddr, err = net.ResolveTCPAddr("tcp", hostPortAddr)
			if err != nil {
				return fmt.Errorf("IPFIX flow collector over TCP proto cannot be resolved: %v", err)
			}
		}
	}
	if o.config.FlowExportInterval == "" {
		o.exportInterval = defaultFlowExportInterval
	} else {
		var err error
		o.exportInterval, err = time.ParseDuration(o.config.FlowExportInterval)
		if err != nil {
			return fmt.Errorf("FlowExportInterval is not provided in right format: %v", err)
		}
		if o.exportInterval < time.Second {
			return fmt.Errorf("FlowExportInterval should be greater than or equal to one second")
		}
	}
	if o.config.AggregatorTransportProtocol == "" {
		o.aggregatorTransportProtocol = defaultAggregatorTransportProtocol
	} else {
		if (o.config.AggregatorTransportProtocol != flowaggregator.AggregatorTransportProtocolUDP) && (o.config.AggregatorTransportProtocol != flowaggregator.AggregatorTransportProtocolTCP) {
			return fmt.Errorf("collecting process over %s proto is not supported", o.config.AggregatorTransportProtocol)
		}
		o.aggregatorTransportProtocol = o.config.AggregatorTransportProtocol
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
