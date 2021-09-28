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
	"antrea.io/antrea/pkg/flowaggregator/kafka"
	"antrea.io/antrea/pkg/util/flowexport"
)

const (
	defaultExternalFlowCollectorTransport = "tcp"
	defaultExternalFlowCollectorPort      = "4739"
	defaultActiveFlowRecordTimeout        = 60 * time.Second
	defaultInactiveFlowRecordTimeout      = 90 * time.Second
	defaultAggregatorTransportProtocol    = flowaggregator.AggregatorTransportProtocolTLS
	defaultFlowAggregatorAddress          = "flow-aggregator.flow-aggregator.svc"
	defaultRecordFormat                   = "IPFIX"
	defaultKafkaProtoSchema               = kafka.AntreaFlowMsg
	defaultKafkaTopic                     = kafka.AntreaTopic
)

type Options struct {
	// The path of configuration file.
	configFile string
	// The configuration object
	config *flowaggregatorconfig.FlowAggregatorConfig
	// IPFIX flow collector address
	externalFlowCollectorAddr string
	// IPFIX flow collector transport protocol
	externalFlowCollectorProto string
	// Expiration timeout for active flow records in the flow aggregator
	activeFlowRecordTimeout time.Duration
	// Expiration timeout for inactive flow records in the flow aggregator
	inactiveFlowRecordTimeout time.Duration
	// Transport protocol over which the aggregator collects IPFIX records from all Agents
	aggregatorTransportProtocol flowaggregator.AggregatorTransportProtocol
	// DNS name or IP address of flow aggregator for generating TLS certificate
	flowAggregatorAddress string
	// Format for record sent to the configured flow collector
	format string
	// includePodLabels indicates whether source and destination Pod labels are included or not
	includePodLabels bool
	// Kafka proto schema for the Flow Aggregator to send the Kafka flow records
	kakfaProtoSchema string
	// Kafka broker topic where the producer in the Flow Aggregator sends the Kafka
	// flow records
	kakfaBrokerTopic string
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
	if o.config.ActiveFlowRecordTimeout == "" {
		o.activeFlowRecordTimeout = defaultActiveFlowRecordTimeout
	} else {
		o.activeFlowRecordTimeout, err = time.ParseDuration(o.config.ActiveFlowRecordTimeout)
		if err != nil {
			return err
		}
	}
	if o.config.InactiveFlowRecordTimeout == "" {
		o.inactiveFlowRecordTimeout = defaultInactiveFlowRecordTimeout
	} else {
		o.inactiveFlowRecordTimeout, err = time.ParseDuration(o.config.ActiveFlowRecordTimeout)
		if err != nil {
			return err
		}
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
	if o.config.FlowAggregatorAddress == "" {
		o.flowAggregatorAddress = defaultFlowAggregatorAddress
	} else {
		o.flowAggregatorAddress = o.config.FlowAggregatorAddress
	}
	if o.config.RecordFormat == "" {
		o.format = defaultRecordFormat
	} else if o.config.RecordFormat != "IPFIX" && o.config.RecordFormat != "JSON" {
		return fmt.Errorf("record format %s is not supported", o.config.RecordFormat)
	} else {
		o.format = o.config.RecordFormat
	}
	o.includePodLabels = o.config.RecordContents.PodLabels
	if o.config.APIServer.APIPort == 0 {
		o.config.APIServer.APIPort = apis.FlowAggregatorAPIPort
	}
	// Validate all parameters related to Kafka flow export. These are optional.
	// We process the parameters only if the Kafka broker address is given.
	if o.config.KafkaParams.BrokerAddress != "" {
		if o.config.KafkaParams.ProtoSchema == "" {
			o.kakfaProtoSchema = defaultKafkaProtoSchema
		} else if o.config.KafkaParams.ProtoSchema != defaultKafkaProtoSchema {
			return fmt.Errorf("kafka flow export supports only one proto schema: %v", defaultKafkaProtoSchema)
		} else {
			o.kakfaProtoSchema = o.config.KafkaParams.ProtoSchema
		}
		if o.config.KafkaParams.Topic == "" {
			o.kakfaBrokerTopic = defaultKafkaTopic
		} else {
			o.kakfaBrokerTopic = o.config.KafkaParams.Topic
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
