// Copyright 2019 Antrea Authors
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
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"gopkg.in/yaml.v2"

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/apis"
	"github.com/vmware-tanzu/antrea/pkg/cni"
	"github.com/vmware-tanzu/antrea/pkg/features"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsconfig"
)

const (
	defaultOVSBridge          = "br-int"
	defaultHostGateway        = "antrea-gw0"
	defaultHostProcPathPrefix = "/host"
	defaultServiceCIDR        = "10.96.0.0/12"
	defaultTunnelType         = ovsconfig.GeneveTunnel
)

type Options struct {
	// The path of configuration file.
	configFile string
	// The configuration object
	config *AgentConfig
	// IPFIX flow collector
	flowCollector net.Addr
	// Flow exporter poll interval
	pollInterval time.Duration
}

func newOptions() *Options {
	return &Options{
		config: new(AgentConfig),
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
	o.setDefaults()
	return features.DefaultMutableFeatureGate.SetFromMap(o.config.FeatureGates)
}

// validate validates all the required options. It must be called after complete.
func (o *Options) validate(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("no positional arguments are supported")
	}
	// Validate service CIDR configuration
	_, _, err := net.ParseCIDR(o.config.ServiceCIDR)
	if err != nil {
		return fmt.Errorf("service CIDR %s is invalid", o.config.ServiceCIDR)
	}
	if o.config.TunnelType != ovsconfig.VXLANTunnel && o.config.TunnelType != ovsconfig.GeneveTunnel &&
		o.config.TunnelType != ovsconfig.GRETunnel && o.config.TunnelType != ovsconfig.STTTunnel {
		return fmt.Errorf("tunnel type %s is invalid", o.config.TunnelType)
	}
	if o.config.EnableIPSecTunnel && o.config.TunnelType != ovsconfig.GRETunnel {
		return fmt.Errorf("IPSec encyption is supported only for GRE tunnel")
	}
	if o.config.OVSDatapathType != ovsconfig.OVSDatapathSystem && o.config.OVSDatapathType != ovsconfig.OVSDatapathNetdev {
		return fmt.Errorf("OVS datapath type %s is not supported", o.config.OVSDatapathType)
	}
	ok, encapMode := config.GetTrafficEncapModeFromStr(o.config.TrafficEncapMode)
	if !ok {
		return fmt.Errorf("TrafficEncapMode %s is unknown", o.config.TrafficEncapMode)
	}
	if encapMode.SupportsNoEncap() && o.config.EnableIPSecTunnel {
		return fmt.Errorf("IPSec tunnel may only be enabled on %s mode", config.TrafficEncapModeEncap)
	}
	return nil
}

func (o *Options) loadConfigFromFile(file string) (*AgentConfig, error) {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	var c AgentConfig
	err = yaml.UnmarshalStrict(data, &c)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (o *Options) setDefaults() {
	if o.config.CNISocket == "" {
		o.config.CNISocket = cni.AntreaCNISocketAddr
	}
	if o.config.OVSBridge == "" {
		o.config.OVSBridge = defaultOVSBridge
	}
	if o.config.OVSDatapathType == "" {
		o.config.OVSDatapathType = ovsconfig.OVSDatapathSystem
	}
	if o.config.OVSRunDir == "" {
		o.config.OVSRunDir = ovsconfig.DefaultOVSRunDir
	}
	if o.config.HostGateway == "" {
		o.config.HostGateway = defaultHostGateway
	}
	if o.config.TunnelType == "" {
		o.config.TunnelType = defaultTunnelType
	}
	if o.config.HostProcPathPrefix == "" {
		o.config.HostProcPathPrefix = defaultHostProcPathPrefix
	}
	if o.config.ServiceCIDR == "" {
		o.config.ServiceCIDR = defaultServiceCIDR
	}
	if o.config.TrafficEncapMode == "" {
		o.config.TrafficEncapMode = config.TrafficEncapModeEncap.String()
	}
	if o.config.APIPort == 0 {
		o.config.APIPort = apis.AntreaAgentAPIPort
	}

	if o.config.FeatureGates[string(features.FlowExporter)] {
		if o.config.FlowPollInterval == "" {
			o.pollInterval = 5 * time.Second
		}
		if o.config.FlowExportFrequency == 0 {
			// This frequency value makes flow export interval as 60s
			o.config.FlowExportFrequency = 12
		}
	}
}

func (o *Options) validateFlowExporterConfig() error {
	if features.DefaultFeatureGate.Enabled(features.FlowExporter) {
		if o.config.FlowCollectorAddr == "" {
			return fmt.Errorf("IPFIX flow collector address should be provided")
		} else {
			// Check if it is TCP or UDP
			strSlice := strings.Split(o.config.FlowCollectorAddr, ":")
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
				o.flowCollector, err = net.ResolveUDPAddr("udp", hostPortAddr)
				if err != nil {
					return fmt.Errorf("IPFIX flow collector over UDP proto cannot be resolved: %v", err)
				}
			} else {
				o.flowCollector, err = net.ResolveTCPAddr("tcp", hostPortAddr)
				if err != nil {
					return fmt.Errorf("IPFIX flow collector over TCP proto cannot be resolved: %v", err)
				}
			}
		}
		if o.config.FlowPollInterval != "" {
			var err error
			o.pollInterval, err = time.ParseDuration(o.config.FlowPollInterval)
			if err != nil {
				return fmt.Errorf("FlowPollInterval is not provided in right format: %v", err)
			}
			if o.pollInterval < time.Second {
				return fmt.Errorf("FlowPollInterval should be greater than or equal to one second")
			}
		}
	}
	return nil
}
