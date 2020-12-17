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
	"regexp"
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
	defaultOVSBridge              = "br-int"
	defaultHostGateway            = "antrea-gw0"
	defaultHostProcPathPrefix     = "/host"
	defaultServiceCIDR            = "10.96.0.0/12"
	defaultTunnelType             = ovsconfig.GeneveTunnel
	defaultFlowCollectorAddress   = "flow-aggregator.flow-aggregator.svc:4739:tcp"
	defaultFlowCollectorTransport = "tcp"
	defaultFlowCollectorPort      = "4739"
	defaultFlowPollInterval       = 5 * time.Second
	defaultFlowExportFrequency    = 12
)

type Options struct {
	// The path of configuration file.
	configFile string
	// The configuration object
	config *AgentConfig
	// IPFIX flow collector address
	flowCollectorAddr string
	// IPFIX flow collector L4 protocol
	flowCollectorProto string
	// Flow exporter poll interval
	pollInterval time.Duration
}

func newOptions() *Options {
	return &Options{
		config: &AgentConfig{
			EnablePrometheusMetrics: true,
		},
	}
}

// addFlags adds flags to fs and binds them to options.
func (o *Options) addFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.configFile, "config", o.configFile, "The path to the configuration file")
}

// complete completes all the required options.
func (o *Options) complete(args []string) error {
	if len(o.configFile) > 0 {
		if err := o.loadConfigFromFile(); err != nil {
			return err
		}
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
		return fmt.Errorf("Service CIDR %s is invalid", o.config.ServiceCIDR)
	}
	if o.config.ServiceCIDRv6 != "" {
		_, _, err := net.ParseCIDR(o.config.ServiceCIDRv6)
		if err != nil {
			return fmt.Errorf("Service CIDR v6 %s is invalid", o.config.ServiceCIDRv6)
		}
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

	// Check if the enabled features are supported on the OS.
	err = o.checkUnsupportedFeatures()
	if err != nil {
		return err
	}

	if encapMode.SupportsNoEncap() {
		if !features.DefaultFeatureGate.Enabled(features.AntreaProxy) {
			return fmt.Errorf("TrafficEncapMode %s requires AntreaProxy to be enabled", o.config.TrafficEncapMode)
		}
		if o.config.EnableIPSecTunnel {
			return fmt.Errorf("IPsec tunnel may only be enabled in %s mode", config.TrafficEncapModeEncap)
		}
	}
	if o.config.NoSNAT && !(encapMode == config.TrafficEncapModeNoEncap || encapMode == config.TrafficEncapModeNetworkPolicyOnly) {
		return fmt.Errorf("noSNAT is only applicable to the %s mode", config.TrafficEncapModeNoEncap)
	}
	if encapMode == config.TrafficEncapModeNetworkPolicyOnly {
		// In the NetworkPolicyOnly mode, Antrea will not perform SNAT
		// (but SNAT can be done by the primary CNI).
		o.config.NoSNAT = true
	}
	if err := o.validateFlowExporterConfig(); err != nil {
		return fmt.Errorf("failed to validate flow exporter config: %v", err)
	}
	return nil
}

func (o *Options) loadConfigFromFile() error {
	data, err := ioutil.ReadFile(o.configFile)
	if err != nil {
		return err
	}

	return yaml.UnmarshalStrict(data, &o.config)
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
	if o.config.TrafficEncapMode == "" {
		o.config.TrafficEncapMode = config.TrafficEncapModeEncap.String()
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
	if o.config.APIPort == 0 {
		o.config.APIPort = apis.AntreaAgentAPIPort
	}

	if o.config.FeatureGates[string(features.FlowExporter)] {
		if o.config.FlowCollectorAddr == "" {
			o.config.FlowCollectorAddr = defaultFlowCollectorAddress
		}
		if o.config.FlowPollInterval == "" {
			o.pollInterval = defaultFlowPollInterval
		}
		if o.config.FlowExportFrequency == 0 {
			// This frequency value makes flow export interval as 60s by default.
			o.config.FlowExportFrequency = defaultFlowExportFrequency
		}
	}
}

func (o *Options) validateFlowExporterConfig() error {
	if features.DefaultFeatureGate.Enabled(features.FlowExporter) {
		var host, port, proto string
		strSlice, err := parseFlowCollectorAddr(o.config.FlowCollectorAddr)
		if err != nil {
			return err
		}
		if len(strSlice) == 3 {
			host = strSlice[0]
			if strSlice[1] == "" {
				port = defaultFlowCollectorPort
			} else {
				port = strSlice[1]
			}
			if (strSlice[2] != "udp") && (strSlice[2] != "tcp") {
				return fmt.Errorf("connection over %s transport proto is not supported", strSlice[2])
			}
			proto = strSlice[2]
		} else if len(strSlice) == 2 {
			host = strSlice[0]
			port = strSlice[1]
			proto = defaultFlowCollectorTransport
		} else if len(strSlice) == 1 {
			host = strSlice[0]
			port = defaultFlowCollectorPort
			proto = defaultFlowCollectorTransport
		} else {
			return fmt.Errorf("flow collector address is given in invalid format")
		}
		o.flowCollectorAddr = net.JoinHostPort(host, port)
		o.flowCollectorProto = proto

		// Parse the given flowPollInterval config
		o.pollInterval, err = time.ParseDuration(o.config.FlowPollInterval)
		if err != nil {
			return fmt.Errorf("FlowPollInterval is not provided in right format")
		}
		if o.pollInterval < time.Second {
			return fmt.Errorf("FlowPollInterval should be greater than or equal to one second")
		}
	}
	return nil
}

func parseFlowCollectorAddr(addr string) ([]string, error) {
	var strSlice []string
	match, err := regexp.MatchString("\\[.*\\]:.*", addr)
	if err != nil {
		return strSlice, fmt.Errorf("Failed to parse FlowCollectorAddr: %s", addr)
	}
	if match {
		idx := strings.Index(addr, "]")
		strSlice = append(strSlice, addr[:idx+1])
		strSlice = append(strSlice, strings.Split(addr[idx+2:], ":")...)
	} else {
		strSlice = strings.Split(addr, ":")
	}
	return strSlice, nil
}
