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
	"time"

	"github.com/spf13/pflag"
	"gopkg.in/yaml.v2"

	"github.com/vmware-tanzu/antrea/pkg/agent/config"
	"github.com/vmware-tanzu/antrea/pkg/apis"
	"github.com/vmware-tanzu/antrea/pkg/cni"
	"github.com/vmware-tanzu/antrea/pkg/features"
	"github.com/vmware-tanzu/antrea/pkg/ovs/ovsconfig"
	"github.com/vmware-tanzu/antrea/pkg/util/flowexport"
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
	defaultNPLPortRange           = "40000-41000"
	defaultNodePortVirtualIP      = "169.254.169.110"
	defaultNodePortVirtualIPv6    = "fec0::ffee:ddcc:bbaa"
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
	// The virtual IP for NodePort Service support.
	nodePortVirtualIP, nodePortVirtualIPv6 net.IP
}

func newOptions() *Options {
	return &Options{
		nodePortVirtualIP:   net.ParseIP(defaultNodePortVirtualIP),
		nodePortVirtualIPv6: net.ParseIP(defaultNodePortVirtualIPv6),
		config: &AgentConfig{
			EnablePrometheusMetrics:   true,
			EnableTLSToFlowAggregator: true,
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
	err := features.DefaultMutableFeatureGate.SetFromMap(o.config.FeatureGates)
	if err != nil {
		return err
	}
	o.setDefaults()
	return nil
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
	if o.config.OVSDatapathType != string(ovsconfig.OVSDatapathSystem) && o.config.OVSDatapathType != string(ovsconfig.OVSDatapathNetdev) {
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
	if err := o.validateAntreaProxyConfig(); err != nil {
		return fmt.Errorf("proxy config is invalid: %w", err)
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
		o.config.OVSDatapathType = string(ovsconfig.OVSDatapathSystem)
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

	if features.DefaultFeatureGate.Enabled(features.FlowExporter) {
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

	if features.DefaultFeatureGate.Enabled(features.NodePortLocal) {
		if o.config.NPLPortRange == "" {
			o.config.NPLPortRange = defaultNPLPortRange
		}
	}
}

func (o *Options) validateAntreaProxyConfig() error {
	if features.DefaultFeatureGate.Enabled(features.AntreaProxyNodePort) {
		for _, nodePortAddress := range o.config.NodePortAddresses {
			if _, _, err := net.ParseCIDR(nodePortAddress); err != nil {
				return fmt.Errorf("NodePortAddress is not valid, can not parse `%s`: %w", nodePortAddress, err)
			}
		}
	}
	return nil
}

func (o *Options) validateFlowExporterConfig() error {
	if features.DefaultFeatureGate.Enabled(features.FlowExporter) {
		host, port, proto, err := flowexport.ParseFlowCollectorAddr(o.config.FlowCollectorAddr, defaultFlowCollectorPort, defaultFlowCollectorTransport)
		if err != nil {
			return err
		}
		o.flowCollectorAddr = net.JoinHostPort(host, port)
		o.flowCollectorProto = proto

		// Parse the given flowPollInterval config
		if o.config.FlowPollInterval != "" {
			flowPollInterval, err := flowexport.ParseFlowIntervalString(o.config.FlowPollInterval)
			if err != nil {
				return err
			}
			o.pollInterval = flowPollInterval
		}
	}
	return nil
}
