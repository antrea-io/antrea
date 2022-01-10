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
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/apis"
	"antrea.io/antrea/pkg/cni"
	agentconfig "antrea.io/antrea/pkg/config/agent"
	"antrea.io/antrea/pkg/features"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/util/env"
	"antrea.io/antrea/pkg/util/flowexport"
)

const (
	defaultOVSBridge               = "br-int"
	defaultHostGateway             = "antrea-gw0"
	defaultHostProcPathPrefix      = "/host"
	defaultServiceCIDR             = "10.96.0.0/12"
	defaultTunnelType              = ovsconfig.GeneveTunnel
	defaultFlowCollectorAddress    = "flow-aggregator.flow-aggregator.svc:4739:tls"
	defaultFlowCollectorTransport  = "tls"
	defaultFlowCollectorPort       = "4739"
	defaultFlowPollInterval        = 5 * time.Second
	defaultActiveFlowExportTimeout = 30 * time.Second
	defaultIdleFlowExportTimeout   = 15 * time.Second
	defaultStaleConnectionTimeout  = 5 * time.Minute
	defaultNPLPortRange            = "61000-62000"
)

type Options struct {
	// The path of configuration file.
	configFile string
	// The configuration object
	config *agentconfig.AgentConfig
	// IPFIX flow collector address
	flowCollectorAddr string
	// IPFIX flow collector protocol
	flowCollectorProto string
	// Flow exporter poll interval
	pollInterval time.Duration
	// Active flow timeout to export records of active flows
	activeFlowTimeout time.Duration
	// Idle flow timeout to export records of inactive flows
	idleFlowTimeout time.Duration
	// Stale connection timeout to delete connections if they are not exported.
	staleConnectionTimeout time.Duration
	nplStartPort           int
	nplEndPort             int
}

func newOptions() *Options {
	return &Options{
		config: &agentconfig.AgentConfig{},
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

	if o.config.TunnelType != ovsconfig.VXLANTunnel && o.config.TunnelType != ovsconfig.GeneveTunnel &&
		o.config.TunnelType != ovsconfig.GRETunnel && o.config.TunnelType != ovsconfig.STTTunnel {
		return fmt.Errorf("tunnel type %s is invalid", o.config.TunnelType)
	}
	ok, encryptionMode := config.GetTrafficEncryptionModeFromStr(o.config.TrafficEncryptionMode)
	if !ok {
		return fmt.Errorf("TrafficEncryptionMode %s is unknown", o.config.TrafficEncryptionMode)
	}
	if o.config.OVSDatapathType != string(ovsconfig.OVSDatapathSystem) && o.config.OVSDatapathType != string(ovsconfig.OVSDatapathNetdev) {
		return fmt.Errorf("OVS datapath type %s is not supported", o.config.OVSDatapathType)
	}
	ok, encapMode := config.GetTrafficEncapModeFromStr(o.config.TrafficEncapMode)
	if !ok {
		return fmt.Errorf("TrafficEncapMode %s is unknown", o.config.TrafficEncapMode)
	}

	// Check if the enabled features are supported on the OS.
	if err := o.checkUnsupportedFeatures(); err != nil {
		return err
	}

	if encapMode.SupportsNoEncap() {
		// When using NoEncap traffic mode without AntreaProxy, Pod-to-Service traffic is handled by kube-proxy
		// (iptables/ipvs) in the root netns. If the Endpoint is not local the DNATed traffic will be output to
		// the physical network directly without going back to OVS for Egress NetworkPolicy enforcement, which
		// breaks basic security functionality. Therefore, we usually do not allow the NoEncap traffic mode without
		// AntreaProxy. But one can bypass this check and force this feature combination to be allowed, by defining
		// the ALLOW_NO_ENCAP_WITHOUT_ANTREA_PROXY environment variable and setting it to true. This may lead to
		// better performance when using NoEncap if Egress NetworkPolicy enforcement is not required.
		if !features.DefaultFeatureGate.Enabled(features.AntreaProxy) {
			if env.GetAllowNoEncapWithoutAntreaProxy() {
				klog.InfoS("Disabling AntreaProxy in NoEncap mode will prevent Egress NetworkPolicy rules from being enforced correctly")
			} else {
				return fmt.Errorf("TrafficEncapMode %s requires AntreaProxy to be enabled", o.config.TrafficEncapMode)
			}
		}
		if encryptionMode != config.TrafficEncryptionModeNone {
			return fmt.Errorf("TrafficEncryptionMode %s may only be enabled in %s mode", encryptionMode, config.TrafficEncapModeEncap)
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
	if features.DefaultFeatureGate.Enabled(features.Egress) {
		for _, cidr := range o.config.Egress.ExceptCIDRs {
			_, _, err := net.ParseCIDR(cidr)
			if err != nil {
				return fmt.Errorf("Egress Except CIDR %s is invalid", cidr)
			}
		}
	}
	if features.DefaultFeatureGate.Enabled(features.NodePortLocal) {
		startPort, endPort, err := parsePortRange(o.config.NodePortLocal.PortRange)
		if err != nil {
			return fmt.Errorf("NodePortLocal portRange is not valid: %v", err)
		}
		o.nplStartPort = startPort
		o.nplEndPort = endPort
	} else if o.config.NodePortLocal.Enable {
		klog.InfoS("The nodePortLocal.enable config option is set to true, but it will be ignored because the NodePortLocal feature gate is disabled")
	}
	if err := o.validateAntreaIPAMConfig(); err != nil {
		return fmt.Errorf("failed to validate AntreaIPAM config: %v", err)
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
	if o.config.TrafficEncryptionMode == "" {
		o.config.TrafficEncryptionMode = config.TrafficEncryptionModeNone.String()
	}
	if o.config.TunnelType == "" {
		o.config.TunnelType = defaultTunnelType
	}
	if o.config.HostProcPathPrefix == "" {
		o.config.HostProcPathPrefix = defaultHostProcPathPrefix
	}
	if features.DefaultFeatureGate.Enabled(features.AntreaProxy) {
		if o.config.AntreaProxy.ProxyLoadBalancerIPs == nil {
			o.config.AntreaProxy.ProxyLoadBalancerIPs = new(bool)
			*o.config.AntreaProxy.ProxyLoadBalancerIPs = true
		}
	} else {
		if o.config.ServiceCIDR == "" {
			o.config.ServiceCIDR = defaultServiceCIDR
		}
	}
	if o.config.APIPort == 0 {
		o.config.APIPort = apis.AntreaAgentAPIPort
	}
	if o.config.ClusterMembershipPort == 0 {
		o.config.ClusterMembershipPort = apis.AntreaAgentClusterMembershipPort
	}
	if o.config.EnablePrometheusMetrics == nil {
		o.config.EnablePrometheusMetrics = new(bool)
		*o.config.EnablePrometheusMetrics = true
	}
	if o.config.WireGuard.Port == 0 {
		o.config.WireGuard.Port = apis.WireGuardListenPort
	}

	if features.DefaultFeatureGate.Enabled(features.FlowExporter) {
		if o.config.FlowCollectorAddr == "" {
			o.config.FlowCollectorAddr = defaultFlowCollectorAddress
		}
		if o.config.FlowPollInterval == "" {
			o.pollInterval = defaultFlowPollInterval
		}
		if o.config.ActiveFlowExportTimeout == "" {
			o.activeFlowTimeout = defaultActiveFlowExportTimeout
		}
		if o.config.IdleFlowExportTimeout == "" {
			o.idleFlowTimeout = defaultIdleFlowExportTimeout
		}
	}

	if features.DefaultFeatureGate.Enabled(features.NodePortLocal) {
		switch {
		case o.config.NodePortLocal.PortRange != "":
		case o.config.NPLPortRange != "":
			klog.InfoS("The nplPortRange option is deprecated, please use nodePortLocal.portRange instead")
			o.config.NodePortLocal.PortRange = o.config.NPLPortRange
		default:
			o.config.NodePortLocal.PortRange = defaultNPLPortRange
		}
	}
}

func (o *Options) validateAntreaProxyConfig() error {
	if !features.DefaultFeatureGate.Enabled(features.AntreaProxy) {
		// Validate service CIDR configuration if AntreaProxy is not enabled.
		if _, _, err := net.ParseCIDR(o.config.ServiceCIDR); err != nil {
			return fmt.Errorf("Service CIDR %s is invalid", o.config.ServiceCIDR)
		}
		if o.config.ServiceCIDRv6 != "" {
			if _, _, err := net.ParseCIDR(o.config.ServiceCIDRv6); err != nil {
				return fmt.Errorf("Service CIDR v6 %s is invalid", o.config.ServiceCIDRv6)
			}
		}
		if len(o.config.AntreaProxy.SkipServices) > 0 {
			klog.InfoS("skipServices will be ignored because AntreaProxy is disabled", "skipServices", o.config.AntreaProxy.SkipServices)
		}
	}

	if o.config.AntreaProxy.ProxyAll {
		for _, nodePortAddress := range o.config.AntreaProxy.NodePortAddresses {
			if _, _, err := net.ParseCIDR(nodePortAddress); err != nil {
				return fmt.Errorf("invalid NodePort IP address `%s`: %w", nodePortAddress, err)
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
		// Parse the given activeFlowExportTimeout config
		if o.config.ActiveFlowExportTimeout != "" {
			o.activeFlowTimeout, err = time.ParseDuration(o.config.ActiveFlowExportTimeout)
			if err != nil {
				return fmt.Errorf("ActiveFlowExportTimeout is not provided in right format")
			}
			if o.activeFlowTimeout < o.pollInterval {
				o.activeFlowTimeout = o.pollInterval
				klog.Warningf("ActiveFlowExportTimeout must be greater than or equal to FlowPollInterval")
			}
		}
		// Parse the given inactiveFlowExportTimeout config
		if o.config.IdleFlowExportTimeout != "" {
			o.idleFlowTimeout, err = time.ParseDuration(o.config.IdleFlowExportTimeout)
			if err != nil {
				return fmt.Errorf("IdleFlowExportTimeout is not provided in right format")
			}
			if o.idleFlowTimeout < o.pollInterval {
				o.idleFlowTimeout = o.pollInterval
				klog.Warningf("IdleFlowExportTimeout must be greater than or equal to FlowPollInterval")
			}
		}
		if (o.activeFlowTimeout > defaultStaleConnectionTimeout) || (o.idleFlowTimeout > defaultStaleConnectionTimeout) {
			if o.activeFlowTimeout > o.idleFlowTimeout {
				o.staleConnectionTimeout = 2 * o.activeFlowTimeout
			} else {
				o.staleConnectionTimeout = 2 * o.idleFlowTimeout
			}
		} else {
			o.staleConnectionTimeout = defaultStaleConnectionTimeout
		}
	}
	return nil
}

func (o *Options) validateAntreaIPAMConfig() error {
	if features.DefaultFeatureGate.Enabled(features.AntreaIPAM) {
		// AntreaIPAM will bridge uplink to OVS bridge, which is not compatible with OVSDatapathSystem 'netdev'
		if o.config.OVSDatapathType != string(ovsconfig.OVSDatapathSystem) {
			return fmt.Errorf("AntreaIPAM requires 'system' OVSDatapathType, current: %s",
				o.config.OVSDatapathType)
		}
		if !strings.EqualFold(o.config.TrafficEncapMode, config.TrafficEncapModeNoEncap.String()) {
			return fmt.Errorf("AntreaIPAM requires 'noEncap' TrafficEncapMode, current: %s",
				o.config.TrafficEncapMode)
		}
		// TODO(gran): support SNAT for Per-Node IPAM Pods
		// SNAT needs to be updated to bypass traffic from AntreaIPAM Pod to Per-Node IPAM Pod
		if !o.config.NoSNAT {
			return fmt.Errorf("AntreaIPAM requires noSNAT")
		}
	}
	return nil
}
