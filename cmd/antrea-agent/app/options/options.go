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

package options

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"gopkg.in/yaml.v2"
	"k8s.io/apimachinery/pkg/util/sets"
	cliflag "k8s.io/component-base/cli/flag"
	"k8s.io/component-base/featuregate"
	"k8s.io/klog/v2"

	agentconfig "antrea.io/antrea/cmd/antrea-agent/app/config"
	"antrea.io/antrea/cmd/antrea-agent/app/util"
	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/apis"
	"antrea.io/antrea/pkg/cni"
	"antrea.io/antrea/pkg/features"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/util/env"
	"antrea.io/antrea/pkg/util/flowexport"
	"antrea.io/antrea/pkg/util/ip"
)

const (
	defaultOVSBridge               = "br-int"
	defaultHostGateway             = "antrea-gw0"
	defaultHostProcPathPrefix      = "/host"
	defaultServiceCIDR             = "10.96.0.0/12"
	defaultTunnelType              = ovsconfig.GeneveTunnel
	defaultFlowCollectorAddress    = "flow-aggregator/flow-aggregator:4739:tls"
	defaultFlowCollectorTransport  = "tls"
	defaultFlowCollectorPort       = "4739"
	defaultFlowPollInterval        = 5 * time.Second
	defaultActiveFlowExportTimeout = 30 * time.Second
	defaultIdleFlowExportTimeout   = 15 * time.Second
	defaultIGMPQueryInterval       = 125 * time.Second
	defaultStaleConnectionTimeout  = 5 * time.Minute
	defaultNPLPortRange            = "61000-62000"
	defaultNodeType                = config.K8sNode
)

type Options struct {
	// The path of configuration file.
	configFile string
	// The configuration object
	Config *agentconfig.AgentConfig
	// tlsCipherSuites is a slice of TLSCipherSuites mapped to input provided by user.
	TlsCipherSuites []string
	// IPFIX flow collector address
	FlowCollectorAddr string
	// IPFIX flow collector protocol
	FlowCollectorProto string
	// Flow exporter poll interval
	PollInterval time.Duration
	// Active flow timeout to export records of active flows
	ActiveFlowTimeout time.Duration
	// Idle flow timeout to export records of inactive flows
	IdleFlowTimeout time.Duration
	// Stale connection timeout to delete connections if they are not exported.
	StaleConnectionTimeout time.Duration
	IgmpQueryInterval      time.Duration
	NplStartPort           int
	NplEndPort             int
	DnsServerOverride      string
	NodeType               config.NodeType
}

func NewOptions() *Options {
	return &Options{
		Config: &agentconfig.AgentConfig{},
	}
}

// addFlags adds flags to fs and binds them to options.
func (o *Options) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.configFile, "config", o.configFile, "The path to the configuration file")
}

// complete completes all the required options.
func (o *Options) Complete() error {
	if len(o.configFile) > 0 {
		if err := o.loadConfigFromFile(); err != nil {
			return err
		}
	}
	err := features.DefaultMutableFeatureGate.SetFromMap(o.Config.FeatureGates)
	if err != nil {
		return err
	}
	o.setDefaults()
	if o.Config.NodeType == config.ExternalNode.String() {
		if err := o.resetVMDefaultFeatures(); err != nil {
			return err
		}
	}
	return nil
}

// validate validates all the required options. It must be called after complete.
func (o *Options) Validate(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("no positional arguments are supported")
	}

	if o.Config.OVSDatapathType != string(ovsconfig.OVSDatapathSystem) {
		return fmt.Errorf("OVS datapath type %s is not supported", o.Config.OVSDatapathType)
	}

	if err := o.validateTLSOptions(); err != nil {
		return err
	}

	if config.ExternalNode.String() == o.Config.NodeType && !features.DefaultFeatureGate.Enabled(features.ExternalNode) {
		return fmt.Errorf("nodeType %s requires feature gate ExternalNode to be enabled", o.Config.NodeType)
	}

	if o.Config.NodeType == config.ExternalNode.String() {
		o.NodeType = config.ExternalNode
		return o.validateExternalNodeOptions()
	} else if o.Config.NodeType == config.K8sNode.String() {
		o.NodeType = config.K8sNode
		return o.validateK8sNodeOptions()
	} else {
		return fmt.Errorf("unsupported nodeType %s", o.Config.NodeType)
	}
}

func (o *Options) loadConfigFromFile() error {
	data, err := os.ReadFile(o.configFile)
	if err != nil {
		return err
	}

	return yaml.UnmarshalStrict(data, &o.Config)
}

func (o *Options) setDefaults() {
	if o.Config.OVSBridge == "" {
		o.Config.OVSBridge = defaultOVSBridge
	}
	if o.Config.OVSDatapathType == "" {
		o.Config.OVSDatapathType = string(ovsconfig.OVSDatapathSystem)
	}
	if o.Config.OVSRunDir == "" {
		o.Config.OVSRunDir = ovsconfig.DefaultOVSRunDir
	}
	if o.Config.APIPort == 0 {
		o.Config.APIPort = apis.AntreaAgentAPIPort
	}
	if o.Config.NodeType == "" {
		o.Config.NodeType = defaultNodeType.String()
	}
	if o.Config.NodeType == config.K8sNode.String() {
		o.setK8sNodeDefaultOptions()
	} else {
		o.setExternalNodeDefaultOptions()
	}
}

func (o *Options) validateTLSOptions() error {
	_, err := cliflag.TLSVersion(o.Config.TLSMinVersion)
	if err != nil {
		return fmt.Errorf("invalid TLSMinVersion: %v", err)
	}
	trimmedTLSCipherSuites := strings.ReplaceAll(o.Config.TLSCipherSuites, " ", "")
	if trimmedTLSCipherSuites != "" {
		tlsCipherSuites := strings.Split(trimmedTLSCipherSuites, ",")
		_, err = cliflag.TLSCipherSuites(tlsCipherSuites)
		if err != nil {
			return fmt.Errorf("invalid TLSCipherSuites: %v", err)
		}
		o.TlsCipherSuites = tlsCipherSuites
	}
	return nil
}

func (o *Options) validateAntreaProxyConfig() error {
	if !features.DefaultFeatureGate.Enabled(features.AntreaProxy) {
		// Validate service CIDR configuration if AntreaProxy is not enabled.
		if _, _, err := net.ParseCIDR(o.Config.ServiceCIDR); err != nil {
			return fmt.Errorf("Service CIDR %s is invalid", o.Config.ServiceCIDR)
		}
		if o.Config.ServiceCIDRv6 != "" {
			if _, _, err := net.ParseCIDR(o.Config.ServiceCIDRv6); err != nil {
				return fmt.Errorf("Service CIDR v6 %s is invalid", o.Config.ServiceCIDRv6)
			}
		}
		if len(o.Config.AntreaProxy.SkipServices) > 0 {
			klog.InfoS("skipServices will be ignored because AntreaProxy is disabled", "skipServices", o.Config.AntreaProxy.SkipServices)
		}
	}

	if o.Config.AntreaProxy.ProxyAll {
		for _, nodePortAddress := range o.Config.AntreaProxy.NodePortAddresses {
			if _, _, err := net.ParseCIDR(nodePortAddress); err != nil {
				return fmt.Errorf("invalid NodePort IP address `%s`: %w", nodePortAddress, err)
			}
		}
	}
	return nil
}

func (o *Options) validateFlowExporterConfig() error {
	if features.DefaultFeatureGate.Enabled(features.FlowExporter) {
		host, port, proto, err := flowexport.ParseFlowCollectorAddr(o.Config.FlowCollectorAddr, defaultFlowCollectorPort, defaultFlowCollectorTransport)
		if err != nil {
			return err
		}
		o.FlowCollectorAddr = net.JoinHostPort(host, port)
		o.FlowCollectorProto = proto

		// Parse the given flowPollInterval config
		if o.Config.FlowPollInterval != "" {
			flowPollInterval, err := flowexport.ParseFlowIntervalString(o.Config.FlowPollInterval)
			if err != nil {
				return err
			}
			o.PollInterval = flowPollInterval
		}
		// Parse the given activeFlowExportTimeout config
		if o.Config.ActiveFlowExportTimeout != "" {
			o.ActiveFlowTimeout, err = time.ParseDuration(o.Config.ActiveFlowExportTimeout)
			if err != nil {
				return fmt.Errorf("ActiveFlowExportTimeout is not provided in right format")
			}
			if o.ActiveFlowTimeout < o.PollInterval {
				o.ActiveFlowTimeout = o.PollInterval
				klog.Warningf("ActiveFlowExportTimeout must be greater than or equal to FlowPollInterval")
			}
		}
		// Parse the given inactiveFlowExportTimeout config
		if o.Config.IdleFlowExportTimeout != "" {
			o.IdleFlowTimeout, err = time.ParseDuration(o.Config.IdleFlowExportTimeout)
			if err != nil {
				return fmt.Errorf("IdleFlowExportTimeout is not provided in right format")
			}
			if o.IdleFlowTimeout < o.PollInterval {
				o.IdleFlowTimeout = o.PollInterval
				klog.Warningf("IdleFlowExportTimeout must be greater than or equal to FlowPollInterval")
			}
		}
		if (o.ActiveFlowTimeout > defaultStaleConnectionTimeout) || (o.IdleFlowTimeout > defaultStaleConnectionTimeout) {
			if o.ActiveFlowTimeout > o.IdleFlowTimeout {
				o.StaleConnectionTimeout = 2 * o.ActiveFlowTimeout
			} else {
				o.StaleConnectionTimeout = 2 * o.IdleFlowTimeout
			}
		} else {
			o.StaleConnectionTimeout = defaultStaleConnectionTimeout
		}
	}
	return nil
}

func (o *Options) validateMulticastConfig() error {
	if features.DefaultFeatureGate.Enabled(features.Multicast) {
		var err error
		if o.Config.Multicast.IGMPQueryInterval != "" {
			o.IgmpQueryInterval, err = time.ParseDuration(o.Config.Multicast.IGMPQueryInterval)
			if err != nil {
				return err
			}
		}
		if len(o.Config.Multicast.MulticastInterfaces) == 0 && len(o.Config.MulticastInterfaces) > 0 {
			klog.InfoS("The multicastInterfaces option is deprecated, please use multicast.multicastInterfaces instead")
			o.Config.Multicast.MulticastInterfaces = o.Config.MulticastInterfaces
		}
	}
	return nil
}

func (o *Options) validateAntreaIPAMConfig() error {
	if !o.Config.EnableBridgingMode {
		return nil
	}
	if !features.DefaultFeatureGate.Enabled(features.AntreaIPAM) {
		return fmt.Errorf("AntreaIPAM feature gate must be enabled to configure bridging mode")
	}
	if !strings.EqualFold(o.Config.TrafficEncapMode, config.TrafficEncapModeNoEncap.String()) {
		return fmt.Errorf("Bridging mode requires 'noEncap' TrafficEncapMode, current: %s",
			o.Config.TrafficEncapMode)
	}
	// TODO(gran): support SNAT for Per-Node IPAM Pods
	// SNAT needs to be updated to bypass traffic from AntreaIPAM Pod to Per-Node IPAM Pod
	if !o.Config.NoSNAT {
		return fmt.Errorf("Bridging mode requires noSNAT")
	}
	return nil
}

func (o *Options) validateMulticlusterConfig(encapMode config.TrafficEncapModeType) error {
	if !o.Config.Multicluster.EnableGateway && !o.Config.Multicluster.EnableStretchedNetworkPolicy {
		return nil
	}

	if !features.DefaultFeatureGate.Enabled(features.Multicluster) {
		klog.InfoS("Multi-cluster feature gate is disabled. Multi-cluster options are ignored")
		return nil
	}

	if !o.Config.Multicluster.EnableGateway && o.Config.Multicluster.EnableStretchedNetworkPolicy {
		return fmt.Errorf("multi-cluster Gateway must be enabled to enable StretchedNetworkPolicy")
	}

	if encapMode != config.TrafficEncapModeEncap {
		// Only Encap mode is supported for Multi-cluster Gateway.
		return fmt.Errorf("Multicluster is only applicable to the %s mode", config.TrafficEncapModeEncap)
	}
	return nil
}

func (o *Options) setK8sNodeDefaultOptions() {
	if o.Config.CNISocket == "" {
		o.Config.CNISocket = cni.AntreaCNISocketAddr
	}
	if o.Config.HostGateway == "" {
		o.Config.HostGateway = defaultHostGateway
	}
	if o.Config.TrafficEncapMode == "" {
		o.Config.TrafficEncapMode = config.TrafficEncapModeEncap.String()
	}
	if o.Config.TrafficEncryptionMode == "" {
		o.Config.TrafficEncryptionMode = config.TrafficEncryptionModeNone.String()
	}
	if o.Config.TunnelType == "" {
		o.Config.TunnelType = defaultTunnelType
	}
	if o.Config.HostProcPathPrefix == "" {
		o.Config.HostProcPathPrefix = defaultHostProcPathPrefix
	}
	if features.DefaultFeatureGate.Enabled(features.AntreaProxy) {
		if o.Config.AntreaProxy.ProxyLoadBalancerIPs == nil {
			o.Config.AntreaProxy.ProxyLoadBalancerIPs = new(bool)
			*o.Config.AntreaProxy.ProxyLoadBalancerIPs = true
		}
	} else {
		if o.Config.ServiceCIDR == "" {
			o.Config.ServiceCIDR = defaultServiceCIDR
		}
	}
	if o.Config.ClusterMembershipPort == 0 {
		o.Config.ClusterMembershipPort = apis.AntreaAgentClusterMembershipPort
	}
	if o.Config.EnablePrometheusMetrics == nil {
		o.Config.EnablePrometheusMetrics = new(bool)
		*o.Config.EnablePrometheusMetrics = true
	}
	if o.Config.WireGuard.Port == 0 {
		o.Config.WireGuard.Port = apis.WireGuardListenPort
	}

	if o.Config.IPsec.AuthenticationMode == "" {
		o.Config.IPsec.AuthenticationMode = config.IPsecAuthenticationModePSK.String()
	}

	if features.DefaultFeatureGate.Enabled(features.FlowExporter) {
		if o.Config.FlowCollectorAddr == "" {
			o.Config.FlowCollectorAddr = defaultFlowCollectorAddress
		}
		if o.Config.FlowPollInterval == "" {
			o.PollInterval = defaultFlowPollInterval
		}
		if o.Config.ActiveFlowExportTimeout == "" {
			o.ActiveFlowTimeout = defaultActiveFlowExportTimeout
		}
		if o.Config.IdleFlowExportTimeout == "" {
			o.IdleFlowTimeout = defaultIdleFlowExportTimeout
		}
	}

	if features.DefaultFeatureGate.Enabled(features.NodePortLocal) {
		switch {
		case o.Config.NodePortLocal.PortRange != "":
		case o.Config.NPLPortRange != "":
			klog.InfoS("The nplPortRange option is deprecated, please use nodePortLocal.portRange instead")
			o.Config.NodePortLocal.PortRange = o.Config.NPLPortRange
		default:
			o.Config.NodePortLocal.PortRange = defaultNPLPortRange
		}
	}

	if features.DefaultFeatureGate.Enabled(features.Multicast) {
		if o.Config.Multicast.IGMPQueryInterval == "" {
			o.IgmpQueryInterval = defaultIGMPQueryInterval
		}
	}

	if features.DefaultFeatureGate.Enabled(features.Multicluster) && o.Config.Multicluster.Enable {
		// Multicluster.Enable is deprecated but it may be set by an earlier version
		// deployment manifest. If it is set to true, pass the value to
		// Multicluster.EnableGateway.
		o.Config.Multicluster.EnableGateway = true
	}
}

func (o *Options) validateK8sNodeOptions() error {
	if o.Config.TunnelType != ovsconfig.VXLANTunnel && o.Config.TunnelType != ovsconfig.GeneveTunnel &&
		o.Config.TunnelType != ovsconfig.GRETunnel && o.Config.TunnelType != ovsconfig.STTTunnel {
		return fmt.Errorf("tunnel type %s is invalid", o.Config.TunnelType)
	}
	ok, encryptionMode := config.GetTrafficEncryptionModeFromStr(o.Config.TrafficEncryptionMode)
	if !ok {
		return fmt.Errorf("TrafficEncryptionMode %s is unknown", o.Config.TrafficEncryptionMode)
	}
	ok, encapMode := config.GetTrafficEncapModeFromStr(o.Config.TrafficEncapMode)
	if !ok {
		return fmt.Errorf("TrafficEncapMode %s is unknown", o.Config.TrafficEncapMode)
	}
	ok, ipsecAuthMode := config.GetIPsecAuthenticationModeFromStr(o.Config.IPsec.AuthenticationMode)
	if !ok {
		return fmt.Errorf("IPsec AuthenticationMode %s is unknown", o.Config.IPsec.AuthenticationMode)
	}
	if ipsecAuthMode == config.IPsecAuthenticationModeCert && !features.DefaultFeatureGate.Enabled(features.IPsecCertAuth) {
		return fmt.Errorf("IPsec AuthenticationMode %s requires feature gate %s to be enabled", o.Config.TrafficEncapMode, features.IPsecCertAuth)
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
				return fmt.Errorf("TrafficEncapMode %s requires AntreaProxy to be enabled", o.Config.TrafficEncapMode)
			}
		}
		if encryptionMode != config.TrafficEncryptionModeNone {
			return fmt.Errorf("TrafficEncryptionMode %s may only be enabled in %s mode", encryptionMode, config.TrafficEncapModeEncap)
		}
	}
	if o.Config.NoSNAT && !(encapMode == config.TrafficEncapModeNoEncap || encapMode == config.TrafficEncapModeNetworkPolicyOnly) {
		return fmt.Errorf("noSNAT is only applicable to the %s mode", config.TrafficEncapModeNoEncap)
	}
	if encapMode == config.TrafficEncapModeNetworkPolicyOnly {
		// In the NetworkPolicyOnly mode, Antrea will not perform SNAT
		// (but SNAT can be done by the primary CNI).
		o.Config.NoSNAT = true
	}
	if err := o.validateAntreaProxyConfig(); err != nil {
		return fmt.Errorf("proxy config is invalid: %w", err)
	}
	if err := o.validateFlowExporterConfig(); err != nil {
		return fmt.Errorf("failed to validate flow exporter config: %v", err)
	}
	if err := o.validateMulticastConfig(); err != nil {
		return fmt.Errorf("failed to validate multicast config: %v", err)
	}
	if features.DefaultFeatureGate.Enabled(features.Egress) {
		for _, cidr := range o.Config.Egress.ExceptCIDRs {
			_, _, err := net.ParseCIDR(cidr)
			if err != nil {
				return fmt.Errorf("egress excepted CIDR %s is invalid", cidr)
			}
		}
	}
	if err := o.validateMulticlusterConfig(encapMode); err != nil {
		return err
	}

	if features.DefaultFeatureGate.Enabled(features.NodePortLocal) {
		startPort, endPort, err := util.ParsePortRange(o.Config.NodePortLocal.PortRange)
		if err != nil {
			return fmt.Errorf("NodePortLocal portRange is not valid: %v", err)
		}
		o.NplStartPort = startPort
		o.NplEndPort = endPort
	} else if o.Config.NodePortLocal.Enable {
		klog.InfoS("The nodePortLocal.enable config option is set to true, but it will be ignored because the NodePortLocal feature gate is disabled")
	}
	if err := o.validateAntreaIPAMConfig(); err != nil {
		return fmt.Errorf("failed to validate AntreaIPAM config: %v", err)
	}

	if o.Config.DNSServerOverride != "" {
		hostPort := ip.AppendPortIfMissing(o.Config.DNSServerOverride, "53")
		_, _, err := net.SplitHostPort(hostPort)
		if err != nil {
			return fmt.Errorf("dnsServerOverride %s is invalid: %v", o.Config.DNSServerOverride, err)
		}
		o.DnsServerOverride = hostPort
	}
	return nil
}

// resetVMDefaultFeatures sets the feature's default enablement status as false if it is not supported on a VM or a BM.
func (o *Options) resetVMDefaultFeatures() error {
	disabledFeatureMap := make(map[string]bool)
	for f, s := range features.DefaultAntreaFeatureGates {
		if s.Default && !features.SupportedOnExternalNode(f) {
			disabledFeatureMap[string(f)] = false
		}
	}
	return features.DefaultMutableFeatureGate.SetFromMap(disabledFeatureMap)
}

func (o *Options) validateExternalNodeOptions() error {
	var unsupported []string
	for f, enabled := range o.Config.FeatureGates {
		if enabled && !features.SupportedOnExternalNode(featuregate.Feature(f)) {
			unsupported = append(unsupported, f)
		}
	}
	if o.Config.TrafficEncapMode != config.TrafficEncapModeNoEncap.String() {
		unsupported = append(unsupported, o.Config.TrafficEncapMode)
	}
	if o.Config.NodePortLocal.Enable {
		unsupported = append(unsupported, "NodePortLocal")
	}
	if o.Config.EnableIPSecTunnel {
		unsupported = append(unsupported, "EnableIPSecTunnel")
	}
	if unsupported != nil {
		return fmt.Errorf("unsupported features on Virtual Machine: {%s}", strings.Join(unsupported, ", "))
	}
	if err := o.validatePolicyBypassRulesConfig(); err != nil {
		return fmt.Errorf("policyBypassRules configuration is invalid: %w", err)
	}
	return nil
}

func (o *Options) validatePolicyBypassRulesConfig() error {
	if len(o.Config.ExternalNode.PolicyBypassRules) == 0 {
		return nil
	}
	allowedProtocols := sets.NewString("tcp", "udp", "icmp", "ip")
	for _, rule := range o.Config.ExternalNode.PolicyBypassRules {
		if rule.Direction != "ingress" && rule.Direction != "egress" {
			return fmt.Errorf("direction %s for policyBypassRule is invalid", rule.Direction)
		}
		if !allowedProtocols.Has(rule.Protocol) {
			return fmt.Errorf("protocol %s for policyBypassRule is invalid", rule.Protocol)
		}
		if _, _, err := net.ParseCIDR(rule.CIDR); err != nil {
			return fmt.Errorf("cidr %s for policyBypassRule is invalid", rule.CIDR)
		}
		if rule.Port == 0 && (rule.Protocol == "tcp" || rule.Protocol == "udp") {
			return fmt.Errorf("missing port for policyBypassRule when protocol is %s", rule.Protocol)
		}
		if rule.Port < 0 || rule.Port > 65535 {
			return fmt.Errorf("port %d for policyBypassRule is invalid", rule.Port)
		}
	}
	return nil

}
func (o *Options) setExternalNodeDefaultOptions() {
	// Following options are default values for agent running on a Virtual Machine.
	// They are set to avoid unexpected agent crash.
	if o.Config.TrafficEncapMode == "" {
		o.Config.TrafficEncapMode = config.TrafficEncapModeNoEncap.String()
	}
	if o.Config.EnablePrometheusMetrics == nil {
		o.Config.EnablePrometheusMetrics = new(bool)
		*o.Config.EnablePrometheusMetrics = false
	}
	if o.Config.ExternalNode.ExternalNodeNamespace == "" {
		o.Config.ExternalNode.ExternalNodeNamespace = "default"
	}
}
