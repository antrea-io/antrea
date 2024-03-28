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
	"net"
	"os"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/util/sets"
	cliflag "k8s.io/component-base/cli/flag"
	"k8s.io/component-base/featuregate"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/apis"
	"antrea.io/antrea/pkg/cni"
	agentconfig "antrea.io/antrea/pkg/config/agent"
	"antrea.io/antrea/pkg/features"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/util/env"
	"antrea.io/antrea/pkg/util/flowexport"
	"antrea.io/antrea/pkg/util/ip"
	"antrea.io/antrea/pkg/util/yaml"
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
	defaultFlowPollInterval        = "5s"
	defaultActiveFlowExportTimeout = "5s"
	defaultIdleFlowExportTimeout   = "15s"
	defaultIGMPQueryInterval       = 125 * time.Second
	defaultStaleConnectionTimeout  = 5 * time.Minute
	defaultNodeType                = config.K8sNode
	defaultMaxEgressIPsPerNode     = 255
	defaultAuditLogsMaxSize        = 100
	defaultAuditLogsMaxBackups     = 3
	defaultAuditLogsMaxAge         = 28
	defaultAuditLogsCompressed     = true
	defaultPacketInRate            = 500
)

var defaultIGMPQueryVersions = []int{1, 2, 3}

type Options struct {
	// The path of configuration file.
	configFile string
	// The configuration object
	config *agentconfig.AgentConfig
	// tlsCipherSuites is a slice of TLSCipherSuites mapped to input provided by user.
	tlsCipherSuites []string
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
	igmpQueryInterval      time.Duration
	igmpQueryVersions      []uint8
	nplStartPort           int
	nplEndPort             int
	dnsServerOverride      string
	nodeType               config.NodeType

	// enableEgress represents whether Egress should run or not, calculated from its feature gate configuration and
	// whether the traffic mode supports it.
	enableEgress bool
	// enableAntreaProxy indicates whether AntreaProxy should be enabled, based on feature gate AntreaProxy and options
	// AntreaProxy.Enable. This is used to maintain compatibility with the AntreaProxy feature gate, which was promoted
	// to GA in v1.14.
	enableAntreaProxy bool
	// enableNodePortLocal indicates whether NodePortLocal should be enabled or not, based on feature gate NodePortLocal
	// and options NodePortLocal.Enable. This is used to maintain compatibility with the NodePortLocal feature gate, which
	// was promoted to GA in v1.14
	enableNodePortLocal bool

	defaultLoadBalancerMode config.LoadBalancerMode
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
	if o.config.NodeType == config.ExternalNode.String() {
		if err := o.resetVMDefaultFeatures(); err != nil {
			return err
		}
	}
	return nil
}

// validate validates all the required options. It must be called after complete.
func (o *Options) validate(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("no positional arguments are supported")
	}

	if o.config.OVSDatapathType != string(ovsconfig.OVSDatapathSystem) {
		return fmt.Errorf("OVS datapath type %s is not supported", o.config.OVSDatapathType)
	}

	if err := o.validateTLSOptions(); err != nil {
		return err
	}

	if config.ExternalNode.String() == o.config.NodeType && !features.DefaultFeatureGate.Enabled(features.ExternalNode) {
		return fmt.Errorf("nodeType %s requires feature gate ExternalNode to be enabled", o.config.NodeType)
	}

	if o.config.NodeType == config.ExternalNode.String() {
		o.nodeType = config.ExternalNode
		return o.validateExternalNodeOptions()
	} else if o.config.NodeType == config.K8sNode.String() {
		o.nodeType = config.K8sNode
		return o.validateK8sNodeOptions()
	} else {
		return fmt.Errorf("unsupported nodeType %s", o.config.NodeType)
	}
}

func (o *Options) loadConfigFromFile() error {
	data, err := os.ReadFile(o.configFile)
	if err != nil {
		return err
	}

	err = yaml.UnmarshalLenient(data, &o.config)
	if err != nil {
		return fmt.Errorf("failed to decode config file %s: %w", o.configFile, err)
	}
	return nil
}

func (o *Options) setDefaults() {
	if o.config.OVSBridge == "" {
		o.config.OVSBridge = defaultOVSBridge
	}
	if o.config.OVSDatapathType == "" {
		o.config.OVSDatapathType = string(ovsconfig.OVSDatapathSystem)
	}
	if o.config.OVSRunDir == "" {
		o.config.OVSRunDir = ovsconfig.DefaultOVSRunDir
	}
	if o.config.APIPort == 0 {
		o.config.APIPort = apis.AntreaAgentAPIPort
	}
	if o.config.NodeType == "" {
		o.config.NodeType = defaultNodeType.String()
	}
	if o.config.NodeType == config.K8sNode.String() {
		o.setK8sNodeDefaultOptions()
	} else {
		o.setExternalNodeDefaultOptions()
	}
	if o.config.Multicluster.EnableGateway {
		o.setMulticlusterDefaultOptions()
	}
	if o.config.PacketInRate == 0 {
		o.config.PacketInRate = defaultPacketInRate
	}
	o.setAuditLoggingDefaultOptions()
}

func (o *Options) validateTLSOptions() error {
	_, err := cliflag.TLSVersion(o.config.TLSMinVersion)
	if err != nil {
		return fmt.Errorf("invalid TLSMinVersion: %v", err)
	}
	trimmedTLSCipherSuites := strings.ReplaceAll(o.config.TLSCipherSuites, " ", "")
	if trimmedTLSCipherSuites != "" {
		tlsCipherSuites := strings.Split(trimmedTLSCipherSuites, ",")
		_, err = cliflag.TLSCipherSuites(tlsCipherSuites)
		if err != nil {
			return fmt.Errorf("invalid TLSCipherSuites: %v", err)
		}
		o.tlsCipherSuites = tlsCipherSuites
	}
	return nil
}

func (o *Options) validateAntreaProxyConfig(encapMode config.TrafficEncapModeType) error {
	if !features.DefaultFeatureGate.Enabled(features.AntreaProxy) {
		klog.InfoS("Feature gate `AntreaProxy` is deprecated, please use option `antreaProxy.enable` to disable AntreaProxy")
	}
	o.enableAntreaProxy = *o.config.AntreaProxy.Enable && features.DefaultFeatureGate.Enabled(features.AntreaProxy)
	if !o.enableAntreaProxy {
		// Validate Service CIDR configuration if AntreaProxy is not enabled.
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

	ok, defaultLoadBalancerMode := config.GetLoadBalancerModeFromStr(o.config.AntreaProxy.DefaultLoadBalancerMode)
	if !ok {
		return fmt.Errorf("LoadBalancerMode %s is unknown", o.config.AntreaProxy.DefaultLoadBalancerMode)
	}
	if defaultLoadBalancerMode == config.LoadBalancerModeDSR {
		if !features.DefaultFeatureGate.Enabled(features.LoadBalancerModeDSR) {
			return fmt.Errorf("LoadBalancerMode DSR requires feature gate %s to be enabled", features.LoadBalancerModeDSR)
		}
		if encapMode != config.TrafficEncapModeEncap {
			return fmt.Errorf("LoadBalancerMode DSR requires %s mode", config.TrafficEncapModeEncap)
		}
	}
	o.defaultLoadBalancerMode = defaultLoadBalancerMode
	return nil
}

func (o *Options) validateFlowExporterConfig() error {
	if features.DefaultFeatureGate.Enabled(features.FlowExporter) {
		host, port, proto, err := flowexport.ParseFlowCollectorAddr(o.config.FlowExporter.FlowCollectorAddr, defaultFlowCollectorPort, defaultFlowCollectorTransport)
		if err != nil {
			return err
		}
		o.flowCollectorAddr = net.JoinHostPort(host, port)
		o.flowCollectorProto = proto

		// Parse the given flowPollInterval config
		if o.config.FlowExporter.FlowPollInterval != "" {
			flowPollInterval, err := flowexport.ParseFlowIntervalString(o.config.FlowExporter.FlowPollInterval)
			if err != nil {
				return err
			}
			o.pollInterval = flowPollInterval
		}
		// Parse the given activeFlowExportTimeout config
		if o.config.FlowExporter.ActiveFlowExportTimeout != "" {
			o.activeFlowTimeout, err = time.ParseDuration(o.config.FlowExporter.ActiveFlowExportTimeout)
			if err != nil {
				return fmt.Errorf("ActiveFlowExportTimeout is not provided in right format")
			}
			if o.activeFlowTimeout < o.pollInterval {
				o.activeFlowTimeout = o.pollInterval
				klog.Warningf("ActiveFlowExportTimeout must be greater than or equal to FlowPollInterval")
			}
		}
		// Parse the given inactiveFlowExportTimeout config
		if o.config.FlowExporter.IdleFlowExportTimeout != "" {
			o.idleFlowTimeout, err = time.ParseDuration(o.config.FlowExporter.IdleFlowExportTimeout)
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
	} else if o.config.FlowExporter.Enable {
		klog.InfoS("The FlowExporter.enable config option is set to true, but it will be ignored because the FlowExporter feature gate is disabled")
	}
	return nil
}

func (o *Options) validateMulticastConfig(encryptionMode config.TrafficEncryptionModeType) error {
	if features.DefaultFeatureGate.Enabled(features.Multicast) && o.config.Multicast.Enable {
		var err error
		if encryptionMode != config.TrafficEncryptionModeNone {
			return fmt.Errorf("Multicast feature doesn't work with the current encryption mode '%s'", encryptionMode)
		}
		if o.config.Multicast.IGMPQueryInterval != "" {
			o.igmpQueryInterval, err = time.ParseDuration(o.config.Multicast.IGMPQueryInterval)
			if err != nil {
				return err
			}
		}
		if !sets.NewInt(defaultIGMPQueryVersions...).HasAll(o.config.Multicast.IGMPQueryVersions...) {
			return fmt.Errorf("igmpQueryVersions should be a subset of %v", defaultIGMPQueryVersions)
		}
		for _, version := range o.config.Multicast.IGMPQueryVersions {
			o.igmpQueryVersions = append(o.igmpQueryVersions, uint8(version))
		}
		if len(o.config.Multicast.MulticastInterfaces) == 0 && len(o.config.MulticastInterfaces) > 0 {
			klog.InfoS("The multicastInterfaces option is deprecated, please use multicast.multicastInterfaces instead")
			o.config.Multicast.MulticastInterfaces = o.config.MulticastInterfaces
		}
	} else if o.config.Multicast.Enable {
		klog.InfoS("The multicast.enable config option is set to true, but it will be ignored because the Multicast feature gate is disabled")
	}
	return nil
}

func (o *Options) validateAntreaIPAMConfig() error {
	if !o.config.EnableBridgingMode {
		return nil
	}
	if !features.DefaultFeatureGate.Enabled(features.AntreaIPAM) {
		return fmt.Errorf("AntreaIPAM feature gate must be enabled to configure bridging mode")
	}
	if !strings.EqualFold(o.config.TrafficEncapMode, config.TrafficEncapModeNoEncap.String()) {
		return fmt.Errorf("Bridging mode requires 'noEncap' TrafficEncapMode, current: %s",
			o.config.TrafficEncapMode)
	}
	// TODO(gran): support SNAT for Per-Node IPAM Pods
	// SNAT needs to be updated to bypass traffic from AntreaIPAM Pod to Per-Node IPAM Pod
	if !o.config.NoSNAT {
		return fmt.Errorf("Bridging mode requires noSNAT")
	}
	return nil
}

func (o *Options) validateMulticlusterConfig(encapMode config.TrafficEncapModeType, encryptionMode config.TrafficEncryptionModeType) error {
	if !o.config.Multicluster.EnableGateway && !o.config.Multicluster.EnableStretchedNetworkPolicy {
		return nil
	}

	if !features.DefaultFeatureGate.Enabled(features.Multicluster) {
		klog.InfoS("Multicluster feature gate is disabled. Multi-cluster options are ignored")
		return nil
	}

	if !o.config.Multicluster.EnableGateway && o.config.Multicluster.EnableStretchedNetworkPolicy {
		return fmt.Errorf("Multi-cluster Gateway must be enabled to enable StretchedNetworkPolicy")
	}
	_, multiclusterEncryptionMode := config.GetTrafficEncryptionModeFromStr(o.config.Multicluster.TrafficEncryptionMode)
	if multiclusterEncryptionMode == config.TrafficEncryptionModeWireGuard && encryptionMode != config.TrafficEncryptionModeNone {
		return fmt.Errorf("Antrea Multi-cluster WireGuard does not support in-cluster encryption mode %s", o.config.TrafficEncryptionMode)
	}

	if encapMode.SupportsEncap() && encryptionMode == config.TrafficEncryptionModeWireGuard {
		return fmt.Errorf("Multi-cluster Gateway doesn't support in-cluster WireGuard encryption")
	}
	return nil
}

func (o *Options) setK8sNodeDefaultOptions() {
	if o.config.CNISocket == "" {
		o.config.CNISocket = cni.AntreaCNISocketAddr
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
	if o.config.AntreaProxy.Enable == nil {
		o.config.AntreaProxy.Enable = ptr.To(true)
	}
	if o.config.AntreaProxy.ProxyLoadBalancerIPs == nil {
		o.config.AntreaProxy.ProxyLoadBalancerIPs = ptr.To(true)
	}
	if o.config.ServiceCIDR == "" {
		//It's okay to set the default value of this field even when AntreaProxy is enabled and the field is not used.
		o.config.ServiceCIDR = defaultServiceCIDR
	}
	if o.config.AntreaProxy.DefaultLoadBalancerMode == "" {
		o.config.AntreaProxy.DefaultLoadBalancerMode = config.LoadBalancerModeNAT.String()
	}
	if o.config.ClusterMembershipPort == 0 {
		o.config.ClusterMembershipPort = apis.AntreaAgentClusterMembershipPort
	}
	if o.config.EnablePrometheusMetrics == nil {
		o.config.EnablePrometheusMetrics = ptr.To(true)
	}
	if o.config.WireGuard.Port == 0 {
		o.config.WireGuard.Port = apis.WireGuardListenPort
	}

	if o.config.IPsec.AuthenticationMode == "" {
		o.config.IPsec.AuthenticationMode = config.IPsecAuthenticationModePSK.String()
	}

	if features.DefaultFeatureGate.Enabled(features.FlowExporter) {
		if o.config.FlowExporter.FlowCollectorAddr == "" {
			o.config.FlowExporter.FlowCollectorAddr = defaultFlowCollectorAddress
			if o.config.FlowCollectorAddr != "" {
				klog.InfoS("The flowCollectorAddr option is deprecated, please use flowExporter.flowCollectorAddr instead")
				o.config.FlowExporter.FlowCollectorAddr = o.config.FlowCollectorAddr
			}
		}
		if o.config.FlowExporter.FlowPollInterval == "" {
			o.config.FlowExporter.FlowPollInterval = defaultFlowPollInterval
			if o.config.FlowPollInterval != "" {
				klog.InfoS("The flowPollInterval option is deprecated, please use flowExporter.flowPollInterval instead")
				o.config.FlowExporter.FlowPollInterval = o.config.FlowPollInterval
			}
		}
		if o.config.FlowExporter.ActiveFlowExportTimeout == "" {
			o.config.FlowExporter.ActiveFlowExportTimeout = defaultActiveFlowExportTimeout
			if o.config.ActiveFlowExportTimeout != "" {
				klog.InfoS("The activeFlowExportTimeout option is deprecated, please use flowExporter.activeFlowExportTimeout instead")
				o.config.FlowExporter.ActiveFlowExportTimeout = o.config.ActiveFlowExportTimeout
			}
		}
		if o.config.FlowExporter.IdleFlowExportTimeout == "" {
			o.config.FlowExporter.IdleFlowExportTimeout = defaultIdleFlowExportTimeout
			if o.config.IdleFlowExportTimeout != "" {
				klog.InfoS("The idleFlowExportTimeout option is deprecated, please use flowExporter.idleFlowExportTimeout instead")
				o.config.FlowExporter.IdleFlowExportTimeout = o.config.IdleFlowExportTimeout
			}
		}
	}

	if o.config.NodePortLocal.Enable {
		if o.config.NodePortLocal.PortRange == "" {
			o.config.NodePortLocal.PortRange = defaultNPLPortRange
		}
	}

	if features.DefaultFeatureGate.Enabled(features.Multicast) {
		if o.config.Multicast.IGMPQueryInterval == "" {
			o.igmpQueryInterval = defaultIGMPQueryInterval
		}
		if len(o.config.Multicast.IGMPQueryVersions) == 0 {
			o.config.Multicast.IGMPQueryVersions = defaultIGMPQueryVersions
		}
	}

	if features.DefaultFeatureGate.Enabled(features.Multicluster) {
		if o.config.Multicluster.Enable {
			// Multicluster.Enable is deprecated but it may be set by an earlier version
			// deployment manifest. If it is set to true, pass the value to
			// Multicluster.EnableGateway.
			o.config.Multicluster.EnableGateway = true
		}

		if o.config.Multicluster.EnableGateway && o.config.Multicluster.Namespace == "" {
			o.config.Multicluster.Namespace = env.GetPodNamespace()
		}
	}

	if features.DefaultFeatureGate.Enabled(features.Egress) {
		if o.config.Egress.MaxEgressIPsPerNode == 0 {
			o.config.Egress.MaxEgressIPsPerNode = defaultMaxEgressIPsPerNode
		}
	}
}

func (o *Options) validateEgressConfig(encapMode config.TrafficEncapModeType) error {
	if !features.DefaultFeatureGate.Enabled(features.Egress) {
		return nil
	}
	if encapMode != config.TrafficEncapModeEncap {
		klog.InfoS("The Egress feature gate is enabled, but it won't work because it is only applicable to the encap mode")
		return nil
	}
	for _, cidr := range o.config.Egress.ExceptCIDRs {
		_, _, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("Egress Except CIDR %s is invalid", cidr)
		}
	}
	if o.config.Egress.MaxEgressIPsPerNode > defaultMaxEgressIPsPerNode {
		return fmt.Errorf("maxEgressIPsPerNode cannot be greater than %d", defaultMaxEgressIPsPerNode)
	}
	o.enableEgress = true
	return nil
}

func (o *Options) validateK8sNodeOptions() error {
	if o.config.TunnelType != ovsconfig.VXLANTunnel && o.config.TunnelType != ovsconfig.GeneveTunnel &&
		o.config.TunnelType != ovsconfig.GRETunnel && o.config.TunnelType != ovsconfig.STTTunnel {
		return fmt.Errorf("tunnel type %s is invalid", o.config.TunnelType)
	}
	ok, encryptionMode := config.GetTrafficEncryptionModeFromStr(o.config.TrafficEncryptionMode)
	if !ok {
		return fmt.Errorf("TrafficEncryptionMode %s is unknown", o.config.TrafficEncryptionMode)
	}
	ok, encapMode := config.GetTrafficEncapModeFromStr(o.config.TrafficEncapMode)
	if !ok {
		return fmt.Errorf("TrafficEncapMode %s is unknown", o.config.TrafficEncapMode)
	}
	ok, ipsecAuthMode := config.GetIPsecAuthenticationModeFromStr(o.config.IPsec.AuthenticationMode)
	if !ok {
		return fmt.Errorf("IPsec AuthenticationMode %s is unknown", o.config.IPsec.AuthenticationMode)
	}
	if ipsecAuthMode == config.IPsecAuthenticationModeCert && !features.DefaultFeatureGate.Enabled(features.IPsecCertAuth) {
		return fmt.Errorf("IPsec AuthenticationMode %s requires feature gate %s to be enabled", o.config.TrafficEncapMode, features.IPsecCertAuth)
	}

	// Check if the enabled features are supported on the OS.
	if err := o.checkUnsupportedFeatures(); err != nil {
		return err
	}
	if err := o.validateAntreaProxyConfig(encapMode); err != nil {
		return fmt.Errorf("proxy config is invalid: %w", err)
	}
	if encapMode.SupportsNoEncap() {
		// When using NoEncap traffic mode without AntreaProxy, Pod-to-Service traffic is handled by kube-proxy
		// (iptables/ipvs) in the root netns. If the Endpoint is not local the DNATed traffic will be output to
		// the physical network directly without going back to OVS for Egress NetworkPolicy enforcement, which
		// breaks basic security functionality. Therefore, we usually do not allow the NoEncap traffic mode without
		// AntreaProxy. But one can bypass this check and force this feature combination to be allowed, by defining
		// the ALLOW_NO_ENCAP_WITHOUT_ANTREA_PROXY environment variable and setting it to true. This may lead to
		// better performance when using NoEncap if Egress NetworkPolicy enforcement is not required.
		if !o.enableAntreaProxy {
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
	if err := o.validateFlowExporterConfig(); err != nil {
		return fmt.Errorf("failed to validate flow exporter config: %v", err)
	}
	if err := o.validateMulticastConfig(encryptionMode); err != nil {
		return fmt.Errorf("failed to validate multicast config: %v", err)
	}
	if err := o.validateEgressConfig(encapMode); err != nil {
		return fmt.Errorf("failed to validate egress config: %v", err)
	}
	if err := o.validateMulticlusterConfig(encapMode, encryptionMode); err != nil {
		return err
	}
	if err := o.validateNodePortLocalConfig(); err != nil {
		return fmt.Errorf("failed to validate nodePortLocal config: %v", err)
	}
	if err := o.validateAntreaIPAMConfig(); err != nil {
		return fmt.Errorf("failed to validate AntreaIPAM config: %v", err)
	}

	if o.config.DNSServerOverride != "" {
		hostPort := ip.AppendPortIfMissing(o.config.DNSServerOverride, "53")
		_, _, err := net.SplitHostPort(hostPort)
		if err != nil {
			return fmt.Errorf("dnsServerOverride %s is invalid: %v", o.config.DNSServerOverride, err)
		}
		o.dnsServerOverride = hostPort
	}

	if err := o.validateSecondaryNetworkConfig(); err != nil {
		return fmt.Errorf("failed to validate secondary network config: %v", err)
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
	for f, enabled := range o.config.FeatureGates {
		if enabled && !features.SupportedOnExternalNode(featuregate.Feature(f)) {
			unsupported = append(unsupported, f)
		}
	}
	if o.config.TrafficEncapMode != config.TrafficEncapModeNoEncap.String() {
		unsupported = append(unsupported, o.config.TrafficEncapMode)
	}
	if o.config.NodePortLocal.Enable {
		unsupported = append(unsupported, "NodePortLocal")
	}
	if o.config.EnableIPSecTunnel {
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
	if len(o.config.ExternalNode.PolicyBypassRules) == 0 {
		return nil
	}
	allowedProtocols := sets.New[string]("tcp", "udp", "icmp", "ip")
	for _, rule := range o.config.ExternalNode.PolicyBypassRules {
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
	if o.config.TrafficEncapMode == "" {
		o.config.TrafficEncapMode = config.TrafficEncapModeNoEncap.String()
	}
	if o.config.EnablePrometheusMetrics == nil {
		o.config.EnablePrometheusMetrics = new(bool)
		*o.config.EnablePrometheusMetrics = false
	}
	if o.config.ExternalNode.ExternalNodeNamespace == "" {
		o.config.ExternalNode.ExternalNodeNamespace = "default"
	}
}

func (o *Options) setMulticlusterDefaultOptions() {
	_, trafficEncryptionModeType := config.GetTrafficEncryptionModeFromStr(o.config.Multicluster.TrafficEncryptionMode)
	if trafficEncryptionModeType == config.TrafficEncryptionModeWireGuard {
		if o.config.Multicluster.WireGuard.Port == 0 {
			o.config.Multicluster.WireGuard.Port = apis.MulticlusterWireGuardListenPort
		}
	}
}

func (o *Options) setAuditLoggingDefaultOptions() {
	auditLogging := &o.config.AuditLogging
	if auditLogging.MaxSize == 0 {
		auditLogging.MaxSize = defaultAuditLogsMaxAge
	}
	if auditLogging.MaxBackups == nil {
		maxBackups := int32(defaultAuditLogsMaxBackups)
		auditLogging.MaxBackups = &maxBackups
	}
	if auditLogging.MaxAge == nil {
		maxAge := int32(defaultAuditLogsMaxAge)
		auditLogging.MaxAge = &maxAge
	}
	if auditLogging.Compress == nil {
		compress := defaultAuditLogsCompressed
		auditLogging.Compress = &compress
	}
}

func (o *Options) validateSecondaryNetworkConfig() error {
	if !features.DefaultFeatureGate.Enabled(features.SecondaryNetwork) {
		return nil
	}

	if len(o.config.SecondaryNetwork.OVSBridges) == 0 {
		return nil
	}
	if len(o.config.SecondaryNetwork.OVSBridges) > 1 {
		return fmt.Errorf("only one OVS bridge can be specified for secondary network")
	}
	brConfig := o.config.SecondaryNetwork.OVSBridges[0]
	if brConfig.BridgeName == "" {
		return fmt.Errorf("bridge name is not provided for the secondary network OVS bridge")
	}
	if len(brConfig.PhysicalInterfaces) > 8 {
		return fmt.Errorf("at most eight physical interfaces can be specified for the secondary network OVS bridge")
	}

	return nil
}

func (o *Options) validateNodePortLocalConfig() error {
	o.enableNodePortLocal = o.config.NodePortLocal.Enable && features.DefaultFeatureGate.Enabled(features.NodePortLocal)
	if !features.DefaultFeatureGate.Enabled(features.NodePortLocal) {
		klog.InfoS("Feature gate `NodePortLocal` is deprecated, please use option `nodePortLocal.enable` to disable NodePortLocal")
	}
	if o.enableNodePortLocal {
		startPort, endPort, err := parsePortRange(o.config.NodePortLocal.PortRange)
		if err != nil {
			return fmt.Errorf("NodePortLocal portRange is not valid: %v", err)
		}
		o.nplStartPort = startPort
		o.nplEndPort = endPort
	}
	return nil
}
