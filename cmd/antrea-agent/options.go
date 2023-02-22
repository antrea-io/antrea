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
	"gopkg.in/yaml.v2"
	cliflag "k8s.io/component-base/cli/flag"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"
	"k8s.io/utils/pointer"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/apis"
	"antrea.io/antrea/pkg/cni"
	agentconfig "antrea.io/antrea/pkg/config/agent"
	"antrea.io/antrea/pkg/features"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/util/env"
	"antrea.io/antrea/pkg/util/flowexport"
	"antrea.io/antrea/pkg/util/ip"
)

const (
	defaultOVSBridge          = "br-int"
	defaultHostGateway        = "antrea-gw0"
	defaultHostProcPathPrefix = "/host"
	defaultServiceCIDR        = "10.96.0.0/12"

	defaultFlowCollectorAddress    = "flow-aggregator/flow-aggregator:4739:tls"
	defaultFlowCollectorTransport  = "tls"
	defaultFlowCollectorPort       = "4739"
	defaultFlowPollInterval        = "5s"
	defaultActiveFlowExportTimeout = "30s"
	defaultIdleFlowExportTimeout   = "15s"
	defaultStaleConnectionTimeout  = 5 * time.Minute

	defaultIGMPQueryInterval     = "125s"
	defaultNPLPortRange          = "61000-62000"
	defaultMaxEgressIPsPerNode   = 255
	defaultExternalNodeNamespace = "default"
)

type Options struct {
	// configFile is the path of configuration file.
	configFile string
	// config is the configuration object parsed from configuration file.
	config *agentconfig.AgentConfig

	// The following fields contains the configuration values that have been validated and converted to Go types from
	// the configuration file.
	// tlsCipherSuites is a slice of TLSCipherSuites mapped to input provided by user.
	tlsCipherSuites []string

	enableFlowExporter bool
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
	nplStartPort           int
	nplEndPort             int
	dnsServerOverride      string
	nodeType               config.NodeType

	ovsDatapathType         ovsconfig.OVSDatapathType
	tunnelType              ovsconfig.TunnelType
	trafficEncapMode        config.TrafficEncapModeType
	trafficEncryptionMode   config.TrafficEncryptionModeType
	ipsecAuthenticationMode config.IPsecAuthenticationMode
	transportInterfaceCIDRs []*net.IPNet

	enableAntreaProxy bool
	nodePortAddresses []*net.IPNet

	enableAntreaPolicy    bool
	enableL7NetworkPolicy bool

	enableEgress bool
	exceptCIDRs  []*net.IPNet

	enableMulticast bool

	enableTrafficControl    bool
	enableServiceExternalIP bool
	enableAntreaIPAM        bool
	enableSecondaryNetwork  bool

	serviceCIDR   *net.IPNet
	serviceCIDRv6 *net.IPNet

	policyBypassRules []*types.PolicyBypassRule
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

	// Validate the Node type first, so we know what configs need to validate according to the Node type.
	if err := o.validateNodeType(); err != nil {
		return err
	}

	// Common options which should be validated regardless of the Node type.
	validators := []func() error{
		o.validateTLSOptions,
		o.validateOVSConfig,
		o.validateAntreaPolicyConfig,
	}
	// Only validate configs applicable to the corresponding Node type.
	if o.nodeType == config.K8sNode {
		validators = append(validators,
			o.validateTrafficModes, // must be validated first as feature specific validation may depend on it.
			o.validateCNIConfig,
			o.validateL7NetworkPolicyConfig,
			o.validateAntreaProxyConfig,
			o.validateFlowExporterConfig,
			o.validateMulticastConfig,
			o.validateMulticlusterConfig,
			o.validateNodePortLocalConfig,
			o.validateAntreaIPAMConfig,
			o.validateEgressConfig,
			o.validateTrafficControlConfig,
			o.validateServiceExternalIP,
		)
	} else if o.nodeType == config.ExternalNode {
		validators = append(validators,
			o.validatePolicyBypassRulesConfig,
		)
	}

	for _, validator := range validators {
		if err := validator(); err != nil {
			return err
		}
	}
	return nil
}

func (o *Options) loadConfigFromFile() error {
	data, err := os.ReadFile(o.configFile)
	if err != nil {
		return err
	}

	return yaml.UnmarshalStrict(data, &o.config)
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
		o.config.NodeType = config.K8sNode.String()
	}
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
		o.config.TunnelType = ovsconfig.GeneveTunnel
	}
	if o.config.HostProcPathPrefix == "" {
		o.config.HostProcPathPrefix = defaultHostProcPathPrefix
	}
	if o.config.AntreaProxy.ProxyLoadBalancerIPs == nil {
		o.config.AntreaProxy.ProxyLoadBalancerIPs = new(bool)
		*o.config.AntreaProxy.ProxyLoadBalancerIPs = true
	}
	if o.config.ServiceCIDR == "" {
		o.config.ServiceCIDR = defaultServiceCIDR
	}
	if o.config.ClusterMembershipPort == 0 {
		o.config.ClusterMembershipPort = apis.AntreaAgentClusterMembershipPort
	}
	if o.config.EnablePrometheusMetrics == nil {
		o.config.EnablePrometheusMetrics = pointer.BoolPtr(true)
	}
	if o.config.WireGuard.Port == 0 {
		o.config.WireGuard.Port = apis.WireGuardListenPort
	}
	if o.config.IPsec.AuthenticationMode == "" {
		o.config.IPsec.AuthenticationMode = config.IPsecAuthenticationModePSK.String()
	}
	if o.config.FlowCollectorAddr == "" {
		o.config.FlowCollectorAddr = defaultFlowCollectorAddress
	}
	if o.config.FlowPollInterval == "" {
		o.config.FlowPollInterval = defaultFlowPollInterval
	}
	if o.config.ActiveFlowExportTimeout == "" {
		o.config.ActiveFlowExportTimeout = defaultActiveFlowExportTimeout
	}
	if o.config.IdleFlowExportTimeout == "" {
		o.config.IdleFlowExportTimeout = defaultIdleFlowExportTimeout
	}
	if o.config.NodePortLocal.PortRange == "" && o.config.NPLPortRange == "" {
		o.config.NodePortLocal.PortRange = defaultNPLPortRange
	}
	if o.config.Multicast.IGMPQueryInterval == "" {
		o.config.Multicast.IGMPQueryInterval = defaultIGMPQueryInterval
	}
	if o.config.Egress.MaxEgressIPsPerNode == 0 {
		o.config.Egress.MaxEgressIPsPerNode = defaultMaxEgressIPsPerNode
	}
	if o.config.ExternalNode.ExternalNodeNamespace == "" {
		o.config.ExternalNode.ExternalNodeNamespace = defaultExternalNodeNamespace
	}
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

func (o *Options) validateAntreaProxyConfig() error {
	if !features.DefaultFeatureGate.Enabled(features.AntreaProxy) {
		klog.InfoS("AntreaProxy is not enabled. NetworkPolicies might not be enforced correctly for Service traffic!")
		if o.trafficEncapMode.SupportsNoEncap() {
			// When using NoEncap traffic mode without AntreaProxy, Pod-to-Service traffic is handled by kube-proxy
			// (iptables/ipvs) in the root netns. If the Endpoint is not local the DNATed traffic will be output to
			// the physical network directly without going back to OVS for Egress NetworkPolicy enforcement, which
			// breaks basic security functionality. Therefore, we usually do not allow the NoEncap traffic mode without
			// AntreaProxy. But one can bypass this check and force this feature combination to be allowed, by defining
			// the ALLOW_NO_ENCAP_WITHOUT_ANTREA_PROXY environment variable and setting it to true. This may lead to
			// better performance when using NoEncap if Egress NetworkPolicy enforcement is not required.
			if env.GetAllowNoEncapWithoutAntreaProxy() {
				klog.InfoS("Disabling AntreaProxy in NoEncap mode will prevent Egress NetworkPolicy rules from being enforced correctly")
			} else {
				return fmt.Errorf("TrafficEncapMode %s requires AntreaProxy to be enabled", o.config.TrafficEncapMode)
			}
		}
		// Validate service CIDR configuration if AntreaProxy is not enabled.
		// TODO: replace it with ServiceCIDRProvider.
		var err error
		if o.config.ServiceCIDR != "" {
			if _, o.serviceCIDR, err = net.ParseCIDR(o.config.ServiceCIDR); err != nil {
				return fmt.Errorf("Service CIDR %s is invalid", o.config.ServiceCIDR)
			}
		}
		if o.config.ServiceCIDRv6 != "" {
			if _, o.serviceCIDRv6, err = net.ParseCIDR(o.config.ServiceCIDRv6); err != nil {
				return fmt.Errorf("Service CIDR v6 %s is invalid", o.config.ServiceCIDRv6)
			}
		}
	} else {
		if o.config.AntreaProxy.ProxyAll {
			var err error
			if o.nodePortAddresses, err = utilnet.ParseCIDRs(o.config.AntreaProxy.NodePortAddresses); err != nil {
				return fmt.Errorf("nodePortAddresses %s is invalid: %w", o.config.AntreaProxy.NodePortAddresses, err)
			}
		}
		o.enableAntreaProxy = true
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
		o.enableFlowExporter = true
	}
	return nil
}

func (o *Options) validateOVSConfig() error {
	if o.config.OVSDatapathType != string(ovsconfig.OVSDatapathSystem) {
		return fmt.Errorf("OVS datapath type %s is not supported", o.config.OVSDatapathType)
	}
	o.ovsDatapathType = ovsconfig.OVSDatapathType(o.config.OVSDatapathType)
	return nil
}

func (o *Options) validateAntreaPolicyConfig() error {
	if !features.DefaultFeatureGate.Enabled(features.AntreaPolicy) {
		return nil
	}
	if o.config.DNSServerOverride != "" {
		hostPort := ip.AppendPortIfMissing(o.config.DNSServerOverride, "53")
		_, _, err := net.SplitHostPort(hostPort)
		if err != nil {
			return fmt.Errorf("dnsServerOverride %s is invalid: %v", o.config.DNSServerOverride, err)
		}
		o.dnsServerOverride = hostPort
	}
	o.enableAntreaPolicy = true
	return nil
}

func (o *Options) validateCNIConfig() error {
	cidrs, err := utilnet.ParseCIDRs(o.config.TransportInterfaceCIDRs)
	if err != nil {
		return fmt.Errorf("transportInterfaceCIDRs %v is invalid: %v", o.config.TransportInterfaceCIDRs, err)
	}
	o.transportInterfaceCIDRs = cidrs
	return nil
}

func (o *Options) validateTrafficControlConfig() error {
	o.enableTrafficControl = features.DefaultFeatureGate.Enabled(features.TrafficControl)
	return nil
}

func (o *Options) validateNodePortLocalConfig() error {
	if !features.DefaultFeatureGate.Enabled(features.NodePortLocal) {
		if o.config.NodePortLocal.Enable {
			klog.InfoS("The nodePortLocal.enable config option is set to true, but it will be ignored because the NodePortLocal feature gate is disabled")
		}
		return nil
	}
	if !o.config.NodePortLocal.Enable {
		return nil
	}
	portRange := o.config.NodePortLocal.PortRange
	if portRange == "" && o.config.NPLPortRange != "" {
		klog.InfoS("The nplPortRange option is deprecated, please use nodePortLocal.portRange instead")
		portRange = o.config.NPLPortRange
	}
	startPort, endPort, err := parsePortRange(portRange)
	if err != nil {
		return fmt.Errorf("NodePortLocal portRange is not valid: %v", err)
	}
	o.nplStartPort = startPort
	o.nplEndPort = endPort
	return nil
}
