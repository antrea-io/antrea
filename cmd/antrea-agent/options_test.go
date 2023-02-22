// Copyright 2022 Antrea Authors
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
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/pointer"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/apis"
	"antrea.io/antrea/pkg/cni"
	agentconfig "antrea.io/antrea/pkg/config/agent"
	"antrea.io/antrea/pkg/features"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/util/ip"
)

func TestOptionsValidateTLSOptions(t *testing.T) {
	tests := []struct {
		name        string
		config      *agentconfig.AgentConfig
		expectedErr string
	}{
		{
			name: "empty input",
			config: &agentconfig.AgentConfig{
				TLSCipherSuites: "",
				TLSMinVersion:   "",
			},
			expectedErr: "",
		},
		{
			name: "invalid TLSMinVersion",
			config: &agentconfig.AgentConfig{
				TLSCipherSuites: "",
				TLSMinVersion:   "foo",
			},
			expectedErr: "invalid TLSMinVersion",
		},
		{
			name: "invalid TLSCipherSuites",
			config: &agentconfig.AgentConfig{
				TLSCipherSuites: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, foo",
				TLSMinVersion:   "VersionTLS10",
			},
			expectedErr: "invalid TLSCipherSuites",
		},
		{
			name: "valid input",
			config: &agentconfig.AgentConfig{
				TLSCipherSuites: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, TLS_RSA_WITH_AES_128_GCM_SHA256",
				TLSMinVersion:   "VersionTLS12",
			},
			expectedErr: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &Options{config: tt.config}
			err := o.validateTLSOptions()
			if tt.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tt.expectedErr)
			}
		})
	}
}

func TestOptionsValidateAntreaPolicyConfig(t *testing.T) {
	tests := []struct {
		name               string
		config             *agentconfig.AgentConfig
		expectedErr        string
		enableAntreaPolicy bool
		dnsServerOverride  string
	}{
		{
			name:               "default",
			config:             &agentconfig.AgentConfig{},
			enableAntreaPolicy: true,
		},
		{
			name: "disabled",
			config: &agentconfig.AgentConfig{
				FeatureGates: map[string]bool{
					"AntreaPolicy": false,
				},
			},
			enableAntreaPolicy: false,
		},
		{
			name: "enabled",
			config: &agentconfig.AgentConfig{
				FeatureGates: map[string]bool{
					"AntreaProxy": true,
				},
				DNSServerOverride: "10.96.0.10",
			},
			enableAntreaPolicy: true,
			dnsServerOverride:  "10.96.0.10:53",
		},
		{
			name: "error",
			config: &agentconfig.AgentConfig{
				FeatureGates: map[string]bool{
					"AntreaProxy": true,
				},
				DNSServerOverride: "10.96.0.",
			},
			expectedErr: "dnsServerOverride 10.96.0. is invalid",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer features.ResetFeatureGates()
			o := &Options{config: tt.config}
			o.complete(nil)
			err := o.validateAntreaPolicyConfig()
			if tt.expectedErr == "" {
				require.NoError(t, err)
				assert.Equal(t, tt.enableAntreaPolicy, o.enableAntreaPolicy)
				assert.Equal(t, tt.dnsServerOverride, o.dnsServerOverride)
			} else {
				assert.ErrorContains(t, err, tt.expectedErr)
			}
		})
	}
}

func TestOptionsValidateCNIConfig(t *testing.T) {
	tests := []struct {
		name                    string
		config                  *agentconfig.AgentConfig
		expectedErr             string
		transportInterfaceCIDRs []*net.IPNet
	}{
		{
			name:                    "default",
			config:                  &agentconfig.AgentConfig{},
			transportInterfaceCIDRs: []*net.IPNet{},
		},
		{
			name: "valid",
			config: &agentconfig.AgentConfig{
				TransportInterfaceCIDRs: []string{"1.1.1.0/24", "2.2.2.0/24"},
			},
			transportInterfaceCIDRs: []*net.IPNet{ip.MustParseCIDR("1.1.1.0/24"), ip.MustParseCIDR("2.2.2.0/24")},
		},
		{
			name: "invalid",
			config: &agentconfig.AgentConfig{
				TransportInterfaceCIDRs: []string{"1.1.1.0/24", "2.2.0/24"},
			},
			expectedErr: "transportInterfaceCIDRs [1.1.1.0/24 2.2.0/24] is invalid",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer features.ResetFeatureGates()
			o := &Options{config: tt.config}
			o.complete(nil)
			err := o.validateCNIConfig()
			if tt.expectedErr == "" {
				require.NoError(t, err)
				assert.Equal(t, tt.transportInterfaceCIDRs, o.transportInterfaceCIDRs)
			} else {
				assert.ErrorContains(t, err, tt.expectedErr)
			}
		})
	}
}

func TestOptionsValidateAntreaProxyConfig(t *testing.T) {
	tests := []struct {
		name                 string
		config               *agentconfig.AgentConfig
		expectedErr          string
		enableAntreaProxy    bool
		proxyAll             bool
		proxyLoadBalancerIPs bool
		nodePortAddresses    []*net.IPNet
		serviceCIDR          *net.IPNet
		serviceCIDRv6        *net.IPNet
	}{
		{
			name:                 "default",
			config:               &agentconfig.AgentConfig{},
			enableAntreaProxy:    true,
			proxyLoadBalancerIPs: true,
		},
		{
			name: "all enabled",
			config: &agentconfig.AgentConfig{
				AntreaProxy: agentconfig.AntreaProxyConfig{
					ProxyAll:             true,
					NodePortAddresses:    []string{"1.1.1.0/24", "2.2.2.0/24"},
					ProxyLoadBalancerIPs: pointer.BoolPtr(true),
				},
			},
			enableAntreaProxy:    true,
			proxyAll:             true,
			proxyLoadBalancerIPs: true,
			nodePortAddresses:    []*net.IPNet{ip.MustParseCIDR("1.1.1.0/24"), ip.MustParseCIDR("2.2.2.0/24")},
		},
		{
			name: "disabled",
			config: &agentconfig.AgentConfig{
				FeatureGates: map[string]bool{
					"AntreaProxy": false,
				},
				ServiceCIDR:   "10.100.0.0/16",
				ServiceCIDRv6: "2001:ab03:cd04:5503::/64",
			},
			enableAntreaProxy:    false,
			proxyLoadBalancerIPs: true,
			serviceCIDR:          ip.MustParseCIDR("10.100.0.0/16"),
			serviceCIDRv6:        ip.MustParseCIDR("2001:ab03:cd04:5503::/64"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer features.ResetFeatureGates()
			o := &Options{config: tt.config}
			o.complete(nil)
			err := o.validateAntreaProxyConfig()
			if tt.expectedErr == "" {
				require.NoError(t, err)
				assert.Equal(t, tt.enableAntreaProxy, o.enableAntreaProxy)
				assert.Equal(t, tt.proxyAll, o.config.AntreaProxy.ProxyAll)
				assert.Equal(t, tt.proxyLoadBalancerIPs, *o.config.AntreaProxy.ProxyLoadBalancerIPs)
				assert.Equal(t, tt.nodePortAddresses, o.nodePortAddresses)
				assert.Equal(t, tt.serviceCIDR, o.serviceCIDR)
				assert.Equal(t, tt.serviceCIDRv6, o.serviceCIDRv6)
			} else {
				assert.ErrorContains(t, err, tt.expectedErr)
			}
		})
	}
}

func TestOptionsComplete(t *testing.T) {
	testCases := []struct {
		name           string
		config         string
		expectedConfig *agentconfig.AgentConfig
		expectedErr    string
	}{
		{
			name:   "default",
			config: "",
			expectedConfig: &agentconfig.AgentConfig{
				CNISocket:             cni.AntreaCNISocketAddr,
				OVSBridge:             defaultOVSBridge,
				OVSDatapathType:       string(ovsconfig.OVSDatapathSystem),
				OVSRunDir:             ovsconfig.DefaultOVSRunDir,
				HostGateway:           defaultHostGateway,
				TrafficEncapMode:      config.TrafficEncapModeEncap.String(),
				TunnelType:            ovsconfig.GeneveTunnel,
				HostProcPathPrefix:    defaultHostProcPathPrefix,
				ServiceCIDR:           defaultServiceCIDR,
				TrafficEncryptionMode: config.TrafficEncryptionModeNone.String(),
				WireGuard: agentconfig.WireGuardConfig{
					Port: apis.WireGuardListenPort,
				},
				APIPort:                 apis.AntreaAgentAPIPort,
				ClusterMembershipPort:   apis.AntreaAgentClusterMembershipPort,
				EnablePrometheusMetrics: pointer.Bool(true),
				FlowCollectorAddr:       defaultFlowCollectorAddress,
				FlowPollInterval:        defaultFlowPollInterval,
				ActiveFlowExportTimeout: defaultActiveFlowExportTimeout,
				IdleFlowExportTimeout:   defaultIdleFlowExportTimeout,
				NodePortLocal: agentconfig.NodePortLocalConfig{
					PortRange: defaultNPLPortRange,
				},
				Multicast: agentconfig.MulticastConfig{
					IGMPQueryInterval: defaultIGMPQueryInterval,
				},
				AntreaProxy: agentconfig.AntreaProxyConfig{
					ProxyLoadBalancerIPs: pointer.BoolPtr(true),
				},
				Egress: agentconfig.EgressConfig{
					MaxEgressIPsPerNode: defaultMaxEgressIPsPerNode,
				},
				IPsec: agentconfig.IPsecConfig{
					AuthenticationMode: config.IPsecAuthenticationModePSK.String(),
				},
				Multicluster: agentconfig.MulticlusterConfig{},
				NodeType:     config.K8sNode.String(),
				ExternalNode: agentconfig.ExternalNodeConfig{
					ExternalNodeNamespace: defaultExternalNodeNamespace,
				},
				SecondaryNetwork: agentconfig.SecondaryNetworkConfig{},
			},
		},
		{
			name: "error",
			config: `
APIPort: 13000
`,
			expectedErr: "field APIPort not found in type agent.AgentConfig",
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			configFile, cleanup := createTempConfig(t, tt.config)
			defer cleanup()

			o := newOptions()
			o.configFile = configFile
			err := o.complete(nil)
			if tt.expectedErr != "" {
				assert.ErrorContains(t, err, tt.expectedErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedConfig, o.config)
			}
		})
	}
}

func createTempConfig(t *testing.T, configData string) (string, func()) {
	configFile, err := os.CreateTemp("", "config")
	require.NoError(t, err)
	configFile.Write([]byte(configData))
	configFile.Close()
	cleanup := func() {
		os.Remove(configFile.Name())
	}
	return configFile.Name(), cleanup
}
