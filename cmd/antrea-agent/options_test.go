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
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
	"k8s.io/utils/ptr"

	"antrea.io/antrea/pkg/agent/config"
	agentconfig "antrea.io/antrea/pkg/config/agent"
	"antrea.io/antrea/pkg/features"
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

func TestOptionsValidateAntreaProxyConfig(t *testing.T) {
	tests := []struct {
		name                            string
		enabledDSR                      bool
		trafficEncapMode                config.TrafficEncapModeType
		antreaProxyConfig               agentconfig.AntreaProxyConfig
		expectedErr                     string
		expectedDefaultLoadBalancerMode config.LoadBalancerMode
	}{
		{
			name:             "default",
			trafficEncapMode: config.TrafficEncapModeEncap,
			antreaProxyConfig: agentconfig.AntreaProxyConfig{
				Enable:                  ptr.To(true),
				DefaultLoadBalancerMode: config.LoadBalancerModeNAT.String(),
			},
			expectedDefaultLoadBalancerMode: config.LoadBalancerModeNAT,
		},
		{
			name:             "DSR enabled",
			enabledDSR:       true,
			trafficEncapMode: config.TrafficEncapModeEncap,
			antreaProxyConfig: agentconfig.AntreaProxyConfig{
				Enable:                  ptr.To(true),
				DefaultLoadBalancerMode: config.LoadBalancerModeDSR.String(),
			},
			expectedDefaultLoadBalancerMode: config.LoadBalancerModeDSR,
		},
		{
			name: "LoadBalancerModeDSR disabled",
			antreaProxyConfig: agentconfig.AntreaProxyConfig{
				Enable:                  ptr.To(true),
				DefaultLoadBalancerMode: config.LoadBalancerModeDSR.String(),
			},
			trafficEncapMode: config.TrafficEncapModeEncap,
			expectedErr:      "LoadBalancerMode DSR requires feature gate LoadBalancerModeDSR to be enabled",
		},
		{
			name:       "unsupported encap mode",
			enabledDSR: true,
			antreaProxyConfig: agentconfig.AntreaProxyConfig{
				Enable:                  ptr.To(true),
				DefaultLoadBalancerMode: config.LoadBalancerModeDSR.String(),
			},
			trafficEncapMode: config.TrafficEncapModeNoEncap,
			expectedErr:      "LoadBalancerMode DSR requires encap mode",
		},
		{
			name:             "invalid LoadBalancerMode",
			trafficEncapMode: config.TrafficEncapModeEncap,
			antreaProxyConfig: agentconfig.AntreaProxyConfig{
				Enable:                  ptr.To(true),
				DefaultLoadBalancerMode: "drs",
			},
			expectedErr: "LoadBalancerMode drs is unknown",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer featuregatetesting.SetFeatureGateDuringTest(t, features.DefaultFeatureGate, features.LoadBalancerModeDSR, tt.enabledDSR)()

			o := &Options{config: &agentconfig.AgentConfig{
				AntreaProxy: tt.antreaProxyConfig,
			}}
			err := o.validateAntreaProxyConfig(tt.trafficEncapMode)
			if tt.expectedErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tt.expectedErr)
			}
			assert.Equal(t, tt.expectedDefaultLoadBalancerMode, o.defaultLoadBalancerMode)
		})
	}
}

func TestOptionsValidateEgressConfig(t *testing.T) {
	tests := []struct {
		name                 string
		featureGateValue     bool
		trafficEncapMode     config.TrafficEncapModeType
		egressConfig         agentconfig.EgressConfig
		expectedErr          string
		expectedEnableEgress bool
	}{
		{
			name:                 "enabled",
			featureGateValue:     true,
			trafficEncapMode:     config.TrafficEncapModeEncap,
			expectedEnableEgress: true,
		},
		{
			name:                 "unsupported encap mode",
			featureGateValue:     true,
			trafficEncapMode:     config.TrafficEncapModeNoEncap,
			expectedEnableEgress: false,
		},
		{
			name:             "too large maxEgressIPsPerNode",
			featureGateValue: true,
			trafficEncapMode: config.TrafficEncapModeEncap,
			egressConfig: agentconfig.EgressConfig{
				MaxEgressIPsPerNode: 300,
			},
			expectedErr:          "maxEgressIPsPerNode cannot be greater than",
			expectedEnableEgress: false,
		},
		{
			name:             "invalid exceptCIDRs",
			featureGateValue: true,
			trafficEncapMode: config.TrafficEncapModeEncap,
			egressConfig: agentconfig.EgressConfig{
				ExceptCIDRs: []string{"1.1.1.300/32"},
			},
			expectedErr:          "Egress Except CIDR 1.1.1.300/32 is invalid",
			expectedEnableEgress: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer featuregatetesting.SetFeatureGateDuringTest(t, features.DefaultFeatureGate, features.Egress, tt.featureGateValue)()

			o := &Options{config: &agentconfig.AgentConfig{
				Egress: tt.egressConfig,
			}}
			err := o.validateEgressConfig(tt.trafficEncapMode)
			if tt.expectedErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tt.expectedErr)
			}
			assert.Equal(t, tt.expectedEnableEgress, o.enableEgress)
		})
	}
}

func TestOptionsValidateMulticastConfig(t *testing.T) {
	tests := []struct {
		name              string
		igmpQueryVersions []int
		encryptionMode    config.TrafficEncryptionModeType
		expectedErr       error
		expectedVersions  []uint8
	}{
		{
			name:              "wrong versions",
			igmpQueryVersions: []int{1, 3, 4},
			encryptionMode:    config.TrafficEncryptionModeNone,
			expectedErr:       fmt.Errorf("igmpQueryVersions should be a subset of [1 2 3]"),
			expectedVersions:  nil,
		},
		{
			name:              "incorrect encryption mode with IPSec",
			igmpQueryVersions: []int{1, 2},
			encryptionMode:    config.TrafficEncryptionModeIPSec,
			expectedErr:       fmt.Errorf("Multicast feature doesn't work with the current encryption mode 'IPsec'"),
			expectedVersions:  nil,
		},
		{
			name:              "incorrect encryption mode with WireGuard",
			igmpQueryVersions: []int{1, 2},
			encryptionMode:    config.TrafficEncryptionModeWireGuard,
			expectedErr:       fmt.Errorf("Multicast feature doesn't work with the current encryption mode 'WireGuard'"),
			expectedVersions:  nil,
		},
		{
			name:              "incorrect encryption mode with invalid",
			igmpQueryVersions: []int{1, 2},
			encryptionMode:    config.TrafficEncryptionModeInvalid,
			expectedErr:       fmt.Errorf("Multicast feature doesn't work with the current encryption mode 'invalid'"),
			expectedVersions:  nil,
		},
		{
			name:              "no error",
			igmpQueryVersions: []int{1, 2},
			encryptionMode:    config.TrafficEncryptionModeNone,
			expectedErr:       nil,
			expectedVersions:  []uint8{1, 2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer featuregatetesting.SetFeatureGateDuringTest(t, features.DefaultFeatureGate, features.Multicast, true)()
			o := &Options{config: &agentconfig.AgentConfig{
				Multicast: agentconfig.MulticastConfig{
					Enable:            true,
					IGMPQueryVersions: tt.igmpQueryVersions},
			}}
			err := o.validateMulticastConfig(tt.encryptionMode)
			require.Equal(t, tt.expectedErr, err)
			if err != nil {
				assert.Equal(t, tt.expectedVersions, o.igmpQueryVersions)
			}
		})
	}
}

func TestOptionsValidateSecondaryNetworkConfig(t *testing.T) {
	tests := []struct {
		name               string
		featureGateValue   bool
		ovsBridges         []string
		physicalInterfaces []string
		expectedErr        string
	}{
		{
			name:       "featureGate off",
			ovsBridges: []string{"br1"},
		},
		{
			name:             "no bridge",
			featureGateValue: true,
		},
		{
			name:             "one bridge",
			featureGateValue: true,
			ovsBridges:       []string{"br1"},
		},
		{
			name:               "one interface",
			featureGateValue:   true,
			ovsBridges:         []string{"br1"},
			physicalInterfaces: []string{"eth1"},
		},
		{
			name:             "two bridges",
			featureGateValue: true,
			ovsBridges:       []string{"br1", "br2"},
			expectedErr:      "only one OVS bridge can be specified for secondary network",
		},
		{
			name:             "no bridge name",
			featureGateValue: true,
			ovsBridges:       []string{""},
			expectedErr:      "bridge name is not provided for the secondary network OVS bridge",
		},
		{
			name:               "two interfaces",
			featureGateValue:   true,
			ovsBridges:         []string{"br1"},
			physicalInterfaces: []string{"eth1", "eth2", "eth3", "eth4", "eth5", "eth6", "eth7", "eth8", "eth9"},
			expectedErr:        "at most eight physical interfaces can be specified for the secondary network OVS bridge",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer featuregatetesting.SetFeatureGateDuringTest(t, features.DefaultFeatureGate, features.SecondaryNetwork, tc.featureGateValue)()

			o := &Options{config: &agentconfig.AgentConfig{}}
			for _, brName := range tc.ovsBridges {
				br := agentconfig.OVSBridgeConfig{BridgeName: brName}
				br.PhysicalInterfaces = tc.physicalInterfaces
				o.config.SecondaryNetwork.OVSBridges = append(o.config.SecondaryNetwork.OVSBridges, br)
			}

			err := o.validateSecondaryNetworkConfig()
			if tc.expectedErr == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err, tc.expectedErr)
			}
		})
	}
}
