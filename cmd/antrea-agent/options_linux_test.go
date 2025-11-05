//go:build linux
// +build linux

// Copyright 2023 Antrea Authors
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
	"testing"

	"github.com/stretchr/testify/assert"

	agentconfig "antrea.io/antrea/pkg/config/agent"
	"antrea.io/antrea/pkg/features"
)

func TestMulticlusterOptions(t *testing.T) {
	tests := []struct {
		name           string
		mcConfig       agentconfig.MulticlusterConfig
		featureGate    bool
		encapMode      string
		encryptionMode string
		expectedErr    string
	}{
		{
			name:        "empty input",
			mcConfig:    agentconfig.MulticlusterConfig{},
			expectedErr: "",
		},
		{
			name: "correct port with feature enabled",
			mcConfig: agentconfig.MulticlusterConfig{
				WireGuard: agentconfig.WireGuardConfig{Port: 51821},
			},
			featureGate: true,
			expectedErr: "",
		},
		{
			name: "invalid multi-cluster WireGuard port",
			mcConfig: agentconfig.MulticlusterConfig{
				EnableGateway:         true,
				TrafficEncryptionMode: "wireGuard",
				WireGuard:             agentconfig.WireGuardConfig{Port: 70000},
			},
			featureGate: true,
			encapMode:   "encap",
			expectedErr: "multicluster.wireGuard.port is invalid: port 70000 is out of range, valid range is 1-65535",
		},
		{
			name: "EnableGateway and EnableStretchedNetworkPolicy",
			mcConfig: agentconfig.MulticlusterConfig{
				EnableGateway:                true,
				EnableStretchedNetworkPolicy: true,
				WireGuard:                    agentconfig.WireGuardConfig{Port: 51821},
			},
			encapMode:   "encap",
			featureGate: true,
			expectedErr: "",
		},
		{
			name: "EnableGateway false and EnableStretchedNetworkPolicy",
			mcConfig: agentconfig.MulticlusterConfig{
				EnableStretchedNetworkPolicy: true,
				WireGuard:                    agentconfig.WireGuardConfig{Port: 51821},
			},
			encapMode:   "encap",
			featureGate: true,
			expectedErr: "Multi-cluster Gateway must be enabled to enable StretchedNetworkPolicy",
		},
		{
			name: "Multicluster with in-cluster WireGuard Encryption",
			mcConfig: agentconfig.MulticlusterConfig{
				EnableGateway: true,
			},
			featureGate:    true,
			encapMode:      "encap",
			encryptionMode: "wireguard",
			expectedErr:    "Multi-cluster Gateway doesn't support in-cluster WireGuard encryption",
		},
		{
			name: "NoEncap and feature disabled",
			mcConfig: agentconfig.MulticlusterConfig{
				EnableGateway: true,
			},
			encapMode:   "noEncap",
			expectedErr: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &agentconfig.AgentConfig{
				FeatureGates:     map[string]bool{"Multicluster": tt.featureGate},
				TrafficEncapMode: tt.encapMode,
				Multicluster:     tt.mcConfig,
			}
			if tt.encryptionMode != "" {
				config.TrafficEncryptionMode = tt.encryptionMode
			}
			o := &Options{config: config, enableAntreaProxy: true}
			features.DefaultMutableFeatureGate.SetFromMap(o.config.FeatureGates)
			o.setDefaults()
			if tt.mcConfig.EnableGateway && tt.featureGate {
				assert.True(t, o.config.Multicluster.EnableGateway)
			}
			if !tt.mcConfig.EnableGateway {
				assert.False(t, o.config.Multicluster.EnableGateway)
			}

			err := o.validate(nil)
			if tt.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tt.expectedErr)
			}
		})
	}
}

func TestValidateK8sNodeOptions(t *testing.T) {
	tests := []struct {
		name                  string
		clusterPort           int
		wireGuardPort         int
		tunnelPort            int32
		trafficEncapMode      string
		dnsServerOverride     string
		kubeAPIServerOverride string
		expectedErr           string
	}{
		{
			name:                  "valid options",
			clusterPort:           10351,
			wireGuardPort:         51821,
			tunnelPort:            10000,
			dnsServerOverride:     "localhost:53",
			kubeAPIServerOverride: "localhost:443",
			expectedErr:           "",
		},
		{
			name:                  "invalid encap mode with WireGuard",
			clusterPort:           10351,
			wireGuardPort:         51821,
			tunnelPort:            10000,
			dnsServerOverride:     "localhost:53",
			kubeAPIServerOverride: "localhost:443",
			trafficEncapMode:      "hybrid",
			expectedErr:           "WireGuard is not applicable to the hybrid mode",
		},
		{
			name:                  "invalid wireGuardPort",
			clusterPort:           10351,
			wireGuardPort:         70000,
			tunnelPort:            10000,
			dnsServerOverride:     "localhost:53",
			kubeAPIServerOverride: "localhost:443",
			expectedErr:           "wireGuard.port is invalid: port 70000 is out of range, valid range is 1-65535",
		},
		{
			name:                  "invalid clusterPort",
			clusterPort:           70000,
			wireGuardPort:         51821,
			tunnelPort:            10000,
			dnsServerOverride:     "localhost:53",
			kubeAPIServerOverride: "localhost:443",
			expectedErr:           "clusterPort is invalid: port 70000 is out of range, valid range is 1-65535",
		},
		{
			name:                  "invalid tunnelPort",
			clusterPort:           10351,
			wireGuardPort:         51821,
			tunnelPort:            70000,
			dnsServerOverride:     "localhost:53",
			kubeAPIServerOverride: "localhost:443",
			expectedErr:           "tunnelPort is invalid: port 70000 is out of range, valid range is 1-65535",
		},
		{
			name:                  "invalid port in dnsServerOverride",
			clusterPort:           10351,
			wireGuardPort:         51821,
			tunnelPort:            10000,
			dnsServerOverride:     "localhost:abc",
			kubeAPIServerOverride: "localhost:443",
			expectedErr:           "port in dnsServerOverride localhost:abc is invalid: invalid port abc: strconv.Atoi: parsing \"abc\": invalid syntax",
		},
		{
			name:                  "invalid port in kubeAPIServerOverride",
			clusterPort:           10351,
			wireGuardPort:         51821,
			tunnelPort:            10000,
			dnsServerOverride:     "localhost:53",
			kubeAPIServerOverride: "localhost:abc",
			expectedErr:           "error in kubeAPIServerOverride 'localhost:abc': invalid port abc: strconv.Atoi: parsing \"abc\": invalid syntax",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enable := true
			config := &agentconfig.AgentConfig{
				TunnelPort:            tt.tunnelPort,
				NodeType:              defaultNodeType.String(),
				TunnelType:            defaultTunnelType,
				TrafficEncapMode:      "encap",
				TrafficEncryptionMode: "WireGuard",
				WireGuard: agentconfig.WireGuardConfig{
					Port: tt.wireGuardPort,
				},
				IPsec: agentconfig.IPsecConfig{AuthenticationMode: "psk"},
				AntreaProxy: agentconfig.AntreaProxyConfig{
					Enable:                  &enable,
					DefaultLoadBalancerMode: "nat",
				},
				DNSServerOverride:     tt.dnsServerOverride,
				KubeAPIServerOverride: tt.kubeAPIServerOverride,
				ClusterMembershipPort: tt.clusterPort,
				HostNetworkMode:       "iptables",
			}
			config.TrafficEncapMode = "encap"
			if tt.trafficEncapMode != "" {
				config.TrafficEncapMode = tt.trafficEncapMode
			}
			o := &Options{config: config, enableAntreaProxy: true}
			err := o.validateK8sNodeOptions()
			if tt.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tt.expectedErr)
			}
		})
	}
}
