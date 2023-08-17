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
			name:        "empty input with feature enabled",
			mcConfig:    agentconfig.MulticlusterConfig{},
			featureGate: true,
			expectedErr: "",
		},
		{
			name: "Enable",
			mcConfig: agentconfig.MulticlusterConfig{
				Enable: true,
			},
			featureGate: true,
			expectedErr: "",
		},
		{
			name: "Enable and EnableGateway",
			mcConfig: agentconfig.MulticlusterConfig{
				Enable:        true,
				EnableGateway: true,
			},
			featureGate: true,
			expectedErr: "",
		},
		{
			name: "EnableGateway and EnableStretchedNetworkPolicy",
			mcConfig: agentconfig.MulticlusterConfig{
				EnableGateway:                true,
				EnableStretchedNetworkPolicy: true,
			},
			featureGate: true,
			expectedErr: "",
		},
		{
			name: "EnableGateway false and EnableStretchedNetworkPolicy",
			mcConfig: agentconfig.MulticlusterConfig{
				EnableStretchedNetworkPolicy: true,
			},
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
			if tt.mcConfig.Enable && tt.featureGate {
				assert.True(t, o.config.Multicluster.EnableGateway)
			}
			if !tt.mcConfig.Enable && !tt.mcConfig.EnableGateway {
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
