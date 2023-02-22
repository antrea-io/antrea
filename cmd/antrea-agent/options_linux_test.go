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
	"github.com/stretchr/testify/require"

	"antrea.io/antrea/pkg/agent/config"
	agentconfig "antrea.io/antrea/pkg/config/agent"
)

func TestMulticlusterOptions(t *testing.T) {
	tests := []struct {
		name        string
		mcConfig    agentconfig.MulticlusterConfig
		featureGate bool
		encapMode   string
		expectedErr string
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
			expectedErr: "Multicluster Gateway must be enabled to enable StretchedNetworkPolicy",
		},
		{
			name: "NoEncap",
			mcConfig: agentconfig.MulticlusterConfig{
				EnableGateway: true,
			},
			featureGate: true,
			encapMode:   "NoEncap",
			expectedErr: "Multicluster is only applicable to the encap mode",
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
			o := &Options{config: config}
			require.NoError(t, o.complete(nil))
			err := o.validate(nil)
			if tt.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tt.expectedErr)
			}
			if tt.mcConfig.Enable && tt.featureGate {
				assert.True(t, o.config.Multicluster.EnableGateway)
			}
			if !tt.mcConfig.Enable && !tt.mcConfig.EnableGateway {
				assert.False(t, o.config.Multicluster.EnableGateway)
			}
		})
	}
}

func TestValidateNodeType(t *testing.T) {
	testCases := []struct {
		name             string
		config           string
		expectedNodeType config.NodeType
		expectedErr      string
	}{
		{
			name:             "default",
			config:           "",
			expectedNodeType: config.K8sNode,
		},
		{
			name: "k8s node",
			config: `
nodeType: k8sNode
`,
			expectedNodeType: config.K8sNode,
		},
		{
			name: "external node with feature disabled",
			config: `
nodeType: externalNode
`,
			expectedErr: "nodeType externalNode requires feature gate ExternalNode to be enabled",
		},
		{
			name: "external node with feature enabled",
			config: `
featureGates:
  ExternalNode: true
nodeType: externalNode
`,
			expectedNodeType: config.ExternalNode,
		},
		{
			name: "external node",
			config: `
nodeType: invalidNode
`,
			expectedErr: "unsupported nodeType invalidNode",
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			configFile, cleanup := createTempConfig(t, tt.config)
			defer cleanup()

			o := newOptions()
			o.configFile = configFile
			require.NoError(t, o.complete(nil))
			err := o.validate(nil)
			if tt.expectedErr != "" {
				assert.ErrorContains(t, err, tt.expectedErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedNodeType, o.nodeType)
			}
		})
	}
}
