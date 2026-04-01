// Copyright 2026 Antrea Authors
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

package antreanodeconfig

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	agenttypes "antrea.io/antrea/v2/pkg/agent/types"
	crdv1alpha1 "antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
	agentconfig "antrea.io/antrea/v2/pkg/config/agent"
)

func TestEffectiveSecondaryOVSBridge(t *testing.T) {
	staticCfg := &agentconfig.SecondaryNetworkConfig{
		OVSBridges: []agentconfig.OVSBridgeConfig{
			{BridgeName: "br-static", PhysicalInterfaces: []string{"eth0"}},
		},
	}
	emptyCfg := &agentconfig.SecondaryNetworkConfig{}

	workerNode := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node1", Labels: map[string]string{"role": "worker"}}}

	ancTime0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ancMatchingWithBridge := &crdv1alpha1.AntreaNodeConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "anc1", CreationTimestamp: metav1.NewTime(ancTime0)},
		Spec: crdv1alpha1.AntreaNodeConfigSpec{
			NodeSelector: metav1.LabelSelector{MatchLabels: map[string]string{"role": "worker"}},
			SecondaryNetwork: &crdv1alpha1.SecondaryNetworkConfig{
				OVSBridges: []crdv1alpha1.OVSBridgeConfig{
					{
						BridgeName: "br-anc",
						PhysicalInterfaces: []crdv1alpha1.OVSPhysicalInterfaceConfig{
							{Name: "eth1", AllowedVLANs: []string{"100"}},
						},
					},
				},
			},
		},
	}
	ancMatchingNoBridge := &crdv1alpha1.AntreaNodeConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "anc2", CreationTimestamp: metav1.NewTime(ancTime0)},
		Spec: crdv1alpha1.AntreaNodeConfigSpec{
			NodeSelector:     metav1.LabelSelector{MatchLabels: map[string]string{"role": "worker"}},
			SecondaryNetwork: &crdv1alpha1.SecondaryNetworkConfig{},
		},
	}
	ancNonMatching := &crdv1alpha1.AntreaNodeConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "anc3", CreationTimestamp: metav1.NewTime(ancTime0)},
		Spec: crdv1alpha1.AntreaNodeConfigSpec{
			NodeSelector: metav1.LabelSelector{MatchLabels: map[string]string{"role": "control-plane"}},
			SecondaryNetwork: &crdv1alpha1.SecondaryNetworkConfig{
				OVSBridges: []crdv1alpha1.OVSBridgeConfig{{BridgeName: "br-other"}},
			},
		},
	}

	tests := []struct {
		name       string
		node       *corev1.Node
		ancConfigs []*crdv1alpha1.AntreaNodeConfig
		listErr    error
		useANC     bool
		staticCfg  *agentconfig.SecondaryNetworkConfig
		wantBridge *agenttypes.OVSBridgeConfig
	}{
		{
			name:       "rule 1: AntreaNodeConfig disabled, use static config",
			node:       workerNode,
			useANC:     false,
			staticCfg:  staticCfg,
			wantBridge: &agenttypes.OVSBridgeConfig{BridgeName: "br-static", PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{{Name: "eth0"}}},
		},
		{
			name:       "rule 1: no matching ANC, use static config",
			node:       workerNode,
			ancConfigs: []*crdv1alpha1.AntreaNodeConfig{ancNonMatching},
			useANC:     true,
			staticCfg:  staticCfg,
			wantBridge: &agenttypes.OVSBridgeConfig{BridgeName: "br-static", PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{{Name: "eth0"}}},
		},
		{
			name:       "rule 1: empty static config and no matching ANC",
			node:       workerNode,
			ancConfigs: []*crdv1alpha1.AntreaNodeConfig{ancNonMatching},
			useANC:     true,
			staticCfg:  emptyCfg,
			wantBridge: nil,
		},
		{
			name:       "rule 2: matching ANC overrides static config",
			node:       workerNode,
			ancConfigs: []*crdv1alpha1.AntreaNodeConfig{ancMatchingWithBridge},
			useANC:     true,
			staticCfg:  staticCfg,
			wantBridge: &agenttypes.OVSBridgeConfig{
				BridgeName: "br-anc",
				PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
					{Name: "eth1", AllowedVLANs: []string{"100"}},
				},
			},
		},
		{
			name:       "rule 2: matching ANC with no bridge yields nil",
			node:       workerNode,
			ancConfigs: []*crdv1alpha1.AntreaNodeConfig{ancMatchingNoBridge},
			useANC:     true,
			staticCfg:  staticCfg,
			wantBridge: nil,
		},
		{
			name:       "nil node returns nil when ANC enabled — do not prefer static over CR",
			node:       nil,
			ancConfigs: []*crdv1alpha1.AntreaNodeConfig{ancMatchingWithBridge},
			useANC:     true,
			staticCfg:  staticCfg,
			wantBridge: nil,
		},
		{
			name:       "list error falls back to static config",
			node:       workerNode,
			ancConfigs: []*crdv1alpha1.AntreaNodeConfig{ancMatchingWithBridge},
			listErr:    errors.New("informer list failed"),
			useANC:     true,
			staticCfg:  staticCfg,
			wantBridge: &agenttypes.OVSBridgeConfig{BridgeName: "br-static", PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{{Name: "eth0"}}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := EffectiveSecondaryOVSBridge(tc.node, tc.ancConfigs, tc.listErr, tc.useANC, tc.staticCfg)
			if tc.wantBridge == nil {
				assert.Nil(t, got)
			} else {
				require.NotNil(t, got)
				assert.Equal(t, tc.wantBridge.BridgeName, got.BridgeName)
				assert.Equal(t, tc.wantBridge.EnableMulticastSnooping, got.EnableMulticastSnooping)
				assert.Equal(t, tc.wantBridge.PhysicalInterfaces, got.PhysicalInterfaces)
			}
		})
	}
}
