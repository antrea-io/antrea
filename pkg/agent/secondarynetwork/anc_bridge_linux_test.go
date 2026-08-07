//go:build linux
// +build linux

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

package secondarynetwork

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"antrea.io/antrea/v2/pkg/agent/antreanodeconfig"
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

	ancNoSecondaryNetwork := &crdv1alpha1.AntreaNodeConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "anc-no-secnet"},
		Spec:       crdv1alpha1.AntreaNodeConfigSpec{},
	}
	ancConflictingBridge := &crdv1alpha1.AntreaNodeConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "anc-conflict"},
		Spec: crdv1alpha1.AntreaNodeConfigSpec{
			SecondaryNetwork: &crdv1alpha1.SecondaryNetworkConfig{
				OVSBridges: []crdv1alpha1.OVSBridgeConfig{
					{BridgeName: "br-int"},
				},
			},
		},
	}
	ancMatchingWithBridge := &crdv1alpha1.AntreaNodeConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "anc1"},
		Spec: crdv1alpha1.AntreaNodeConfigSpec{
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
	wantStaticBridge := &agenttypes.OVSBridgeConfig{
		BridgeName:         "br-static",
		PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{{Name: "eth0"}},
	}

	tests := []struct {
		name       string
		snapshot   *antreanodeconfig.Snapshot
		staticCfg  *agentconfig.SecondaryNetworkConfig
		wantBridge *agenttypes.OVSBridgeConfig
	}{
		{
			name:       "AntreaNodeConfig disabled, use static config",
			staticCfg:  staticCfg,
			wantBridge: wantStaticBridge,
		},
		{
			name:      "empty static config and no ANC in snapshot",
			snapshot:  antreanodeconfig.NewSnapshot(nil, nil),
			staticCfg: emptyCfg,
		},
		{
			name:       "no ANC in snapshot falls back to static config",
			snapshot:   antreanodeconfig.NewSnapshot(nil, nil),
			staticCfg:  staticCfg,
			wantBridge: wantStaticBridge,
		},
		{
			name:       "matching ANC ignored when static config is present",
			snapshot:   antreanodeconfig.NewSnapshot(ancMatchingWithBridge, nil),
			staticCfg:  staticCfg,
			wantBridge: wantStaticBridge, // Static config now takes precedence
		},
		{
			name:      "matching ANC is used when static config is empty",
			snapshot:  antreanodeconfig.NewSnapshot(ancMatchingWithBridge, nil),
			staticCfg: emptyCfg,
			wantBridge: &agenttypes.OVSBridgeConfig{
				BridgeName: "br-anc",
				PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
					{Name: "eth1", AllowedVLANs: []string{"100"}},
				},
			},
		},
		{
			name:       "list error falls back to static config",
			snapshot:   antreanodeconfig.NewSnapshot(nil, errors.New("informer list failed")),
			staticCfg:  staticCfg,
			wantBridge: wantStaticBridge,
		},
		{
			name:      "ANC without SecondaryNetwork is ignored",
			snapshot:  antreanodeconfig.NewSnapshot(ancNoSecondaryNetwork, nil),
			staticCfg: emptyCfg,
		},
		{
			name:      "ANC bridge conflicting with primary OVS bridge is ignored",
			snapshot:  antreanodeconfig.NewSnapshot(ancConflictingBridge, nil),
			staticCfg: emptyCfg,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got *agenttypes.OVSBridgeConfig
			if tc.snapshot == nil {
				got = ovsBridgeFromStatic(tc.staticCfg)
			} else {
				got = effectiveSecondaryOVSBridgeFromSnapshot(tc.snapshot, tc.staticCfg, "br-int")
			}
			assert.Equal(t, tc.wantBridge, got)
		})
	}
}

func makeBridge(name string, mcast bool, ifaces ...crdv1alpha1.OVSPhysicalInterfaceConfig) crdv1alpha1.OVSBridgeConfig {
	return crdv1alpha1.OVSBridgeConfig{
		BridgeName:              name,
		EnableMulticastSnooping: mcast,
		PhysicalInterfaces:      ifaces,
	}
}

func makeIface(name string, vlans ...string) crdv1alpha1.OVSPhysicalInterfaceConfig {
	return crdv1alpha1.OVSPhysicalInterfaceConfig{Name: name, AllowedVLANs: vlans}
}

func TestConvertCRDSecondaryNetwork(t *testing.T) {
	const testANCName = "test-antrea-node-config"

	tests := []struct {
		name                 string
		in                   *crdv1alpha1.SecondaryNetworkConfig
		antreaNodeConfigName string
		want                 *agenttypes.SecondaryNetworkConfig
	}{
		{
			name:                 "empty bridges yields nil OVSBridge",
			in:                   &crdv1alpha1.SecondaryNetworkConfig{},
			antreaNodeConfigName: testANCName,
			want:                 nil,
		},
		{
			name: "empty bridge name yields nil OVSBridge",
			in: &crdv1alpha1.SecondaryNetworkConfig{
				OVSBridges: []crdv1alpha1.OVSBridgeConfig{
					{BridgeName: "", PhysicalInterfaces: []crdv1alpha1.OVSPhysicalInterfaceConfig{{Name: "eth0"}}},
				},
			},
			antreaNodeConfigName: "anc-empty-bridge-name",
			want:                 nil,
		},
		{
			name: "interface without AllowedVLANs has nil AllowedVLANs in output",
			in: &crdv1alpha1.SecondaryNetworkConfig{
				OVSBridges: []crdv1alpha1.OVSBridgeConfig{
					makeBridge("br0", false, makeIface("eth0")),
				},
			},
			antreaNodeConfigName: testANCName,
			want: &agenttypes.SecondaryNetworkConfig{
				OVSBridge: &agenttypes.OVSBridgeConfig{
					BridgeName: "br0",
					PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
						{Name: "eth0", AllowedVLANs: nil},
					},
				},
			},
		},
		{
			name: "bridge with no physical interfaces",
			in: &crdv1alpha1.SecondaryNetworkConfig{
				OVSBridges: []crdv1alpha1.OVSBridgeConfig{
					makeBridge("br0", false),
				},
			},
			antreaNodeConfigName: testANCName,
			want: &agenttypes.SecondaryNetworkConfig{
				OVSBridge: &agenttypes.OVSBridgeConfig{
					BridgeName: "br0",
				},
			},
		},
		{
			name: "bridge with multiple interfaces",
			in: &crdv1alpha1.SecondaryNetworkConfig{
				OVSBridges: []crdv1alpha1.OVSBridgeConfig{
					makeBridge("br0", true, makeIface("eth0"), makeIface("eth1", "10")),
				},
			},
			antreaNodeConfigName: testANCName,
			want: &agenttypes.SecondaryNetworkConfig{
				OVSBridge: &agenttypes.OVSBridgeConfig{
					BridgeName:              "br0",
					EnableMulticastSnooping: true,
					PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
						{Name: "eth0", AllowedVLANs: nil},
						{Name: "eth1", AllowedVLANs: []string{"10"}},
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &crdv1alpha1.AntreaNodeConfig{
				ObjectMeta: metav1.ObjectMeta{Name: tc.antreaNodeConfigName},
				Spec: crdv1alpha1.AntreaNodeConfigSpec{
					SecondaryNetwork: tc.in,
				},
			}
			got := applySecondaryNetworkConfig(cfg)
			assert.Equal(t, tc.want, got)
		})
	}
}
