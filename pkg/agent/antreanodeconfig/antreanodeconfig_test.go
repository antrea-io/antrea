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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	agenttypes "antrea.io/antrea/pkg/agent/types"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
)

func makeNode(labels map[string]string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "node1",
			Labels: labels,
		},
	}
}

func makeANC(name string, ts time.Time, nodeSelector map[string]string, secNet *crdv1alpha1.SecondaryNetworkConfig) *crdv1alpha1.AntreaNodeConfig {
	return &crdv1alpha1.AntreaNodeConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			CreationTimestamp: metav1.NewTime(ts),
		},
		Spec: crdv1alpha1.AntreaNodeConfigSpec{
			NodeSelector: metav1.LabelSelector{
				MatchLabels: nodeSelector,
			},
			SecondaryNetwork: secNet,
		},
	}
}

func makeBridge(name string, mcast bool, ifaces ...crdv1alpha1.PhysicalInterfaceConfig) crdv1alpha1.OVSBridgeConfig {
	return crdv1alpha1.OVSBridgeConfig{
		BridgeName:              name,
		EnableMulticastSnooping: mcast,
		PhysicalInterfaces:      ifaces,
	}
}

func makeIface(name string, vlans ...string) crdv1alpha1.PhysicalInterfaceConfig {
	return crdv1alpha1.PhysicalInterfaceConfig{Name: name, AllowedVLANs: vlans}
}

var (
	t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 = t0.Add(time.Minute)
	t2 = t0.Add(2 * time.Minute)
)

func TestSelectMatchingConfigs(t *testing.T) {
	node := makeNode(map[string]string{"role": "worker", "zone": "us-east"})

	anc1 := makeANC("anc1", t0, map[string]string{"role": "worker"}, nil)
	anc2 := makeANC("anc2", t1, map[string]string{"role": "control-plane"}, nil)
	anc3 := makeANC("anc3", t2, map[string]string{"zone": "us-east"}, nil)
	ancInvalidSel := &crdv1alpha1.AntreaNodeConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "invalid"},
		Spec: crdv1alpha1.AntreaNodeConfigSpec{
			NodeSelector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "x", Operator: "BadOp", Values: []string{"v"}},
				},
			},
		},
	}

	tests := []struct {
		name      string
		configs   []*crdv1alpha1.AntreaNodeConfig
		wantLen   int
		wantOrder []string
	}{
		{
			name:    "no configs",
			configs: nil,
			wantLen: 0,
		},
		{
			name:    "one matching",
			configs: []*crdv1alpha1.AntreaNodeConfig{anc1},
			wantLen: 1,
		},
		{
			name:    "one non-matching",
			configs: []*crdv1alpha1.AntreaNodeConfig{anc2},
			wantLen: 0,
		},
		{
			name:      "two matching sorted oldest-first",
			configs:   []*crdv1alpha1.AntreaNodeConfig{anc3, anc1}, // deliberately reversed
			wantLen:   2,
			wantOrder: []string{"anc1", "anc3"},
		},
		{
			name:    "invalid selector is skipped",
			configs: []*crdv1alpha1.AntreaNodeConfig{ancInvalidSel, anc1},
			wantLen: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := SelectMatchingConfigs(node, tc.configs)
			require.Len(t, got, tc.wantLen)
			if tc.wantOrder != nil {
				for i, name := range tc.wantOrder {
					assert.Equal(t, name, got[i].Name)
				}
			}
		})
	}
}

func TestSelectMatchingConfigs_TimestampTiebreaker(t *testing.T) {
	// Two configs with the same timestamp; name is the tiebreaker.
	node := makeNode(map[string]string{"role": "worker"})
	ancA := makeANC("zzz", t0, map[string]string{"role": "worker"}, nil)
	ancB := makeANC("aaa", t0, map[string]string{"role": "worker"}, nil)

	got := SelectMatchingConfigs(node, []*crdv1alpha1.AntreaNodeConfig{ancA, ancB})
	require.Len(t, got, 2)
	assert.Equal(t, "aaa", got[0].Name, "alphabetically earlier name should sort first")
	assert.Equal(t, "zzz", got[1].Name)
}

func TestApplyConfigs(t *testing.T) {
	secNet1 := &crdv1alpha1.SecondaryNetworkConfig{
		OVSBridges: []crdv1alpha1.OVSBridgeConfig{
			makeBridge("br0", false, makeIface("eth0")),
		},
	}
	secNet2 := &crdv1alpha1.SecondaryNetworkConfig{
		OVSBridges: []crdv1alpha1.OVSBridgeConfig{
			makeBridge("br1", true, makeIface("eth1", "100", "200-300")),
		},
	}

	anc1 := makeANC("anc1", t0, nil, secNet1)
	anc2 := makeANC("anc2", t1, nil, secNet2)
	ancNoSec := makeANC("ancNoSec", t2, nil, nil)

	tests := []struct {
		name    string
		configs []*crdv1alpha1.AntreaNodeConfig
		want    *agenttypes.SecondaryNetworkConfig
	}{
		{
			name:    "empty input returns nil",
			configs: nil,
			want:    nil,
		},
		{
			name:    "all configs have nil SecondaryNetwork returns nil",
			configs: []*crdv1alpha1.AntreaNodeConfig{ancNoSec},
			want:    nil,
		},
		{
			name:    "single config with SecondaryNetwork",
			configs: []*crdv1alpha1.AntreaNodeConfig{anc1},
			want: &agenttypes.SecondaryNetworkConfig{
				OVSBridge: &agenttypes.OVSBridgeConfig{
					BridgeName: "br0", EnableMulticastSnooping: false,
					PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
						{Name: "eth0"},
					},
				},
			},
		},
		{
			name: "older config wins over newer one",
			// anc1 (older) sets br0/eth0; anc2 (newer) sets br1/eth1 — br0 wins.
			configs: []*crdv1alpha1.AntreaNodeConfig{anc1, anc2},
			want: &agenttypes.SecondaryNetworkConfig{
				OVSBridge: &agenttypes.OVSBridgeConfig{
					BridgeName: "br0", EnableMulticastSnooping: false,
					PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
						{Name: "eth0"},
					},
				},
			},
		},
		{
			name: "nil SecondaryNetwork in between does not clear result",
			// anc1 sets br0; ancNoSec has nil; the result should still be anc1's br0.
			configs: []*crdv1alpha1.AntreaNodeConfig{anc1, ancNoSec},
			want: &agenttypes.SecondaryNetworkConfig{
				OVSBridge: &agenttypes.OVSBridgeConfig{
					BridgeName: "br0",
					PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
						{Name: "eth0"},
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ApplyConfigs(tc.configs)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestSelectAndApply(t *testing.T) {
	node := makeNode(map[string]string{"role": "worker"})

	secNetA := &crdv1alpha1.SecondaryNetworkConfig{
		OVSBridges: []crdv1alpha1.OVSBridgeConfig{makeBridge("brA", false, makeIface("eth0"))},
	}
	secNetB := &crdv1alpha1.SecondaryNetworkConfig{
		OVSBridges: []crdv1alpha1.OVSBridgeConfig{makeBridge("brB", true, makeIface("eth1", "100"))},
	}

	// anc-old matches, sets brA (older timestamp) — should win
	ancOld := makeANC("anc-old", t0, map[string]string{"role": "worker"}, secNetA)
	// anc-new matches, sets brB (newer timestamp)
	ancNew := makeANC("anc-new", t1, map[string]string{"role": "worker"}, secNetB)
	// anc-other does not match the node
	ancOther := makeANC("anc-other", t2, map[string]string{"role": "control-plane"}, secNetA)

	t.Run("no configs returns nil", func(t *testing.T) {
		assert.Nil(t, SelectAndApply(node, nil))
	})

	t.Run("non-matching config returns nil", func(t *testing.T) {
		assert.Nil(t, SelectAndApply(node, []*crdv1alpha1.AntreaNodeConfig{ancOther}))
	})

	t.Run("single matching config applied", func(t *testing.T) {
		got := SelectAndApply(node, []*crdv1alpha1.AntreaNodeConfig{ancOld})
		require.NotNil(t, got)
		require.NotNil(t, got.OVSBridge)
		assert.Equal(t, "brA", got.OVSBridge.BridgeName)
	})

	t.Run("older matching config takes effect over newer one", func(t *testing.T) {
		got := SelectAndApply(node, []*crdv1alpha1.AntreaNodeConfig{ancOld, ancNew, ancOther})
		require.NotNil(t, got)
		require.NotNil(t, got.OVSBridge)
		assert.Equal(t, "brA", got.OVSBridge.BridgeName)
		assert.False(t, got.OVSBridge.EnableMulticastSnooping)
		assert.Nil(t, got.OVSBridge.PhysicalInterfaces[0].AllowedVLANs)
	})
}

func TestConvertSecondaryNetwork(t *testing.T) {
	t.Run("empty bridges yields nil OVSBridge", func(t *testing.T) {
		got := convertSecondaryNetwork(&crdv1alpha1.SecondaryNetworkConfig{})
		assert.Nil(t, got.OVSBridge)
	})

	t.Run("interface without AllowedVLANs has nil AllowedVLANs in output", func(t *testing.T) {
		in := &crdv1alpha1.SecondaryNetworkConfig{
			OVSBridges: []crdv1alpha1.OVSBridgeConfig{
				makeBridge("br0", false, makeIface("eth0")),
			},
		}
		got := convertSecondaryNetwork(in)
		require.NotNil(t, got.OVSBridge)
		require.Len(t, got.OVSBridge.PhysicalInterfaces, 1)
		assert.Equal(t, "eth0", got.OVSBridge.PhysicalInterfaces[0].Name)
		assert.Nil(t, got.OVSBridge.PhysicalInterfaces[0].AllowedVLANs)
	})

	t.Run("AllowedVLANs are preserved", func(t *testing.T) {
		in := &crdv1alpha1.SecondaryNetworkConfig{
			OVSBridges: []crdv1alpha1.OVSBridgeConfig{
				makeBridge("br0", false, makeIface("eth0", "100", "200-300")),
			},
		}
		got := convertSecondaryNetwork(in)
		require.NotNil(t, got.OVSBridge)
		assert.Equal(t, []string{"100", "200-300"}, got.OVSBridge.PhysicalInterfaces[0].AllowedVLANs)
	})

	t.Run("multicast snooping flag is preserved", func(t *testing.T) {
		in := &crdv1alpha1.SecondaryNetworkConfig{
			OVSBridges: []crdv1alpha1.OVSBridgeConfig{
				makeBridge("br0", true),
			},
		}
		got := convertSecondaryNetwork(in)
		require.NotNil(t, got.OVSBridge)
		assert.True(t, got.OVSBridge.EnableMulticastSnooping)
	})

	t.Run("bridge with multiple interfaces", func(t *testing.T) {
		in := &crdv1alpha1.SecondaryNetworkConfig{
			OVSBridges: []crdv1alpha1.OVSBridgeConfig{
				makeBridge("br0", false, makeIface("eth0"), makeIface("eth1", "10")),
			},
		}
		got := convertSecondaryNetwork(in)
		require.NotNil(t, got.OVSBridge)
		assert.Equal(t, "br0", got.OVSBridge.BridgeName)
		assert.Len(t, got.OVSBridge.PhysicalInterfaces, 2)
		assert.Nil(t, got.OVSBridge.PhysicalInterfaces[0].AllowedVLANs)
		assert.Equal(t, []string{"10"}, got.OVSBridge.PhysicalInterfaces[1].AllowedVLANs)
	})

	t.Run("empty bridge name defaults to br1", func(t *testing.T) {
		in := &crdv1alpha1.SecondaryNetworkConfig{
			OVSBridges: []crdv1alpha1.OVSBridgeConfig{
				makeBridge("", false, makeIface("eth0")),
			},
		}
		got := convertSecondaryNetwork(in)
		require.NotNil(t, got.OVSBridge)
		assert.Equal(t, "br1", got.OVSBridge.BridgeName)
		assert.Equal(t, "eth0", got.OVSBridge.PhysicalInterfaces[0].Name)
	})
}
