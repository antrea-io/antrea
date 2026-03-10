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

package secondarynetwork

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/TomCodeLV/OVSDB-golang-lib/pkg/ovsdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	mock "go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	agenttypes "antrea.io/antrea/pkg/agent/types"
	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	crdv1alpha1listers "antrea.io/antrea/pkg/client/listers/crd/v1alpha1"
	agentconfig "antrea.io/antrea/pkg/config/agent"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	ovsconfigtest "antrea.io/antrea/pkg/ovs/ovsconfig/testing"
)

const (
	nonExistingInterface = "non-existing"
	// uplinkOFPort is a placeholder OF port number used in GetOFPort mock stubs to indicate
	// that an interface is already connected to the bridge. The exact value is not significant.
	uplinkOFPort = 1
)

func TestCreateOVSBridge(t *testing.T) {
	tests := []struct {
		name          string
		ovsBridges    []string
		expectedErr   string
		expectedCalls func(m *ovsconfigtest.MockOVSBridgeClient)
	}{
		{
			name: "no bridge",
		},
		{
			name:       "no interface",
			ovsBridges: []string{"br1"},
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().Create().Return(nil)
			},
		},
		{
			name:       "two bridges",
			ovsBridges: []string{"br1", "br2"},
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().Create().Return(nil)
			},
		},
		{
			name:        "create br error",
			ovsBridges:  []string{"br1", "br2"},
			expectedErr: "create error",
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().Create().Return(ovsconfig.InvalidArgumentsError("create error"))
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var bridges []agentconfig.OVSBridgeConfig
			for _, brName := range tc.ovsBridges {
				bridges = append(bridges, agentconfig.OVSBridgeConfig{BridgeName: brName})
			}

			ctrl := mock.NewController(t)
			mockOVSBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(ctrl)

			mockNewOVSBridge(t, mockOVSBridgeClient)
			if tc.expectedCalls != nil {
				tc.expectedCalls(mockOVSBridgeClient)
			}

			brClient, err := createOVSBridge(bridges, nil)
			if tc.expectedErr != "" {
				assert.ErrorContains(t, err, tc.expectedErr)
				assert.Nil(t, brClient)
			} else {
				require.NoError(t, err)
				if tc.expectedCalls != nil {
					assert.NotNil(t, brClient)
				}
			}
		})
	}
}

func TestConnectPhyInterfacesToOVSBridge(t *testing.T) {
	tests := []struct {
		name               string
		physicalInterfaces []agenttypes.PhysicalInterfaceConfig
		expectedErr        string
		expectedCalls      func(m *ovsconfigtest.MockOVSBridgeClient)
	}{
		{
			name: "one interface no VLANs",
			physicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
				{Name: "eth0~"},
			},
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().GetOFPort("eth0~", false).Return(int32(uplinkOFPort), ovsconfig.InvalidArgumentsError("port not found"))
				m.EXPECT().CreateUplinkPort("eth0~", int32(0), map[string]interface{}{"antrea-type": "uplink"}).Return("", nil)
			},
		},
		{
			name: "two interfaces no VLANs",
			physicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
				{Name: "eth1"},
				{Name: "eth2"},
			},
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().GetOFPort("eth1", false).Return(int32(uplinkOFPort), ovsconfig.InvalidArgumentsError("port not found"))
				m.EXPECT().CreateUplinkPort("eth1", int32(0), map[string]interface{}{"antrea-type": "uplink"}).Return("", nil)
				m.EXPECT().GetOFPort("eth2", false).Return(int32(uplinkOFPort+1), ovsconfig.InvalidArgumentsError("port not found"))
				m.EXPECT().CreateUplinkPort("eth2", int32(0), map[string]interface{}{"antrea-type": "uplink"}).Return("", nil)
			},
		},
		{
			name: "interface already attached, no VLANs",
			physicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
				{Name: "eth1"},
			},
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().GetOFPort("eth1", false).Return(int32(uplinkOFPort), nil)
			},
		},
		{
			name: "non-existing interface",
			physicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
				{Name: nonExistingInterface},
				{Name: "eth2"},
			},
			expectedErr: "failed to get interface",
		},
		{
			name: "create port error",
			physicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
				{Name: "eth1"},
			},
			expectedErr: "create error",
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().GetOFPort("eth1", false).Return(int32(uplinkOFPort), ovsconfig.InvalidArgumentsError("port not found"))
				m.EXPECT().CreateUplinkPort("eth1", int32(0), map[string]interface{}{"antrea-type": "uplink"}).Return("", ovsconfig.InvalidArgumentsError("create error"))
			},
		},
		{
			name: "one interface with single VLAN",
			physicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
				{Name: "eth1", AllowedVLANs: []string{"100"}},
			},
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().GetOFPort("eth1", false).Return(int32(uplinkOFPort), ovsconfig.InvalidArgumentsError("port not found"))
				m.EXPECT().CreateTrunkPort("eth1", int32(0), []string{"100"}, map[string]interface{}{"antrea-type": "uplink"}).Return("", nil)
			},
		},
		{
			name: "one interface with VLAN range",
			physicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
				{Name: "eth1", AllowedVLANs: []string{"200-202"}},
			},
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().GetOFPort("eth1", false).Return(int32(uplinkOFPort), ovsconfig.InvalidArgumentsError("port not found"))
				m.EXPECT().CreateTrunkPort("eth1", int32(0), []string{"200-202"}, map[string]interface{}{"antrea-type": "uplink"}).Return("", nil)
			},
		},
		{
			name: "one interface with mixed VLANs",
			physicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
				{Name: "eth1", AllowedVLANs: []string{"100", "200-201"}},
			},
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().GetOFPort("eth1", false).Return(int32(uplinkOFPort), ovsconfig.InvalidArgumentsError("port not found"))
				m.EXPECT().CreateTrunkPort("eth1", int32(0), []string{"100", "200-201"}, map[string]interface{}{"antrea-type": "uplink"}).Return("", nil)
			},
		},
		{
			name: "trunk port creation error",
			physicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
				{Name: "eth1", AllowedVLANs: []string{"100"}},
			},
			expectedErr: "trunk error",
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().GetOFPort("eth1", false).Return(int32(uplinkOFPort), ovsconfig.InvalidArgumentsError("port not found"))
				m.EXPECT().CreateTrunkPort("eth1", int32(0), []string{"100"}, map[string]interface{}{"antrea-type": "uplink"}).Return("", ovsconfig.InvalidArgumentsError("trunk error"))
			},
		},
		{
			name: "already attached with VLANs — always update trunks",
			physicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
				{Name: "eth1", AllowedVLANs: []string{"100", "300"}},
			},
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().GetOFPort("eth1", false).Return(int32(uplinkOFPort), nil)
				m.EXPECT().SetPortTrunks("eth1", []string{"100", "300"}).Return(nil)
			},
		},
		{
			name: "SetPortTrunks error",
			physicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
				{Name: "eth1", AllowedVLANs: []string{"100"}},
			},
			expectedErr: "update error",
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().GetOFPort("eth1", false).Return(int32(uplinkOFPort), nil)
				m.EXPECT().SetPortTrunks("eth1", []string{"100"}).Return(ovsconfig.InvalidArgumentsError("update error"))
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := mock.NewController(t)
			mockOVSBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(ctrl)

			mockInterfaceByName(t)
			if tc.expectedCalls != nil {
				tc.expectedCalls(mockOVSBridgeClient)
			}

			err := connectPhyInterfacesToOVSBridge(mockOVSBridgeClient, tc.physicalInterfaces)
			if tc.expectedErr != "" {
				assert.ErrorContains(t, err, tc.expectedErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestInitialize(t *testing.T) {
	tests := []struct {
		name          string
		bridgeCfg     *agenttypes.OVSBridgeConfig
		expectedCalls func(m *ovsconfigtest.MockOVSBridgeClient)
		expectedErr   string
	}{
		{
			name:      "no bridge config — no-op",
			bridgeCfg: nil,
		},
		{
			// Regression: agent restarts; OVS ports have stale trunk VLANs from a
			// previous run but the current desired config has no allowedVLANs.
			// Initialize must clear the stale trunk list.
			name: "existing ports with stale trunks — cleared at startup",
			bridgeCfg: &agenttypes.OVSBridgeConfig{
				BridgeName: "br1",
				PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
					{Name: eth1},
					{Name: eth2},
				},
			},
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				// restoreStaleHostConnections: no internal ports — no-op.
				m.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{Name: eth1, IFName: eth1, IFType: ""},
					{Name: eth2, IFName: eth2, IFType: ""},
				}, nil).Times(1)
				// eth1 and eth2 already present — connectPhyInterfacesToOVSBridge skips them.
				m.EXPECT().GetOFPort(eth1, false).Return(int32(uplinkOFPort), nil)
				m.EXPECT().GetOFPort(eth2, false).Return(int32(uplinkOFPort+1), nil)
				// clearStaleTrunks finds stale trunks on both ports and clears them.
				// Name (Port name) and IFName (Interface name) are both set to match
				// real OVS behaviour for uplink ports; SetPortTrunks uses p.Name.
				m.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{Name: eth1, IFName: eth1, Trunks: []uint16{100, 300}},
					{Name: eth2, IFName: eth2, Trunks: []uint16{200}},
				}, nil).Times(1)
				m.EXPECT().SetPortTrunks(eth1, nil).Return(nil)
				m.EXPECT().SetPortTrunks(eth2, nil).Return(nil)
			},
		},
		{
			name: "existing ports without trunks — no SetPortTrunks call",
			bridgeCfg: &agenttypes.OVSBridgeConfig{
				BridgeName: "br1",
				PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
					{Name: eth1},
					{Name: eth2},
				},
			},
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				// restoreStaleHostConnections: no internal ports — no-op.
				m.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{Name: eth1, IFName: eth1, IFType: ""},
					{Name: eth2, IFName: eth2, IFType: ""},
				}, nil).Times(1)
				m.EXPECT().GetOFPort(eth1, false).Return(int32(uplinkOFPort), nil)
				m.EXPECT().GetOFPort(eth2, false).Return(int32(uplinkOFPort+1), nil)
				// No stale trunks — clearStaleTrunks must not call SetPortTrunks.
				m.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{Name: eth1, IFName: eth1, Trunks: nil},
					{Name: eth2, IFName: eth2, Trunks: nil},
				}, nil).Times(1)
			},
		},
		{
			// Regression: bridge has a stale host-connection setup (eth1 internal + eth1~
			// uplink) from a previous single-interface run, plus eth2 in trunk mode.
			// The new desired config wants both eth1 and eth2 as plain uplinks.
			// Initialize must: detect and restore the eth1 host-connection, then add eth1
			// as a plain uplink, and clear the stale trunks on eth2.
			name: "stale host-connection (eth1 internal + eth1~) with stale trunk on eth2",
			bridgeCfg: &agenttypes.OVSBridgeConfig{
				BridgeName: "br1",
				PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
					{Name: eth1},
					{Name: eth2},
				},
			},
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				// restoreStaleHostConnections queries GetPortList and finds eth1 (internal)
				// + eth1~ (uplink sibling) — triggers RestoreHostInterfaceConfiguration.
				// eth2 is a plain uplink (type ""), not an internal port — skipped.
				eth1Tilde := eth1 + "~"
				m.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{Name: eth1, IFName: eth1, IFType: "internal"},
					{Name: eth1Tilde, IFName: eth1Tilde, IFType: ""},
					{Name: eth2, IFName: eth2, IFType: "", Trunks: []uint16{200}},
				}, nil).Times(1)

				// After restore, eth1~ is gone and eth1 is a plain kernel interface again.
				// connectPhyInterfacesToOVSBridge: eth1 not connected → CreateUplinkPort;
				// eth2 already connected (no VLANs) → skipped.
				m.EXPECT().GetOFPort(eth1, false).Return(int32(0), ovsconfig.InvalidArgumentsError("not found"))
				m.EXPECT().CreateUplinkPort(eth1, int32(0), map[string]interface{}{"antrea-type": "uplink"}).Return("", nil)
				m.EXPECT().GetOFPort(eth2, false).Return(int32(uplinkOFPort+1), nil)

				// clearStaleTrunks: eth2 still has Trunks from above GetPortList result.
				// A second GetPortList is issued to read the current OVS state.
				m.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{Name: eth1, IFName: eth1, IFType: ""},
					{Name: eth2, IFName: eth2, IFType: "", Trunks: []uint16{200}},
				}, nil).Times(1)
				m.EXPECT().SetPortTrunks(eth2, nil).Return(nil)
			},
		},
		{
			name: "ports with AllowedVLANs — clearStaleTrunks skips them",
			bridgeCfg: &agenttypes.OVSBridgeConfig{
				BridgeName: "br1",
				PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
					{Name: eth1, AllowedVLANs: []string{"100"}},
					{Name: eth2, AllowedVLANs: []string{"200"}},
				},
			},
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				// restoreStaleHostConnections: no internal ports — no-op.
				m.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{Name: eth1, IFName: eth1, IFType: ""},
					{Name: eth2, IFName: eth2, IFType: ""},
				}, nil).Times(1)
				// Both ports exist — SetPortTrunks is called by connectPhyInterfacesToOVSBridge.
				m.EXPECT().GetOFPort(eth1, false).Return(int32(uplinkOFPort), nil)
				m.EXPECT().SetPortTrunks(eth1, []string{"100"}).Return(nil)
				m.EXPECT().GetOFPort(eth2, false).Return(int32(uplinkOFPort+1), nil)
				m.EXPECT().SetPortTrunks(eth2, []string{"200"}).Return(nil)
				// clearStaleTrunks has nothing to do: all interfaces have AllowedVLANs.
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := mock.NewController(t)
			mockOVSBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(ctrl)

			mockInterfaceByName(t)
			// Replace the real RestoreHostInterfaceConfiguration with a no-op so
			// tests don't touch kernel interfaces.
			origRestore := restoreHostInterfaceConfigFn
			t.Cleanup(func() { restoreHostInterfaceConfigFn = origRestore })
			restoreHostInterfaceConfigFn = func(brName, ifaceName string) error { return nil }

			if tc.expectedCalls != nil {
				tc.expectedCalls(mockOVSBridgeClient)
			}

			c := &Controller{
				ovsBridgeClient:    mockOVSBridgeClient,
				effectiveBridgeCfg: tc.bridgeCfg,
			}
			err := c.Initialize()
			if tc.expectedErr != "" {
				assert.ErrorContains(t, err, tc.expectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

const (
	brOld = "br-old"
	brNew = "br-new"
	eth1  = "eth1"
	eth2  = "eth2"
)

// TestReconcileBridge tests the reconcileBridge function with various transitions.
func TestReconcileBridge(t *testing.T) {
	portUUID := "uuid-eth1"

	tests := []struct {
		name                string
		prevCfg             *agenttypes.OVSBridgeConfig
		desiredCfg          *agenttypes.OVSBridgeConfig // returned by resolveEffectiveBridgeConfig via ancLister
		expectedCalls       func(old, new *ovsconfigtest.MockOVSBridgeClient)
		wantNewClient       bool // whether c.ovsBridgeClient should be the "new" mock after reconcile
		wantUpdateBridgeN   int  // expected number of UpdateOVSBridge calls on the podController
		wantUpdateBridgeNil bool // whether the last UpdateOVSBridge call should pass nil
		// wantRestoreCalls lists the (bridge, iface) pairs that restoreHostInterfaceConfigFn
		// must be called with, in order, when an interface is removed from the config.
		wantRestoreCalls []struct{ bridge, iface string }
		expectedErr      string
	}{
		{
			name:          "no change (both nil)",
			prevCfg:       nil,
			desiredCfg:    nil,
			expectedCalls: func(old, new *ovsconfigtest.MockOVSBridgeClient) {},
		},
		{
			name:          "no change (same config)",
			prevCfg:       &agenttypes.OVSBridgeConfig{BridgeName: brOld, PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{{Name: eth1}}},
			desiredCfg:    &agenttypes.OVSBridgeConfig{BridgeName: brOld, PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{{Name: eth1}}},
			expectedCalls: func(old, new *ovsconfigtest.MockOVSBridgeClient) {},
		},
		{
			name:       "bridge deleted (desired is nil)",
			prevCfg:    &agenttypes.OVSBridgeConfig{BridgeName: brOld, PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{{Name: eth1}}},
			desiredCfg: nil,
			expectedCalls: func(old, new *ovsconfigtest.MockOVSBridgeClient) {
				old.EXPECT().Delete().Return(nil)
			},
			wantUpdateBridgeN:   1,
			wantUpdateBridgeNil: true,
		},
		{
			// Use two interfaces to bypass the single-interface PrepareHostInterfaceConnection path.
			name:       "bridge created (prev is nil, two interfaces)",
			prevCfg:    nil,
			desiredCfg: &agenttypes.OVSBridgeConfig{BridgeName: brNew, PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{{Name: eth1}, {Name: eth2}}},
			expectedCalls: func(old, new *ovsconfigtest.MockOVSBridgeClient) {
				new.EXPECT().Create().Return(nil)
				new.EXPECT().GetOFPort(eth1, false).Return(int32(0), ovsconfig.InvalidArgumentsError("not found"))
				new.EXPECT().CreateUplinkPort(eth1, int32(0), map[string]interface{}{"antrea-type": "uplink"}).Return("", nil)
				new.EXPECT().GetOFPort(eth2, false).Return(int32(0), ovsconfig.InvalidArgumentsError("not found"))
				new.EXPECT().CreateUplinkPort(eth2, int32(0), map[string]interface{}{"antrea-type": "uplink"}).Return("", nil)
			},
			wantNewClient:     true,
			wantUpdateBridgeN: 1,
		},
		{
			// Use two interfaces to bypass the single-interface PrepareHostInterfaceConnection path.
			name:       "rule 4: different bridge name — delete old, create new",
			prevCfg:    &agenttypes.OVSBridgeConfig{BridgeName: brOld, PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{{Name: eth1}, {Name: eth2}}},
			desiredCfg: &agenttypes.OVSBridgeConfig{BridgeName: brNew, PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{{Name: eth1}, {Name: eth2}}},
			expectedCalls: func(old, new *ovsconfigtest.MockOVSBridgeClient) {
				old.EXPECT().Delete().Return(nil)
				new.EXPECT().Create().Return(nil)
				new.EXPECT().GetOFPort(eth1, false).Return(int32(0), ovsconfig.InvalidArgumentsError("not found"))
				new.EXPECT().CreateUplinkPort(eth1, int32(0), map[string]interface{}{"antrea-type": "uplink"}).Return("", nil)
				new.EXPECT().GetOFPort(eth2, false).Return(int32(0), ovsconfig.InvalidArgumentsError("not found"))
				new.EXPECT().CreateUplinkPort(eth2, int32(0), map[string]interface{}{"antrea-type": "uplink"}).Return("", nil)
			},
			wantNewClient:     true,
			wantUpdateBridgeN: 1,
		},
		{
			// When the old ANC CR stops matching (e.g. Node labels change) and a new ANC with a
			// different bridge name becomes effective, the old OVS bridge must be deleted before
			// the new one is created.  State must be cleared immediately after deletion so that a
			// retry does not attempt to delete an already-removed bridge.
			name:       "rule 4: old ANC stops matching, new ANC bridge created — old bridge deleted first",
			prevCfg:    &agenttypes.OVSBridgeConfig{BridgeName: brOld, PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{{Name: eth1}, {Name: eth2}}},
			desiredCfg: &agenttypes.OVSBridgeConfig{BridgeName: brNew, PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{{Name: eth1}, {Name: eth2}}},
			expectedCalls: func(old, new *ovsconfigtest.MockOVSBridgeClient) {
				// Deletion of old bridge is expected before creation of new bridge.
				old.EXPECT().Delete().Return(nil)
				new.EXPECT().Create().Return(nil)
				new.EXPECT().GetOFPort(eth1, false).Return(int32(0), ovsconfig.InvalidArgumentsError("not found"))
				new.EXPECT().CreateUplinkPort(eth1, int32(0), map[string]interface{}{"antrea-type": "uplink"}).Return("", nil)
				new.EXPECT().GetOFPort(eth2, false).Return(int32(0), ovsconfig.InvalidArgumentsError("not found"))
				new.EXPECT().CreateUplinkPort(eth2, int32(0), map[string]interface{}{"antrea-type": "uplink"}).Return("", nil)
			},
			wantNewClient:     true,
			wantUpdateBridgeN: 1,
		},
		{
			name:       "rule 3: same bridge name — add new interface",
			prevCfg:    &agenttypes.OVSBridgeConfig{BridgeName: brOld, PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{{Name: eth1}}},
			desiredCfg: &agenttypes.OVSBridgeConfig{BridgeName: brOld, PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{{Name: eth1}, {Name: eth2}}},
			expectedCalls: func(old, new *ovsconfigtest.MockOVSBridgeClient) {
				old.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{UUID: portUUID, IFName: eth1},
				}, nil).Times(1)
				// eth2 is new — connect it.
				old.EXPECT().GetOFPort(eth2, false).Return(int32(0), ovsconfig.InvalidArgumentsError("not found"))
				old.EXPECT().CreateUplinkPort(eth2, int32(0), map[string]interface{}{"antrea-type": "uplink"}).Return("", nil)
				// clearStaleTrunks: eth1 already exists with no AllowedVLANs; second GetPortList
				// shows no trunks on eth1 so SetPortTrunks is not called.
				old.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{Name: eth1, IFName: eth1, Trunks: nil},
				}, nil).Times(1)
			},
			// No UpdateOVSBridge: same bridge, client unchanged.
		},
		{
			name:       "rule 3: same bridge name — remove old interface",
			prevCfg:    &agenttypes.OVSBridgeConfig{BridgeName: brOld, PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{{Name: eth1}, {Name: eth2}}},
			desiredCfg: &agenttypes.OVSBridgeConfig{BridgeName: brOld, PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{{Name: eth1}}},
			expectedCalls: func(old, new *ovsconfigtest.MockOVSBridgeClient) {
				old.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{UUID: portUUID, IFName: eth1},
					{UUID: "uuid-eth2", IFName: eth2},
				}, nil).Times(1)
				// eth2 is removed in a single batch call.
				old.EXPECT().DeletePorts([]string{"uuid-eth2"}).Return(nil)
				// clearStaleTrunks: eth1 remains with no AllowedVLANs; no trunks → no-op.
				old.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{Name: eth1, IFName: eth1, Trunks: nil},
				}, nil).Times(1)
			},
			// No UpdateOVSBridge: same bridge, client unchanged.
		},
		{
			name:    "rule 3: same bridge, add interface with VLANs (rule 5)",
			prevCfg: &agenttypes.OVSBridgeConfig{BridgeName: brOld, PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{{Name: eth1}}},
			desiredCfg: &agenttypes.OVSBridgeConfig{BridgeName: brOld, PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
				{Name: eth1},
				{Name: eth2, AllowedVLANs: []string{"100"}},
			}},
			expectedCalls: func(old, new *ovsconfigtest.MockOVSBridgeClient) {
				old.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{UUID: portUUID, IFName: eth1},
				}, nil).Times(1)
				old.EXPECT().GetOFPort(eth2, false).Return(int32(0), ovsconfig.InvalidArgumentsError("not found"))
				old.EXPECT().CreateTrunkPort(eth2, int32(0), []string{"100"}, map[string]interface{}{"antrea-type": "uplink"}).Return("", nil)
				// clearStaleTrunks: eth1 exists with no AllowedVLANs; no trunks → no-op.
				old.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{Name: eth1, IFName: eth1, Trunks: nil},
				}, nil).Times(1)
			},
			// No UpdateOVSBridge: same bridge, client unchanged.
		},
		{
			// Regression test: existing port gains AllowedVLANs (e.g. ANC CR applied after
			// agent started with static config that had no VLANs). The port is already
			// present on the bridge so only SetPortTrunks must be called to update it.
			name:    "rule 3: same bridge, existing interface gains AllowedVLANs",
			prevCfg: &agenttypes.OVSBridgeConfig{BridgeName: brOld, PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{{Name: eth1}}},
			desiredCfg: &agenttypes.OVSBridgeConfig{BridgeName: brOld, PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
				{Name: eth1, AllowedVLANs: []string{"100", "300"}},
			}},
			expectedCalls: func(old, new *ovsconfigtest.MockOVSBridgeClient) {
				old.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{UUID: portUUID, IFName: eth1},
				}, nil)
				// eth1 already exists and now has AllowedVLANs — trunk list must be updated.
				old.EXPECT().GetOFPort(eth1, false).Return(int32(uplinkOFPort), nil)
				old.EXPECT().SetPortTrunks(eth1, []string{"100", "300"}).Return(nil)
			},
			// No UpdateOVSBridge: same bridge, client unchanged.
		},
		{
			// Regression test: existing trunk ports have AllowedVLANs cleared (e.g. ANC CR
			// updated to remove allowedVLANs).  clearStaleTrunks reads the actual OVS port
			// state and calls SetPortTrunks(nil) for ports that still have trunks set.
			name: "rule 3: same bridge, existing interface loses AllowedVLANs",
			prevCfg: &agenttypes.OVSBridgeConfig{BridgeName: brOld, PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
				{Name: eth1, AllowedVLANs: []string{"100", "300"}},
				{Name: eth2, AllowedVLANs: []string{"200"}},
			}},
			desiredCfg: &agenttypes.OVSBridgeConfig{BridgeName: brOld, PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
				{Name: eth1},
				{Name: eth2},
			}},
			expectedCalls: func(old, new *ovsconfigtest.MockOVSBridgeClient) {
				// First GetPortList: build existingPorts map.
				old.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{UUID: portUUID, IFName: eth1},
					{UUID: "uuid-eth2", IFName: eth2},
				}, nil).Times(1)
				// Second GetPortList: clearStaleTrunks reads actual OVS trunks and clears them.
				old.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{Name: eth1, IFName: eth1, Trunks: []uint16{100, 300}},
					{Name: eth2, IFName: eth2, Trunks: []uint16{200}},
				}, nil).Times(1)
				old.EXPECT().SetPortTrunks(eth1, nil).Return(nil)
				old.EXPECT().SetPortTrunks(eth2, nil).Return(nil)
			},
			// No UpdateOVSBridge: same bridge, client unchanged.
		},
		{
			// Regression: eth1 loses AllowedVLANs AND eth2 has a stale trunk 300 that
			// was never reflected in prev (set externally or from a run the controller
			// didn't track).  clearStaleTrunks reads actual OVS state and clears both.
			name: "rule 3: stale trunk on eth2 not in prev config — cleared via OVS state",
			prevCfg: &agenttypes.OVSBridgeConfig{BridgeName: brOld, PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
				{Name: eth1, AllowedVLANs: []string{"100"}},
				{Name: eth2},
			}},
			desiredCfg: &agenttypes.OVSBridgeConfig{BridgeName: brOld, PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
				{Name: eth1},
				{Name: eth2},
			}},
			expectedCalls: func(old, new *ovsconfigtest.MockOVSBridgeClient) {
				// First GetPortList: build existingPorts map.
				old.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{UUID: portUUID, IFName: eth1},
					{UUID: "uuid-eth2", IFName: eth2},
				}, nil).Times(1)
				// Second GetPortList: clearStaleTrunks reads actual OVS state.
				// eth1 has trunks from its prev AllowedVLANs; eth2 has stale trunk 300
				// that was never tracked in prev — both are cleared.
				old.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{Name: eth1, IFName: eth1, Trunks: []uint16{100}},
					{Name: eth2, IFName: eth2, Trunks: []uint16{300}},
				}, nil).Times(1)
				old.EXPECT().SetPortTrunks(eth1, nil).Return(nil)
				old.EXPECT().SetPortTrunks(eth2, nil).Return(nil)
			},
			// No UpdateOVSBridge: same bridge, client unchanged.
		},
		{
			// anc.yaml → anc1.yaml: eth1 had allowedVLANs:["100"] and eth2 had
			// allowedVLANs:["200-300"]. The updated ANC removes allowedVLANs from both.
			// Both OVS trunk ports must be cleared to plain uplinks.
			name: "anc.yaml→anc1.yaml: both interfaces lose AllowedVLANs",
			prevCfg: &agenttypes.OVSBridgeConfig{BridgeName: brOld, PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
				{Name: eth1, AllowedVLANs: []string{"100"}},
				{Name: eth2, AllowedVLANs: []string{"200-300"}},
			}},
			desiredCfg: &agenttypes.OVSBridgeConfig{BridgeName: brOld, PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
				{Name: eth1},
				{Name: eth2},
			}},
			expectedCalls: func(old, new *ovsconfigtest.MockOVSBridgeClient) {
				// First GetPortList: both ports already on the bridge.
				old.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{UUID: portUUID, IFName: eth1},
					{UUID: "uuid-eth2", IFName: eth2},
				}, nil).Times(1)
				// Second GetPortList: clearStaleTrunks reads actual OVS trunk state.
				// eth1 has trunk [100] and eth2 has trunks [200, 300] (range expanded).
				// Both must be cleared; connectPhyInterfacesToOVSBridge is not called
				// because toConnect is empty (both ports exist, no desired AllowedVLANs).
				old.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{Name: eth1, IFName: eth1, Trunks: []uint16{100}},
					{Name: eth2, IFName: eth2, Trunks: []uint16{200, 201, 202, 203, 204, 205,
						206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219,
						220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233,
						234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247,
						248, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261,
						262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275,
						276, 277, 278, 279, 280, 281, 282, 283, 284, 285, 286, 287, 288, 289,
						290, 291, 292, 293, 294, 295, 296, 297, 298, 299, 300}},
				}, nil).Times(1)
				old.EXPECT().SetPortTrunks(eth1, nil).Return(nil)
				old.EXPECT().SetPortTrunks(eth2, nil).Return(nil)
			},
			// No UpdateOVSBridge: same bridge, client unchanged.
		},
		{
			// Regression: eth1 was connected via PrepareHostInterfaceConnection (single-interface
			// host-connection path), so the bridge holds two ports: "eth1" (internal) and "eth1~"
			// (uplink).  The ANC is updated to replace eth1 with eth2.  updatePhysicalInterfaces
			// must call restoreHostInterfaceConfigFn(brOld, eth1) to remove both ports and restore
			// the kernel interface name — NOT merely DeletePorts("eth1"), which would leave "eth1~"
			// stranded on the bridge and the host kernel interface stuck under the renamed name.
			name: "rule 3: host-connection port removed — RestoreHostInterfaceConfiguration called",
			prevCfg: &agenttypes.OVSBridgeConfig{BridgeName: brOld, PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
				{Name: eth1},
			}},
			desiredCfg: &agenttypes.OVSBridgeConfig{BridgeName: brOld, PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
				{Name: eth2},
			}},
			expectedCalls: func(old, new *ovsconfigtest.MockOVSBridgeClient) {
				eth1Tilde := eth1 + "~"
				// First GetPortList: bridge has eth1 (internal) + eth1~ (uplink).
				// restoreHostInterfaceConfigFn is called (tracked via wantRestoreCalls);
				// no DeletePorts expected because the restore handles both ports.
				old.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{UUID: "uuid-eth1", IFName: eth1, IFType: "internal"},
					{UUID: "uuid-eth1-tilde", IFName: eth1Tilde, IFType: ""},
				}, nil).Times(1)
				// eth2 is new — add it as a plain uplink.
				old.EXPECT().GetOFPort(eth2, false).Return(int32(0), ovsconfig.InvalidArgumentsError("not found"))
				old.EXPECT().CreateUplinkPort(eth2, int32(0), map[string]interface{}{"antrea-type": "uplink"}).Return("", nil)
				// clearStaleTrunks: eth2 has no AllowedVLANs; second GetPortList shows no trunks.
				old.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{Name: eth2, IFName: eth2, Trunks: nil},
				}, nil).Times(1)
			},
			wantRestoreCalls: []struct{ bridge, iface string }{{brOld, eth1}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := mock.NewController(t)
			oldMock := ovsconfigtest.NewMockOVSBridgeClient(ctrl)
			newMock := ovsconfigtest.NewMockOVSBridgeClient(ctrl)

			mockInterfaceByName(t)
			mockNewOVSBridge(t, newMock)

			// Capture restoreHostInterfaceConfigFn calls for verification.
			var gotRestoreCalls []struct{ bridge, iface string }
			origRestore := restoreHostInterfaceConfigFn
			restoreHostInterfaceConfigFn = func(brName, ifaceName string) error {
				gotRestoreCalls = append(gotRestoreCalls, struct{ bridge, iface string }{brName, ifaceName})
				return nil
			}
			t.Cleanup(func() { restoreHostInterfaceConfigFn = origRestore })

			if tc.expectedCalls != nil {
				tc.expectedCalls(oldMock, newMock)
			}

			// Build ancLister that returns the desired config.
			ancLister := &fakeANCLister{} // empty — desired driven by staticCfg
			var staticCfg *agentconfig.SecondaryNetworkConfig
			if tc.desiredCfg != nil {
				phyIfaces := make([]string, 0, len(tc.desiredCfg.PhysicalInterfaces))
				for _, pi := range tc.desiredCfg.PhysicalInterfaces {
					phyIfaces = append(phyIfaces, pi.Name)
				}
				staticCfg = &agentconfig.SecondaryNetworkConfig{
					OVSBridges: []agentconfig.OVSBridgeConfig{{
						BridgeName:         tc.desiredCfg.BridgeName,
						PhysicalInterfaces: phyIfaces,
					}},
				}
				// For VLAN cases, use ANC CR instead (staticCfg doesn't carry VLANs).
				if hasAllowedVLANs(tc.desiredCfg) {
					ancLister = makeANCListerFromBridgeCfg(tc.desiredCfg)
					staticCfg = &agentconfig.SecondaryNetworkConfig{}
				}
			} else {
				staticCfg = &agentconfig.SecondaryNetworkConfig{}
			}

			fakePc := &fakePodController{}
			c := &Controller{
				ovsBridgeClient:    oldMock,
				secNetConfig:       staticCfg,
				effectiveBridgeCfg: tc.prevCfg,
				ancLister:          ancLister,
				node:               &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node1"}},
				ovsdbConn:          nil,
				podController:      fakePc,
			}

			err := c.reconcileBridge()
			if tc.expectedErr != "" {
				assert.ErrorContains(t, err, tc.expectedErr)
			} else {
				require.NoError(t, err)
				c.mu.RLock()
				if tc.wantNewClient {
					assert.Equal(t, newMock, c.ovsBridgeClient)
				}
				c.mu.RUnlock()
				// Verify UpdateOVSBridge was called the expected number of times.
				assert.Len(t, fakePc.updateBridgeCalls, tc.wantUpdateBridgeN,
					"unexpected number of UpdateOVSBridge calls")
				if tc.wantUpdateBridgeN > 0 {
					last := fakePc.updateBridgeCalls[len(fakePc.updateBridgeCalls)-1]
					if tc.wantUpdateBridgeNil {
						assert.Nil(t, last, "expected UpdateOVSBridge(nil) for bridge deletion")
					} else {
						assert.Equal(t, newMock, last, "expected UpdateOVSBridge(newMock) for bridge creation")
					}
				}
				// Verify restoreHostInterfaceConfigFn calls.
				if tc.wantRestoreCalls != nil {
					assert.Equal(t, tc.wantRestoreCalls, gotRestoreCalls,
						"unexpected restoreHostInterfaceConfigFn calls")
				} else {
					assert.Empty(t, gotRestoreCalls, "unexpected restoreHostInterfaceConfigFn calls")
				}
			}
		})
	}
}

// TestReconcileBridgeStateCleared verifies that when the bridge name changes (rule 4) —
// for example when an old AntreaNodeConfig CR stops matching the Node and a new ANC with a
// different bridge name takes effect — the controller's state (effectiveBridgeCfg and
// ovsBridgeClient) is cleared immediately after the old bridge is deleted. This ensures that
// if createAndConnectBridge subsequently fails, a retry attempt does not try to delete the
// already-removed bridge a second time.
func TestReconcileBridgeStateCleared(t *testing.T) {
	ctrl := mock.NewController(t)
	oldMock := ovsconfigtest.NewMockOVSBridgeClient(ctrl)
	newMock := ovsconfigtest.NewMockOVSBridgeClient(ctrl)
	mockInterfaceByName(t)

	createErr := ovsconfig.InvalidArgumentsError("create failed")

	// The new-bridge factory returns newMock; its Create() will fail to simulate a partial
	// failure after the old bridge has already been deleted.
	prevNewOVSBridgeFn := newOVSBridgeFn
	var capturedController *Controller
	newOVSBridgeFn = func(bridgeName string, ovsDatapathType ovsconfig.OVSDatapathType, ovsdb *ovsdb.OVSDB, options ...ovsconfig.OVSBridgeOption) ovsconfig.OVSBridgeClient {
		// Verify that state was already cleared at this point (delete happened before create).
		if capturedController != nil {
			capturedController.mu.RLock()
			assert.Nil(t, capturedController.effectiveBridgeCfg, "effectiveBridgeCfg should be nil after old bridge deleted")
			assert.Nil(t, capturedController.ovsBridgeClient, "ovsBridgeClient should be nil after old bridge deleted")
			capturedController.mu.RUnlock()
		}
		return newMock
	}
	t.Cleanup(func() { newOVSBridgeFn = prevNewOVSBridgeFn })

	prevCfg := &agenttypes.OVSBridgeConfig{
		BridgeName:         brOld,
		PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{{Name: eth1}, {Name: eth2}},
	}

	// Old bridge is deleted; new bridge creation fails.
	oldMock.EXPECT().Delete().Return(nil)
	newMock.EXPECT().Create().Return(createErr)

	staticCfg := &agentconfig.SecondaryNetworkConfig{
		OVSBridges: []agentconfig.OVSBridgeConfig{{
			BridgeName:         brNew,
			PhysicalInterfaces: []string{eth1, eth2},
		}},
	}

	c := &Controller{
		ovsBridgeClient:    oldMock,
		secNetConfig:       staticCfg,
		effectiveBridgeCfg: prevCfg,
		ancLister:          &fakeANCLister{},
		node:               &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node1"}},
		ovsdbConn:          nil,
		podController:      &fakePodController{},
	}
	capturedController = c

	err := c.reconcileBridge()
	require.Error(t, err, "expected error from failed bridge creation")

	// After the failed reconcile, state must reflect that the old bridge is gone.
	c.mu.RLock()
	assert.Nil(t, c.effectiveBridgeCfg, "effectiveBridgeCfg should remain nil after failed create")
	assert.Nil(t, c.ovsBridgeClient, "ovsBridgeClient should remain nil after failed create")
	c.mu.RUnlock()
}

// hasAllowedVLANs reports whether any physical interface in cfg has AllowedVLANs set.
func hasAllowedVLANs(cfg *agenttypes.OVSBridgeConfig) bool {
	if cfg == nil {
		return false
	}
	for _, pi := range cfg.PhysicalInterfaces {
		if len(pi.AllowedVLANs) > 0 {
			return true
		}
	}
	return false
}

// makeANCListerFromBridgeCfg builds a fakeANCLister whose single item covers the bridge.
func makeANCListerFromBridgeCfg(cfg *agenttypes.OVSBridgeConfig) *fakeANCLister {
	phyIfaces := make([]crdv1alpha1.PhysicalInterfaceConfig, 0, len(cfg.PhysicalInterfaces))
	for _, pi := range cfg.PhysicalInterfaces {
		phyIfaces = append(phyIfaces, crdv1alpha1.PhysicalInterfaceConfig{
			Name:         pi.Name,
			AllowedVLANs: pi.AllowedVLANs,
		})
	}
	anc := &crdv1alpha1.AntreaNodeConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "anc-test",
			CreationTimestamp: metav1.NewTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
		},
		Spec: crdv1alpha1.AntreaNodeConfigSpec{
			// Empty nodeSelector matches everything.
			NodeSelector: metav1.LabelSelector{},
			SecondaryNetwork: &crdv1alpha1.SecondaryNetworkConfig{
				OVSBridges: []crdv1alpha1.OVSBridgeConfig{
					{
						BridgeName:         cfg.BridgeName,
						PhysicalInterfaces: phyIfaces,
					},
				},
			},
		},
	}
	return &fakeANCLister{items: []*crdv1alpha1.AntreaNodeConfig{anc}}
}

// fakeANCLister is a trivial in-memory AntreaNodeConfigLister for testing.
type fakeANCLister struct {
	items []*crdv1alpha1.AntreaNodeConfig
	err   error
}

func (f *fakeANCLister) List(_ labels.Selector) ([]*crdv1alpha1.AntreaNodeConfig, error) {
	return f.items, f.err
}

func (f *fakeANCLister) Get(name string) (*crdv1alpha1.AntreaNodeConfig, error) {
	for _, item := range f.items {
		if item.Name == name {
			return item, nil
		}
	}
	return nil, nil
}

var _ crdv1alpha1listers.AntreaNodeConfigLister = (*fakeANCLister)(nil)

func mockInterfaceByName(t *testing.T) {
	prevFunc := interfaceByNameFn
	interfaceByNameFn = func(name string) (*net.Interface, error) {
		if name == nonExistingInterface {
			return nil, errors.New("interface not found")
		}
		return nil, nil
	}
	t.Cleanup(func() { interfaceByNameFn = prevFunc })
}

func mockNewOVSBridge(t *testing.T, brClient ovsconfig.OVSBridgeClient) {
	prevFunc := newOVSBridgeFn
	newOVSBridgeFn = func(bridgeName string, ovsDatapathType ovsconfig.OVSDatapathType, ovsdb *ovsdb.OVSDB, options ...ovsconfig.OVSBridgeOption) ovsconfig.OVSBridgeClient {
		return brClient
	}
	t.Cleanup(func() { newOVSBridgeFn = prevFunc })
}
