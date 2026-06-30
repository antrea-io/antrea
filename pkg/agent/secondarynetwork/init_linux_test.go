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

	"github.com/TomCodeLV/OVSDB-golang-lib/pkg/ovsdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	mock "go.uber.org/mock/gomock"

	agenttypes "antrea.io/antrea/v2/pkg/agent/types"
	agentconfig "antrea.io/antrea/v2/pkg/config/agent"
	"antrea.io/antrea/v2/pkg/ovs/ovsconfig"
	ovsconfigtest "antrea.io/antrea/v2/pkg/ovs/ovsconfig/testing"
)

const (
	nonExistingInterface = "non-existing"
	// uplinkOFPort is a placeholder OF port number used in GetOFPort mock stubs to indicate
	// that an interface is already connected to the bridge. The exact value is not significant.
	uplinkOFPort = 1
)

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
		name             string
		bridgeCfg        *agenttypes.OVSBridgeConfig
		expectedCalls    func(m *ovsconfigtest.MockOVSBridgeClient)
		wantRestoreCalls []struct{ bridge, iface string }
		expectedErr      string
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
					{Name: eth1, IFName: eth1, IFType: "internal", ExternalIDs: map[string]string{"antrea-type": "host"}},
					{Name: eth1Tilde, IFName: eth1Tilde, IFType: "", ExternalIDs: map[string]string{"antrea-type": "uplink"}},
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
			wantRestoreCalls: []struct{ bridge, iface string }{{"br1", eth1}},
		},
		{
			// Regression: bridge has a stale host-connection setup (eth1 internal
			// + eth1~ uplink) from a previous single-interface run, but the new
			// desired multi-interface config no longer includes eth1. Initialize
			// must still restore eth1 so the kernel rename and old OVS ports do
			// not remain after eth1 is removed from the desired config.
			name: "stale host-connection removed from desired config",
			bridgeCfg: &agenttypes.OVSBridgeConfig{
				BridgeName: "br1",
				PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
					{Name: eth2},
					{Name: eth3},
				},
			},
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				eth1Tilde := eth1 + "~"
				m.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{Name: eth1, IFName: eth1, IFType: "internal", ExternalIDs: map[string]string{"antrea-type": "host"}},
					{Name: eth1Tilde, IFName: eth1Tilde, IFType: "", ExternalIDs: map[string]string{"antrea-type": "uplink"}},
				}, nil).Times(1)

				m.EXPECT().GetOFPort(eth2, false).Return(int32(0), ovsconfig.InvalidArgumentsError("not found"))
				m.EXPECT().CreateUplinkPort(eth2, int32(0), map[string]interface{}{"antrea-type": "uplink"}).Return("", nil)
				m.EXPECT().GetOFPort(eth3, false).Return(int32(0), ovsconfig.InvalidArgumentsError("not found"))
				m.EXPECT().CreateUplinkPort(eth3, int32(0), map[string]interface{}{"antrea-type": "uplink"}).Return("", nil)

				m.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{Name: eth2, IFName: eth2, IFType: ""},
					{Name: eth3, IFName: eth3, IFType: ""},
				}, nil).Times(1)
			},
			wantRestoreCalls: []struct{ bridge, iface string }{{"br1", eth1}},
		},
		{
			name: "unmanaged internal port with sibling is not restored",
			bridgeCfg: &agenttypes.OVSBridgeConfig{
				BridgeName: "br1",
				PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
					{Name: eth2},
					{Name: eth3},
				},
			},
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				eth1Tilde := eth1 + "~"
				m.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{Name: eth1, IFName: eth1, IFType: "internal"},
					{Name: eth1Tilde, IFName: eth1Tilde, IFType: ""},
				}, nil).Times(1)

				m.EXPECT().GetOFPort(eth2, false).Return(int32(0), ovsconfig.InvalidArgumentsError("not found"))
				m.EXPECT().CreateUplinkPort(eth2, int32(0), map[string]interface{}{"antrea-type": "uplink"}).Return("", nil)
				m.EXPECT().GetOFPort(eth3, false).Return(int32(0), ovsconfig.InvalidArgumentsError("not found"))
				m.EXPECT().CreateUplinkPort(eth3, int32(0), map[string]interface{}{"antrea-type": "uplink"}).Return("", nil)

				m.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{Name: eth1, IFName: eth1, IFType: "internal"},
					{Name: eth1Tilde, IFName: eth1Tilde, IFType: ""},
					{Name: eth2, IFName: eth2, IFType: ""},
					{Name: eth3, IFName: eth3, IFType: ""},
				}, nil).Times(1)
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
			var gotRestoreCalls []struct{ bridge, iface string }
			restoreHostInterfaceConfigFn = func(brName, ifaceName string) error {
				gotRestoreCalls = append(gotRestoreCalls, struct{ bridge, iface string }{brName, ifaceName})
				return nil
			}

			if tc.expectedCalls != nil {
				tc.expectedCalls(mockOVSBridgeClient)
			}

			c := &Controller{
				ovsBridgeClient:    mockOVSBridgeClient,
				effectiveBridgeCfg: tc.bridgeCfg,
			}
			err := c.Initialize(nil)
			if tc.expectedErr != "" {
				assert.ErrorContains(t, err, tc.expectedErr)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tc.wantRestoreCalls, gotRestoreCalls)
		})
	}
}

const (
	brOld = "br-old"
	brNew = "br-new"
	eth1  = "eth1"
	eth2  = "eth2"
	eth3  = "eth3"
)

// TestReconcileBridge tests the reconcileBridge function with various transitions.
// fakePodController implements podControllerInterface for unit tests.
// It records calls to UpdateOVSBridgeClient so tests can assert on them.
type fakePodController struct {
	updateBridgeCalls []ovsconfig.OVSBridgeClient
	updateBridgeErr   error
}

func (f *fakePodController) Run(_ <-chan struct{}) {}

func (f *fakePodController) AllowCNIDelete(_, _ string) bool { return true }

func (f *fakePodController) UpdateOVSBridgeClient(c ovsconfig.OVSBridgeClient) error {
	f.updateBridgeCalls = append(f.updateBridgeCalls, c)
	return f.updateBridgeErr
}

func TestReconcileBridge(t *testing.T) {
	portUUID := "uuid-eth1"

	tests := []struct {
		name                string
		prevCfg             *agenttypes.OVSBridgeConfig
		desiredCfg          *agenttypes.OVSBridgeConfig // returned by effectiveBridge() in production
		expectedCalls       func(old, new *ovsconfigtest.MockOVSBridgeClient)
		wantNewClient       bool // whether c.ovsBridgeClient should be the "new" mock after reconcile
		wantUpdateBridgeN   int  // expected number of UpdateOVSBridgeClient calls on the podController
		wantUpdateBridgeNil bool // whether the last UpdateOVSBridgeClient call should pass nil
		// wantRestoreCalls lists the (bridge, iface) pairs that restoreHostInterfaceConfigFn
		// must be called with, in order, when an interface is removed from the config.
		wantRestoreCalls []struct{ bridge, iface string }
		wantPrepareCalls []string
		expectedErr      string
	}{
		{
			name:          "no change (both nil)",
			prevCfg:       nil,
			desiredCfg:    nil,
			expectedCalls: func(old, new *ovsconfigtest.MockOVSBridgeClient) {},
		},
		{
			name:       "no change (same config)",
			prevCfg:    &agenttypes.OVSBridgeConfig{BridgeName: brOld, PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{{Name: eth1}}},
			desiredCfg: &agenttypes.OVSBridgeConfig{BridgeName: brOld, PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{{Name: eth1}}},
			expectedCalls: func(old, new *ovsconfigtest.MockOVSBridgeClient) {
				eth1Tilde := eth1 + "~"
				old.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{UUID: "uuid-eth1", IFName: eth1, IFType: "internal"},
					{UUID: "uuid-eth1-tilde", IFName: eth1Tilde, ExternalIDs: map[string]string{"antrea-type": "uplink"}},
				}, nil).Times(1)
				old.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{Name: eth1Tilde, IFName: eth1Tilde, Trunks: nil},
				}, nil).Times(1)
			},
		},
		{
			name:       "bridge deleted (desired is nil)",
			prevCfg:    &agenttypes.OVSBridgeConfig{BridgeName: brOld, PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{{Name: eth1}}},
			desiredCfg: nil,
			expectedCalls: func(old, new *ovsconfigtest.MockOVSBridgeClient) {
				old.EXPECT().Create().Return(nil)
				// deleteBridge queries OVSDB for host-connection ports before deletion.
				old.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{IFName: eth1, IFType: "internal", ExternalIDs: map[string]string{"antrea-type": "host"}},
				}, nil)
				old.EXPECT().Delete().Return(nil)
			},
			wantUpdateBridgeN:   1,
			wantUpdateBridgeNil: true,
			wantRestoreCalls:    []struct{ bridge, iface string }{{brOld, eth1}},
		},
		{
			// Use two interfaces to bypass the single-interface PrepareHostInterfaceConnection path.
			name:       "bridge created (prev is nil, two interfaces)",
			prevCfg:    nil,
			desiredCfg: &agenttypes.OVSBridgeConfig{BridgeName: brNew, PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{{Name: eth1}, {Name: eth2}}},
			expectedCalls: func(old, new *ovsconfigtest.MockOVSBridgeClient) {
				new.EXPECT().Create().Return(nil)
				new.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{}, nil).Times(1)
				new.EXPECT().GetOFPort(eth1, false).Return(int32(0), ovsconfig.InvalidArgumentsError("not found"))
				new.EXPECT().CreateUplinkPort(eth1, int32(0), map[string]interface{}{"antrea-type": "uplink"}).Return("", nil)
				new.EXPECT().GetOFPort(eth2, false).Return(int32(0), ovsconfig.InvalidArgumentsError("not found"))
				new.EXPECT().CreateUplinkPort(eth2, int32(0), map[string]interface{}{"antrea-type": "uplink"}).Return("", nil)
				new.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{Name: eth1, IFName: eth1, Trunks: nil},
					{Name: eth2, IFName: eth2, Trunks: nil},
				}, nil).Times(1)
			},
			wantNewClient:     true,
			wantUpdateBridgeN: 1,
		},
		{
			// OVSBridge.Create() attaches to an existing bridge; uplinks may already be present
			// with stale trunk VLANs while the new desired config has no AllowedVLANs.
			// connectPhyInterfacesToOVSBridge skips existing plain uplinks, so clearStaleTrunks
			// after connect must clear the trunks (regression for createAndConnectBridge).
			name:       "bridge created — pre-existing uplinks with stale trunks cleared",
			prevCfg:    nil,
			desiredCfg: &agenttypes.OVSBridgeConfig{BridgeName: brNew, PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{{Name: eth1}, {Name: eth2}}},
			expectedCalls: func(old, new *ovsconfigtest.MockOVSBridgeClient) {
				new.EXPECT().Create().Return(nil)
				new.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{Name: eth1, IFName: eth1, IFType: ""},
					{Name: eth2, IFName: eth2, IFType: ""},
				}, nil).Times(1)
				new.EXPECT().GetOFPort(eth1, false).Return(int32(uplinkOFPort), nil)
				new.EXPECT().GetOFPort(eth2, false).Return(int32(uplinkOFPort+1), nil)
				new.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{Name: eth1, IFName: eth1, Trunks: []uint16{100}},
					{Name: eth2, IFName: eth2, Trunks: []uint16{200}},
				}, nil).Times(1)
				new.EXPECT().SetPortTrunks(eth1, nil).Return(nil)
				new.EXPECT().SetPortTrunks(eth2, nil).Return(nil)
			},
			wantNewClient:     true,
			wantUpdateBridgeN: 1,
		},
		{
			// Use two interfaces to bypass the single-interface PrepareHostInterfaceConnection path.
			name:       "different bridge name — delete old, create new",
			prevCfg:    &agenttypes.OVSBridgeConfig{BridgeName: brOld, PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{{Name: eth1}, {Name: eth2}}},
			desiredCfg: &agenttypes.OVSBridgeConfig{BridgeName: brNew, PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{{Name: eth1}, {Name: eth2}}},
			expectedCalls: func(old, new *ovsconfigtest.MockOVSBridgeClient) {
				old.EXPECT().Create().Return(nil)
				// deleteBridge queries OVSDB for host ports (none for multi-iface).
				old.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{}, nil)
				old.EXPECT().Delete().Return(nil)
				new.EXPECT().Create().Return(nil)
				new.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{}, nil).Times(1)
				new.EXPECT().GetOFPort(eth1, false).Return(int32(0), ovsconfig.InvalidArgumentsError("not found"))
				new.EXPECT().CreateUplinkPort(eth1, int32(0), map[string]interface{}{"antrea-type": "uplink"}).Return("", nil)
				new.EXPECT().GetOFPort(eth2, false).Return(int32(0), ovsconfig.InvalidArgumentsError("not found"))
				new.EXPECT().CreateUplinkPort(eth2, int32(0), map[string]interface{}{"antrea-type": "uplink"}).Return("", nil)
				new.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{Name: eth1, IFName: eth1, Trunks: nil},
					{Name: eth2, IFName: eth2, Trunks: nil},
				}, nil).Times(1)
			},
			wantNewClient: true,
			// UpdateOVSBridgeClient(nil) after old bridge deleted, then UpdateOVSBridgeClient(new) from createAndConnectBridge.
			wantUpdateBridgeN: 2,
		},
		{
			name:       "same bridge name — add new interface",
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
			// No UpdateOVSBridgeClient: same bridge, client unchanged.
		},
		{
			name:       "same bridge name — remove old interface",
			prevCfg:    &agenttypes.OVSBridgeConfig{BridgeName: brOld, PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{{Name: eth1}, {Name: eth2}}},
			desiredCfg: &agenttypes.OVSBridgeConfig{BridgeName: brOld, PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{{Name: eth1}}},
			expectedCalls: func(old, new *ovsconfigtest.MockOVSBridgeClient) {
				old.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{UUID: portUUID, IFName: eth1, IFType: ""},
					{UUID: "uuid-eth2", IFName: eth2, ExternalIDs: map[string]string{"antrea-type": "uplink"}},
				}, nil).Times(1)
				// eth1 transitions from a plain uplink to the single-uplink host-connection
				// setup, so the plain eth1 OVS port is removed before PrepareHostInterfaceConnection.
				old.EXPECT().DeletePorts([]string{portUUID}).Return(nil)
				// eth2 is no longer desired and is removed based on the observed OVSDB state.
				old.EXPECT().DeletePorts([]string{"uuid-eth2"}).Return(nil)
				// clearStaleTrunks: eth1~ will be the physical uplink port and has no trunks.
				old.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{Name: eth1, IFName: eth1, IFType: "internal"},
				}, nil).Times(1)
				old.EXPECT().GetOFPort(eth1+"~", false).Return(int32(0), ovsconfig.InvalidArgumentsError("not found"))
				old.EXPECT().CreateUplinkPort(eth1+"~", int32(0), map[string]interface{}{"antrea-type": "uplink"}).Return("", nil)
			},
			wantPrepareCalls: []string{eth1},
			// No UpdateOVSBridgeClient: same bridge, client unchanged.
		},
		{
			name:    "same bridge, add interface with VLANs",
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
			// No UpdateOVSBridgeClient: same bridge, client unchanged.
		},
		{
			// Regression test: existing port gains AllowedVLANs (e.g. ANC CR applied after
			// agent started with static config that had no VLANs). The port is already
			// present on the bridge so only SetPortTrunks must be called to update it.
			name:    "same bridge, existing interface gains AllowedVLANs",
			prevCfg: &agenttypes.OVSBridgeConfig{BridgeName: brOld, PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{{Name: eth1}}},
			desiredCfg: &agenttypes.OVSBridgeConfig{BridgeName: brOld, PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
				{Name: eth1, AllowedVLANs: []string{"100", "300"}},
			}},
			expectedCalls: func(old, new *ovsconfigtest.MockOVSBridgeClient) {
				eth1Tilde := eth1 + "~"
				old.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{UUID: "uuid-eth1", IFName: eth1, IFType: "internal"},
					{UUID: "uuid-eth1-tilde", IFName: eth1Tilde, IFType: ""},
				}, nil)
				// eth1 is a single-uplink host connection, so trunk list must be updated on eth1~.
				old.EXPECT().GetOFPort(eth1Tilde, false).Return(int32(uplinkOFPort), nil)
				old.EXPECT().SetPortTrunks(eth1Tilde, []string{"100", "300"}).Return(nil)
			},
			// No UpdateOVSBridgeClient: same bridge, client unchanged.
		},
		{
			// Regression test: existing trunk ports have AllowedVLANs cleared (e.g. ANC CR
			// updated to remove allowedVLANs).  clearStaleTrunks reads the actual OVS port
			// state and calls SetPortTrunks(nil) for ports that still have trunks set.
			name: "same bridge, existing interface loses AllowedVLANs",
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
			// No UpdateOVSBridgeClient: same bridge, client unchanged.
		},
		{
			// Regression: eth1 loses AllowedVLANs AND eth2 has a stale trunk 300 that
			// was never reflected in prev (set externally or from a run the controller
			// didn't track).  clearStaleTrunks reads actual OVS state and clears both.
			name: "stale trunk on eth2 not in prev config — cleared via OVS state",
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
			// No UpdateOVSBridgeClient: same bridge, client unchanged.
		},
		{
			// Regression: eth1 was connected via PrepareHostInterfaceConnection (single-interface
			// host-connection path), so the bridge holds two ports: "eth1" (internal) and "eth1~"
			// (uplink).  The ANC is updated to replace eth1 with eth2.  updatePhysicalInterfaces
			// must call restoreHostInterfaceConfigFn(brOld, eth1) to remove both ports and restore
			// the kernel interface name — NOT merely DeletePorts("eth1"), which would leave "eth1~"
			// stranded on the bridge and the host kernel interface stuck under the renamed name.
			name: "host-connection port removed — RestoreHostInterfaceConfiguration called",
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
					{UUID: "uuid-eth1", IFName: eth1, IFType: "internal", ExternalIDs: map[string]string{"antrea-type": "host"}},
					{UUID: "uuid-eth1-tilde", IFName: eth1Tilde, IFType: "", ExternalIDs: map[string]string{"antrea-type": "uplink"}},
				}, nil).Times(1)
				// eth2 is the new single uplink, so the bridge port is eth2~ after
				// PrepareHostInterfaceConnection.
				old.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{Name: eth2, IFName: eth2, IFType: "internal"},
				}, nil).Times(1)
				old.EXPECT().GetOFPort(eth2+"~", false).Return(int32(0), ovsconfig.InvalidArgumentsError("not found"))
				old.EXPECT().CreateUplinkPort(eth2+"~", int32(0), map[string]interface{}{"antrea-type": "uplink"}).Return("", nil)
			},
			wantRestoreCalls: []struct{ bridge, iface string }{{brOld, eth1}},
			wantPrepareCalls: []string{eth2},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := mock.NewController(t)
			oldMock := ovsconfigtest.NewMockOVSBridgeClient(ctrl)
			newMock := ovsconfigtest.NewMockOVSBridgeClient(ctrl)

			mockInterfaceByName(t)
			mockNewOVSBridgeByName(t, map[string]ovsconfig.OVSBridgeClient{
				brOld: oldMock,
				brNew: newMock,
			})

			// Mock the OVSDB query to return the bridge name implied by prevCfg.
			origFindManaged := findManagedSecondaryBridgeFn
			currentBrName := ""
			if tc.prevCfg != nil {
				currentBrName = tc.prevCfg.BridgeName
			}
			findManagedSecondaryBridgeFn = func(ovsdbConn *ovsdb.OVSDB) (string, error) {
				return currentBrName, nil
			}
			t.Cleanup(func() { findManagedSecondaryBridgeFn = origFindManaged })

			origAdoptStatic := adoptSecondaryBridgeFn
			adoptSecondaryBridgeFn = func(staticBridge *agenttypes.OVSBridgeConfig, ovsdbConn *ovsdb.OVSDB) (string, error) {
				return "", nil
			}
			t.Cleanup(func() { adoptSecondaryBridgeFn = origAdoptStatic })

			if tc.prevCfg != nil && tc.desiredCfg != nil && tc.prevCfg.BridgeName == tc.desiredCfg.BridgeName {
				// Same-bridge reconciliation calls createOVSBridgeClient to apply
				// bridge-level options on the existing bridge.
				oldMock.EXPECT().Create().Return(nil)
			}
			// Capture restoreHostInterfaceConfigFn calls for verification.
			var gotRestoreCalls []struct{ bridge, iface string }
			origRestore := restoreHostInterfaceConfigFn
			restoreHostInterfaceConfigFn = func(brName, ifaceName string) error {
				gotRestoreCalls = append(gotRestoreCalls, struct{ bridge, iface string }{brName, ifaceName})
				return nil
			}
			t.Cleanup(func() { restoreHostInterfaceConfigFn = origRestore })

			var gotPrepareCalls []string
			origPrepare := prepareHostInterfaceConnectionFn
			prepareHostInterfaceConnectionFn = func(_ ovsconfig.OVSBridgeClient, ifaceName string, _ int32, _ map[string]interface{}, _ int) (string, bool, error) {
				gotPrepareCalls = append(gotPrepareCalls, ifaceName)
				return ifaceName + "~", false, nil
			}
			t.Cleanup(func() { prepareHostInterfaceConnectionFn = origPrepare })

			if tc.expectedCalls != nil {
				tc.expectedCalls(oldMock, newMock)
			}

			fakePc := &fakePodController{}
			desiredCfg := tc.desiredCfg
			var ovsBridgeClient ovsconfig.OVSBridgeClient
			if tc.prevCfg != nil {
				ovsBridgeClient = oldMock
			}
			c := &Controller{
				ovsBridgeClient:         ovsBridgeClient,
				secNetConfig:            &agentconfig.SecondaryNetworkConfig{},
				effectiveBridgeCfg:      tc.prevCfg,
				effectiveBridgeOverride: func() *agenttypes.OVSBridgeConfig { return desiredCfg },
				ovsdbConn:               nil,
				podController:           fakePc,
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
				// Verify UpdateOVSBridgeClient was called the expected number of times.
				assert.Len(t, fakePc.updateBridgeCalls, tc.wantUpdateBridgeN,
					"unexpected number of UpdateOVSBridgeClient calls")
				if tc.wantUpdateBridgeN > 0 {
					last := fakePc.updateBridgeCalls[len(fakePc.updateBridgeCalls)-1]
					if tc.wantUpdateBridgeNil {
						assert.Nil(t, last, "expected UpdateOVSBridgeClient(nil) for bridge deletion")
					} else {
						assert.Equal(t, newMock, last, "expected UpdateOVSBridgeClient(newMock) for bridge creation")
					}
				}
				// Verify restoreHostInterfaceConfigFn calls.
				if tc.wantRestoreCalls != nil {
					assert.Equal(t, tc.wantRestoreCalls, gotRestoreCalls,
						"unexpected restoreHostInterfaceConfigFn calls")
				} else {
					assert.Empty(t, gotRestoreCalls, "unexpected restoreHostInterfaceConfigFn calls")
				}
				assert.Equal(t, tc.wantPrepareCalls, gotPrepareCalls,
					"unexpected PrepareHostInterfaceConnection calls")
			}
		})
	}
}

// TestReconcileBridgeStateCleared verifies that when the bridge name changes —
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

	// Mock the OVSDB query to return the old bridge name, so reconcileBridge
	// takes the delete+create path.
	origFindManaged := findManagedSecondaryBridgeFn
	findManagedSecondaryBridgeFn = func(ovsdbConn *ovsdb.OVSDB) (string, error) {
		return brOld, nil
	}
	t.Cleanup(func() { findManagedSecondaryBridgeFn = origFindManaged })
	origAdoptStatic := adoptSecondaryBridgeFn
	adoptSecondaryBridgeFn = func(staticBridge *agenttypes.OVSBridgeConfig, ovsdbConn *ovsdb.OVSDB) (string, error) {
		return "", nil
	}
	t.Cleanup(func() { adoptSecondaryBridgeFn = origAdoptStatic })

	// The new-bridge factory returns newMock; its Create() will fail to simulate a partial
	// failure after the old bridge has already been deleted.
	prevNewOVSBridgeFn := newOVSBridgeFn
	var capturedController *Controller
	newOVSBridgeFn = func(bridgeName string, ovsDatapathType ovsconfig.OVSDatapathType, ovsdb *ovsdb.OVSDB, options ...ovsconfig.OVSBridgeOption) ovsconfig.OVSBridgeClient {
		if bridgeName == brOld {
			return oldMock
		}
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

	// deleteBridge queries OVSDB for host ports (none for multi-iface), then deletes.
	oldMock.EXPECT().Create().Return(nil)
	oldMock.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{}, nil)
	oldMock.EXPECT().Delete().Return(nil)
	newMock.EXPECT().Create().Return(createErr)

	desired := &agenttypes.OVSBridgeConfig{
		BridgeName:         brNew,
		PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{{Name: eth1}, {Name: eth2}},
	}

	c := &Controller{
		ovsBridgeClient:         oldMock,
		secNetConfig:            &agentconfig.SecondaryNetworkConfig{},
		effectiveBridgeCfg:      prevCfg,
		effectiveBridgeOverride: func() *agenttypes.OVSBridgeConfig { return desired },
		ovsdbConn:               nil,
		podController:           &fakePodController{},
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

func TestCreateAndConnectBridgeDoesNotRecordStateOnPodControllerUpdateFailure(t *testing.T) {
	ctrl := mock.NewController(t)
	newMock := ovsconfigtest.NewMockOVSBridgeClient(ctrl)

	mockInterfaceByName(t)
	mockNewOVSBridge(t, newMock)

	desired := &agenttypes.OVSBridgeConfig{
		BridgeName:         brNew,
		PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{{Name: eth1}, {Name: eth2}},
	}
	updateErr := errors.New("interface store reload failed")

	newMock.EXPECT().Create().Return(nil)
	newMock.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{}, nil).Times(1)
	newMock.EXPECT().GetOFPort(eth1, false).Return(int32(0), ovsconfig.InvalidArgumentsError("not found"))
	newMock.EXPECT().CreateUplinkPort(eth1, int32(0), map[string]interface{}{"antrea-type": "uplink"}).Return("", nil)
	newMock.EXPECT().GetOFPort(eth2, false).Return(int32(0), ovsconfig.InvalidArgumentsError("not found"))
	newMock.EXPECT().CreateUplinkPort(eth2, int32(0), map[string]interface{}{"antrea-type": "uplink"}).Return("", nil)
	newMock.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
		{Name: eth1, IFName: eth1, Trunks: nil},
		{Name: eth2, IFName: eth2, Trunks: nil},
	}, nil).Times(1)

	c := &Controller{
		secNetConfig:       &agentconfig.SecondaryNetworkConfig{},
		ovsdbConn:          nil,
		podController:      &fakePodController{updateBridgeErr: updateErr},
		ovsBridgeClient:    nil,
		effectiveBridgeCfg: nil,
	}

	err := c.createAndConnectBridge(desired)
	require.ErrorIs(t, err, updateErr)

	c.mu.RLock()
	assert.Nil(t, c.effectiveBridgeCfg, "effectiveBridgeCfg should not advance when PodController update fails")
	assert.Nil(t, c.ovsBridgeClient, "ovsBridgeClient should not advance when PodController update fails")
	c.mu.RUnlock()
}

func TestDeleteAndDisconnectBridgeClearsStateAfterPodControllerUpdate(t *testing.T) {
	ctrl := mock.NewController(t)
	oldMock := ovsconfigtest.NewMockOVSBridgeClient(ctrl)

	updateErr := errors.New("interface store reload failed")
	fakePc := &fakePodController{updateBridgeErr: updateErr}
	prevCfg := &agenttypes.OVSBridgeConfig{
		BridgeName:         brOld,
		PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{{Name: eth1}, {Name: eth2}},
	}
	desiredCfg := (*agenttypes.OVSBridgeConfig)(nil)

	// Mock findManagedSecondaryBridgeFn: first call returns brOld (bridge exists),
	// second call returns "" (bridge deleted from OVSDB by the first reconcile).
	callCount := 0
	origFindManaged := findManagedSecondaryBridgeFn
	findManagedSecondaryBridgeFn = func(ovsdbConn *ovsdb.OVSDB) (string, error) {
		callCount++
		if callCount == 1 {
			return brOld, nil
		}
		return "", nil
	}
	t.Cleanup(func() { findManagedSecondaryBridgeFn = origFindManaged })
	origAdoptStatic := adoptSecondaryBridgeFn
	adoptSecondaryBridgeFn = func(staticBridge *agenttypes.OVSBridgeConfig, ovsdbConn *ovsdb.OVSDB) (string, error) {
		return "", nil
	}
	t.Cleanup(func() { adoptSecondaryBridgeFn = origAdoptStatic })

	// deleteBridge calls GetPortList before Delete. Called once — on the second
	// reconcile OVSDB shows no bridge so deleteBridge is not re-entered.
	oldMock.EXPECT().Create().Return(nil).Times(1)
	oldMock.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{}, nil).Times(1)
	oldMock.EXPECT().Delete().Return(nil).Times(1)

	c := &Controller{
		ovsBridgeClient:         oldMock,
		secNetConfig:            &agentconfig.SecondaryNetworkConfig{},
		effectiveBridgeCfg:      prevCfg,
		effectiveBridgeOverride: func() *agenttypes.OVSBridgeConfig { return desiredCfg },
		ovsdbConn:               nil,
		podController:           fakePc,
	}

	// First reconcile: delete succeeds, clearBridgeState runs, but
	// UpdateOVSBridgeClient(nil) fails → error returned.
	err := c.reconcileBridge()
	require.ErrorIs(t, err, updateErr)
	assert.Len(t, fakePc.updateBridgeCalls, 1)
	assert.Nil(t, fakePc.updateBridgeCalls[0])
	// State is cleared before UpdateOVSBridgeClient, so it is already nil.
	c.mu.RLock()
	assert.Nil(t, c.effectiveBridgeCfg, "effectiveBridgeCfg should be cleared after bridge deletion")
	assert.Nil(t, c.ovsBridgeClient, "ovsBridgeClient should be cleared after bridge deletion")
	c.mu.RUnlock()

	// Second reconcile: OVSDB shows no bridge, desired is nil → no-op.
	// The PodController still has a stale client, but it will be overwritten
	// when a new bridge is created.
	fakePc.updateBridgeErr = nil
	err = c.reconcileBridge()
	require.NoError(t, err)
	// No additional UpdateOVSBridgeClient call because reconcile is a no-op.
	assert.Len(t, fakePc.updateBridgeCalls, 1)
	c.mu.RLock()
	assert.Nil(t, c.effectiveBridgeCfg, "effectiveBridgeCfg should remain nil after successful no-op reconcile")
	assert.Nil(t, c.ovsBridgeClient, "ovsBridgeClient should remain nil after successful no-op reconcile")
	c.mu.RUnlock()
}

func TestReconcileBridgeDeletesCurrentBridgeAfterAgentRestart(t *testing.T) {
	ctrl := mock.NewController(t)
	oldMock := ovsconfigtest.NewMockOVSBridgeClient(ctrl)

	mockInterfaceByName(t)
	mockNewOVSBridgeByName(t, map[string]ovsconfig.OVSBridgeClient{
		brOld: oldMock,
	})

	origFindManaged := findManagedSecondaryBridgeFn
	findManagedSecondaryBridgeFn = func(ovsdbConn *ovsdb.OVSDB) (string, error) {
		return brOld, nil
	}
	t.Cleanup(func() { findManagedSecondaryBridgeFn = origFindManaged })
	origAdoptStatic := adoptSecondaryBridgeFn
	adoptSecondaryBridgeFn = func(staticBridge *agenttypes.OVSBridgeConfig, ovsdbConn *ovsdb.OVSDB) (string, error) {
		return "", nil
	}
	t.Cleanup(func() { adoptSecondaryBridgeFn = origAdoptStatic })

	var gotRestoreCalls []struct{ bridge, iface string }
	origRestore := restoreHostInterfaceConfigFn
	restoreHostInterfaceConfigFn = func(brName, ifaceName string) error {
		gotRestoreCalls = append(gotRestoreCalls, struct{ bridge, iface string }{brName, ifaceName})
		return nil
	}
	t.Cleanup(func() { restoreHostInterfaceConfigFn = origRestore })

	oldMock.EXPECT().Create().Return(nil)
	oldMock.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
		{IFName: eth1, IFType: "internal", ExternalIDs: map[string]string{"antrea-type": "host"}},
	}, nil)
	oldMock.EXPECT().Delete().Return(nil)

	fakePc := &fakePodController{}
	c := &Controller{
		secNetConfig:            &agentconfig.SecondaryNetworkConfig{},
		effectiveBridgeOverride: func() *agenttypes.OVSBridgeConfig { return nil },
		ovsdbConn:               nil,
		podController:           fakePc,
	}

	err := c.reconcileBridge()
	require.NoError(t, err)
	assert.Equal(t, []struct{ bridge, iface string }{{brOld, eth1}}, gotRestoreCalls)
	assert.Len(t, fakePc.updateBridgeCalls, 1)
	assert.Nil(t, fakePc.updateBridgeCalls[0])
}

func TestReconcileBridgeAdoptsStaticBridgeWhenUnmarked(t *testing.T) {
	ctrl := mock.NewController(t)
	oldMock := ovsconfigtest.NewMockOVSBridgeClient(ctrl)

	mockInterfaceByName(t)
	mockNewOVSBridgeByName(t, map[string]ovsconfig.OVSBridgeClient{
		brOld: oldMock,
	})

	origFindManaged := findManagedSecondaryBridgeFn
	findManagedSecondaryBridgeFn = func(ovsdbConn *ovsdb.OVSDB) (string, error) {
		return "", nil
	}
	t.Cleanup(func() { findManagedSecondaryBridgeFn = origFindManaged })

	origAdoptStatic := adoptSecondaryBridgeFn
	adoptSecondaryBridgeFn = func(staticBridge *agenttypes.OVSBridgeConfig, ovsdbConn *ovsdb.OVSDB) (string, error) {
		assert.Equal(t, brOld, staticBridge.BridgeName)
		return brOld, nil
	}
	t.Cleanup(func() { adoptSecondaryBridgeFn = origAdoptStatic })

	oldMock.EXPECT().Create().Return(nil)
	oldMock.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{}, nil)
	oldMock.EXPECT().Delete().Return(nil)

	fakePc := &fakePodController{}
	c := &Controller{
		secNetConfig: &agentconfig.SecondaryNetworkConfig{
			OVSBridges: []agentconfig.OVSBridgeConfig{{BridgeName: brOld}},
		},
		effectiveBridgeOverride: func() *agenttypes.OVSBridgeConfig { return nil },
		ovsdbConn:               nil,
		podController:           fakePc,
	}

	err := c.reconcileBridge()
	require.NoError(t, err)
	assert.Len(t, fakePc.updateBridgeCalls, 1)
	assert.Nil(t, fakePc.updateBridgeCalls[0])
}

func TestReconcileBridgeUpdatesCurrentBridgeAfterAgentRestart(t *testing.T) {
	ctrl := mock.NewController(t)
	oldMock := ovsconfigtest.NewMockOVSBridgeClient(ctrl)

	mockInterfaceByName(t)
	mockNewOVSBridgeByName(t, map[string]ovsconfig.OVSBridgeClient{
		brOld: oldMock,
	})

	origFindManaged := findManagedSecondaryBridgeFn
	findManagedSecondaryBridgeFn = func(ovsdbConn *ovsdb.OVSDB) (string, error) {
		return brOld, nil
	}
	t.Cleanup(func() { findManagedSecondaryBridgeFn = origFindManaged })
	origAdoptStatic := adoptSecondaryBridgeFn
	adoptSecondaryBridgeFn = func(staticBridge *agenttypes.OVSBridgeConfig, ovsdbConn *ovsdb.OVSDB) (string, error) {
		return "", nil
	}
	t.Cleanup(func() { adoptSecondaryBridgeFn = origAdoptStatic })

	desired := &agenttypes.OVSBridgeConfig{
		BridgeName:         brOld,
		PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{{Name: eth1}, {Name: eth2}},
	}
	oldMock.EXPECT().Create().Return(nil)
	oldMock.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
		{UUID: "uuid-eth1", IFName: eth1},
	}, nil)
	oldMock.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
		{Name: eth1, IFName: eth1, Trunks: nil},
	}, nil)
	oldMock.EXPECT().GetOFPort(eth2, false).Return(int32(0), ovsconfig.InvalidArgumentsError("not found"))
	oldMock.EXPECT().CreateUplinkPort(eth2, int32(0), map[string]interface{}{"antrea-type": "uplink"}).Return("", nil)

	fakePc := &fakePodController{}
	c := &Controller{
		secNetConfig:            &agentconfig.SecondaryNetworkConfig{},
		effectiveBridgeOverride: func() *agenttypes.OVSBridgeConfig { return desired },
		ovsdbConn:               nil,
		podController:           fakePc,
	}

	err := c.reconcileBridge()
	require.NoError(t, err)
	assert.Equal(t, []ovsconfig.OVSBridgeClient{oldMock}, fakePc.updateBridgeCalls)
	c.mu.RLock()
	assert.Equal(t, oldMock, c.ovsBridgeClient)
	assert.Equal(t, desired, c.effectiveBridgeCfg)
	c.mu.RUnlock()
}

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

func mockNewOVSBridgeByName(t *testing.T, brClients map[string]ovsconfig.OVSBridgeClient) {
	prevFunc := newOVSBridgeFn
	newOVSBridgeFn = func(bridgeName string, ovsDatapathType ovsconfig.OVSDatapathType, ovsdb *ovsdb.OVSDB, options ...ovsconfig.OVSBridgeOption) ovsconfig.OVSBridgeClient {
		return brClients[bridgeName]
	}
	t.Cleanup(func() { newOVSBridgeFn = prevFunc })
}
