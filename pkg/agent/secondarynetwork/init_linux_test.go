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
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/ovn-kubernetes/libovsdb/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	mock "go.uber.org/mock/gomock"
	"k8s.io/client-go/util/workqueue"

	"antrea.io/antrea/v2/pkg/agent/interfacestore"
	"antrea.io/antrea/v2/pkg/agent/secondarynetwork/podwatch"
	agenttypes "antrea.io/antrea/v2/pkg/agent/types"
	agentconfig "antrea.io/antrea/v2/pkg/config/agent"
	"antrea.io/antrea/v2/pkg/ovs/ovsconfig"
	ovsconfigtest "antrea.io/antrea/v2/pkg/ovs/ovsconfig/testing"
)

const (
	nonExistingInterface = "non-existing"
	primaryOVSBridge     = "br-int"
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
				m.EXPECT().GetOFPort("eth0~").Return(int32(uplinkOFPort), client.ErrNotFound)
				m.EXPECT().CreateUplinkPort("eth0~", int32(0), map[string]string{"antrea-type": "uplink"}).Return("", nil)
			},
		},
		{
			name: "two interfaces no VLANs",
			physicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
				{Name: "eth1"},
				{Name: "eth2"},
			},
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().GetOFPort("eth1").Return(int32(uplinkOFPort), client.ErrNotFound)
				m.EXPECT().CreateUplinkPort("eth1", int32(0), map[string]string{"antrea-type": "uplink"}).Return("", nil)
				m.EXPECT().GetOFPort("eth2").Return(int32(uplinkOFPort+1), client.ErrNotFound)
				m.EXPECT().CreateUplinkPort("eth2", int32(0), map[string]string{"antrea-type": "uplink"}).Return("", nil)
			},
		},
		{
			name: "interface already attached, no VLANs",
			physicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
				{Name: "eth1"},
			},
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().GetOFPort("eth1").Return(int32(uplinkOFPort), nil)
			},
		},
		{
			name: "stale interface record from another bridge",
			physicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
				{Name: "eth1"},
			},
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				getOFPortErr := fmt.Errorf("port eth1 not found on bridge br1: %w", client.ErrNotFound)
				m.EXPECT().GetOFPort("eth1").Return(int32(0), getOFPortErr)
				m.EXPECT().CreateUplinkPort("eth1", int32(0), map[string]string{"antrea-type": "uplink"}).Return("", nil)
			},
		},
		{
			name: "GetOFPort error for existing uplink",
			physicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
				{Name: "eth1"},
			},
			expectedErr: "invalid ofport -1",
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().GetOFPort("eth1").Return(int32(0), errors.New("invalid ofport -1"))
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
				m.EXPECT().GetOFPort("eth1").Return(int32(uplinkOFPort), client.ErrNotFound)
				m.EXPECT().CreateUplinkPort("eth1", int32(0), map[string]string{"antrea-type": "uplink"}).Return("", errors.New("create error"))
			},
		},
		{
			name: "one interface with single VLAN",
			physicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
				{Name: "eth1", AllowedVLANs: []string{"100"}},
			},
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().GetOFPort("eth1").Return(int32(uplinkOFPort), client.ErrNotFound)
				m.EXPECT().CreateTrunkPort("eth1", int32(0), []string{"100"}, map[string]string{"antrea-type": "uplink"}).Return("", nil)
			},
		},
		{
			name: "one interface with VLAN range",
			physicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
				{Name: "eth1", AllowedVLANs: []string{"200-202"}},
			},
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().GetOFPort("eth1").Return(int32(uplinkOFPort), client.ErrNotFound)
				m.EXPECT().CreateTrunkPort("eth1", int32(0), []string{"200-202"}, map[string]string{"antrea-type": "uplink"}).Return("", nil)
			},
		},
		{
			name: "one interface with mixed VLANs",
			physicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
				{Name: "eth1", AllowedVLANs: []string{"100", "200-201"}},
			},
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().GetOFPort("eth1").Return(int32(uplinkOFPort), client.ErrNotFound)
				m.EXPECT().CreateTrunkPort("eth1", int32(0), []string{"100", "200-201"}, map[string]string{"antrea-type": "uplink"}).Return("", nil)
			},
		},
		{
			name: "trunk port creation error",
			physicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
				{Name: "eth1", AllowedVLANs: []string{"100"}},
			},
			expectedErr: "trunk error",
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().GetOFPort("eth1").Return(int32(uplinkOFPort), client.ErrNotFound)
				m.EXPECT().CreateTrunkPort("eth1", int32(0), []string{"100"}, map[string]string{"antrea-type": "uplink"}).Return("", errors.New("trunk error"))
			},
		},
		{
			name: "already attached with VLANs — always update trunks",
			physicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
				{Name: "eth1", AllowedVLANs: []string{"100", "300"}},
			},
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().GetOFPort("eth1").Return(int32(uplinkOFPort), nil)
				m.EXPECT().SetPortTrunks("eth1", []string{"100", "300"}).Return(nil)
			},
		},
		{
			name: "GetOFPort error for existing trunk",
			physicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
				{Name: "eth1", AllowedVLANs: []string{"100"}},
			},
			expectedErr: "timeout waiting for ofport",
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().GetOFPort("eth1").Return(int32(0), errors.New("timeout waiting for ofport"))
			},
		},
		{
			name: "SetPortTrunks error",
			physicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
				{Name: "eth1", AllowedVLANs: []string{"100"}},
			},
			expectedErr: "update error",
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().GetOFPort("eth1").Return(int32(uplinkOFPort), nil)
				m.EXPECT().SetPortTrunks("eth1", []string{"100"}).Return(errors.New("update error"))
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
				m.EXPECT().GetOFPort(eth1).Return(int32(uplinkOFPort), nil)
				m.EXPECT().GetOFPort(eth2).Return(int32(uplinkOFPort+1), nil)
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
				m.EXPECT().GetOFPort(eth1).Return(int32(uplinkOFPort), nil)
				m.EXPECT().GetOFPort(eth2).Return(int32(uplinkOFPort+1), nil)
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
				m.EXPECT().GetOFPort(eth1).Return(int32(0), client.ErrNotFound)
				m.EXPECT().CreateUplinkPort(eth1, int32(0), map[string]string{"antrea-type": "uplink"}).Return("", nil)
				m.EXPECT().GetOFPort(eth2).Return(int32(uplinkOFPort+1), nil)

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

				m.EXPECT().GetOFPort(eth2).Return(int32(0), client.ErrNotFound)
				m.EXPECT().CreateUplinkPort(eth2, int32(0), map[string]string{"antrea-type": "uplink"}).Return("", nil)
				m.EXPECT().GetOFPort(eth3).Return(int32(0), client.ErrNotFound)
				m.EXPECT().CreateUplinkPort(eth3, int32(0), map[string]string{"antrea-type": "uplink"}).Return("", nil)

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

				m.EXPECT().GetOFPort(eth2).Return(int32(0), client.ErrNotFound)
				m.EXPECT().CreateUplinkPort(eth2, int32(0), map[string]string{"antrea-type": "uplink"}).Return("", nil)
				m.EXPECT().GetOFPort(eth3).Return(int32(0), client.ErrNotFound)
				m.EXPECT().CreateUplinkPort(eth3, int32(0), map[string]string{"antrea-type": "uplink"}).Return("", nil)

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
				m.EXPECT().GetOFPort(eth1).Return(int32(uplinkOFPort), nil)
				m.EXPECT().SetPortTrunks(eth1, []string{"100"}).Return(nil)
				m.EXPECT().GetOFPort(eth2).Return(int32(uplinkOFPort+1), nil)
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

func TestInitializeRequeuesDynamicReconcileError(t *testing.T) {
	prevFindManagedSecondaryBridgeFn := findManagedSecondaryBridgeFn
	findCalls := 0
	findManagedSecondaryBridgeFn = func(client.Client) (string, error) {
		findCalls++
		if findCalls == 1 {
			return "", errors.New("OVSDB unavailable")
		}
		return "", nil
	}
	t.Cleanup(func() { findManagedSecondaryBridgeFn = prevFindManagedSecondaryBridgeFn })

	firstSnapshotCh := make(chan struct{})
	close(firstSnapshotCh)
	queue := workqueue.NewTypedRateLimitingQueue(
		workqueue.NewTypedItemExponentialFailureRateLimiter[string](time.Millisecond, time.Millisecond))
	t.Cleanup(queue.ShutDown)
	c := &Controller{
		dynamicBridgeReconcile: true,
		ancFirstSnapshotCh:     firstSnapshotCh,
		queue:                  queue,
	}

	require.NoError(t, c.Initialize(nil))
	assert.Equal(t, 1, queue.NumRequeues(reconcileKey))
	require.Eventually(t, func() bool { return queue.Len() == 1 }, time.Second, time.Millisecond)
	assert.True(t, c.processNextItem())
	assert.Equal(t, 0, queue.NumRequeues(reconcileKey))
	assert.Equal(t, 2, findCalls)
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
	drainBridgeCalls  []struct {
		bridgeName string
		client     ovsconfig.OVSBridgeClient
	}
	cancelDrainCalls []string
	drainDeleteErr   error
}

func (f *fakePodController) Run(_ <-chan struct{}) {}

func (f *fakePodController) AllowCNIDelete(_, _ string) bool { return true }

func (f *fakePodController) DrainAndDeleteOVSBridge(bridgeName string, client ovsconfig.OVSBridgeClient, deleteBridge func() error) error {
	f.drainBridgeCalls = append(f.drainBridgeCalls, struct {
		bridgeName string
		client     ovsconfig.OVSBridgeClient
	}{bridgeName: bridgeName, client: client})
	if f.drainDeleteErr != nil {
		return f.drainDeleteErr
	}
	return deleteBridge()
}

func (f *fakePodController) CancelOVSBridgeDrain(bridgeName string) error {
	f.cancelDrainCalls = append(f.cancelDrainCalls, bridgeName)
	return nil
}

func (f *fakePodController) UpdateOVSBridgeClient(c ovsconfig.OVSBridgeClient) error {
	f.updateBridgeCalls = append(f.updateBridgeCalls, c)
	return f.updateBridgeErr
}

func TestReconcileBridge(t *testing.T) {
	portUUID := "uuid-eth1"

	tests := []struct {
		name              string
		primaryBridgeName string
		prevCfg           *agenttypes.OVSBridgeConfig
		desiredCfg        *agenttypes.OVSBridgeConfig // returned by effectiveBridge() in production
		expectedCalls     func(old, new *ovsconfigtest.MockOVSBridgeClient)
		wantNewClient     bool // whether c.ovsBridgeClient should be the "new" mock after reconcile
		wantUpdateBridgeN int  // expected number of UpdateOVSBridgeClient calls on the podController
		// wantRestoreCalls lists the (bridge, iface) pairs that restoreHostInterfaceConfigFn
		// must be called with, in order, when an interface is removed from the config.
		wantRestoreCalls []struct{ bridge, iface string }
		wantPrepareCalls []string
		expectedErr      string
	}{
		{
			name:              "desired bridge conflicts with primary bridge",
			primaryBridgeName: primaryOVSBridge,
			desiredCfg:        bridgeConfig(primaryOVSBridge, eth1),
			expectedErr:       "secondary OVS bridge \"br-int\" conflicts with primary OVS bridge",
		},
		{
			name:              "managed bridge conflicts with primary bridge",
			primaryBridgeName: primaryOVSBridge,
			prevCfg:           bridgeConfig(primaryOVSBridge, eth1),
			expectedErr:       "refusing to reconcile managed bridge: secondary OVS bridge \"br-int\" conflicts with primary OVS bridge",
		},
		{
			name:       "no change (both nil)",
			prevCfg:    nil,
			desiredCfg: nil,
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
			name:       "same bridge resumes incomplete host connection",
			prevCfg:    bridgeConfig(brOld, eth1),
			desiredCfg: bridgeConfig(brOld, eth1),
			expectedCalls: func(old, new *ovsconfigtest.MockOVSBridgeClient) {
				eth1Tilde := eth1 + "~"
				old.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{
						UUID:        "uuid-eth1",
						IFName:      eth1,
						IFType:      "internal",
						ExternalIDs: map[string]string{interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaHost},
					},
				}, nil)
				old.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{Name: eth1, IFName: eth1, IFType: "internal"},
				}, nil)
				old.EXPECT().GetOFPort(eth1Tilde).Return(int32(0), client.ErrNotFound)
				old.EXPECT().CreateUplinkPort(eth1Tilde, int32(0), map[string]string{
					interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaUplink,
				}).Return("", nil)
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
			wantRestoreCalls: []struct{ bridge, iface string }{{brOld, eth1}},
		},
		{
			name:       "bridge removal blocked by container Port",
			prevCfg:    bridgeConfig(brOld, eth1),
			desiredCfg: nil,
			expectedCalls: func(old, new *ovsconfigtest.MockOVSBridgeClient) {
				old.EXPECT().Create().Return(nil)
				old.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{Name: "pod1-eth1", ExternalIDs: map[string]string{interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaContainer}},
				}, nil)
			},
			expectedErr: "cannot delete or replace secondary bridge \"br-old\": Pod interface cleanup is still pending: [pod1-eth1]",
		},
		{
			name:       "bridge replacement blocked by container Port",
			prevCfg:    bridgeConfig(brOld, eth1),
			desiredCfg: bridgeConfig(brNew, eth1),
			expectedCalls: func(old, new *ovsconfigtest.MockOVSBridgeClient) {
				old.EXPECT().Create().Return(nil)
				old.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{Name: "pod1-eth1", ExternalIDs: map[string]string{interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaContainer}},
				}, nil)
			},
			expectedErr: "cannot delete or replace secondary bridge \"br-old\": Pod interface cleanup is still pending: [pod1-eth1]",
		},
		{
			// Use two interfaces to bypass the single-interface PrepareHostInterfaceConnection path.
			name:       "bridge created (prev is nil, two interfaces)",
			prevCfg:    nil,
			desiredCfg: &agenttypes.OVSBridgeConfig{BridgeName: brNew, PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{{Name: eth1}, {Name: eth2}}},
			expectedCalls: func(old, new *ovsconfigtest.MockOVSBridgeClient) {
				new.EXPECT().Create().Return(nil)
				new.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{}, nil).Times(1)
				new.EXPECT().GetOFPort(eth1).Return(int32(0), client.ErrNotFound)
				new.EXPECT().CreateUplinkPort(eth1, int32(0), map[string]string{"antrea-type": "uplink"}).Return("", nil)
				new.EXPECT().GetOFPort(eth2).Return(int32(0), client.ErrNotFound)
				new.EXPECT().CreateUplinkPort(eth2, int32(0), map[string]string{"antrea-type": "uplink"}).Return("", nil)
				new.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{Name: eth1, IFName: eth1, Trunks: nil},
					{Name: eth2, IFName: eth2, Trunks: nil},
				}, nil).Times(1)
			},
			wantNewClient:     true,
			wantUpdateBridgeN: 1,
		},
		{
			name:       "bridge created without physical interfaces",
			prevCfg:    nil,
			desiredCfg: bridgeConfig(brNew),
			expectedCalls: func(old, new *ovsconfigtest.MockOVSBridgeClient) {
				new.EXPECT().Create().Return(nil)
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
				new.EXPECT().GetOFPort(eth1).Return(int32(uplinkOFPort), nil)
				new.EXPECT().GetOFPort(eth2).Return(int32(uplinkOFPort+1), nil)
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
				new.EXPECT().GetOFPort(eth1).Return(int32(0), client.ErrNotFound)
				new.EXPECT().CreateUplinkPort(eth1, int32(0), map[string]string{"antrea-type": "uplink"}).Return("", nil)
				new.EXPECT().GetOFPort(eth2).Return(int32(0), client.ErrNotFound)
				new.EXPECT().CreateUplinkPort(eth2, int32(0), map[string]string{"antrea-type": "uplink"}).Return("", nil)
				new.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{Name: eth1, IFName: eth1, Trunks: nil},
					{Name: eth2, IFName: eth2, Trunks: nil},
				}, nil).Times(1)
			},
			wantNewClient: true,
			// The old bridge is drained before deletion; only the new bridge is activated.
			wantUpdateBridgeN: 1,
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
				old.EXPECT().GetOFPort(eth2).Return(int32(0), client.ErrNotFound)
				old.EXPECT().CreateUplinkPort(eth2, int32(0), map[string]string{"antrea-type": "uplink"}).Return("", nil)
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
				old.EXPECT().GetOFPort(eth1+"~").Return(int32(0), client.ErrNotFound)
				old.EXPECT().CreateUplinkPort(eth1+"~", int32(0), map[string]string{"antrea-type": "uplink"}).Return("", nil)
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
				old.EXPECT().GetOFPort(eth2).Return(int32(0), client.ErrNotFound)
				old.EXPECT().CreateTrunkPort(eth2, int32(0), []string{"100"}, map[string]string{"antrea-type": "uplink"}).Return("", nil)
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
				old.EXPECT().GetOFPort(eth1Tilde).Return(int32(uplinkOFPort), nil)
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
				old.EXPECT().GetOFPort(eth2+"~").Return(int32(0), client.ErrNotFound)
				old.EXPECT().CreateUplinkPort(eth2+"~", int32(0), map[string]string{"antrea-type": "uplink"}).Return("", nil)
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

			currentBrName := ""
			if tc.prevCfg != nil {
				currentBrName = tc.prevCfg.BridgeName
			}
			mockManagedSecondaryBridge(t, currentBrName)
			mockNoSecondaryBridgeAdoption(t)

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
			prepareHostInterfaceConnectionFn = func(_ ovsconfig.OVSBridgeClient, ifaceName string, _ int32, _ map[string]string, _ int) (string, bool, error) {
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
				primaryOVSBridgeName:    tc.primaryBridgeName,
				effectiveBridgeCfg:      tc.prevCfg,
				effectiveBridgeOverride: func() *agenttypes.OVSBridgeConfig { return desiredCfg },
				ovsdbClient:             nil,
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
					assert.Equal(t, newMock, last, "expected UpdateOVSBridgeClient(newMock) for bridge creation")
				}
				if tc.prevCfg != nil && tc.desiredCfg != nil && tc.prevCfg.BridgeName == tc.desiredCfg.BridgeName {
					assert.Equal(t, []string{tc.desiredCfg.BridgeName}, fakePc.cancelDrainCalls,
						"same-bridge reconciliation should make the bridge active")
				} else {
					assert.Empty(t, fakePc.cancelDrainCalls)
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

func TestValidateSecondaryBridgeName(t *testing.T) {
	tests := []struct {
		name                 string
		bridgeName           string
		primaryOVSBridgeName string
		wantErr              string
	}{
		{
			name:                 "different bridge names",
			bridgeName:           "br-secondary",
			primaryOVSBridgeName: primaryOVSBridge,
		},
		{
			name:       "primary bridge name is not available",
			bridgeName: "br-secondary",
		},
		{
			name:                 "secondary bridge conflicts with primary bridge",
			bridgeName:           primaryOVSBridge,
			primaryOVSBridgeName: primaryOVSBridge,
			wantErr:              "secondary OVS bridge \"br-int\" conflicts with primary OVS bridge",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSecondaryBridgeName(tt.bridgeName, tt.primaryOVSBridgeName)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.EqualError(t, err, tt.wantErr)
		})
	}
}

func TestDeletePrimaryOVSBridgeRejected(t *testing.T) {
	c := &Controller{primaryOVSBridgeName: primaryOVSBridge}
	require.ErrorContains(t, c.deleteBridge(primaryOVSBridge),
		"refusing to delete bridge: secondary OVS bridge \"br-int\" conflicts with primary OVS bridge")
}

func TestResolveAndCreatePrimaryOVSBridgeRejected(t *testing.T) {
	originalNewOVSBridgeFn := newOVSBridgeFn
	newOVSBridgeCalled := false
	newOVSBridgeFn = func(string, ovsconfig.OVSDatapathType, client.Client, ...ovsconfig.OVSBridgeOption) ovsconfig.OVSBridgeClient {
		newOVSBridgeCalled = true
		return nil
	}
	t.Cleanup(func() { newOVSBridgeFn = originalNewOVSBridgeFn })

	bridgeCfg, bridgeClient, err := resolveAndCreateOVSBridge(
		func() *agenttypes.OVSBridgeConfig { return bridgeConfig(primaryOVSBridge, eth1) },
		primaryOVSBridge,
		nil,
	)
	require.ErrorContains(t, err, "secondary OVS bridge \"br-int\" conflicts with primary OVS bridge")
	assert.Nil(t, bridgeCfg)
	assert.Nil(t, bridgeClient)
	assert.False(t, newOVSBridgeCalled, "primary OVS bridge must be rejected before creating an OVS client")
}

func TestReconcileBridgeStateCleared(t *testing.T) {
	ctrl := mock.NewController(t)
	oldMock := ovsconfigtest.NewMockOVSBridgeClient(ctrl)
	newMock := ovsconfigtest.NewMockOVSBridgeClient(ctrl)
	mockInterfaceByName(t)

	createErr := errors.New("create failed")

	mockManagedSecondaryBridge(t, brOld)
	mockNoSecondaryBridgeAdoption(t)

	prevNewOVSBridgeFn := newOVSBridgeFn
	var capturedController *Controller
	newOVSBridgeFn = func(bridgeName string, ovsDatapathType ovsconfig.OVSDatapathType, ovsdb client.Client, options ...ovsconfig.OVSBridgeOption) ovsconfig.OVSBridgeClient {
		if bridgeName == brOld {
			return oldMock
		}
		if capturedController != nil {
			capturedController.mu.RLock()
			assert.Nil(t, capturedController.effectiveBridgeCfg, "effectiveBridgeCfg should be nil after old bridge deleted")
			assert.Nil(t, capturedController.ovsBridgeClient, "ovsBridgeClient should be nil after old bridge deleted")
			capturedController.mu.RUnlock()
		}
		return newMock
	}
	t.Cleanup(func() { newOVSBridgeFn = prevNewOVSBridgeFn })

	oldMock.EXPECT().Create().Return(nil)
	oldMock.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{}, nil)
	oldMock.EXPECT().Delete().Return(nil)
	newMock.EXPECT().Create().Return(createErr)

	desired := bridgeConfig(brNew, eth1, eth2)
	c := newTestSecondaryNetworkController(bridgeConfig(brOld, eth1, eth2), desired, &fakePodController{})
	c.ovsBridgeClient = oldMock
	capturedController = c

	err := c.reconcileBridge()
	require.Error(t, err, "expected error from failed bridge creation")

	c.mu.RLock()
	assert.Nil(t, c.effectiveBridgeCfg, "effectiveBridgeCfg should remain nil after failed create")
	assert.Nil(t, c.ovsBridgeClient, "ovsBridgeClient should remain nil after failed create")
	c.mu.RUnlock()
}

func TestReconcileBridgeDoesNotRecordStateOnPodControllerUpdateFailure(t *testing.T) {
	ctrl := mock.NewController(t)
	newMock := ovsconfigtest.NewMockOVSBridgeClient(ctrl)

	mockInterfaceByName(t)
	mockNewOVSBridge(t, newMock)
	mockManagedSecondaryBridge(t, "")
	mockNoSecondaryBridgeAdoption(t)

	desired := bridgeConfig(brNew, eth1, eth2)
	updateErr := errors.New("interface store reload failed")

	newMock.EXPECT().Create().Return(nil)
	newMock.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{}, nil).Times(1)
	newMock.EXPECT().GetOFPort(eth1).Return(int32(0), client.ErrNotFound)
	newMock.EXPECT().CreateUplinkPort(eth1, int32(0), map[string]string{"antrea-type": "uplink"}).Return("", nil)
	newMock.EXPECT().GetOFPort(eth2).Return(int32(0), client.ErrNotFound)
	newMock.EXPECT().CreateUplinkPort(eth2, int32(0), map[string]string{"antrea-type": "uplink"}).Return("", nil)
	newMock.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
		{Name: eth1, IFName: eth1, Trunks: nil},
		{Name: eth2, IFName: eth2, Trunks: nil},
	}, nil).Times(1)

	c := newTestSecondaryNetworkController(nil, desired, &fakePodController{updateBridgeErr: updateErr})

	err := c.reconcileBridge()
	require.ErrorIs(t, err, updateErr)

	c.mu.RLock()
	assert.Nil(t, c.effectiveBridgeCfg, "effectiveBridgeCfg should not advance when PodController update fails")
	assert.Nil(t, c.ovsBridgeClient, "ovsBridgeClient should not advance when PodController update fails")
	c.mu.RUnlock()
}

func TestBridgeDrainFailurePreservesState(t *testing.T) {
	ctrl := mock.NewController(t)
	oldMock := ovsconfigtest.NewMockOVSBridgeClient(ctrl)

	mockInterfaceByName(t)
	mockNewOVSBridgeByName(t, map[string]ovsconfig.OVSBridgeClient{
		brOld: oldMock,
	})

	drainErr := errors.New("bridge drain failed")
	fakePc := &fakePodController{drainDeleteErr: drainErr}
	desiredCfg := (*agenttypes.OVSBridgeConfig)(nil)

	mockManagedSecondaryBridgeSequence(t, brOld, brOld)
	mockNoSecondaryBridgeAdoption(t)

	oldMock.EXPECT().Create().Return(nil).Times(2)
	oldMock.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{}, nil).Times(1)
	oldMock.EXPECT().Delete().Return(nil).Times(1)

	c := newTestSecondaryNetworkController(bridgeConfig(brOld, eth1, eth2), desiredCfg, fakePc)
	c.ovsBridgeClient = oldMock

	err := c.reconcileBridge()
	require.ErrorIs(t, err, drainErr)
	assert.Empty(t, fakePc.updateBridgeCalls)
	c.mu.RLock()
	assert.NotNil(t, c.effectiveBridgeCfg, "effectiveBridgeCfg should be preserved when draining fails")
	assert.NotNil(t, c.ovsBridgeClient, "ovsBridgeClient should be preserved when draining fails")
	c.mu.RUnlock()

	fakePc.drainDeleteErr = nil
	err = c.reconcileBridge()
	require.NoError(t, err)
	assert.Empty(t, fakePc.updateBridgeCalls)
	c.mu.RLock()
	assert.Nil(t, c.effectiveBridgeCfg, "effectiveBridgeCfg should be cleared after PodController update succeeds")
	assert.Nil(t, c.ovsBridgeClient, "ovsBridgeClient should be cleared after PodController update succeeds")
	c.mu.RUnlock()
}

func TestReconcileBridgeDeletesCurrentBridgeFromOVSDB(t *testing.T) {
	tests := []struct {
		name             string
		setupDiscovery   func(t *testing.T)
		secNetConfig     *agentconfig.SecondaryNetworkConfig
		portList         []ovsconfig.OVSPortData
		wantRestoreCalls []struct{ bridge, iface string }
	}{
		{
			name:           "managed bridge after agent restart",
			setupDiscovery: func(t *testing.T) { mockManagedSecondaryBridge(t, brOld); mockNoSecondaryBridgeAdoption(t) },
			portList: []ovsconfig.OVSPortData{
				{IFName: eth1, IFType: "internal", ExternalIDs: map[string]string{"antrea-type": "host"}},
			},
			wantRestoreCalls: []struct{ bridge, iface string }{{brOld, eth1}},
		},
		{
			name: "legacy static bridge adoption",
			setupDiscovery: func(t *testing.T) {
				mockManagedSecondaryBridge(t, "")
				mockSecondaryBridgeAdoption(t, func(staticBridge *agenttypes.OVSBridgeConfig, ovsdbClient client.Client) (string, error) {
					assert.Equal(t, brOld, staticBridge.BridgeName)
					return brOld, nil
				})
			},
			secNetConfig: &agentconfig.SecondaryNetworkConfig{
				OVSBridges: []agentconfig.OVSBridgeConfig{{BridgeName: brOld}},
			},
			portList: []ovsconfig.OVSPortData{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := mock.NewController(t)
			oldMock := ovsconfigtest.NewMockOVSBridgeClient(ctrl)

			mockInterfaceByName(t)
			mockNewOVSBridgeByName(t, map[string]ovsconfig.OVSBridgeClient{brOld: oldMock})
			tc.setupDiscovery(t)

			var gotRestoreCalls []struct{ bridge, iface string }
			origRestore := restoreHostInterfaceConfigFn
			restoreHostInterfaceConfigFn = func(brName, ifaceName string) error {
				gotRestoreCalls = append(gotRestoreCalls, struct{ bridge, iface string }{brName, ifaceName})
				return nil
			}
			t.Cleanup(func() { restoreHostInterfaceConfigFn = origRestore })

			oldMock.EXPECT().Create().Return(nil)
			oldMock.EXPECT().GetPortList().Return(tc.portList, nil)
			oldMock.EXPECT().Delete().Return(nil)

			fakePc := &fakePodController{}
			c := newTestSecondaryNetworkController(nil, nil, fakePc)
			if tc.secNetConfig != nil {
				c.secNetConfig = tc.secNetConfig
			}

			require.NoError(t, c.reconcileBridge())
			assert.Equal(t, tc.wantRestoreCalls, gotRestoreCalls)
			assert.Empty(t, fakePc.updateBridgeCalls)
			require.Len(t, fakePc.drainBridgeCalls, 1)
			assert.Equal(t, oldMock, fakePc.drainBridgeCalls[0].client)
		})
	}
}

func TestReconcileBridgeStartsDrainAfterAgentRestart(t *testing.T) {
	ctrl := mock.NewController(t)
	oldMock := ovsconfigtest.NewMockOVSBridgeClient(ctrl)
	mockNewOVSBridgeByName(t, map[string]ovsconfig.OVSBridgeClient{brOld: oldMock})
	mockManagedSecondaryBridge(t, brOld)
	mockNoSecondaryBridgeAdoption(t)
	oldMock.EXPECT().Create().Return(nil)

	fakePc := &fakePodController{
		drainDeleteErr: &podwatch.BridgeNotDrainedError{Interfaces: []string{"pod1-eth1"}},
	}
	c := newTestSecondaryNetworkController(nil, nil, fakePc)

	err := c.reconcileBridge()
	require.ErrorContains(t, err, "Pod interface cleanup is still pending: [pod1-eth1]")
	require.Len(t, fakePc.drainBridgeCalls, 1)
	assert.Equal(t, brOld, fakePc.drainBridgeCalls[0].bridgeName)
	assert.Equal(t, oldMock, fakePc.drainBridgeCalls[0].client)
}

func TestReconcileBridgeUpdatesCurrentBridgeAfterAgentRestart(t *testing.T) {
	updateErr := errors.New("interface store reload failed")
	for _, tt := range []struct {
		name      string
		updateErr error
	}{
		{name: "success"},
		{name: "PodController update failure", updateErr: updateErr},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := mock.NewController(t)
			oldMock := ovsconfigtest.NewMockOVSBridgeClient(ctrl)

			mockInterfaceByName(t)
			mockNewOVSBridgeByName(t, map[string]ovsconfig.OVSBridgeClient{
				brOld: oldMock,
			})
			mockManagedSecondaryBridge(t, brOld)
			mockNoSecondaryBridgeAdoption(t)

			desired := bridgeConfig(brOld, eth1, eth2)
			oldMock.EXPECT().Create().Return(nil)
			oldMock.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
				{UUID: "uuid-eth1", IFName: eth1},
			}, nil)
			oldMock.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
				{Name: eth1, IFName: eth1, Trunks: nil},
			}, nil)
			oldMock.EXPECT().GetOFPort(eth2).Return(int32(0), client.ErrNotFound)
			oldMock.EXPECT().CreateUplinkPort(eth2, int32(0), map[string]string{"antrea-type": "uplink"}).Return("", nil)

			fakePc := &fakePodController{updateBridgeErr: tt.updateErr}
			c := newTestSecondaryNetworkController(nil, desired, fakePc)

			err := c.reconcileBridge()
			assert.Equal(t, []ovsconfig.OVSBridgeClient{oldMock}, fakePc.updateBridgeCalls)
			c.mu.RLock()
			defer c.mu.RUnlock()
			if tt.updateErr != nil {
				require.ErrorIs(t, err, tt.updateErr)
				assert.Nil(t, c.ovsBridgeClient)
				assert.Nil(t, c.effectiveBridgeCfg)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, oldMock, c.ovsBridgeClient)
			assert.Equal(t, desired, c.effectiveBridgeCfg)
		})
	}
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

func bridgeConfig(bridgeName string, ifNames ...string) *agenttypes.OVSBridgeConfig {
	physicalInterfaces := make([]agenttypes.PhysicalInterfaceConfig, 0, len(ifNames))
	for _, ifName := range ifNames {
		physicalInterfaces = append(physicalInterfaces, agenttypes.PhysicalInterfaceConfig{Name: ifName})
	}
	return &agenttypes.OVSBridgeConfig{
		BridgeName:         bridgeName,
		PhysicalInterfaces: physicalInterfaces,
	}
}

func newTestSecondaryNetworkController(prevCfg, desiredCfg *agenttypes.OVSBridgeConfig, podController podControllerInterface) *Controller {
	return &Controller{
		secNetConfig:            &agentconfig.SecondaryNetworkConfig{},
		effectiveBridgeCfg:      prevCfg,
		effectiveBridgeOverride: func() *agenttypes.OVSBridgeConfig { return desiredCfg },
		ovsdbClient:             nil,
		podController:           podController,
	}
}

func mockManagedSecondaryBridge(t *testing.T, bridgeName string) {
	mockManagedSecondaryBridgeSequence(t, bridgeName)
}

func mockManagedSecondaryBridgeSequence(t *testing.T, bridgeNames ...string) {
	require.NotEmpty(t, bridgeNames)

	prevFunc := findManagedSecondaryBridgeFn
	callCount := 0
	findManagedSecondaryBridgeFn = func(ovsdbClient client.Client) (string, error) {
		if callCount >= len(bridgeNames) {
			return bridgeNames[len(bridgeNames)-1], nil
		}
		bridgeName := bridgeNames[callCount]
		callCount++
		return bridgeName, nil
	}
	t.Cleanup(func() { findManagedSecondaryBridgeFn = prevFunc })
}

func mockNoSecondaryBridgeAdoption(t *testing.T) {
	mockSecondaryBridgeAdoption(t, func(staticBridge *agenttypes.OVSBridgeConfig, ovsdbClient client.Client) (string, error) {
		return "", nil
	})
}

func mockSecondaryBridgeAdoption(t *testing.T, fn func(*agenttypes.OVSBridgeConfig, client.Client) (string, error)) {
	prevFunc := adoptSecondaryBridgeFn
	adoptSecondaryBridgeFn = fn
	t.Cleanup(func() { adoptSecondaryBridgeFn = prevFunc })
}

func mockNewOVSBridge(t *testing.T, brClient ovsconfig.OVSBridgeClient) {
	prevFunc := newOVSBridgeFn
	newOVSBridgeFn = func(bridgeName string, ovsDatapathType ovsconfig.OVSDatapathType, ovsdb client.Client, options ...ovsconfig.OVSBridgeOption) ovsconfig.OVSBridgeClient {
		return brClient
	}
	t.Cleanup(func() { newOVSBridgeFn = prevFunc })
}

func mockNewOVSBridgeByName(t *testing.T, brClients map[string]ovsconfig.OVSBridgeClient) {
	prevFunc := newOVSBridgeFn
	newOVSBridgeFn = func(bridgeName string, ovsDatapathType ovsconfig.OVSDatapathType, ovsdb client.Client, options ...ovsconfig.OVSBridgeOption) ovsconfig.OVSBridgeClient {
		return brClients[bridgeName]
	}
	t.Cleanup(func() { newOVSBridgeFn = prevFunc })
}
