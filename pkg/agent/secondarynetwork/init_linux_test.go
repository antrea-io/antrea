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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ovn-kubernetes/libovsdb/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	mock "go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	componentbaseconfig "k8s.io/component-base/config"

	"antrea.io/antrea/v2/pkg/agent/antreanodeconfig"
	"antrea.io/antrea/v2/pkg/agent/config"
	"antrea.io/antrea/v2/pkg/agent/interfacestore"
	agenttypes "antrea.io/antrea/v2/pkg/agent/types"
	crdv1alpha1 "antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
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
				{Name: "eth1"},
				{Name: nonExistingInterface},
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

func TestRestoreStaleHostConnections(t *testing.T) {
	tests := []struct {
		name             string
		desired          *agenttypes.OVSBridgeConfig
		ports            []ovsconfig.OVSPortData
		restoreErr       error
		wantRestoreCalls []struct{ bridge, iface string }
		expectedErr      string
	}{
		{
			name:    "multi-interface desired restores all host connections",
			desired: bridgeConfig(brOld, eth1, eth2),
			ports: []ovsconfig.OVSPortData{
				{IFName: eth1, IFType: "internal", ExternalIDs: map[string]string{"antrea-type": "host"}},
				{IFName: eth1 + "~", ExternalIDs: map[string]string{"antrea-type": "uplink"}},
			},
			wantRestoreCalls: []struct{ bridge, iface string }{{brOld, eth1}},
		},
		{
			// The host connection of the desired single interface is the desired
			// state and must be kept.
			name:    "single-interface desired keeps its own host connection",
			desired: bridgeConfig(brOld, eth1),
			ports: []ovsconfig.OVSPortData{
				{IFName: eth1, IFType: "internal", ExternalIDs: map[string]string{"antrea-type": "host"}},
				{IFName: eth1 + "~", ExternalIDs: map[string]string{"antrea-type": "uplink"}},
			},
		},
		{
			// A host connection for an interface which is not desired (e.g. leftover
			// from a previous single-interface config) is stale and must be restored.
			name:    "single-interface desired restores other host connection",
			desired: bridgeConfig(brOld, eth1),
			ports: []ovsconfig.OVSPortData{
				{IFName: eth2, IFType: "internal", ExternalIDs: map[string]string{"antrea-type": "host"}},
				{IFName: eth2 + "~", ExternalIDs: map[string]string{"antrea-type": "uplink"}},
			},
			wantRestoreCalls: []struct{ bridge, iface string }{{brOld, eth2}},
		},
		{
			name:    "unmanaged internal port",
			desired: bridgeConfig(brOld, eth1),
			ports: []ovsconfig.OVSPortData{
				{IFName: eth1, IFType: "internal"},
				{IFName: eth1 + "~", ExternalIDs: map[string]string{"antrea-type": "uplink"}},
			},
		},
		{
			name:    "uplink sibling is not managed",
			desired: bridgeConfig(brOld, eth1),
			ports: []ovsconfig.OVSPortData{
				{IFName: eth1, IFType: "internal", ExternalIDs: map[string]string{"antrea-type": "host"}},
				{IFName: eth1 + "~"},
			},
		},
		{
			// Restoring a stale host connection (here eth2, leftover from a previous
			// single-interface config) fails.
			name:    "restore error",
			desired: bridgeConfig(brOld, eth1),
			ports: []ovsconfig.OVSPortData{
				{IFName: eth2, IFType: "internal", ExternalIDs: map[string]string{"antrea-type": "host"}},
				{IFName: eth2 + "~", ExternalIDs: map[string]string{"antrea-type": "uplink"}},
			},
			restoreErr:       errors.New("restore error"),
			wantRestoreCalls: []struct{ bridge, iface string }{{brOld, eth2}},
			expectedErr:      "failed to restore stale host-connection interface",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var gotRestoreCalls []struct{ bridge, iface string }
			origRestore := restoreHostInterfaceConfigFn
			restoreHostInterfaceConfigFn = func(brName, ifaceName string) error {
				gotRestoreCalls = append(gotRestoreCalls, struct{ bridge, iface string }{brName, ifaceName})
				return tc.restoreErr
			}
			t.Cleanup(func() { restoreHostInterfaceConfigFn = origRestore })

			existingPorts := make(map[string]ovsconfig.OVSPortData, len(tc.ports))
			for _, p := range tc.ports {
				existingPorts[p.IFName] = p
			}

			err := restoreStaleHostConnections(tc.desired, tc.ports, existingPorts)
			if tc.expectedErr != "" {
				assert.ErrorContains(t, err, tc.expectedErr)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tc.wantRestoreCalls, gotRestoreCalls)
			// Restored interfaces (including stale uplink ports) must be removed from
			// existingPorts so the caller does not re-add them. When restore fails the
			// reconciliation is aborted and the ports are left in place for a retry.
			if tc.expectedErr == "" {
				for _, conn := range tc.wantRestoreCalls {
					_, exists := existingPorts[conn.iface]
					assert.False(t, exists, "restored interface %s should be removed from existingPorts", conn.iface)
					_, exists = existingPorts[conn.iface+"~"]
					assert.False(t, exists, "restored uplink %s~ should be removed from existingPorts", conn.iface)
				}
			}
		})
	}
}

func TestClearStaleTrunks(t *testing.T) {
	tests := []struct {
		name               string
		physicalInterfaces []agenttypes.PhysicalInterfaceConfig
		portList           []ovsconfig.OVSPortData
		existingPorts      map[string]ovsconfig.OVSPortData
		expectedCalls      func(m *ovsconfigtest.MockOVSBridgeClient)
		expectedErr        string
	}{
		{
			name: "clear trunks only from desired plain ports",
			physicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
				{Name: eth1},
				{Name: eth2, AllowedVLANs: []string{"200"}},
				{Name: eth3},
			},
			portList: []ovsconfig.OVSPortData{
				{Name: "port-eth1", IFName: eth1, Trunks: []uint16{100}},
				{Name: "port-eth2", IFName: eth2, Trunks: []uint16{200}},
				{Name: "port-eth3", IFName: eth3},
				{Name: "other-port", IFName: "eth4", Trunks: []uint16{400}},
			},
			existingPorts: map[string]ovsconfig.OVSPortData{
				eth1: {UUID: "uuid-eth1"},
				eth2: {UUID: "uuid-eth2"},
				eth3: {UUID: "uuid-eth3"},
			},
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().SetPortTrunks("port-eth1", nil).Return(nil)
			},
		},
		{
			name: "all desired ports have allowed VLANs",
			physicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
				{Name: eth1, AllowedVLANs: []string{"100"}},
				{Name: eth2, AllowedVLANs: []string{"200"}},
			},
		},
		{
			name: "skip ports already removed from the bridge",
			physicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
				{Name: eth1},
			},
			// eth1 was deleted earlier in the same reconciliation: it is still in
			// portList but no longer in existingPorts, so its trunks must not be touched.
			portList: []ovsconfig.OVSPortData{
				{Name: eth1, IFName: eth1, Trunks: []uint16{100}},
			},
			existingPorts: map[string]ovsconfig.OVSPortData{},
		},
		{
			name: "clear trunks error",
			physicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
				{Name: eth1},
			},
			portList: []ovsconfig.OVSPortData{
				{Name: eth1, IFName: eth1, Trunks: []uint16{100}},
			},
			existingPorts: map[string]ovsconfig.OVSPortData{eth1: {UUID: "uuid-eth1"}},
			expectedErr:   "failed to clear stale trunk VLANs",
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().SetPortTrunks(eth1, nil).Return(errors.New("update trunks error"))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := mock.NewController(t)
			mockOVSBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(ctrl)

			if tc.expectedCalls != nil {
				tc.expectedCalls(mockOVSBridgeClient)
			}

			err := clearStaleTrunks(mockOVSBridgeClient, tc.physicalInterfaces, tc.portList, tc.existingPorts)
			if tc.expectedErr != "" {
				assert.ErrorContains(t, err, tc.expectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestNewControllerDefersStaticBridgeInitialization(t *testing.T) {
	kubeconfig := filepath.Join(t.TempDir(), "kubeconfig")
	require.NoError(t, os.WriteFile(kubeconfig, []byte(`apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://127.0.0.1
  name: test
contexts:
- context:
    cluster: test
    user: test
  name: test
current-context: test
users:
- name: test
  user: {}
`), 0o600))

	originalNewOVSBridgeFn := newOVSBridgeFn
	newOVSBridgeFn = func(
		string,
		ovsconfig.OVSDatapathType,
		client.Client,
		...ovsconfig.OVSBridgeOption,
	) ovsconfig.OVSBridgeClient {
		t.Fatal("NewController must not create an OVS bridge")
		return nil
	}
	t.Cleanup(func() { newOVSBridgeFn = originalNewOVSBridgeFn })

	podInformer := cache.NewSharedIndexInformer(&cache.ListWatch{}, &corev1.Pod{}, 0, cache.Indexers{})
	c, err := NewController(
		componentbaseconfig.ClientConnectionConfiguration{Kubeconfig: kubeconfig},
		"",
		k8sfake.NewSimpleClientset(),
		podInformer,
		nil,
		interfacestore.NewInterfaceStore(),
		&config.NodeConfig{Name: "node", OVSBridge: primaryOVSBridge},
		&agentconfig.SecondaryNetworkConfig{
			OVSBridges: []agentconfig.OVSBridgeConfig{{BridgeName: brNew}},
		},
		nil,
		nil,
		nil,
	)
	require.NoError(t, err)
	assert.Nil(t, c.ovsBridgeClient)
	assert.Nil(t, c.effectiveBridgeCfg)
}

func TestInitializeWithStaticBridgeConfig(t *testing.T) {
	tests := []struct {
		name              string
		startupBridgeName string
	}{
		{
			name: "missing bridge",
		},
		{
			name:              "discovered bridge",
			startupBridgeName: brNew,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := mock.NewController(t)
			bridgeClient := ovsconfigtest.NewMockOVSBridgeClient(ctrl)
			mockNewOVSBridge(t, bridgeClient)
			mockStartupSecondaryBridge(t, tt.startupBridgeName)

			bridgeClient.EXPECT().Create().Return(nil)
			if tt.startupBridgeName != "" {
				bridgeClient.EXPECT().GetBridgeName().Return(brNew)
				bridgeClient.EXPECT().SetMcastSnooping(false).Return(nil)
				bridgeClient.EXPECT().GetPortList().Return(nil, nil)
			} else {
				// The bridge is created and reconciled through createAndConfigureBridge.
				bridgeClient.EXPECT().SetMcastSnooping(false).Return(nil)
				bridgeClient.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{}, nil)
			}

			podController := &fakePodController{}
			desired := &agenttypes.OVSBridgeConfig{BridgeName: brNew}
			c := &Controller{
				secNetConfig: &agentconfig.SecondaryNetworkConfig{
					OVSBridges: []agentconfig.OVSBridgeConfig{{BridgeName: brNew}},
				},
				podController: podController,
			}

			expectedStartupClient := ovsconfig.OVSBridgeClient(nil)
			if tt.startupBridgeName != "" {
				expectedStartupClient = bridgeClient
			}
			require.NoError(t, c.Initialize(nil))
			assert.Equal(t, []ovsconfig.OVSBridgeClient{expectedStartupClient}, podController.initializeBridgeCalls)
			assert.Equal(t, []ovsconfig.OVSBridgeClient{bridgeClient}, podController.setBridgeCalls)
			assert.Equal(t, bridgeClient, c.ovsBridgeClient)
			assert.Equal(t, desired, c.effectiveBridgeCfg)
		})
	}
}

func TestInitializeRequeuesDynamicBridgeReconciliationFailure(t *testing.T) {
	prevFindStartupSecondaryBridgeFn := findStartupSecondaryBridgeFn
	findCalls := 0
	findStartupSecondaryBridgeFn = func(client.Client, string) (string, error) {
		findCalls++
		if findCalls == 1 {
			return "", errors.New("OVSDB unavailable")
		}
		return "", nil
	}
	t.Cleanup(func() { findStartupSecondaryBridgeFn = prevFindStartupSecondaryBridgeFn })

	firstSnapshotCh := make(chan struct{})
	close(firstSnapshotCh)
	queue := workqueue.NewTypedRateLimitingQueue(
		workqueue.NewTypedItemExponentialFailureRateLimiter[string](time.Millisecond, time.Millisecond))
	t.Cleanup(queue.ShutDown)
	c := &Controller{
		dynamicBridgeReconcile: true,
		ancFirstSnapshotCh:     firstSnapshotCh,
		queue:                  queue,
		podController:          &fakePodController{},
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

// fakePodController implements podControllerInterface for unit tests.
type fakePodController struct {
	initializeBridgeCalls []ovsconfig.OVSBridgeClient
	initializeBridgeErr   error
	setBridgeCalls        []ovsconfig.OVSBridgeClient
	drainCalls            int
	drainPending          bool
	runFn                 func(<-chan struct{})
}

func (f *fakePodController) Run(stopCh <-chan struct{}) {
	if f.runFn != nil {
		f.runFn(stopCh)
	}
}

func (f *fakePodController) AllowCNIDelete(_, _ string) bool { return true }

func (f *fakePodController) InitializeOVSBridge(client ovsconfig.OVSBridgeClient) error {
	f.initializeBridgeCalls = append(f.initializeBridgeCalls, client)
	return f.initializeBridgeErr
}

func (f *fakePodController) DrainOVSBridge() bool {
	f.drainCalls++
	return !f.drainPending
}

func (f *fakePodController) SetOVSBridgeClient(client ovsconfig.OVSBridgeClient) {
	f.setBridgeCalls = append(f.setBridgeCalls, client)
}

func TestRunDoesNotWaitForPodController(t *testing.T) {
	podControllerStarted := make(chan struct{})
	podControllerRelease := make(chan struct{})
	t.Cleanup(func() { close(podControllerRelease) })
	stopCh := make(chan struct{})
	runDone := make(chan struct{})
	c := &Controller{
		podController: &fakePodController{
			runFn: func(<-chan struct{}) {
				close(podControllerStarted)
				<-podControllerRelease
			},
		},
	}

	go func() {
		defer close(runDone)
		c.Run(stopCh)
	}()
	<-podControllerStarted
	close(stopCh)

	select {
	case <-runDone:
	case <-time.After(time.Second):
		t.Fatal("Controller.Run waited for PodController to stop")
	}
}

func TestShutdownAndRestore(t *testing.T) {
	reconcileStarted := make(chan struct{})
	reconcileRelease := make(chan struct{})
	findCalls := 0
	prevFindStartupSecondaryBridgeFn := findStartupSecondaryBridgeFn
	findStartupSecondaryBridgeFn = func(client.Client, string) (string, error) {
		findCalls++
		if findCalls == 1 {
			close(reconcileStarted)
			<-reconcileRelease
		} else {
			t.Fatal("must not reconcile bridge after queue shutdown")
		}
		return "", nil
	}
	t.Cleanup(func() { findStartupSecondaryBridgeFn = prevFindStartupSecondaryBridgeFn })

	queue := workqueue.NewTypedRateLimitingQueue(
		workqueue.NewTypedItemExponentialFailureRateLimiter[string](time.Millisecond, time.Millisecond))
	c := &Controller{
		dynamicBridgeReconcile: true,
		queue:                  queue,
		podController:          &fakePodController{},
	}

	reconcileDone := make(chan error, 1)
	go func() {
		reconcileDone <- c.syncBridge()
	}()
	<-reconcileStarted

	restoreDone := make(chan struct{})
	go func() {
		defer close(restoreDone)
		c.ShutdownAndRestore()
	}()
	require.Eventually(t, queue.ShuttingDown, time.Second, time.Millisecond)

	queuedReconcileDone := make(chan error, 1)
	go func() {
		queuedReconcileDone <- c.syncBridge()
	}()

	select {
	case <-restoreDone:
		t.Fatal("ShutdownAndRestore returned while bridge reconciliation was still running")
	default:
	}

	close(reconcileRelease)
	select {
	case err := <-reconcileDone:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("bridge reconciliation did not complete")
	}
	select {
	case err := <-queuedReconcileDone:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("queued reconciliation did not exit after queue shutdown")
	}
	select {
	case <-restoreDone:
	case <-time.After(time.Second):
		t.Fatal("ShutdownAndRestore did not continue after bridge reconciliation completed")
	}
	assert.Equal(t, 1, findCalls)
}

// TestReconcileBridge tests the reconcileBridge function with various transitions.
func TestReconcileBridge(t *testing.T) {
	portUUID := "uuid-eth1"

	tests := []struct {
		name          string
		prevCfg       *agenttypes.OVSBridgeConfig
		desiredCfg    *agenttypes.OVSBridgeConfig
		expectedCalls func(old, new *ovsconfigtest.MockOVSBridgeClient)
		// wantRestoreCalls lists the (bridge, iface) pairs that restoreHostInterfaceConfigFn
		// must be called with, in order, when an interface is removed from the config.
		wantRestoreCalls []struct{ bridge, iface string }
		wantPrepareCalls []string
		drainPending     bool // whether DrainOVSBridge should return false
		expectedErr      string
	}{
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
				old.EXPECT().GetBridgeName().Return(brOld)
				// deleteBridgeWithClient queries OVSDB for host-connection ports before deletion.
				old.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{IFName: eth1, IFType: "internal", ExternalIDs: map[string]string{"antrea-type": "host"}},
				}, nil)
				old.EXPECT().Delete().Return(nil)
			},
			wantRestoreCalls: []struct{ bridge, iface string }{{brOld, eth1}},
		},
		{
			name:       "bridge deletion fails",
			prevCfg:    bridgeConfig(brOld, eth1, eth2),
			desiredCfg: nil,
			expectedCalls: func(old, new *ovsconfigtest.MockOVSBridgeClient) {
				old.EXPECT().GetBridgeName().Return(brOld)
				old.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{}, nil)
				old.EXPECT().Delete().Return(errors.New("delete failed"))
			},
			expectedErr: "failed to delete OVS bridge br-old: delete failed",
		},
		{
			name:         "bridge replacement blocked by container Port",
			prevCfg:      bridgeConfig(brOld, eth1),
			desiredCfg:   bridgeConfig(brNew, eth1),
			drainPending: true,
			expectedErr:  errStaleBridgeInUse.Error(),
		},
		{
			name:       "bridge created (prev is nil, single interface)",
			prevCfg:    nil,
			desiredCfg: bridgeConfig(brNew, eth1),
			expectedCalls: func(old, new *ovsconfigtest.MockOVSBridgeClient) {
				new.EXPECT().Create().Return(nil)
				new.EXPECT().SetMcastSnooping(false).Return(nil)
				new.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{}, nil).Times(1)
				new.EXPECT().GetOFPort(eth1+"~").Return(int32(0), client.ErrNotFound)
				new.EXPECT().CreateUplinkPort(eth1+"~", int32(0), map[string]string{"antrea-type": "uplink"}).Return("", nil)
			},
			wantPrepareCalls: []string{eth1},
		},
		{
			// The bridge may not be freshly created (Create is a no-op on an existing
			// bridge); a leftover host connection from a previous single-interface
			// config must be restored before the interface is re-added as a plain uplink.
			name:       "bridge created with stale host connection",
			prevCfg:    nil,
			desiredCfg: &agenttypes.OVSBridgeConfig{BridgeName: brNew, PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{{Name: eth1}, {Name: eth2}}},
			expectedCalls: func(old, new *ovsconfigtest.MockOVSBridgeClient) {
				new.EXPECT().Create().Return(nil)
				new.EXPECT().SetMcastSnooping(false).Return(nil)
				new.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{IFName: eth1, IFType: "internal", ExternalIDs: map[string]string{"antrea-type": "host"}},
					{IFName: eth1 + "~", ExternalIDs: map[string]string{"antrea-type": "uplink"}},
					{Name: eth2, IFName: eth2, Trunks: []uint16{200}},
				}, nil).Times(1)
				new.EXPECT().GetOFPort(eth1).Return(int32(0), client.ErrNotFound)
				new.EXPECT().CreateUplinkPort(eth1, int32(0), map[string]string{"antrea-type": "uplink"}).Return("", nil)
				new.EXPECT().SetPortTrunks(eth2, nil).Return(nil)
			},
			wantRestoreCalls: []struct{ bridge, iface string }{{brNew, eth1}},
		},
		{
			// Use two interfaces to bypass the single-interface PrepareHostInterfaceConnection path.
			name:       "bridge created (prev is nil, two interfaces)",
			prevCfg:    nil,
			desiredCfg: &agenttypes.OVSBridgeConfig{BridgeName: brNew, PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{{Name: eth1}, {Name: eth2}}},
			expectedCalls: func(old, new *ovsconfigtest.MockOVSBridgeClient) {
				new.EXPECT().Create().Return(nil)
				new.EXPECT().SetMcastSnooping(false).Return(nil)
				new.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{}, nil).Times(1)
				new.EXPECT().GetOFPort(eth1).Return(int32(0), client.ErrNotFound)
				new.EXPECT().CreateUplinkPort(eth1, int32(0), map[string]string{"antrea-type": "uplink"}).Return("", nil)
				new.EXPECT().GetOFPort(eth2).Return(int32(0), client.ErrNotFound)
				new.EXPECT().CreateUplinkPort(eth2, int32(0), map[string]string{"antrea-type": "uplink"}).Return("", nil)
			},
		},
		{
			name:       "bridge created without physical interfaces",
			prevCfg:    nil,
			desiredCfg: bridgeConfig(brNew),
			expectedCalls: func(old, new *ovsconfigtest.MockOVSBridgeClient) {
				new.EXPECT().Create().Return(nil)
				new.EXPECT().SetMcastSnooping(false).Return(nil)
				new.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{}, nil).Times(1)
			},
		},
		{
			// Use two interfaces to bypass the single-interface PrepareHostInterfaceConnection path.
			name:       "different bridge name — delete old, create new",
			prevCfg:    &agenttypes.OVSBridgeConfig{BridgeName: brOld, PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{{Name: eth1}, {Name: eth2}}},
			desiredCfg: &agenttypes.OVSBridgeConfig{BridgeName: brNew, PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{{Name: eth1}, {Name: eth2}}},
			expectedCalls: func(old, new *ovsconfigtest.MockOVSBridgeClient) {
				old.EXPECT().GetBridgeName().Return(brOld)
				// deleteBridgeWithClient queries OVSDB for host ports (none for multi-iface).
				old.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{}, nil)
				old.EXPECT().Delete().Return(nil)
				new.EXPECT().Create().Return(nil)
				new.EXPECT().SetMcastSnooping(false).Return(nil)
				new.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{}, nil).Times(1)
				new.EXPECT().GetOFPort(eth1).Return(int32(0), client.ErrNotFound)
				new.EXPECT().CreateUplinkPort(eth1, int32(0), map[string]string{"antrea-type": "uplink"}).Return("", nil)
				new.EXPECT().GetOFPort(eth2).Return(int32(0), client.ErrNotFound)
				new.EXPECT().CreateUplinkPort(eth2, int32(0), map[string]string{"antrea-type": "uplink"}).Return("", nil)
			},
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
			},
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
				old.EXPECT().GetOFPort(eth1+"~").Return(int32(0), client.ErrNotFound)
				old.EXPECT().CreateUplinkPort(eth1+"~", int32(0), map[string]string{"antrea-type": "uplink"}).Return("", nil)
			},
			wantPrepareCalls: []string{eth1},
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
			},
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
		},
		{
			// Regression: eth1 loses AllowedVLANs AND eth2 has a stale trunk 300 that
			// was never reflected in prev (set externally or from a run the controller
			// didn't track).  clearStaleTrunks clears both from the observed port list.
			name: "stale trunk on eth2 not in prev config — cleared from observed state",
			prevCfg: &agenttypes.OVSBridgeConfig{BridgeName: brOld, PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
				{Name: eth1, AllowedVLANs: []string{"100"}},
				{Name: eth2},
			}},
			desiredCfg: &agenttypes.OVSBridgeConfig{BridgeName: brOld, PhysicalInterfaces: []agenttypes.PhysicalInterfaceConfig{
				{Name: eth1},
				{Name: eth2},
			}},
			expectedCalls: func(old, new *ovsconfigtest.MockOVSBridgeClient) {
				// eth1 has trunks from its prev AllowedVLANs; eth2 has stale trunk 300
				// that was never tracked in prev — both are cleared from the observed
				// port list by clearStaleTrunks.
				old.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
					{UUID: portUUID, IFName: eth1, Name: eth1, Trunks: []uint16{100}},
					{UUID: "uuid-eth2", IFName: eth2, Name: eth2, Trunks: []uint16{300}},
				}, nil).Times(1)
				old.EXPECT().SetPortTrunks(eth1, nil).Return(nil)
				old.EXPECT().SetPortTrunks(eth2, nil).Return(nil)
			},
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

			fakePc := &fakePodController{drainPending: tc.drainPending}
			var ovsBridgeClient ovsconfig.OVSBridgeClient
			if tc.prevCfg != nil {
				ovsBridgeClient = oldMock
				oldMock.EXPECT().GetBridgeName().Return(tc.prevCfg.BridgeName)
			}
			c := &Controller{
				ovsBridgeClient:    ovsBridgeClient,
				effectiveBridgeCfg: tc.prevCfg,
				podController:      fakePc,
			}

			err := c.reconcileBridge(tc.desiredCfg)
			if tc.expectedErr != "" {
				assert.ErrorContains(t, err, tc.expectedErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.desiredCfg, c.effectiveBridgeCfg)
				switch {
				case tc.desiredCfg == nil:
					assert.Nil(t, c.ovsBridgeClient)
				case tc.prevCfg != nil && tc.prevCfg.BridgeName == tc.desiredCfg.BridgeName:
					assert.Equal(t, oldMock, c.ovsBridgeClient)
				default:
					assert.Equal(t, newMock, c.ovsBridgeClient)
				}

				var expectedSetBridgeCalls []ovsconfig.OVSBridgeClient
				if tc.desiredCfg != nil {
					expectedClient := ovsconfig.OVSBridgeClient(newMock)
					if tc.prevCfg != nil && tc.prevCfg.BridgeName == tc.desiredCfg.BridgeName {
						expectedClient = oldMock
					}
					expectedSetBridgeCalls = append(expectedSetBridgeCalls, expectedClient)
				}
				assert.Equal(t, expectedSetBridgeCalls, fakePc.setBridgeCalls,
					"unexpected bridge clients installed in PodController")
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

func TestReconcileBridgeUpdatesMcastSnooping(t *testing.T) {
	updateErr := errors.New("multicast snooping update failed")
	tests := []struct {
		name            string
		previousEnabled bool
		desiredEnabled  bool
		updateErr       error
	}{
		{
			name:           "enable",
			desiredEnabled: true,
		},
		{
			name:            "disable",
			previousEnabled: true,
		},
		{
			name:           "update failure",
			desiredEnabled: true,
			updateErr:      updateErr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := mock.NewController(t)
			bridgeClient := ovsconfigtest.NewMockOVSBridgeClient(ctrl)
			bridgeClient.EXPECT().GetBridgeName().Return(brOld)
			bridgeClient.EXPECT().SetMcastSnooping(tt.desiredEnabled).Return(tt.updateErr)
			if tt.updateErr == nil {
				bridgeClient.EXPECT().GetPortList().Return(nil, nil)
			}
			previous := bridgeConfig(brOld)
			previous.EnableMulticastSnooping = tt.previousEnabled
			desired := bridgeConfig(brOld)
			desired.EnableMulticastSnooping = tt.desiredEnabled
			fakePc := &fakePodController{}
			c := newTestSecondaryNetworkController(previous, desired, fakePc)
			c.ovsBridgeClient = bridgeClient

			err := c.reconcileBridge(desired)
			if tt.updateErr != nil {
				require.ErrorIs(t, err, tt.updateErr)
				assert.Equal(t, bridgeClient, c.ovsBridgeClient)
				assert.Equal(t, previous, c.effectiveBridgeCfg)
				assert.Empty(t, fakePc.setBridgeCalls)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, bridgeClient, c.ovsBridgeClient)
			assert.Equal(t, desired, c.effectiveBridgeCfg)
			assert.Equal(t, []ovsconfig.OVSBridgeClient{bridgeClient}, fakePc.setBridgeCalls)
		})
	}
}

func TestReconcileBridgeClearsStateBeforeCreatingReplacement(t *testing.T) {
	ctrl := mock.NewController(t)
	oldMock := ovsconfigtest.NewMockOVSBridgeClient(ctrl)
	newMock := ovsconfigtest.NewMockOVSBridgeClient(ctrl)
	mockInterfaceByName(t)

	createErr := errors.New("create failed")

	prevNewOVSBridgeFn := newOVSBridgeFn
	var capturedController *Controller
	newOVSBridgeFn = func(bridgeName string, ovsDatapathType ovsconfig.OVSDatapathType, ovsdb client.Client, options ...ovsconfig.OVSBridgeOption) ovsconfig.OVSBridgeClient {
		if bridgeName == brOld {
			return oldMock
		}
		if capturedController != nil {
			assert.Nil(t, capturedController.effectiveBridgeCfg, "effectiveBridgeCfg should be nil after old bridge deleted")
			assert.Nil(t, capturedController.ovsBridgeClient, "ovsBridgeClient should be nil after old bridge deleted")
		}
		return newMock
	}
	t.Cleanup(func() { newOVSBridgeFn = prevNewOVSBridgeFn })

	oldMock.EXPECT().GetBridgeName().Return(brOld).Times(2)
	oldMock.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{}, nil)
	oldMock.EXPECT().Delete().Return(nil)
	newMock.EXPECT().Create().Return(createErr)

	desired := bridgeConfig(brNew, eth1, eth2)
	c := newTestSecondaryNetworkController(bridgeConfig(brOld, eth1, eth2), desired, &fakePodController{})
	c.ovsBridgeClient = oldMock
	capturedController = c

	err := c.reconcileBridge(desired)
	require.Error(t, err, "expected error from failed bridge creation")

	assert.Nil(t, c.effectiveBridgeCfg, "effectiveBridgeCfg should remain nil after failed create")
	assert.Nil(t, c.ovsBridgeClient, "ovsBridgeClient should remain nil after failed create")
}

func TestSyncBridgeRetriesStartupBridgeInitialization(t *testing.T) {
	ctrl := mock.NewController(t)
	bridgeClient := ovsconfigtest.NewMockOVSBridgeClient(ctrl)
	desired := bridgeConfig(brOld)

	findCalls := 0
	prevFindStartupSecondaryBridgeFn := findStartupSecondaryBridgeFn
	findStartupSecondaryBridgeFn = func(client.Client, string) (string, error) {
		findCalls++
		return brOld, nil
	}
	t.Cleanup(func() { findStartupSecondaryBridgeFn = prevFindStartupSecondaryBridgeFn })

	mockNewOVSBridge(t, bridgeClient)
	bridgeClient.EXPECT().Create().Return(nil).Times(2)
	bridgeClient.EXPECT().GetBridgeName().Return(brOld)
	bridgeClient.EXPECT().SetMcastSnooping(false).Return(nil)
	bridgeClient.EXPECT().GetPortList().Return(nil, nil)

	initializationErr := errors.New("interface store initialization failed")
	fakePc := &fakePodController{initializeBridgeErr: initializationErr}
	c := newTestSecondaryNetworkController(nil, desired, fakePc)

	require.ErrorIs(t, c.syncBridge(), initializationErr)
	assert.False(t, c.bridgeStateInitDone)
	assert.Empty(t, fakePc.setBridgeCalls)
	assert.Nil(t, c.effectiveBridgeCfg)
	assert.Nil(t, c.ovsBridgeClient)
	assert.Equal(t, 1, findCalls)

	fakePc.initializeBridgeErr = nil
	require.NoError(t, c.syncBridge())
	assert.True(t, c.bridgeStateInitDone)
	assert.Equal(t, []ovsconfig.OVSBridgeClient{bridgeClient, bridgeClient}, fakePc.initializeBridgeCalls)
	assert.Equal(t, []ovsconfig.OVSBridgeClient{bridgeClient}, fakePc.setBridgeCalls)
	assert.Equal(t, desired, c.effectiveBridgeCfg)
	assert.Equal(t, 2, findCalls)
}

func TestSyncBridgeRetriesDesiredBridgeCreation(t *testing.T) {
	ctrl := mock.NewController(t)
	bridgeClient := ovsconfigtest.NewMockOVSBridgeClient(ctrl)
	desired := bridgeConfig(brOld)
	createErr := errors.New("failed to create bridge")

	findCalls := 0
	prevFindStartupSecondaryBridgeFn := findStartupSecondaryBridgeFn
	findStartupSecondaryBridgeFn = func(client.Client, string) (string, error) {
		findCalls++
		return "", nil
	}
	t.Cleanup(func() { findStartupSecondaryBridgeFn = prevFindStartupSecondaryBridgeFn })

	mockNewOVSBridge(t, bridgeClient)
	mock.InOrder(
		bridgeClient.EXPECT().Create().Return(createErr),
		bridgeClient.EXPECT().Create().Return(nil),
		bridgeClient.EXPECT().SetMcastSnooping(false).Return(nil),
		bridgeClient.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{}, nil),
	)

	fakePc := &fakePodController{}
	c := newTestSecondaryNetworkController(nil, desired, fakePc)

	require.ErrorIs(t, c.syncBridge(), createErr)
	assert.True(t, c.bridgeStateInitDone)
	assert.Nil(t, c.ovsBridgeClient)
	assert.Equal(t, 1, findCalls)

	require.NoError(t, c.syncBridge())
	assert.Equal(t, bridgeClient, c.ovsBridgeClient)
	assert.Equal(t, []ovsconfig.OVSBridgeClient{nil}, fakePc.initializeBridgeCalls)
	assert.Equal(t, []ovsconfig.OVSBridgeClient{bridgeClient}, fakePc.setBridgeCalls)
	assert.Equal(t, 1, findCalls)
}

func TestSyncBridgeDeletesDiscoveredBridgeWhenUndesired(t *testing.T) {
	ctrl := mock.NewController(t)
	bridgeClient := ovsconfigtest.NewMockOVSBridgeClient(ctrl)
	mockInterfaceByName(t)
	mockNewOVSBridgeByName(t, map[string]ovsconfig.OVSBridgeClient{brOld: bridgeClient})
	mockStartupSecondaryBridge(t, brOld)

	var gotRestoreCalls []struct{ bridge, iface string }
	origRestore := restoreHostInterfaceConfigFn
	restoreHostInterfaceConfigFn = func(brName, ifaceName string) error {
		gotRestoreCalls = append(gotRestoreCalls, struct{ bridge, iface string }{brName, ifaceName})
		return nil
	}
	t.Cleanup(func() { restoreHostInterfaceConfigFn = origRestore })

	bridgeClient.EXPECT().Create().Return(nil)
	bridgeClient.EXPECT().GetBridgeName().Return(brOld).Times(2)
	bridgeClient.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
		{IFName: eth1, IFType: "internal", ExternalIDs: map[string]string{"antrea-type": "host"}},
	}, nil)
	bridgeClient.EXPECT().Delete().Return(nil)

	fakePc := &fakePodController{}
	c := newTestSecondaryNetworkController(nil, nil, fakePc)
	require.NoError(t, c.syncBridge())

	assert.Equal(t, []struct{ bridge, iface string }{{brOld, eth1}}, gotRestoreCalls)
	assert.Equal(t, []ovsconfig.OVSBridgeClient{bridgeClient}, fakePc.initializeBridgeCalls)
	assert.Empty(t, fakePc.setBridgeCalls)
	assert.Equal(t, 1, fakePc.drainCalls)
}

func TestSyncBridgeWaitsForDiscoveredBridgeToDrain(t *testing.T) {
	ctrl := mock.NewController(t)
	oldMock := ovsconfigtest.NewMockOVSBridgeClient(ctrl)
	mockNewOVSBridgeByName(t, map[string]ovsconfig.OVSBridgeClient{brOld: oldMock})
	mockStartupSecondaryBridge(t, brOld)
	oldMock.EXPECT().Create().Return(nil)
	oldMock.EXPECT().GetBridgeName().Return(brOld)

	fakePc := &fakePodController{
		drainPending: true,
	}
	c := newTestSecondaryNetworkController(nil, nil, fakePc)

	err := c.syncBridge()
	require.ErrorIs(t, err, errStaleBridgeInUse)
	assert.Equal(t, []ovsconfig.OVSBridgeClient{oldMock}, fakePc.initializeBridgeCalls)
	assert.Equal(t, 1, fakePc.drainCalls)
}

func TestSyncBridgeCancelsDrainWhenDiscoveredBridgeBecomesDesired(t *testing.T) {
	ctrl := mock.NewController(t)
	oldMock := ovsconfigtest.NewMockOVSBridgeClient(ctrl)
	mockNewOVSBridgeByName(t, map[string]ovsconfig.OVSBridgeClient{brOld: oldMock})
	findCalls := 0
	prevFindStartupSecondaryBridgeFn := findStartupSecondaryBridgeFn
	findStartupSecondaryBridgeFn = func(client.Client, string) (string, error) {
		findCalls++
		return brOld, nil
	}
	t.Cleanup(func() { findStartupSecondaryBridgeFn = prevFindStartupSecondaryBridgeFn })

	// The bridge is discovered and attached once. A desired-state rollback
	// reuses the cached client and cancels the in-progress drain.
	oldMock.EXPECT().Create().Return(nil)
	oldMock.EXPECT().GetBridgeName().Return(brOld).Times(2)
	oldMock.EXPECT().SetMcastSnooping(false).Return(nil)
	oldMock.EXPECT().GetPortList().Return(nil, nil)

	fakePc := &fakePodController{drainPending: true}
	queue := workqueue.NewTypedRateLimitingQueue(
		workqueue.NewTypedItemExponentialFailureRateLimiter[string](time.Millisecond, time.Millisecond))
	t.Cleanup(queue.ShutDown)
	c := &Controller{
		dynamicBridgeReconcile: true,
		secNetConfig:           &agentconfig.SecondaryNetworkConfig{},
		primaryOVSBridgeName:   primaryOVSBridge,
		podController:          fakePc,
		queue:                  queue,
	}
	c.latestANCSnapshot.Store(snapshotWithBridge(brNew))

	err := c.syncBridge()
	require.ErrorIs(t, err, errStaleBridgeInUse)
	assert.Equal(t, oldMock, c.ovsBridgeClient)
	assert.Nil(t, c.effectiveBridgeCfg)

	c.latestANCSnapshot.Store(snapshotWithBridge(brOld))
	desired := &agenttypes.OVSBridgeConfig{BridgeName: brOld}
	require.NoError(t, c.syncBridge())

	assert.Equal(t, oldMock, c.ovsBridgeClient)
	assert.Equal(t, desired, c.effectiveBridgeCfg)
	assert.Equal(t, []ovsconfig.OVSBridgeClient{oldMock}, fakePc.setBridgeCalls)
	assert.Equal(t, 1, findCalls)
}

func TestSyncBridgeReconcilesDiscoveredManagedBridge(t *testing.T) {
	ctrl := mock.NewController(t)
	oldMock := ovsconfigtest.NewMockOVSBridgeClient(ctrl)

	mockInterfaceByName(t)
	mockNewOVSBridgeByName(t, map[string]ovsconfig.OVSBridgeClient{
		brOld: oldMock,
	})
	mockStartupSecondaryBridge(t, brOld)

	desired := bridgeConfig(brOld, eth1, eth2)
	oldMock.EXPECT().Create().Return(nil)
	oldMock.EXPECT().GetBridgeName().Return(brOld)
	oldMock.EXPECT().SetMcastSnooping(false).Return(nil)
	oldMock.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{
		{UUID: "uuid-eth1", IFName: eth1},
	}, nil)
	oldMock.EXPECT().GetOFPort(eth2).Return(int32(0), client.ErrNotFound)
	oldMock.EXPECT().CreateUplinkPort(eth2, int32(0), map[string]string{
		"antrea-type": "uplink",
	}).Return("", nil)

	fakePc := &fakePodController{}
	c := newTestSecondaryNetworkController(nil, desired, fakePc)

	require.NoError(t, c.syncBridge())
	assert.Equal(t, []ovsconfig.OVSBridgeClient{oldMock}, fakePc.initializeBridgeCalls)
	assert.Equal(t, []ovsconfig.OVSBridgeClient{oldMock}, fakePc.setBridgeCalls)
	assert.Equal(t, oldMock, c.ovsBridgeClient)
	assert.Equal(t, desired, c.effectiveBridgeCfg)
}

func TestSyncBridgeSkipsReconciliationOnANCListErrorWithoutStaticConfig(t *testing.T) {
	findCalls := 0
	prevFindStartupSecondaryBridgeFn := findStartupSecondaryBridgeFn
	findStartupSecondaryBridgeFn = func(client.Client, string) (string, error) {
		findCalls++
		return "", nil
	}
	t.Cleanup(func() { findStartupSecondaryBridgeFn = prevFindStartupSecondaryBridgeFn })

	queue := workqueue.NewTypedRateLimitingQueue(
		workqueue.NewTypedItemExponentialFailureRateLimiter[string](time.Millisecond, time.Millisecond))
	t.Cleanup(queue.ShutDown)
	c := &Controller{
		dynamicBridgeReconcile: true,
		secNetConfig:           &agentconfig.SecondaryNetworkConfig{},
		podController:          &fakePodController{},
		queue:                  queue,
	}
	c.latestANCSnapshot.Store(antreanodeconfig.NewSnapshot(nil, errors.New("informer list failed")))

	require.NoError(t, c.syncBridge())
	assert.Zero(t, findCalls)
	assert.False(t, c.bridgeStateInitDone)
	assert.Nil(t, c.effectiveBridgeCfg)
	assert.Nil(t, c.ovsBridgeClient)
}

func TestSyncBridgeReconcilesStaticBridgeOnANCListError(t *testing.T) {
	ctrl := mock.NewController(t)
	bridgeClient := ovsconfigtest.NewMockOVSBridgeClient(ctrl)

	findCalls := 0
	prevFindStartupSecondaryBridgeFn := findStartupSecondaryBridgeFn
	findStartupSecondaryBridgeFn = func(client.Client, string) (string, error) {
		findCalls++
		return "", nil
	}
	t.Cleanup(func() { findStartupSecondaryBridgeFn = prevFindStartupSecondaryBridgeFn })

	mockNewOVSBridge(t, bridgeClient)
	bridgeClient.EXPECT().Create().Return(nil)
	bridgeClient.EXPECT().SetMcastSnooping(false).Return(nil)
	bridgeClient.EXPECT().GetPortList().Return([]ovsconfig.OVSPortData{}, nil)

	fakePc := &fakePodController{}
	desired := bridgeConfig(brOld)
	c := newTestSecondaryNetworkController(nil, desired, fakePc)
	c.dynamicBridgeReconcile = true
	queue := workqueue.NewTypedRateLimitingQueue(
		workqueue.NewTypedItemExponentialFailureRateLimiter[string](time.Millisecond, time.Millisecond))
	t.Cleanup(queue.ShutDown)
	c.queue = queue
	c.latestANCSnapshot.Store(antreanodeconfig.NewSnapshot(nil, errors.New("informer list failed")))

	require.NoError(t, c.syncBridge())
	assert.True(t, c.bridgeStateInitDone)
	assert.Equal(t, bridgeClient, c.ovsBridgeClient)
	assert.Equal(t, desired, c.effectiveBridgeCfg)
	assert.Equal(t, []ovsconfig.OVSBridgeClient{bridgeClient}, fakePc.setBridgeCalls)
	assert.Equal(t, 1, findCalls)
}

func mockInterfaceByName(t *testing.T) {
	t.Helper()
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
	var physicalInterfaces []agenttypes.PhysicalInterfaceConfig
	for _, ifName := range ifNames {
		physicalInterfaces = append(physicalInterfaces, agenttypes.PhysicalInterfaceConfig{Name: ifName})
	}
	return &agenttypes.OVSBridgeConfig{
		BridgeName:         bridgeName,
		PhysicalInterfaces: physicalInterfaces,
	}
}

func snapshotWithBridge(bridgeName string) *antreanodeconfig.Snapshot {
	return antreanodeconfig.NewSnapshot(&crdv1alpha1.AntreaNodeConfig{
		Spec: crdv1alpha1.AntreaNodeConfigSpec{
			SecondaryNetwork: &crdv1alpha1.SecondaryNetworkConfig{
				OVSBridges: []crdv1alpha1.OVSBridgeConfig{{BridgeName: bridgeName}},
			},
		},
	}, nil)
}

func newTestSecondaryNetworkController(prevCfg, desiredCfg *agenttypes.OVSBridgeConfig, podController podControllerInterface) *Controller {
	secNetConfig := &agentconfig.SecondaryNetworkConfig{}
	if desiredCfg != nil {
		staticBridge := agentconfig.OVSBridgeConfig{
			BridgeName:              desiredCfg.BridgeName,
			EnableMulticastSnooping: desiredCfg.EnableMulticastSnooping,
		}
		for _, iface := range desiredCfg.PhysicalInterfaces {
			staticBridge.PhysicalInterfaces = append(staticBridge.PhysicalInterfaces, iface.Name)
		}
		secNetConfig.OVSBridges = []agentconfig.OVSBridgeConfig{staticBridge}
	}
	return &Controller{
		secNetConfig:       secNetConfig,
		effectiveBridgeCfg: prevCfg,
		ovsdbClient:        nil,
		podController:      podController,
	}
}

func mockStartupSecondaryBridge(t *testing.T, bridgeName string) {
	t.Helper()
	prevFunc := findStartupSecondaryBridgeFn
	findStartupSecondaryBridgeFn = func(client.Client, string) (string, error) {
		return bridgeName, nil
	}
	t.Cleanup(func() { findStartupSecondaryBridgeFn = prevFunc })
}

func mockNewOVSBridge(t *testing.T, brClient ovsconfig.OVSBridgeClient) {
	t.Helper()
	prevFunc := newOVSBridgeFn
	newOVSBridgeFn = func(bridgeName string, ovsDatapathType ovsconfig.OVSDatapathType, ovsdb client.Client, options ...ovsconfig.OVSBridgeOption) ovsconfig.OVSBridgeClient {
		return brClient
	}
	t.Cleanup(func() { newOVSBridgeFn = prevFunc })
}

func mockNewOVSBridgeByName(t *testing.T, brClients map[string]ovsconfig.OVSBridgeClient) {
	t.Helper()
	prevFunc := newOVSBridgeFn
	newOVSBridgeFn = func(bridgeName string, ovsDatapathType ovsconfig.OVSDatapathType, ovsdb client.Client, options ...ovsconfig.OVSBridgeOption) ovsconfig.OVSBridgeClient {
		return brClients[bridgeName]
	}
	t.Cleanup(func() { newOVSBridgeFn = prevFunc })
}
