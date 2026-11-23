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
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ovn-kubernetes/libovsdb/client"
	"github.com/ovn-kubernetes/libovsdb/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	clocktesting "k8s.io/utils/clock/testing"

	"antrea.io/antrea/v2/pkg/agent/antreanodeconfig"
	crdv1alpha1 "antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
	agentconfig "antrea.io/antrea/v2/pkg/config/agent"
	"antrea.io/antrea/v2/pkg/ovs/ovsconfig"
	ovsconfigtest "antrea.io/antrea/v2/pkg/ovs/ovsconfig/testing"
)

func newStatusTestController(t *testing.T) (*Controller, *fakePodController) {
	t.Helper()
	queue := workqueue.NewTypedRateLimitingQueue(
		workqueue.NewTypedItemExponentialFailureRateLimiter[string](minRetryDelay, maxRetryDelay))
	t.Cleanup(queue.ShutDown)
	firstSnapshotCh := make(chan struct{})
	close(firstSnapshotCh)
	pods := &fakePodController{}
	c := &Controller{
		secNetConfig:           &agentconfig.SecondaryNetworkConfig{},
		primaryOVSBridgeName:   primaryOVSBridge,
		dynamicBridgeReconcile: true,
		queue:                  queue,
		statusUpdates:          make(chan struct{}, 1),
		ancFirstSnapshotCh:     firstSnapshotCh,
		podController:          pods,
	}
	return c, pods
}

func statusSnapshot(uid types.UID) *antreanodeconfig.Snapshot {
	return antreanodeconfig.NewSnapshot(&crdv1alpha1.AntreaNodeConfig{
		ObjectMeta: metav1.ObjectMeta{Name: string(uid), UID: uid, Generation: 1},
		Spec: crdv1alpha1.AntreaNodeConfigSpec{
			SecondaryNetwork: &crdv1alpha1.SecondaryNetworkConfig{
				OVSBridges: []crdv1alpha1.OVSBridgeConfig{{BridgeName: brNew}},
			},
		},
	}, nil)
}

func TestReconcileDoesNotWaitForStatusPublication(t *testing.T) {
	bridge := ovsconfigtest.NewMockOVSBridgeClient(gomock.NewController(t))
	mockNewOVSBridge(t, bridge)
	mockStartupSecondaryBridge(t, "")
	bridge.EXPECT().Create().Return(nil)
	bridge.EXPECT().SetMcastSnooping(false).Return(nil)
	bridge.EXPECT().GetPortList().Return(nil, nil)
	bridge.EXPECT().GetBridgeName().Return(brNew)
	c, pods := newStatusTestController(t)
	snap := statusSnapshot("config-a")
	c.latestANCSnapshot.Store(snap)
	require.NoError(t, c.Initialize(nil))
	assert.Equal(t, []ovsconfig.OVSBridgeClient{nil}, pods.initializeBridgeCalls)
	assert.Equal(t, []ovsconfig.OVSBridgeClient{bridge}, pods.setBridgeCalls)
	report := c.GetSecondaryNetworkStatus()
	require.NotNil(t, report)
	assert.Equal(t, snap.AntreaNodeConfig.UID, report.ConfigUID)
	assert.Equal(t, brNew, report.CurrentBridge)
	assert.True(t, meta.IsStatusConditionTrue(report.Conditions, "Ready"))
	assert.Zero(t, c.queue.Len())
}

func TestRetainedEmptyConfigurationReportsDrainCompletion(t *testing.T) {
	bridge := ovsconfigtest.NewMockOVSBridgeClient(gomock.NewController(t))
	mockNewOVSBridge(t, bridge)
	mockStartupSecondaryBridge(t, "")
	bridge.EXPECT().GetBridgeName().Return(brNew).AnyTimes()
	gomock.InOrder(
		bridge.EXPECT().Create().Return(nil),
		bridge.EXPECT().SetMcastSnooping(false).Return(nil),
		bridge.EXPECT().GetPortList().Return(nil, nil),
		bridge.EXPECT().GetPortList().Return(nil, nil),
		bridge.EXPECT().Delete().Return(nil),
	)
	c, pods := newStatusTestController(t)
	snap := statusSnapshot("config-a")
	c.latestANCSnapshot.Store(snap)
	require.NoError(t, c.syncBridge())
	empty := snap.DeepCopy()
	empty.AntreaNodeConfig.Generation++
	empty.AntreaNodeConfig.Spec.SecondaryNetwork = nil
	c.latestANCSnapshot.Store(empty)
	pods.drainPending = true
	require.ErrorIs(t, c.syncBridge(), errStaleBridgeInUse)
	report := c.GetSecondaryNetworkStatus()
	assert.Equal(t, snap.AntreaNodeConfig.UID, report.ConfigUID)
	assert.Equal(t, int64(2), meta.FindStatusCondition(report.Conditions, "Ready").ObservedGeneration)
	assert.Empty(t, report.DesiredBridge)
	assert.Equal(t, brNew, report.CurrentBridge)
	assert.Equal(t, "BridgeInUse", meta.FindStatusCondition(report.Conditions, "Ready").Reason)
	assert.True(t, meta.IsStatusConditionFalse(report.Conditions, "Ready"))
	pods.drainPending = false
	require.NoError(t, c.syncBridge())
	report = c.GetSecondaryNetworkStatus()
	assert.Equal(t, snap.AntreaNodeConfig.UID, report.ConfigUID)
	assert.Equal(t, int64(2), meta.FindStatusCondition(report.Conditions, "Ready").ObservedGeneration)
	assert.Empty(t, report.CurrentBridge)
	assert.Empty(t, report.DesiredBridge)
	assert.True(t, meta.IsStatusConditionTrue(report.Conditions, "Ready"))
	assert.Nil(t, c.ovsBridgeClient)
	assert.Nil(t, c.effectiveBridgeCfg)
	assert.Equal(t, 2, pods.drainCalls)
}

// emptyBridgeDB supplies a bridge without ports to the real OVS bridge client.
type emptyBridgeDB struct {
	client.Client
	getErr error
}

func (db *emptyBridgeDB) Get(_ context.Context, _ model.Model) error {
	return db.getErr
}

func (db *emptyBridgeDB) WhereCache(_ any) client.ConditionalAPI {
	return &emptyBridgeTable{}
}

type emptyBridgeTable struct {
	client.ConditionalAPI
}

func (*emptyBridgeTable) List(_ context.Context, _ any) error {
	return nil
}

func TestSameBridgeStatusRequiresExistingBridge(t *testing.T) {
	for _, tt := range []struct {
		name string
		err  error
	}{
		{name: "healthy bridge"},
		{name: "missing bridge", err: client.ErrNotFound},
		{name: "OVS query failure", err: errors.New("OVS query failed")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, pods := newStatusTestController(t)
			snap := statusSnapshot("config-a")
			c.latestANCSnapshot.Store(snap)
			c.bridgeStateInitDone = true
			c.effectiveBridgeCfg = effectiveSecondaryOVSBridgeFromSnapshot(snap, c.secNetConfig, c.primaryOVSBridgeName)
			db := &emptyBridgeDB{}
			c.ovsBridgeClient = ovsconfig.NewOVSBridge(brNew, ovsconfig.OVSDatapathSystem, db)
			require.NoError(t, c.syncBridge())
			require.True(t, meta.IsStatusConditionTrue(c.GetSecondaryNetworkStatus().Conditions, "Ready"))

			next := snap.DeepCopy()
			next.AntreaNodeConfig.Generation++
			c.latestANCSnapshot.Store(next)
			db.getErr = tt.err
			err := c.syncBridge()
			report := c.GetSecondaryNetworkStatus()
			require.Len(t, report.Conditions, 1)
			ready := meta.FindStatusCondition(report.Conditions, "Ready")
			require.NotNil(t, ready)
			assert.Equal(t, next.AntreaNodeConfig.Generation, ready.ObservedGeneration)
			if tt.err == nil {
				assert.NoError(t, err)
				assert.Equal(t, metav1.ConditionTrue, ready.Status)
				assert.Equal(t, "Reconciled", ready.Reason)
				return
			}
			assert.ErrorIs(t, err, tt.err)
			assert.Equal(t, metav1.ConditionFalse, ready.Status)
			assert.Equal(t, "ReconcileFailed", ready.Reason)
			assert.Contains(t, ready.Message, tt.err.Error())
			assert.Len(t, pods.setBridgeCalls, 1, "failed reconciliation must not reattach the bridge")

			db.getErr = nil
			require.NoError(t, c.syncBridge())
			report = c.GetSecondaryNetworkStatus()
			ready = meta.FindStatusCondition(report.Conditions, "Ready")
			require.NotNil(t, ready)
			assert.Equal(t, next.AntreaNodeConfig.Generation, ready.ObservedGeneration)
			assert.Equal(t, metav1.ConditionTrue, ready.Status)
			assert.Equal(t, "Reconciled", ready.Reason)
			assert.Equal(t, brNew, report.CurrentBridge)
		})
	}
}

func TestBridgeReconciliationQueueLifecycle(t *testing.T) {
	for _, tt := range []struct {
		name       string
		drain      bool
		portError  bool
		retryDelay time.Duration
		wantReason string
	}{
		{name: "success"},
		{name: "bridge in use", drain: true, retryDelay: bridgeInUseRetryDelay, wantReason: "BridgeInUse"},
		{name: "OVS error", portError: true, retryDelay: minRetryDelay, wantReason: "ReconcileFailed"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// The delaying queue uses a heartbeat ticker and a timer for its next delayed item.
			clock := clocktesting.NewFakeClock(time.Now())
			queue := workqueue.NewTypedRateLimitingQueueWithConfig(
				workqueue.NewTypedItemExponentialFailureRateLimiter[string](minRetryDelay, maxRetryDelay),
				workqueue.TypedRateLimitingQueueConfig[string]{Clock: clock})
			t.Cleanup(queue.ShutDown)
			oldBridge := ovsconfigtest.NewMockOVSBridgeClient(gomock.NewController(t))
			oldBridge.EXPECT().GetBridgeName().Return(brOld).AnyTimes()
			if tt.portError {
				oldBridge.EXPECT().GetPortList().Return(nil, errors.New("OVSDB unavailable"))
			}
			oldBridge.EXPECT().GetPortList().Return(nil, nil)
			oldBridge.EXPECT().Delete().Return(nil)
			pods := &fakePodController{drainPending: tt.drain}
			c := &Controller{
				dynamicBridgeReconcile: true,
				bridgeStateInitDone:    true,
				ovsBridgeClient:        oldBridge,
				podController:          pods,
				queue:                  queue,
				statusUpdates:          make(chan struct{}, 1),
			}
			snapshot := statusSnapshot("config-a")
			snapshot.AntreaNodeConfig.Spec.SecondaryNetwork = nil
			c.latestANCSnapshot.Store(snapshot)
			c.enqueue()
			require.True(t, c.processNextItem())
			if tt.retryDelay != 0 {
				ready := meta.FindStatusCondition(c.GetSecondaryNetworkStatus().Conditions, "Ready")
				require.NotNil(t, ready)
				assert.Equal(t, metav1.ConditionFalse, ready.Status)
				assert.Equal(t, tt.wantReason, ready.Reason)
				require.Eventually(t, func() bool { return clock.Waiters() == 2 }, time.Second, time.Millisecond)
				assert.Zero(t, queue.Len())
				clock.Step(tt.retryDelay)
				require.Eventually(t, func() bool { return queue.Len() == 1 }, time.Second, time.Millisecond)
				pods.drainPending = false
				require.True(t, c.processNextItem())
			}
			assert.True(t, meta.IsStatusConditionTrue(c.GetSecondaryNetworkStatus().Conditions, "Ready"))
			assert.Zero(t, queue.NumRequeues(reconcileKey))

			assertNoScheduledReconciliation := func() {
				t.Helper()
				queue.AddAfter("idle-barrier", 2*time.Minute)
				require.Eventually(t, func() bool { return clock.Waiters() == 2 }, time.Second, time.Millisecond)
				clock.Step(2 * time.Minute)
				require.Eventually(t, func() bool { return queue.Len() != 0 }, time.Second, time.Millisecond)
				key, shutdown := queue.Get()
				require.False(t, shutdown)
				queue.Done(key)
				require.Equal(t, "idle-barrier", key, "successful reconciliation must not schedule more work")
				assert.Zero(t, queue.Len())
			}
			assertNoScheduledReconciliation()

			newBridge := ovsconfigtest.NewMockOVSBridgeClient(gomock.NewController(t))
			mockNewOVSBridge(t, newBridge)
			newBridge.EXPECT().Create().Return(nil)
			newBridge.EXPECT().SetMcastSnooping(false).Return(nil)
			newBridge.EXPECT().GetPortList().Return(nil, nil)
			newBridge.EXPECT().GetBridgeName().Return(brNew)
			next := statusSnapshot("config-a")
			next.AntreaNodeConfig.Generation++
			c.latestANCSnapshot.Store(next)
			c.enqueue()
			require.True(t, c.processNextItem())
			report := c.GetSecondaryNetworkStatus()
			assert.Equal(t, brNew, report.CurrentBridge)
			ready := meta.FindStatusCondition(report.Conditions, "Ready")
			require.NotNil(t, ready)
			assert.Equal(t, int64(2), ready.ObservedGeneration)
			assert.Equal(t, metav1.ConditionTrue, ready.Status)
			assertNoScheduledReconciliation()
		})
	}
}
