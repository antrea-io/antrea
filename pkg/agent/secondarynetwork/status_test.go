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
	"testing/synctest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"antrea.io/antrea/v2/pkg/agent/antreanodeconfig"
	agenttypes "antrea.io/antrea/v2/pkg/agent/types"
	crdv1alpha1 "antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
	agentconfig "antrea.io/antrea/v2/pkg/config/agent"
	ovsconfigtest "antrea.io/antrea/v2/pkg/ovs/ovsconfig/testing"
)

func TestNodeConfigStatus(t *testing.T) {
	cfg := &crdv1alpha1.AntreaNodeConfig{ObjectMeta: metav1.ObjectMeta{Name: "anc", UID: "anc-uid", Generation: 2}}
	snap := antreanodeconfig.NewSnapshot(cfg, nil)
	for _, tt := range []struct {
		name       string
		snapshot   *antreanodeconfig.Snapshot
		err        error
		static     *agentconfig.SecondaryNetworkConfig
		wantStatus metav1.ConditionStatus
		wantReason string
	}{
		{name: "success", snapshot: snap, wantStatus: metav1.ConditionTrue, wantReason: "Reconciled"},
		{name: "draining", snapshot: snap, err: errStaleBridgeInUse, wantStatus: metav1.ConditionFalse, wantReason: "BridgeInUse"},
		{name: "OVS failure", snapshot: snap, err: errors.New("OVS transaction failed"), wantStatus: metav1.ConditionFalse, wantReason: "ReconcileFailed"},
		{name: "snapshot unavailable", wantStatus: metav1.ConditionUnknown, wantReason: "ConfigurationUnavailable"},
		{name: "list failed", snapshot: antreanodeconfig.NewSnapshot(nil, errors.New("list failed")), wantStatus: metav1.ConditionUnknown, wantReason: "ConfigurationUnavailable"},
		{name: "static override", snapshot: snap, static: &agentconfig.SecondaryNetworkConfig{OVSBridges: []agentconfig.OVSBridgeConfig{{BridgeName: "static"}}}, wantStatus: metav1.ConditionFalse, wantReason: "OverriddenByStaticConfig"},
		{name: "no configuration after cleanup", snapshot: antreanodeconfig.NewSnapshot(nil, nil), wantStatus: metav1.ConditionTrue, wantReason: "Reconciled"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := &Controller{statusUpdates: make(chan struct{}, 1), secNetConfig: tt.static}
			c.updateNodeConfigStatus(tt.snapshot, &agenttypes.OVSBridgeConfig{BridgeName: "br-test"}, tt.err)
			report := c.GetAntreaNodeConfigStatus()
			require.NotNil(t, report)
			require.NotNil(t, report.SecondaryNetwork)
			require.Len(t, report.SecondaryNetwork.Conditions, 1)
			assert.Equal(t, "br-test", report.SecondaryNetwork.DesiredBridge)
			ready := meta.FindStatusCondition(report.SecondaryNetwork.Conditions, "Ready")
			require.NotNil(t, ready)
			assert.Equal(t, tt.wantStatus, ready.Status)
			assert.Equal(t, tt.wantReason, ready.Reason)
			if tt.snapshot != nil && tt.snapshot.AntreaNodeConfig != nil {
				assert.Equal(t, cfg.UID, report.ConfigUID)
				assert.Equal(t, cfg.Generation, ready.ObservedGeneration)
			}
			select {
			case <-c.AntreaNodeConfigStatusUpdates():
			default:
				t.Fatal("Status transition did not signal the monitor")
			}
			c.updateNodeConfigStatus(tt.snapshot, &agenttypes.OVSBridgeConfig{BridgeName: "br-test"}, tt.err)
			assert.Equal(t, report.SecondaryNetwork.Conditions, c.GetAntreaNodeConfigStatus().SecondaryNetwork.Conditions)
			select {
			case <-c.AntreaNodeConfigStatusUpdates():
			default:
				t.Fatal("A new reconciliation completion must signal the monitor")
			}
			report.SecondaryNetwork.Conditions[0].Status = metav1.ConditionUnknown
			assert.Equal(t, tt.wantStatus, c.GetAntreaNodeConfigStatus().SecondaryNetwork.Conditions[0].Status, "Reports must not alias controller state")
		})
	}
}

func TestNodeConfigStatusNotificationWithIdenticalReport(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Freeze time to exercise platforms on which consecutive reconciliations
		// can complete within the same clock tick.
		c := &Controller{statusUpdates: make(chan struct{}, 1)}
		snap := antreanodeconfig.NewSnapshot(nil, nil)
		c.updateNodeConfigStatus(snap, nil, nil)
		report := c.GetAntreaNodeConfigStatus()
		require.Len(t, c.statusUpdates, 1)
		<-c.statusUpdates

		c.updateNodeConfigStatus(snap, nil, nil)
		require.Equal(t, report, c.GetAntreaNodeConfigStatus(), "The frozen clock must produce identical reports")
		select {
		case <-c.statusUpdates:
		default:
			t.Fatal("A completed reconciliation must notify even when its report is unchanged")
		}
		c.updateNodeConfigStatus(snap, nil, nil)
		c.updateNodeConfigStatus(snap, nil, nil)
		assert.Len(t, c.statusUpdates, 1)
	})
}

func TestStaticReconcileFailureRetainsOverrideReason(t *testing.T) {
	c := &Controller{secNetConfig: &agentconfig.SecondaryNetworkConfig{OVSBridges: []agentconfig.OVSBridgeConfig{{BridgeName: "static"}}}}
	cfg := &crdv1alpha1.AntreaNodeConfig{ObjectMeta: metav1.ObjectMeta{UID: "anc-uid", Generation: 1}}
	c.updateNodeConfigStatus(antreanodeconfig.NewSnapshot(cfg, nil), &agenttypes.OVSBridgeConfig{BridgeName: "static"}, errors.New("missing static uplink"))
	report := c.GetAntreaNodeConfigStatus()
	assert.Equal(t, "OverriddenByStaticConfig", meta.FindStatusCondition(report.SecondaryNetwork.Conditions, "Ready").Reason)
	assert.Contains(t, meta.FindStatusCondition(report.SecondaryNetwork.Conditions, "Ready").Message, "missing static uplink")
	assert.Len(t, report.SecondaryNetwork.Conditions, 1)
}

func TestNodeConfigStatusTracksCurrentSelection(t *testing.T) {
	bridge := ovsconfigtest.NewMockOVSBridgeClient(gomock.NewController(t))
	bridge.EXPECT().GetBridgeName().Return("br-current").AnyTimes()
	c := &Controller{statusUpdates: make(chan struct{}, 1)}
	for i, tt := range []struct {
		uid           types.UID
		currentBridge bool
		err           error
	}{
		{uid: "config-a", currentBridge: true},
		{uid: "config-b", currentBridge: true, err: errStaleBridgeInUse},
		{uid: "config-a"},
	} {
		cfg := &crdv1alpha1.AntreaNodeConfig{ObjectMeta: metav1.ObjectMeta{Name: string(tt.uid), UID: tt.uid, Generation: int64(i + 1)}}
		c.ovsBridgeClient = nil
		if tt.currentBridge {
			c.ovsBridgeClient = bridge
		}
		c.updateNodeConfigStatus(antreanodeconfig.NewSnapshot(cfg, nil), nil, tt.err)
		report := c.GetAntreaNodeConfigStatus()
		assert.Equal(t, tt.uid, report.ConfigUID)
		assert.Equal(t, string(tt.uid), report.ConfigName)
		assert.Equal(t, cfg.Generation, meta.FindStatusCondition(report.SecondaryNetwork.Conditions, "Ready").ObservedGeneration)
		if tt.currentBridge {
			assert.Equal(t, "br-current", report.SecondaryNetwork.CurrentBridge)
		} else {
			assert.Empty(t, report.SecondaryNetwork.CurrentBridge, "A new result must not inherit a historical bridge")
		}
		assert.Empty(t, report.SecondaryNetwork.DesiredBridge)
		assert.Equal(t, tt.err == nil, meta.IsStatusConditionTrue(report.SecondaryNetwork.Conditions, "Ready"))
	}
	c.updateNodeConfigStatus(antreanodeconfig.NewSnapshot(nil, nil), nil, nil)
	report := c.GetAntreaNodeConfigStatus()
	assert.Empty(t, report.ConfigUID)
	assert.Empty(t, report.ConfigName)
	assert.Zero(t, meta.FindStatusCondition(report.SecondaryNetwork.Conditions, "Ready").ObservedGeneration)
}
