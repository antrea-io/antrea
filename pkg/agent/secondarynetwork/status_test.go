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
	crdv1beta1 "antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
	agentconfig "antrea.io/antrea/v2/pkg/config/agent"
	ovsconfigtest "antrea.io/antrea/v2/pkg/ovs/ovsconfig/testing"
)

func TestSecondaryNetworkStatus(t *testing.T) {
	cfg := &crdv1alpha1.AntreaNodeConfig{ObjectMeta: metav1.ObjectMeta{Name: "anc", UID: "anc-uid", Generation: 2}}
	snap := antreanodeconfig.NewSnapshot(cfg, nil)
	for _, tt := range []struct {
		name       string
		snapshot   *antreanodeconfig.Snapshot
		err        error
		staticMode bool
		static     *agentconfig.SecondaryNetworkConfig
		wantStatus metav1.ConditionStatus
		wantReason string
	}{
		{name: "success", snapshot: snap, wantStatus: metav1.ConditionTrue, wantReason: "Reconciled"},
		{name: "draining", snapshot: snap, err: errStaleBridgeInUse, wantStatus: metav1.ConditionFalse, wantReason: "BridgeInUse"},
		{name: "OVS failure", snapshot: snap, err: errors.New("OVS transaction failed"), wantStatus: metav1.ConditionFalse, wantReason: "ReconcileFailed"},
		{name: "snapshot unavailable", wantStatus: metav1.ConditionUnknown, wantReason: "ConfigurationUnavailable"},
		{name: "list failed", snapshot: antreanodeconfig.NewSnapshot(nil, errors.New("list failed")), wantStatus: metav1.ConditionUnknown, wantReason: "ConfigurationUnavailable"},
		{name: "static override", snapshot: snap, static: &agentconfig.SecondaryNetworkConfig{OVSBridges: []agentconfig.OVSBridgeConfig{{BridgeName: "static"}}}, wantStatus: metav1.ConditionTrue, wantReason: "Reconciled"},
		{name: "static without ANC", staticMode: true, static: &agentconfig.SecondaryNetworkConfig{OVSBridges: []agentconfig.OVSBridgeConfig{{BridgeName: "static"}}}, wantStatus: metav1.ConditionTrue, wantReason: "Reconciled"},
		{name: "static despite ANC list error", snapshot: antreanodeconfig.NewSnapshot(nil, errors.New("list failed")), static: &agentconfig.SecondaryNetworkConfig{OVSBridges: []agentconfig.OVSBridgeConfig{{BridgeName: "static"}}}, wantStatus: metav1.ConditionTrue, wantReason: "Reconciled"},
		{name: "static failure without ANC", staticMode: true, static: &agentconfig.SecondaryNetworkConfig{OVSBridges: []agentconfig.OVSBridgeConfig{{BridgeName: "static"}}}, err: errors.New("missing uplink"), wantStatus: metav1.ConditionFalse, wantReason: "ReconcileFailed"},
		{name: "no configuration after cleanup", snapshot: antreanodeconfig.NewSnapshot(nil, nil), wantStatus: metav1.ConditionTrue, wantReason: "Reconciled"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := &Controller{dynamicBridgeReconcile: !tt.staticMode, statusUpdates: make(chan struct{}, 1), secNetConfig: tt.static}
			c.updateSecondaryNetworkStatus(tt.snapshot, &agenttypes.OVSBridgeConfig{BridgeName: "br-test"}, tt.err)
			report := c.GetSecondaryNetworkStatus()
			require.NotNil(t, report)
			require.Len(t, report.Conditions, 1)
			assert.Equal(t, "br-test", report.DesiredBridge)
			ready := meta.FindStatusCondition(report.Conditions, "Ready")
			require.NotNil(t, ready)
			assert.Equal(t, tt.wantStatus, ready.Status)
			assert.Equal(t, tt.wantReason, ready.Reason)
			if tt.static != nil {
				assert.Equal(t, crdv1beta1.SecondaryNetworkConfigSourceAgentConfig, report.Source)
				assert.Empty(t, report.ConfigUID)
				assert.Empty(t, report.ConfigName)
				assert.Zero(t, ready.ObservedGeneration)
			} else if tt.snapshot != nil && tt.snapshot.AntreaNodeConfig != nil {
				assert.Equal(t, crdv1beta1.SecondaryNetworkConfigSourceAntreaNodeConfig, report.Source)
				assert.Equal(t, cfg.UID, report.ConfigUID)
				assert.Equal(t, cfg.Generation, ready.ObservedGeneration)
			}
			select {
			case <-c.SecondaryNetworkStatusUpdates():
			default:
				t.Fatal("Status transition did not signal the monitor")
			}
			c.updateSecondaryNetworkStatus(tt.snapshot, &agenttypes.OVSBridgeConfig{BridgeName: "br-test"}, tt.err)
			assert.Equal(t, report.Conditions, c.GetSecondaryNetworkStatus().Conditions)
			select {
			case <-c.SecondaryNetworkStatusUpdates():
			default:
				t.Fatal("A new reconciliation completion must signal the monitor")
			}
			report.Conditions[0].Status = metav1.ConditionUnknown
			assert.Equal(t, tt.wantStatus, c.GetSecondaryNetworkStatus().Conditions[0].Status, "Reports must not alias controller state")
		})
	}
}

func TestSecondaryNetworkStatusNotificationWithIdenticalReport(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Freeze time to exercise platforms on which consecutive reconciliations
		// can complete within the same clock tick.
		c := &Controller{statusUpdates: make(chan struct{}, 1)}
		snap := antreanodeconfig.NewSnapshot(nil, nil)
		c.updateSecondaryNetworkStatus(snap, nil, nil)
		report := c.GetSecondaryNetworkStatus()
		require.Len(t, c.statusUpdates, 1)
		<-c.statusUpdates

		c.updateSecondaryNetworkStatus(snap, nil, nil)
		require.Equal(t, report, c.GetSecondaryNetworkStatus(), "The frozen clock must produce identical reports")
		select {
		case <-c.statusUpdates:
		default:
			t.Fatal("A completed reconciliation must notify even when its report is unchanged")
		}
		c.updateSecondaryNetworkStatus(snap, nil, nil)
		c.updateSecondaryNetworkStatus(snap, nil, nil)
		assert.Len(t, c.statusUpdates, 1)
	})
}

func TestStaticReconcileFailureReportsActualResult(t *testing.T) {
	c := &Controller{secNetConfig: &agentconfig.SecondaryNetworkConfig{OVSBridges: []agentconfig.OVSBridgeConfig{{BridgeName: "static"}}}}
	cfg := &crdv1alpha1.AntreaNodeConfig{ObjectMeta: metav1.ObjectMeta{UID: "anc-uid", Generation: 1}}
	c.updateSecondaryNetworkStatus(antreanodeconfig.NewSnapshot(cfg, nil), &agenttypes.OVSBridgeConfig{BridgeName: "static"}, errors.New("missing static uplink"))
	report := c.GetSecondaryNetworkStatus()
	assert.Equal(t, "ReconcileFailed", meta.FindStatusCondition(report.Conditions, "Ready").Reason)
	assert.Contains(t, meta.FindStatusCondition(report.Conditions, "Ready").Message, "missing static uplink")
	assert.Len(t, report.Conditions, 1)
}

func TestSecondaryNetworkStatusTracksCurrentSelection(t *testing.T) {
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
		c.updateSecondaryNetworkStatus(antreanodeconfig.NewSnapshot(cfg, nil), nil, tt.err)
		report := c.GetSecondaryNetworkStatus()
		assert.Equal(t, tt.uid, report.ConfigUID)
		assert.Equal(t, string(tt.uid), report.ConfigName)
		assert.Equal(t, cfg.Generation, meta.FindStatusCondition(report.Conditions, "Ready").ObservedGeneration)
		if tt.currentBridge {
			assert.Equal(t, "br-current", report.CurrentBridge)
		} else {
			assert.Empty(t, report.CurrentBridge, "A new result must not inherit a historical bridge")
		}
		assert.Empty(t, report.DesiredBridge)
		assert.Equal(t, tt.err == nil, meta.IsStatusConditionTrue(report.Conditions, "Ready"))
	}
	cfg := &crdv1alpha1.AntreaNodeConfig{ObjectMeta: metav1.ObjectMeta{Name: "config-a", UID: "config-a", Generation: 4}}
	c.secNetConfig = &agentconfig.SecondaryNetworkConfig{OVSBridges: []agentconfig.OVSBridgeConfig{{BridgeName: "static"}}}
	c.updateSecondaryNetworkStatus(antreanodeconfig.NewSnapshot(cfg, nil), nil, nil)
	static := c.GetSecondaryNetworkStatus()
	assert.Equal(t, crdv1beta1.SecondaryNetworkConfigSourceAgentConfig, static.Source)
	assert.Empty(t, static.ConfigUID, "Static results must not inherit the previous ANC identity")
	assert.Zero(t, meta.FindStatusCondition(static.Conditions, "Ready").ObservedGeneration)
	c.secNetConfig = nil
	c.updateSecondaryNetworkStatus(antreanodeconfig.NewSnapshot(cfg, nil), nil, nil)
	assert.Equal(t, crdv1beta1.SecondaryNetworkConfigSourceAntreaNodeConfig, c.GetSecondaryNetworkStatus().Source)
	assert.Equal(t, cfg.UID, c.GetSecondaryNetworkStatus().ConfigUID)

	c.updateSecondaryNetworkStatus(antreanodeconfig.NewSnapshot(nil, nil), nil, nil)
	report := c.GetSecondaryNetworkStatus()
	assert.Empty(t, report.ConfigUID)
	assert.Empty(t, report.ConfigName)
	assert.Zero(t, meta.FindStatusCondition(report.Conditions, "Ready").ObservedGeneration)
}
