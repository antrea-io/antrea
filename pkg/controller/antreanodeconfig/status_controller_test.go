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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	cgtesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"

	crdv1alpha1 "antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
	crdv1beta1 "antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
	clientset "antrea.io/antrea/v2/pkg/client/clientset/versioned"
	fakeclient "antrea.io/antrea/v2/pkg/client/clientset/versioned/fake"
	crdinformers "antrea.io/antrea/v2/pkg/client/informers/externalversions"
	"antrea.io/antrea/v2/pkg/util/k8s"
)

func statusFixture(now time.Time) (*crdv1alpha1.AntreaNodeConfig, *corev1.Node, *crdv1beta1.AntreaNodeConfigAgentStatus) {
	cfg := &crdv1alpha1.AntreaNodeConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "config", UID: "config-uid", Generation: 2, CreationTimestamp: metav1.NewTime(now)},
		Spec:       crdv1alpha1.AntreaNodeConfigSpec{NodeSelector: metav1.LabelSelector{MatchLabels: map[string]string{"pool": "one"}}},
	}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node", UID: "node-uid", Labels: map[string]string{"pool": "one"}}, Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}}}
	report := &crdv1beta1.AntreaNodeConfigAgentStatus{
		NodeUID: node.UID, ConfigName: cfg.Name, ConfigUID: cfg.UID,
		LastHeartbeatTime: metav1.NewTime(now),
		SecondaryNetwork: &crdv1beta1.SecondaryNetworkStatus{
			Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Reconciled", ObservedGeneration: cfg.Generation, LastTransitionTime: metav1.NewTime(now)}},
		},
	}
	return cfg, node, report
}

func TestCalculateStatus(t *testing.T) {
	now := time.Now()
	for _, tt := range []struct {
		name        string
		change      func(*crdv1alpha1.AntreaNodeConfig, *corev1.Node, *crdv1beta1.AntreaNodeConfigAgentStatus)
		missing     bool
		wantStatus  metav1.ConditionStatus
		wantReason  string
		wantMessage string
		realized    int32
	}{
		{name: "realized", wantStatus: metav1.ConditionTrue, wantReason: "Reconciled", realized: 1},
		{name: "missing report", missing: true, wantStatus: metav1.ConditionUnknown, wantReason: "AgentUnavailable"},
		{name: "old generation", change: func(_ *crdv1alpha1.AntreaNodeConfig, _ *corev1.Node, r *crdv1beta1.AntreaNodeConfigAgentStatus) {
			r.SecondaryNetwork.Conditions[0].ObservedGeneration--
		}, wantStatus: metav1.ConditionFalse, wantReason: "GenerationNotObserved"},
		{name: "recreated configuration", change: func(_ *crdv1alpha1.AntreaNodeConfig, _ *corev1.Node, r *crdv1beta1.AntreaNodeConfigAgentStatus) {
			r.ConfigUID = "previous-uid"
		}, wantStatus: metav1.ConditionFalse, wantReason: "GenerationNotObserved"},
		{name: "recreated node", change: func(_ *crdv1alpha1.AntreaNodeConfig, n *corev1.Node, _ *crdv1beta1.AntreaNodeConfigAgentStatus) {
			n.UID = "new-node"
		}, wantStatus: metav1.ConditionUnknown, wantReason: "AgentUnavailable"},
		{name: "expired heartbeat", change: func(_ *crdv1alpha1.AntreaNodeConfig, _ *corev1.Node, r *crdv1beta1.AntreaNodeConfigAgentStatus) {
			r.LastHeartbeatTime = metav1.NewTime(now.Add(-4 * time.Minute))
		}, wantStatus: metav1.ConditionUnknown, wantReason: "AgentUnavailable"},
		{name: "future heartbeat", change: func(_ *crdv1alpha1.AntreaNodeConfig, _ *corev1.Node, r *crdv1beta1.AntreaNodeConfigAgentStatus) {
			r.LastHeartbeatTime = metav1.NewTime(now.Add(2 * time.Minute))
		}, wantStatus: metav1.ConditionUnknown, wantReason: "AgentUnavailable"},
		{name: "no heartbeat", change: func(_ *crdv1alpha1.AntreaNodeConfig, _ *corev1.Node, r *crdv1beta1.AntreaNodeConfigAgentStatus) {
			r.LastHeartbeatTime = metav1.Time{}
		}, wantStatus: metav1.ConditionUnknown, wantReason: "AgentUnavailable"},
		{name: "node offline", change: func(_ *crdv1alpha1.AntreaNodeConfig, n *corev1.Node, _ *crdv1beta1.AntreaNodeConfigAgentStatus) {
			n.Status.Conditions[0].Status = corev1.ConditionFalse
		}, wantStatus: metav1.ConditionUnknown, wantReason: "AgentUnavailable"},
		{name: "node readiness unknown", change: func(_ *crdv1alpha1.AntreaNodeConfig, n *corev1.Node, _ *crdv1beta1.AntreaNodeConfigAgentStatus) {
			n.Status.Conditions = nil
		}, wantStatus: metav1.ConditionUnknown, wantReason: "AgentUnavailable"},
		{name: "draining", change: func(_ *crdv1alpha1.AntreaNodeConfig, _ *corev1.Node, r *crdv1beta1.AntreaNodeConfigAgentStatus) {
			r.SecondaryNetwork.Conditions[0].Status, r.SecondaryNetwork.Conditions[0].Reason = metav1.ConditionFalse, "BridgeInUse"
			r.SecondaryNetwork.Conditions[0].Message = "bridge br-old still serves a Pod"
		}, wantStatus: metav1.ConditionFalse, wantReason: "BridgeInUse", wantMessage: "Node node: bridge br-old still serves a Pod"},
		{name: "static override", change: func(_ *crdv1alpha1.AntreaNodeConfig, _ *corev1.Node, r *crdv1beta1.AntreaNodeConfigAgentStatus) {
			r.SecondaryNetwork.Conditions[0].Status, r.SecondaryNetwork.Conditions[0].Reason = metav1.ConditionFalse, "OverriddenByStaticConfig"
			r.SecondaryNetwork.Conditions[0].Message = "static bridge br-local failed to initialize"
		}, wantStatus: metav1.ConditionFalse, wantReason: "OverriddenByStaticConfig", wantMessage: "Node node: static bridge br-local failed to initialize"},
		{name: "missing secondary network status", change: func(_ *crdv1alpha1.AntreaNodeConfig, _ *corev1.Node, r *crdv1beta1.AntreaNodeConfigAgentStatus) {
			r.SecondaryNetwork = nil
		}, wantStatus: metav1.ConditionUnknown, wantReason: "ConfigurationUnavailable"},
		{name: "missing ready condition", change: func(_ *crdv1alpha1.AntreaNodeConfig, _ *corev1.Node, r *crdv1beta1.AntreaNodeConfigAgentStatus) {
			r.SecondaryNetwork.Conditions = []metav1.Condition{{Type: "Other", Status: metav1.ConditionTrue, Reason: "OtherReady"}}
		}, wantStatus: metav1.ConditionUnknown, wantReason: "ConfigurationUnavailable"},
		{name: "future ready condition", change: func(_ *crdv1alpha1.AntreaNodeConfig, _ *corev1.Node, r *crdv1beta1.AntreaNodeConfigAgentStatus) {
			r.SecondaryNetwork.Conditions[0].ObservedGeneration++
		}, wantStatus: metav1.ConditionFalse, wantReason: "GenerationNotObserved"},
		{name: "zero generation", change: func(c *crdv1alpha1.AntreaNodeConfig, _ *corev1.Node, r *crdv1beta1.AntreaNodeConfigAgentStatus) {
			c.Generation, r.SecondaryNetwork.Conditions[0].ObservedGeneration = 0, 0
		}, wantStatus: metav1.ConditionFalse, wantReason: "GenerationNotObserved"},
		{name: "disabled", change: func(_ *crdv1alpha1.AntreaNodeConfig, _ *corev1.Node, r *crdv1beta1.AntreaNodeConfigAgentStatus) {
			r.ConfigName, r.ConfigUID = "", ""
			r.SecondaryNetwork.Conditions[0].Status, r.SecondaryNetwork.Conditions[0].Reason, r.SecondaryNetwork.Conditions[0].ObservedGeneration = metav1.ConditionFalse, "FeatureDisabled", 0
		}, wantStatus: metav1.ConditionFalse, wantReason: "FeatureDisabled"},
		{name: "stale disabled", change: func(_ *crdv1alpha1.AntreaNodeConfig, _ *corev1.Node, r *crdv1beta1.AntreaNodeConfigAgentStatus) {
			r.ConfigName, r.ConfigUID = "", ""
			r.SecondaryNetwork.Conditions[0].Status, r.SecondaryNetwork.Conditions[0].Reason, r.SecondaryNetwork.Conditions[0].ObservedGeneration = metav1.ConditionFalse, "FeatureDisabled", 0
			r.LastHeartbeatTime = metav1.NewTime(now.Add(-4 * time.Minute))
		}, wantStatus: metav1.ConditionUnknown, wantReason: "AgentUnavailable"},
		{name: "disabled wrong node", change: func(_ *crdv1alpha1.AntreaNodeConfig, _ *corev1.Node, r *crdv1beta1.AntreaNodeConfigAgentStatus) {
			r.ConfigName, r.ConfigUID = "", ""
			r.SecondaryNetwork.Conditions[0].Status, r.SecondaryNetwork.Conditions[0].Reason, r.SecondaryNetwork.Conditions[0].ObservedGeneration = metav1.ConditionFalse, "FeatureDisabled", 0
			r.NodeUID = "old-node"
		}, wantStatus: metav1.ConditionUnknown, wantReason: "AgentUnavailable"},
		{name: "windows with unsupported report", change: func(_ *crdv1alpha1.AntreaNodeConfig, n *corev1.Node, r *crdv1beta1.AntreaNodeConfigAgentStatus) {
			n.Labels[corev1.LabelOSStable] = "windows"
			r.ConfigName, r.ConfigUID = "", ""
			r.SecondaryNetwork.Conditions[0].Status, r.SecondaryNetwork.Conditions[0].Reason, r.SecondaryNetwork.Conditions[0].ObservedGeneration = metav1.ConditionFalse, "UnsupportedNode", 0
		}, wantStatus: metav1.ConditionFalse, wantReason: "UnsupportedNode"},
		{name: "windows without report", missing: true, change: func(_ *crdv1alpha1.AntreaNodeConfig, n *corev1.Node, _ *crdv1beta1.AntreaNodeConfigAgentStatus) {
			n.Labels[corev1.LabelOSStable] = "windows"
		}, wantStatus: metav1.ConditionUnknown, wantReason: "AgentUnavailable"},
		{name: "configuration unavailable", change: func(_ *crdv1alpha1.AntreaNodeConfig, _ *corev1.Node, r *crdv1beta1.AntreaNodeConfigAgentStatus) {
			r.ConfigName, r.ConfigUID = "", ""
			r.SecondaryNetwork.Conditions[0].Status, r.SecondaryNetwork.Conditions[0].Reason, r.SecondaryNetwork.Conditions[0].ObservedGeneration = metav1.ConditionUnknown, "ConfigurationUnavailable", 0
		}, wantStatus: metav1.ConditionUnknown, wantReason: "ConfigurationUnavailable"},
		{name: "known configuration unavailable", change: func(_ *crdv1alpha1.AntreaNodeConfig, _ *corev1.Node, r *crdv1beta1.AntreaNodeConfigAgentStatus) {
			r.SecondaryNetwork.Conditions[0].Status, r.SecondaryNetwork.Conditions[0].Reason, r.SecondaryNetwork.Conditions[0].ObservedGeneration = metav1.ConditionUnknown, "ConfigurationUnavailable", 0
		}, wantStatus: metav1.ConditionUnknown, wantReason: "ConfigurationUnavailable"},
		{name: "obsolete configuration placeholder", change: func(_ *crdv1alpha1.AntreaNodeConfig, _ *corev1.Node, r *crdv1beta1.AntreaNodeConfigAgentStatus) {
			r.ConfigUID = "old-config"
			r.SecondaryNetwork.Conditions[0].Status, r.SecondaryNetwork.Conditions[0].Reason, r.SecondaryNetwork.Conditions[0].ObservedGeneration = metav1.ConditionUnknown, "ConfigurationUnavailable", 0
		}, wantStatus: metav1.ConditionFalse, wantReason: "GenerationNotObserved"},
		{name: "identity-free unsupported", change: func(_ *crdv1alpha1.AntreaNodeConfig, _ *corev1.Node, r *crdv1beta1.AntreaNodeConfigAgentStatus) {
			r.ConfigName, r.ConfigUID = "", ""
			r.SecondaryNetwork.Conditions[0].Status, r.SecondaryNetwork.Conditions[0].Reason, r.SecondaryNetwork.Conditions[0].ObservedGeneration = metav1.ConditionFalse, "UnsupportedNode", 0
		}, wantStatus: metav1.ConditionFalse, wantReason: "UnsupportedNode"},
		{name: "stale identity-free unsupported", change: func(_ *crdv1alpha1.AntreaNodeConfig, _ *corev1.Node, r *crdv1beta1.AntreaNodeConfigAgentStatus) {
			r.ConfigName, r.ConfigUID = "", ""
			r.SecondaryNetwork.Conditions[0].Status, r.SecondaryNetwork.Conditions[0].Reason, r.SecondaryNetwork.Conditions[0].ObservedGeneration = metav1.ConditionFalse, "UnsupportedNode", 0
			r.LastHeartbeatTime = metav1.NewTime(now.Add(-4 * time.Minute))
		}, wantStatus: metav1.ConditionUnknown, wantReason: "AgentUnavailable"},
		{name: "windows wrong node identity", change: func(_ *crdv1alpha1.AntreaNodeConfig, n *corev1.Node, r *crdv1beta1.AntreaNodeConfigAgentStatus) {
			n.Labels[corev1.LabelOSStable] = "windows"
			r.ConfigName, r.ConfigUID = "", ""
			r.SecondaryNetwork.Conditions[0].Status, r.SecondaryNetwork.Conditions[0].Reason, r.SecondaryNetwork.Conditions[0].ObservedGeneration = metav1.ConditionFalse, "UnsupportedNode", 0
			r.NodeUID = "previous-node"
		}, wantStatus: metav1.ConditionUnknown, wantReason: "AgentUnavailable"},
		{name: "identity-free custom failure is not trusted", change: func(_ *crdv1alpha1.AntreaNodeConfig, _ *corev1.Node, r *crdv1beta1.AntreaNodeConfigAgentStatus) {
			r.ConfigName, r.ConfigUID = "", ""
			r.SecondaryNetwork.Conditions[0].Status, r.SecondaryNetwork.Conditions[0].Reason, r.SecondaryNetwork.Conditions[0].ObservedGeneration = metav1.ConditionFalse, "BridgeInUse", 0
		}, wantStatus: metav1.ConditionFalse, wantReason: "GenerationNotObserved"},
		{name: "disabled with obsolete configuration identity", change: func(_ *crdv1alpha1.AntreaNodeConfig, _ *corev1.Node, r *crdv1beta1.AntreaNodeConfigAgentStatus) {
			r.ConfigUID = "previous-config"
			r.SecondaryNetwork.Conditions[0].Status, r.SecondaryNetwork.Conditions[0].Reason, r.SecondaryNetwork.Conditions[0].ObservedGeneration = metav1.ConditionFalse, "FeatureDisabled", 0
		}, wantStatus: metav1.ConditionFalse, wantReason: "GenerationNotObserved"},
		{name: "partially identified disabled report", change: func(_ *crdv1alpha1.AntreaNodeConfig, _ *corev1.Node, r *crdv1beta1.AntreaNodeConfigAgentStatus) {
			r.ConfigUID = ""
			r.SecondaryNetwork.Conditions[0].Status, r.SecondaryNetwork.Conditions[0].Reason, r.SecondaryNetwork.Conditions[0].ObservedGeneration = metav1.ConditionFalse, "FeatureDisabled", 0
		}, wantStatus: metav1.ConditionFalse, wantReason: "GenerationNotObserved"},
		{name: "identity-free ready with current generation", change: func(_ *crdv1alpha1.AntreaNodeConfig, _ *corev1.Node, r *crdv1beta1.AntreaNodeConfigAgentStatus) {
			r.ConfigName, r.ConfigUID = "", ""
		}, wantStatus: metav1.ConditionFalse, wantReason: "GenerationNotObserved"},
		{name: "old failure condition", change: func(_ *crdv1alpha1.AntreaNodeConfig, _ *corev1.Node, r *crdv1beta1.AntreaNodeConfigAgentStatus) {
			r.SecondaryNetwork.Conditions[0].ObservedGeneration--
			r.SecondaryNetwork.Conditions[0].Status, r.SecondaryNetwork.Conditions[0].Reason = metav1.ConditionFalse, "BridgeInUse"
		}, wantStatus: metav1.ConditionFalse, wantReason: "GenerationNotObserved"},
		{name: "identity-free ready is not realized", change: func(_ *crdv1alpha1.AntreaNodeConfig, _ *corev1.Node, r *crdv1beta1.AntreaNodeConfigAgentStatus) {
			r.ConfigName, r.ConfigUID = "", ""
			r.SecondaryNetwork.Conditions[0].ObservedGeneration = 0
		}, wantStatus: metav1.ConditionFalse, wantReason: "GenerationNotObserved"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg, node, report := statusFixture(now)
			if tt.change != nil {
				tt.change(cfg, node, report)
			}
			nodes := []*corev1.Node{node}
			selected := k8s.SelectAntreaNodeConfigs(nodes, []*crdv1alpha1.AntreaNodeConfig{cfg})
			reports := map[string]*crdv1beta1.AntreaNodeConfigAgentStatus{node.Name: report}
			if tt.missing {
				delete(reports, node.Name)
			}
			status := calculateStatus(cfg, selected, nodes, reports, now)
			ready := meta.FindStatusCondition(status.Conditions, "Ready")
			require.NotNil(t, ready)
			assert.Equal(t, tt.wantStatus, ready.Status)
			assert.Equal(t, tt.wantReason, ready.Reason)
			if tt.wantMessage != "" {
				assert.Equal(t, tt.wantMessage, ready.Message)
			}
			assert.Equal(t, cfg.Generation, ready.ObservedGeneration)
			assert.Equal(t, cfg.Generation, status.ObservedGeneration)
			assert.Equal(t, int32(1), status.DesiredNodes)
			assert.Equal(t, tt.realized, status.RealizedNodes)
			assert.True(t, meta.IsStatusConditionTrue(status.Conditions, "ConflictFree"))
			cfg.Status = status
			assert.Equal(t, status, calculateStatus(cfg, selected, nodes, reports, now.Add(time.Second)), "Unchanged observations must preserve condition transition times")
		})
	}
}

func TestCurrentMembershipAndPrecedence(t *testing.T) {
	now := time.Now()
	cfg, node, report := statusFixture(now)
	shadowed := node.DeepCopy()
	shadowed.Name, shadowed.UID = "shadowed", "shadowed-uid"
	shadowed.Labels = map[string]string{"pool": "one", "older": "true"}
	older := cfg.DeepCopy()
	older.Name, older.UID = "older", "older-uid"
	older.CreationTimestamp = metav1.NewTime(now.Add(-time.Hour))
	older.Spec.NodeSelector.MatchLabels = map[string]string{"older": "true"}
	unrelated := node.DeepCopy()
	unrelated.Name, unrelated.UID, unrelated.Labels = "unrelated", "unrelated-uid", map[string]string{"pool": "other"}
	nodes := []*corev1.Node{node, shadowed, unrelated}
	configs := []*crdv1alpha1.AntreaNodeConfig{cfg, older}
	reports := map[string]*crdv1beta1.AntreaNodeConfigAgentStatus{node.Name: report}
	status := calculateStatus(cfg, k8s.SelectAntreaNodeConfigs(nodes, configs), nodes, reports, now)
	assert.Equal(t, int32(1), status.DesiredNodes, "Only effective current members form the denominator")
	assert.Equal(t, int32(1), status.RealizedNodes)
	assert.True(t, meta.IsStatusConditionTrue(status.Conditions, "Ready"))
	assert.True(t, meta.IsStatusConditionFalse(status.Conditions, "ConflictFree"))
	assert.Contains(t, meta.FindStatusCondition(status.Conditions, "ConflictFree").Message, "1 matching Nodes")
	cfg.Status = status
	node.Labels = map[string]string{"pool": "other"}
	status = calculateStatus(cfg, k8s.SelectAntreaNodeConfigs(nodes, configs), nodes, reports, now)
	assert.Zero(t, status.DesiredNodes)
	assert.Zero(t, status.RealizedNodes)
	assert.Equal(t, "ConfigurationNotSelected", meta.FindStatusCondition(status.Conditions, "Ready").Reason)
	assert.True(t, meta.IsStatusConditionFalse(status.Conditions, "ConflictFree"))
	shadowed.Labels = map[string]string{"pool": "other"}
	status = calculateStatus(cfg, k8s.SelectAntreaNodeConfigs(nodes, configs), nodes, reports, now)
	assert.Equal(t, "NoMatchingNodes", meta.FindStatusCondition(status.Conditions, "Ready").Reason)
	assert.True(t, meta.IsStatusConditionTrue(status.Conditions, "ConflictFree"))
	status = calculateStatus(cfg, nil, nil, reports, now)
	assert.Zero(t, status.DesiredNodes, "Removed Nodes do not remain in the denominator")
	assert.Zero(t, status.RealizedNodes)
}

func TestInvalidSelector(t *testing.T) {
	now := time.Now()
	cfg, node, report := statusFixture(now)
	cfg.Spec.NodeSelector.MatchExpressions = []metav1.LabelSelectorRequirement{{Key: "key", Operator: metav1.LabelSelectorOpIn}}
	nodes := []*corev1.Node{node}
	status := calculateStatus(cfg, k8s.SelectAntreaNodeConfigs(nodes, []*crdv1alpha1.AntreaNodeConfig{cfg}), nodes, map[string]*crdv1beta1.AntreaNodeConfigAgentStatus{node.Name: report}, now)
	assert.Zero(t, status.DesiredNodes)
	assert.True(t, meta.IsStatusConditionFalse(status.Conditions, "Ready"))
	assert.Equal(t, "InvalidNodeSelector", meta.FindStatusCondition(status.Conditions, "Ready").Reason)
	assert.Equal(t, metav1.ConditionUnknown, meta.FindStatusCondition(status.Conditions, "ConflictFree").Status)
}

func TestRetainedEmptyConfiguration(t *testing.T) {
	now := time.Now()
	cfg, node, report := statusFixture(now)
	cfg.Spec.SecondaryNetwork = &crdv1alpha1.SecondaryNetworkConfig{}
	cfg.Generation++
	nodes := []*corev1.Node{node}
	selected := k8s.SelectAntreaNodeConfigs(nodes, []*crdv1alpha1.AntreaNodeConfig{cfg})
	reports := map[string]*crdv1beta1.AntreaNodeConfigAgentStatus{node.Name: report}
	status := calculateStatus(cfg, selected, nodes, reports, now)
	assert.Equal(t, "GenerationNotObserved", meta.FindStatusCondition(status.Conditions, "Ready").Reason)
	report.SecondaryNetwork.Conditions[0].ObservedGeneration = cfg.Generation
	report.SecondaryNetwork.Conditions[0].Status, report.SecondaryNetwork.Conditions[0].Reason = metav1.ConditionFalse, "BridgeInUse"
	report.SecondaryNetwork.CurrentBridge = "br-old"
	status = calculateStatus(cfg, selected, nodes, reports, now)
	assert.Equal(t, "BridgeInUse", meta.FindStatusCondition(status.Conditions, "Ready").Reason)
	assert.Zero(t, status.RealizedNodes)
	report.SecondaryNetwork.Conditions[0].Status, report.SecondaryNetwork.Conditions[0].Reason = metav1.ConditionTrue, "Reconciled"
	report.SecondaryNetwork.CurrentBridge = ""
	status = calculateStatus(cfg, selected, nodes, reports, now)
	assert.Equal(t, int32(1), status.DesiredNodes)
	assert.Equal(t, int32(1), status.RealizedNodes)
	assert.True(t, meta.IsStatusConditionTrue(status.Conditions, "Ready"))
}

func TestDeterministicRepresentative(t *testing.T) {
	now := time.Now()
	cfg, base, report := statusFixture(now)
	var nodes []*corev1.Node
	reports := make(map[string]*crdv1beta1.AntreaNodeConfigAgentStatus)
	for i, name := range []string{"a-unknown", "b-draining", "c-failed", "d-ready"} {
		node := base.DeepCopy()
		node.Name, node.UID = name, types.UID(name)
		nodes = append(nodes, node)
		if i == 0 {
			continue
		}
		r := report.DeepCopy()
		r.NodeUID = node.UID
		if i < 3 {
			r.SecondaryNetwork.Conditions[0].Status = metav1.ConditionFalse
			r.SecondaryNetwork.Conditions[0].Reason = "BridgeInUse"
			if i == 2 {
				r.SecondaryNetwork.Conditions[0].Reason = "ReconcileFailed"
			}
			r.SecondaryNetwork.Conditions[0].Message = strings.Repeat("bridge error ", 100)
		}
		reports[name] = r
	}
	selected := k8s.SelectAntreaNodeConfigs(nodes, []*crdv1alpha1.AntreaNodeConfig{cfg})
	expected := calculateStatus(cfg, selected, nodes, reports, now)
	assert.Equal(t, int32(4), expected.DesiredNodes)
	assert.Equal(t, int32(1), expected.RealizedNodes)
	ready := meta.FindStatusCondition(expected.Conditions, "Ready")
	assert.Equal(t, "BridgeInUse", ready.Reason, "False outranks Unknown, then the first Node by name supplies the reason")
	assert.True(t, strings.HasPrefix(ready.Message, "Node b-draining:"))
	assert.LessOrEqual(t, len(ready.Message), maxNodeMessageLength)
	for range len(nodes) {
		assert.Equal(t, expected, calculateStatus(cfg, selected, nodes, reports, now))
		slices.Reverse(nodes)
		assert.Equal(t, expected, calculateStatus(cfg, selected, nodes, reports, now))
		slices.Reverse(nodes)
		nodes = append(nodes[1:], nodes[0])
	}
}

func TestStatusSizeWithFiveThousandNodes(t *testing.T) {
	now := time.Now()
	cfg, node, _ := statusFixture(now)
	cfg.Status.Conditions = []metav1.Condition{{Type: "Obsolete", Status: metav1.ConditionTrue, Reason: "OldStatus", Message: strings.Repeat("old status ", 1000)}}
	nodes := make([]*corev1.Node, 5000)
	for i := range nodes {
		n := node.DeepCopy()
		n.Name, n.UID = fmt.Sprintf("node-%04d", i), types.UID(fmt.Sprintf("uid-%04d", i))
		nodes[i] = n
	}
	selected := k8s.SelectAntreaNodeConfigs(nodes, []*crdv1alpha1.AntreaNodeConfig{cfg})
	status := calculateStatus(cfg, selected, nodes, nil, now)
	assert.Equal(t, int32(5000), status.DesiredNodes)
	assert.Zero(t, status.RealizedNodes)
	require.Len(t, status.Conditions, 2)
	encoded, err := json.Marshal(status)
	require.NoError(t, err)
	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(encoded, &fields))
	assert.ElementsMatch(t, []string{"observedGeneration", "desiredNodes", "realizedNodes", "conditions"}, slices.Collect(maps.Keys(fields)))
	one, err := json.Marshal(calculateStatus(cfg, selected, nodes[:1], nil, now))
	require.NoError(t, err)
	assert.Equal(t, len(one)+3, len(encoded), "Status grows only by the decimal digits of the count")
}

func TestStatusControllerUsesOnlyStatusWrites(t *testing.T) {
	now := time.Now()
	cfg, node, report := statusFixture(now)
	cfg.Finalizers = []string{"example.com/unrelated"}
	original := cfg.DeepCopy()
	info := &crdv1beta1.AntreaAgentInfo{ObjectMeta: metav1.ObjectMeta{Name: node.Name}, NodeConfigStatus: report}
	client := fakeclient.NewSimpleClientset(cfg, info)
	coreClient := k8sfake.NewSimpleClientset(node)
	factory := crdinformers.NewSharedInformerFactory(client, 0)
	kfactory := informers.NewSharedInformerFactory(coreClient, 0)
	ancInformer, infoInformer, nodeInformer := factory.Crd().V1alpha1().AntreaNodeConfigs(), factory.Crd().V1beta1().AntreaAgentInfos(), kfactory.Core().V1().Nodes()
	c := NewStatusController(client, ancInformer, infoInformer, nodeInformer)
	t.Cleanup(c.queue.ShutDown)
	require.NoError(t, ancInformer.Informer().GetStore().Add(cfg))
	require.NoError(t, infoInformer.Informer().GetStore().Add(info))
	require.NoError(t, nodeInformer.Informer().GetStore().Add(node))
	client.PrependReactor("*", "*", func(action cgtesting.Action) (bool, runtime.Object, error) {
		if action.GetVerb() != "update" || action.GetSubresource() != "status" {
			return true, nil, fmt.Errorf("unexpected API operation %s %s", action.GetVerb(), action.GetResource().Resource)
		}
		return false, nil, nil
	})
	require.NoError(t, c.syncStatus(context.Background(), cfg.Name))
	require.Len(t, client.Actions(), 1)
	updated := client.Actions()[0].(cgtesting.UpdateAction).GetObject().(*crdv1alpha1.AntreaNodeConfig)
	assert.Equal(t, original.ObjectMeta, updated.ObjectMeta, "Status observation must not mutate metadata or add finalizers")
	assert.True(t, meta.IsStatusConditionTrue(updated.Status.Conditions, "Ready"))
	require.NoError(t, ancInformer.Informer().GetStore().Update(updated))
	require.NoError(t, c.syncStatus(context.Background(), cfg.Name))
	require.Len(t, client.Actions(), 1, "An unchanged summary must not be written")
	require.NoError(t, infoInformer.Informer().GetStore().Delete(info))
	require.NoError(t, c.syncStatus(context.Background(), cfg.Name))
	require.Len(t, client.Actions(), 2)
	updated = client.Actions()[1].(cgtesting.UpdateAction).GetObject().(*crdv1alpha1.AntreaNodeConfig)
	assert.Equal(t, metav1.ConditionUnknown, meta.FindStatusCondition(updated.Status.Conditions, "Ready").Status)
	assert.Equal(t, original.ObjectMeta, cfg.ObjectMeta, "Cached objects must remain immutable")
	assert.Empty(t, coreClient.Actions(), "Aggregation must not read Nodes from the live API")
}

func TestReportHeartbeatFiltering(t *testing.T) {
	now := time.Now()
	_, _, before := statusFixture(now)
	after := before.DeepCopy()
	after.LastHeartbeatTime = metav1.NewTime(now.Add(time.Minute))
	assert.False(t, reportNeedsSync(before, after, now.Add(time.Minute)))
	after.SecondaryNetwork.Conditions[0].Reason = "BridgeInUse"
	assert.True(t, reportNeedsSync(before, after, now.Add(time.Minute)))
	for _, tt := range []struct {
		name   string
		change func(*crdv1beta1.AntreaNodeConfigAgentStatus)
	}{
		{name: "feature omitted", change: func(r *crdv1beta1.AntreaNodeConfigAgentStatus) { r.SecondaryNetwork = nil }},
		{name: "ready omitted", change: func(r *crdv1beta1.AntreaNodeConfigAgentStatus) { r.SecondaryNetwork.Conditions = nil }},
		{name: "feature generation", change: func(r *crdv1beta1.AntreaNodeConfigAgentStatus) { r.SecondaryNetwork.Conditions[0].ObservedGeneration++ }},
		{name: "current bridge", change: func(r *crdv1beta1.AntreaNodeConfigAgentStatus) { r.SecondaryNetwork.CurrentBridge = "br-new" }},
		{name: "desired bridge", change: func(r *crdv1beta1.AntreaNodeConfigAgentStatus) { r.SecondaryNetwork.DesiredBridge = "br-new" }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			changed := before.DeepCopy()
			tt.change(changed)
			assert.True(t, reportNeedsSync(before, changed, now), "Feature changes must promptly refresh the summary")
			assert.Equal(t, "Reconciled", before.SecondaryNetwork.Conditions[0].Reason)
		})
	}
	after = before.DeepCopy()
	before.LastHeartbeatTime = metav1.NewTime(now.Add(-4 * time.Minute))
	assert.True(t, reportNeedsSync(before, after, now), "Recovery from a stale report must refresh readiness promptly")
	assert.True(t, reportNeedsSync(before, nil, now))
	assert.True(t, reportNeedsSync(nil, after, now))
	assert.False(t, reportNeedsSync(nil, nil, now))
}

func TestStatusControllerShutdownCancelsRequests(t *testing.T) {
	started := make(chan string, 1)
	canceled := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Errorf("Read update request: %v", err)
			return
		}
		started <- r.Method + " " + r.URL.Path
		<-r.Context().Done()
		canceled <- struct{}{}
	}))
	t.Cleanup(server.Close)
	t.Cleanup(server.CloseClientConnections)
	client, err := clientset.NewForConfig(&rest.Config{Host: server.URL})
	require.NoError(t, err)
	cfg, _, _ := statusFixture(time.Now())
	factory := crdinformers.NewSharedInformerFactory(fakeclient.NewSimpleClientset(), 0)
	kfactory := informers.NewSharedInformerFactory(k8sfake.NewSimpleClientset(), 0)
	ancInformer := factory.Crd().V1alpha1().AntreaNodeConfigs()
	c := NewStatusController(client, ancInformer, factory.Crd().V1beta1().AntreaAgentInfos(), kfactory.Core().V1().Nodes())
	require.NoError(t, ancInformer.Informer().GetStore().Add(cfg))
	c.synced = []cache.InformerSynced{func() bool { return true }}
	stopCh := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-stopCh:
		default:
			close(stopCh)
		}
	})
	done := make(chan struct{})
	go func() { c.Run(stopCh); close(done) }()
	select {
	case request := <-started:
		assert.Equal(t, "PUT /apis/crd.antrea.io/v1alpha1/antreanodeconfigs/"+cfg.Name+"/status", request)
	case <-time.After(5 * time.Second):
		t.Fatal("Controller did not start the status request")
	}
	close(stopCh)
	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("Controller shutdown did not cancel the in-flight status request")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Controller did not stop")
	}
	assert.Zero(t, c.queue.NumRequeues(cfg.Name), "Shutdown must not retry canceled requests")
}

func TestAgentInfoEventsRouteCurrentMembership(t *testing.T) {
	for _, tt := range []struct {
		name      string
		initial   bool
		nilBefore bool
		remove    bool
		nilAfter  bool
		newName   string
	}{
		{name: "add missing report", nilAfter: true},
		{name: "add obsolete identity", newName: "obsolete"},
		{name: "clear report", initial: true, nilAfter: true},
		{name: "replace report", initial: true, newName: "replacement"},
		{name: "delete report", initial: true, remove: true},
		{name: "delete missing report", initial: true, nilBefore: true, remove: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg, node, report := statusFixture(time.Now())
			shadowed := cfg.DeepCopy()
			shadowed.Name, shadowed.UID = "shadowed", "shadowed-uid"
			shadowed.CreationTimestamp = metav1.NewTime(cfg.CreationTimestamp.Add(time.Hour))
			client := fakeclient.NewSimpleClientset()
			factory := crdinformers.NewSharedInformerFactory(client, 0)
			kfactory := informers.NewSharedInformerFactory(k8sfake.NewSimpleClientset(), 0)
			ancInformer, infoInformer, nodeInformer := factory.Crd().V1alpha1().AntreaNodeConfigs(), factory.Crd().V1beta1().AntreaAgentInfos(), kfactory.Core().V1().Nodes()
			c := NewStatusController(client, ancInformer, infoInformer, nodeInformer)
			t.Cleanup(c.queue.ShutDown)
			require.NoError(t, ancInformer.Informer().GetStore().Add(cfg))
			require.NoError(t, ancInformer.Informer().GetStore().Add(shadowed))
			require.NoError(t, nodeInformer.Informer().GetStore().Add(node))
			// Only the AgentInfo informer runs. There are no unrelated initial
			// Node or configuration events which could hide a routing failure.
			stop := make(chan struct{})
			t.Cleanup(func() { close(stop) })
			go infoInformer.Informer().Run(stop)
			require.True(t, cache.WaitForCacheSync(stop, infoInformer.Informer().HasSynced))
			info := &crdv1beta1.AntreaAgentInfo{ObjectMeta: metav1.ObjectMeta{Name: node.Name}, NodeConfigStatus: report.DeepCopy()}
			info.NodeConfigStatus.NodeUID = "previous-node-uid"
			info.NodeConfigStatus.ConfigName, info.NodeConfigStatus.ConfigUID = "previous", "previous-config-uid"
			if tt.initial {
				if tt.nilBefore {
					info.NodeConfigStatus = nil
				}
				_, err := client.CrdV1beta1().AntreaAgentInfos().Create(context.Background(), info, metav1.CreateOptions{})
				require.NoError(t, err)
				want := []string{cfg.Name, shadowed.Name}
				if !tt.nilBefore {
					want = append(want, "previous")
				}
				assertQueued(t, c, want)
			}
			want := []string{cfg.Name, shadowed.Name}
			if tt.remove {
				require.NoError(t, client.CrdV1beta1().AntreaAgentInfos().Delete(context.Background(), info.Name, metav1.DeleteOptions{}))
				if !tt.nilBefore {
					want = append(want, "previous")
				}
			} else {
				if tt.nilAfter {
					info.NodeConfigStatus = nil
				} else {
					info.NodeConfigStatus.ConfigName = tt.newName
					want = append(want, tt.newName)
				}
				if tt.initial {
					_, err := client.CrdV1beta1().AntreaAgentInfos().Update(context.Background(), info, metav1.UpdateOptions{})
					require.NoError(t, err)
					want = append(want, "previous")
				} else {
					_, err := client.CrdV1beta1().AntreaAgentInfos().Create(context.Background(), info, metav1.CreateOptions{})
					require.NoError(t, err)
				}
			}
			assertQueued(t, c, want)
		})
	}
}

func assertQueued(t *testing.T, c *StatusController, want []string) {
	t.Helper()
	require.Eventually(t, func() bool { return c.queue.Len() >= len(want) }, 5*time.Second, time.Millisecond,
		"Report event did not promptly enqueue current matching configurations")
	var got []string
	for c.queue.Len() > 0 {
		key, shutdown := c.queue.Get()
		require.False(t, shutdown)
		got = append(got, key)
		c.queue.Done(key)
	}
	assert.ElementsMatch(t, want, got)
}

func TestNodeEventsInvalidateCurrentMembership(t *testing.T) {
	cfg, node, _ := statusFixture(time.Now())
	other := cfg.DeepCopy()
	other.Name, other.UID = "other", "other-uid"
	other.Spec.NodeSelector.MatchLabels = map[string]string{"pool": "other"}
	client := fakeclient.NewSimpleClientset()
	coreClient := k8sfake.NewSimpleClientset()
	factory := crdinformers.NewSharedInformerFactory(client, 0)
	kfactory := informers.NewSharedInformerFactory(coreClient, 0)
	ancInformer, nodeInformer := factory.Crd().V1alpha1().AntreaNodeConfigs(), kfactory.Core().V1().Nodes()
	c := NewStatusController(client, ancInformer, factory.Crd().V1beta1().AntreaAgentInfos(), nodeInformer)
	t.Cleanup(c.queue.ShutDown)
	require.NoError(t, ancInformer.Informer().GetStore().Add(cfg))
	require.NoError(t, ancInformer.Informer().GetStore().Add(other))
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go nodeInformer.Informer().Run(stop)
	require.True(t, cache.WaitForCacheSync(stop, nodeInformer.Informer().HasSynced))
	_, err := coreClient.CoreV1().Nodes().Create(context.Background(), node, metav1.CreateOptions{})
	require.NoError(t, err)
	assertQueued(t, c, []string{cfg.Name, other.Name})
	version := c.selectionVersion.Load()
	node.Status.Conditions[0].Status = corev1.ConditionFalse
	_, err = coreClient.CoreV1().Nodes().Update(context.Background(), node, metav1.UpdateOptions{})
	require.NoError(t, err)
	assertQueued(t, c, []string{cfg.Name})
	assert.Equal(t, version, c.selectionVersion.Load(), "Node readiness must not invalidate selection")
	node.Labels["pool"] = "other"
	_, err = coreClient.CoreV1().Nodes().Update(context.Background(), node, metav1.UpdateOptions{})
	require.NoError(t, err)
	assertQueued(t, c, []string{cfg.Name, other.Name})
	assert.Greater(t, c.selectionVersion.Load(), version)
	version = c.selectionVersion.Load()
	require.NoError(t, coreClient.CoreV1().Nodes().Delete(context.Background(), node.Name, metav1.DeleteOptions{}))
	assertQueued(t, c, []string{cfg.Name, other.Name})
	assert.Greater(t, c.selectionVersion.Load(), version)
}
