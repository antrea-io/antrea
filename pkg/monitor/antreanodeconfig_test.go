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

package monitor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/yaml"

	"antrea.io/antrea/v2/pkg/agent/antreanodeconfig"
	crdv1alpha1 "antrea.io/antrea/v2/pkg/apis/crd/v1alpha1"
	"antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
	fakeclientset "antrea.io/antrea/v2/pkg/client/clientset/versioned/fake"
)

type testANCProvider struct {
	mu       sync.RWMutex
	snapshot *antreanodeconfig.Snapshot
	updates  chan struct{}
}

func (p *testANCProvider) GetAntreaNodeConfigSnapshot() *antreanodeconfig.Snapshot {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.snapshot.DeepCopy()
}
func (p *testANCProvider) AntreaNodeConfigSnapshotUpdates() <-chan struct{} { return p.updates }
func (p *testANCProvider) set(snapshot *antreanodeconfig.Snapshot) {
	p.mu.Lock()
	p.snapshot = snapshot
	p.mu.Unlock()
	p.updates <- struct{}{}
}

func currentANCSnapshot() *antreanodeconfig.Snapshot {
	return antreanodeconfig.NewSnapshot(&crdv1alpha1.AntreaNodeConfig{ObjectMeta: metav1.ObjectMeta{Name: "current-config", UID: "current-uid", Generation: 2}}, nil)
}

func TestAggregateFeatureConditions(t *testing.T) {
	for _, tt := range []struct {
		name     string
		features []metav1.Condition
		status   metav1.ConditionStatus
		reason   string
	}{
		{name: "no results", status: metav1.ConditionUnknown, reason: "WaitingForFeatureResults"},
		{name: "all ready", features: []metav1.Condition{{ObservedGeneration: 4, Status: metav1.ConditionTrue}, {ObservedGeneration: 4, Status: metav1.ConditionTrue}}, status: metav1.ConditionTrue, reason: "Reconciled"},
		{name: "current unknown", features: []metav1.Condition{{ObservedGeneration: 4, Status: metav1.ConditionUnknown}}, status: metav1.ConditionUnknown, reason: "WaitingForFeatureResults"},
		{name: "older success", features: []metav1.Condition{{ObservedGeneration: 4, Status: metav1.ConditionTrue}, {ObservedGeneration: 3, Status: metav1.ConditionTrue}}, status: metav1.ConditionUnknown, reason: "WaitingForFeatureResults"},
		{name: "older failure", features: []metav1.Condition{{ObservedGeneration: 4, Status: metav1.ConditionTrue}, {ObservedGeneration: 3, Status: metav1.ConditionFalse}}, status: metav1.ConditionUnknown, reason: "WaitingForFeatureResults"},
		{name: "failure beats unknown", features: []metav1.Condition{{ObservedGeneration: 4, Status: metav1.ConditionUnknown}, {ObservedGeneration: 4, Status: metav1.ConditionFalse, Message: "feature error"}}, status: metav1.ConditionFalse, reason: "FeaturesNotReady"},
		{name: "unknown does not hide failure", features: []metav1.Condition{{ObservedGeneration: 4, Status: metav1.ConditionFalse}, {ObservedGeneration: 4, Status: metav1.ConditionUnknown}}, status: metav1.ConditionFalse, reason: "FeaturesNotReady"},
		{name: "static override", features: []metav1.Condition{{ObservedGeneration: 4, Status: metav1.ConditionFalse, Reason: "OverriddenByStaticConfig"}, {ObservedGeneration: 4, Status: metav1.ConditionFalse}}, status: metav1.ConditionFalse, reason: "OverriddenByStaticConfig"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			condition := aggregateFeatureConditions(4, tt.features...)
			assert.Equal(t, tt.status, condition.Status)
			assert.Equal(t, tt.reason, condition.Reason)
			assert.Equal(t, int64(4), condition.ObservedGeneration)
			assert.Empty(t, condition.Message)
		})
	}
}

func TestAntreaNodeConfigPublication(t *testing.T) {
	for _, tt := range []struct {
		name          string
		change        func(*testANCProvider, *testSecondaryNetworkProvider, *corev1.Node)
		disabled      bool
		noTarget      bool
		status        metav1.ConditionStatus
		reason        string
		featureStatus metav1.ConditionStatus
	}{
		{name: "ready", status: metav1.ConditionTrue, reason: "Reconciled", featureStatus: metav1.ConditionTrue},
		{name: "reconcile failure", change: func(_ *testANCProvider, p *testSecondaryNetworkProvider, _ *corev1.Node) {
			p.report.Conditions[0].Status = metav1.ConditionFalse
			p.report.Conditions[0].Reason = "BridgeInUse"
			p.report.Conditions[0].Message = "old bridge still has Pods"
		}, status: metav1.ConditionFalse, reason: "FeaturesNotReady", featureStatus: metav1.ConditionFalse},
		{name: "old generation", change: func(_ *testANCProvider, p *testSecondaryNetworkProvider, _ *corev1.Node) {
			p.report.Conditions[0].ObservedGeneration--
		}, status: metav1.ConditionUnknown, reason: "WaitingForFeatureResults", featureStatus: metav1.ConditionUnknown},
		{name: "recreated ANC same generation", change: func(p *testANCProvider, _ *testSecondaryNetworkProvider, _ *corev1.Node) {
			p.snapshot.AntreaNodeConfig.UID = "new-uid"
		}, status: metav1.ConditionUnknown, reason: "WaitingForFeatureResults", featureStatus: metav1.ConditionUnknown},
		{name: "missing feature", change: func(_ *testANCProvider, p *testSecondaryNetworkProvider, _ *corev1.Node) { p.report = nil }, status: metav1.ConditionUnknown, reason: "WaitingForFeatureResults", featureStatus: metav1.ConditionUnknown},
		{name: "static success", change: func(_ *testANCProvider, p *testSecondaryNetworkProvider, _ *corev1.Node) {
			p.report.Source = v1beta1.SecondaryNetworkConfigSourceAgentConfig
			p.report.Conditions[0].ObservedGeneration = 0
		}, status: metav1.ConditionFalse, reason: "OverriddenByStaticConfig", featureStatus: metav1.ConditionTrue},
		{name: "static failure", change: func(_ *testANCProvider, p *testSecondaryNetworkProvider, _ *corev1.Node) {
			p.report.Source = v1beta1.SecondaryNetworkConfigSourceAgentConfig
			p.report.Conditions[0].ObservedGeneration = 0
			p.report.Conditions[0].Status = metav1.ConditionFalse
		}, status: metav1.ConditionFalse, reason: "OverriddenByStaticConfig", featureStatus: metav1.ConditionFalse},
		{name: "disabled", disabled: true, status: metav1.ConditionFalse, reason: "FeaturesNotReady", featureStatus: metav1.ConditionFalse},
		{name: "unsupported", change: func(_ *testANCProvider, _ *testSecondaryNetworkProvider, n *corev1.Node) {
			n.Labels = map[string]string{corev1.LabelOSStable: "windows"}
		}, status: metav1.ConditionFalse, reason: "FeaturesNotReady", featureStatus: metav1.ConditionFalse},
		{name: "ANC deleted", change: func(p *testANCProvider, _ *testSecondaryNetworkProvider, _ *corev1.Node) {
			p.snapshot = antreanodeconfig.NewSnapshot(nil, nil)
		}, noTarget: true, featureStatus: metav1.ConditionUnknown},
		{name: "snapshot unavailable", change: func(p *testANCProvider, _ *testSecondaryNetworkProvider, _ *corev1.Node) {
			p.snapshot = antreanodeconfig.NewSnapshot(nil, errors.New("list failed"))
		}, noTarget: true, featureStatus: metav1.ConditionUnknown},
	} {
		t.Run(tt.name, func(t *testing.T) {
			info := &v1beta1.AntreaAgentInfo{ObjectMeta: metav1.ObjectMeta{Name: "testAgentCRD"}}
			client := fakeclientset.NewSimpleClientset(info)
			monitor := newAgentMonitor(client, t)
			target := &testANCProvider{snapshot: currentANCSnapshot()}
			feature := &testSecondaryNetworkProvider{report: readySecondaryNetworkReport()}
			node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: info.Name, UID: "node-uid"}}
			if tt.change != nil {
				tt.change(target, feature, node)
			}
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			require.NoError(t, indexer.Add(node))
			monitor.querier = &testSecondaryNetworkQuerier{AgentQuerier: monitor.querier, nodeLister: corelisters.NewNodeLister(indexer)}
			monitor.SetAntreaNodeConfigSnapshotProvider(target)
			if !tt.disabled {
				monitor.SetSecondaryNetworkStatusProvider(feature)
			}
			original := feature.report.DeepCopy()
			monitor.syncAgentCRD(context.Background())
			published, err := client.CrdV1beta1().AntreaAgentInfos().Get(context.Background(), info.Name, metav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, original, feature.report, "Publication must not mutate feature results")
			require.NotNil(t, published.SecondaryNetwork)
			assert.Equal(t, tt.featureStatus, published.SecondaryNetwork.Conditions[0].Status)
			if tt.noTarget {
				assert.Nil(t, published.AntreaNodeConfig)
				return
			}
			require.NotNil(t, published.AntreaNodeConfig)
			assert.Equal(t, target.snapshot.AntreaNodeConfig.UID, published.AntreaNodeConfig.UID)
			ready := meta.FindStatusCondition(published.AntreaNodeConfig.Conditions, "Ready")
			require.NotNil(t, ready)
			assert.Equal(t, tt.status, ready.Status)
			assert.Equal(t, tt.reason, ready.Reason)
			assert.Equal(t, int64(2), ready.ObservedGeneration)
			assert.Empty(t, ready.Message)
			assert.False(t, ready.LastTransitionTime.IsZero())
			monitor.syncAgentCRD(context.Background())
			assert.Equal(t, ready.LastTransitionTime, monitor.agentCRD.AntreaNodeConfig.Conditions[0].LastTransitionTime)
			copy := published.DeepCopy()
			copy.AntreaNodeConfig.Conditions[0].Message = "changed"
			assert.Empty(t, published.AntreaNodeConfig.Conditions[0].Message)
		})
	}
}

func TestSelectionUpdatePublishesBeforeFeatureCompletion(t *testing.T) {
	info := &v1beta1.AntreaAgentInfo{ObjectMeta: metav1.ObjectMeta{Name: "testAgentCRD"}}
	client := fakeclientset.NewSimpleClientset(info)
	monitor := newAgentMonitor(client, t)
	target := &testANCProvider{snapshot: currentANCSnapshot(), updates: make(chan struct{}, 1)}
	monitor.SetAntreaNodeConfigSnapshotProvider(target)
	monitor.SetSecondaryNetworkStatusProvider(&testSecondaryNetworkProvider{report: readySecondaryNetworkReport()})
	stop, done := make(chan struct{}), make(chan struct{})
	go func() { defer close(done); monitor.Run(stop) }()
	defer func() { close(stop); <-done }()
	require.Eventually(t, func() bool {
		current, err := client.CrdV1beta1().AntreaAgentInfos().Get(context.Background(), info.Name, metav1.GetOptions{})
		return err == nil && current.AntreaNodeConfig != nil && meta.IsStatusConditionTrue(current.AntreaNodeConfig.Conditions, "Ready")
	}, time.Second, time.Millisecond)
	next := currentANCSnapshot()
	next.AntreaNodeConfig.UID = "new-uid"
	target.set(next)
	require.Eventually(t, func() bool {
		current, err := client.CrdV1beta1().AntreaAgentInfos().Get(context.Background(), info.Name, metav1.GetOptions{})
		return err == nil && current.AntreaNodeConfig != nil && current.AntreaNodeConfig.UID == "new-uid" &&
			meta.IsStatusConditionPresentAndEqual(current.AntreaNodeConfig.Conditions, "Ready", metav1.ConditionUnknown) &&
			meta.IsStatusConditionPresentAndEqual(current.SecondaryNetwork.Conditions, "Ready", metav1.ConditionUnknown)
	}, time.Second, time.Millisecond)
}

func TestAntreaNodeConfigSchema(t *testing.T) {
	data, err := os.ReadFile("../../build/charts/antrea/crds/antreaagentinfo.yaml")
	require.NoError(t, err)
	var crd apiextensionsv1.CustomResourceDefinition
	require.NoError(t, yaml.Unmarshal(data, &crd))
	var schema apiextensions.JSONSchemaProps
	require.NoError(t, apiextensionsv1.Convert_v1_JSONSchemaProps_To_apiextensions_JSONSchemaProps(crd.Spec.Versions[0].Schema.OpenAPIV3Schema, &schema, nil))
	validator, _, err := validation.NewSchemaValidator(&schema)
	require.NoError(t, err)
	info := &v1beta1.AntreaAgentInfo{AntreaNodeConfig: &v1beta1.AntreaNodeConfigStatus{Name: "config", UID: "uid", Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Reconciled", ObservedGeneration: 2, LastTransitionTime: metav1.Now()}}}}
	for _, message := range []string{"", "must remain in feature conditions"} {
		info.AntreaNodeConfig.Conditions[0].Message = message
		data, err := json.Marshal(info)
		require.NoError(t, err)
		var object map[string]interface{}
		require.NoError(t, json.Unmarshal(data, &object))
		errors := validation.ValidateCustomResource(field.NewPath(""), object, validator)
		if message == "" {
			assert.Empty(t, errors)
		} else {
			assert.NotEmpty(t, errors)
		}
	}
}

func TestReviewNodeRecreation(t *testing.T) {
	for _, tt := range []struct {
		name            string
		startupUID      types.UID
		publishBefore   bool
		rereadAgentInfo bool
	}{
		{name: "partial publication", startupUID: "node-uid", publishBefore: true},
		{name: "replacement before first publication", startupUID: "node-uid"},
		{name: "full publication after rereading another Agent report", startupUID: "node-uid", publishBefore: true, rereadAgentInfo: true},
		{name: "missing startup identity"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			info := &v1beta1.AntreaAgentInfo{ObjectMeta: metav1.ObjectMeta{Name: "testAgentCRD"}}
			client := fakeclientset.NewSimpleClientset(info)
			monitor := newAgentMonitor(client, t)
			monitor.querier.GetNodeConfig().UID = tt.startupUID
			node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: info.Name, UID: "node-uid"}}
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			require.NoError(t, indexer.Add(node))
			monitor.querier = &testSecondaryNetworkQuerier{AgentQuerier: monitor.querier, nodeLister: corelisters.NewNodeLister(indexer)}
			monitor.SetAntreaNodeConfigSnapshotProvider(&testANCProvider{snapshot: currentANCSnapshot()})
			monitor.SetSecondaryNetworkStatusProvider(&testSecondaryNetworkProvider{report: readySecondaryNetworkReport()})
			if tt.publishBefore {
				monitor.syncAgentCRD(ctx)
				first, err := client.CrdV1beta1().AntreaAgentInfos().Get(ctx, info.Name, metav1.GetOptions{})
				require.NoError(t, err)
				require.Equal(t, tt.startupUID, first.NodeRef.UID)
				require.True(t, meta.IsStatusConditionTrue(first.AntreaNodeConfig.Conditions, "Ready"))
			}

			replacement := node.DeepCopy()
			replacement.UID = "replacement-node"
			require.NoError(t, indexer.Update(replacement))
			if tt.rereadAgentInfo {
				published, err := client.CrdV1beta1().AntreaAgentInfos().Get(ctx, info.Name, metav1.GetOptions{})
				require.NoError(t, err)
				published.NodeRef.UID = replacement.UID
				_, err = client.CrdV1beta1().AntreaAgentInfos().Update(ctx, published, metav1.UpdateOptions{})
				require.NoError(t, err)
				monitor.agentCRD = nil
			}
			monitor.syncAgentCRD(ctx)
			published, err := client.CrdV1beta1().AntreaAgentInfos().Get(ctx, info.Name, metav1.GetOptions{})
			require.NoError(t, err)
			require.Equal(t, tt.startupUID, published.NodeRef.UID,
				"the original Agent must retain its startup Node identity")
			require.True(t, meta.IsStatusConditionTrue(published.AntreaNodeConfig.Conditions, "Ready"))

			replacementMonitor := newAgentMonitor(client, t)
			replacementMonitor.querier.GetNodeConfig().UID = replacement.UID
			replacementMonitor.querier = &testSecondaryNetworkQuerier{AgentQuerier: replacementMonitor.querier, nodeLister: corelisters.NewNodeLister(indexer)}
			replacementMonitor.SetAntreaNodeConfigSnapshotProvider(&testANCProvider{snapshot: currentANCSnapshot()})
			replacementMonitor.SetSecondaryNetworkStatusProvider(&testSecondaryNetworkProvider{report: readySecondaryNetworkReport()})
			replacementMonitor.syncAgentCRD(ctx)
			published, err = client.CrdV1beta1().AntreaAgentInfos().Get(ctx, info.Name, metav1.GetOptions{})
			require.NoError(t, err)
			require.Equal(t, replacement.UID, published.NodeRef.UID)
			require.True(t, meta.IsStatusConditionTrue(published.AntreaNodeConfig.Conditions, "Ready"))
		})
	}
}
