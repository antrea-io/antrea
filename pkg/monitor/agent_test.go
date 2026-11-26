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

package monitor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/kubernetes/fake"
	corelisters "k8s.io/client-go/listers/core/v1"
	cgtesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/yaml"

	"antrea.io/antrea/v2/pkg/agent/config"
	interfacestoretest "antrea.io/antrea/v2/pkg/agent/interfacestore/testing"
	openflowtest "antrea.io/antrea/v2/pkg/agent/openflow/testing"
	"antrea.io/antrea/v2/pkg/agent/querier"
	agenttypes "antrea.io/antrea/v2/pkg/agent/types"
	"antrea.io/antrea/v2/pkg/apis/crd/v1beta1"
	fakeclientset "antrea.io/antrea/v2/pkg/client/clientset/versioned/fake"
	binding "antrea.io/antrea/v2/pkg/ovs/openflow"
	ovsconfigtest "antrea.io/antrea/v2/pkg/ovs/ovsconfig/testing"
	queriertest "antrea.io/antrea/v2/pkg/querier/testing"
)

const ovsVersion = "2.10.0"

var fakeCertData = []byte("foobar")

func TestSyncAgentCRD(t *testing.T) {
	ctx := context.Background()
	crdName := "antrea-agent-foo"
	existingCRD := &v1beta1.AntreaAgentInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name: "testAgentCRD",
		},
		NetworkPolicyControllerInfo: v1beta1.NetworkPolicyControllerInfo{
			NetworkPolicyNum: 1,
		},
		APIPort: 0,
	}
	partiallyUpdatedCRD := &v1beta1.AntreaAgentInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name: crdName,
		},
		NetworkPolicyControllerInfo: v1beta1.NetworkPolicyControllerInfo{
			NetworkPolicyNum: 10,
		},
		APIPort: 0,
	}
	entirelyUpdatedCRD := &v1beta1.AntreaAgentInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name: crdName,
		},
		NetworkPolicyControllerInfo: v1beta1.NetworkPolicyControllerInfo{
			NetworkPolicyNum: 0,
		},
		APIPort:     10349,
		APICABundle: fakeCertData,
	}
	t.Run("partial update-success", func(t *testing.T) {
		clientset := fakeclientset.NewSimpleClientset(existingCRD)
		monitor := newAgentMonitor(clientset, t)
		monitor.agentCRD = existingCRD
		monitor.syncAgentCRD(context.Background())
		crd, err := monitor.client.CrdV1beta1().AntreaAgentInfos().Get(ctx, "testAgentCRD", metav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, partiallyUpdatedCRD.NetworkPolicyControllerInfo.NetworkPolicyNum, crd.NetworkPolicyControllerInfo.NetworkPolicyNum)
	})
	t.Run("partial update-failure", func(t *testing.T) {
		clientset := fakeclientset.NewSimpleClientset(existingCRD)
		clientset.PrependReactor("update", "antreaagentinfos", func(action cgtesting.Action) (handled bool, ret runtime.Object, err error) {
			return true, &v1beta1.AntreaAgentInfo{}, errors.New("error updating agent crd")
		})
		monitor := newAgentMonitor(clientset, t)
		monitor.agentCRD = existingCRD
		monitor.syncAgentCRD(context.Background())
		assert.Nil(t, monitor.agentCRD)
	})
	t.Run("get-failure", func(t *testing.T) {
		clientset := fakeclientset.NewSimpleClientset()
		clientset.PrependReactor("get", "antreaagentinfos", func(action cgtesting.Action) (handled bool, ret runtime.Object, err error) {
			return true, &v1beta1.AntreaAgentInfo{}, errors.New("error getting agent crd")
		})
		monitor := newAgentMonitor(clientset, t)
		monitor.agentCRD = existingCRD
		monitor.syncAgentCRD(context.Background())
		assert.Nil(t, monitor.agentCRD)
	})
	t.Run("entire update-success", func(t *testing.T) {
		clientset := fakeclientset.NewSimpleClientset(existingCRD)
		monitor := newAgentMonitor(clientset, t)
		monitor.syncAgentCRD(context.Background())
		crd, err := monitor.client.CrdV1beta1().AntreaAgentInfos().Get(ctx, "testAgentCRD", metav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, entirelyUpdatedCRD.APIPort, crd.APIPort)
		assert.Equal(t, entirelyUpdatedCRD.APICABundle, crd.APICABundle)
	})
	t.Run("entire update-failure", func(t *testing.T) {
		clientset := fakeclientset.NewSimpleClientset(existingCRD)
		clientset.PrependReactor("update", "antreaagentinfos", func(action cgtesting.Action) (handled bool, ret runtime.Object, err error) {
			return true, &v1beta1.AntreaAgentInfo{}, errors.New("error updating agent crd")
		})
		monitor := newAgentMonitor(clientset, t)
		monitor.syncAgentCRD(context.Background())
		assert.Nil(t, monitor.agentCRD)
	})
}

func newAgentMonitor(crdClient *fakeclientset.Clientset, t *testing.T) *agentMonitor {
	client := fake.NewSimpleClientset()
	ctrl := gomock.NewController(t)

	nodeConfig := &config.NodeConfig{
		UID:  "node-uid",
		Name: "testAgentCRD",
	}

	interfaceStore := interfacestoretest.NewMockInterfaceStore(ctrl)
	interfaceStore.EXPECT().GetContainerInterfaceNum().Return(2).AnyTimes()

	ofClient := openflowtest.NewMockClient(ctrl)
	ofClient.EXPECT().GetFlowTableStatus().Return([]binding.TableStatus{
		{
			ID:        1,
			Name:      "1",
			FlowCount: 2,
		},
	}).AnyTimes()
	ofClient.EXPECT().IsConnected().Return(true).AnyTimes()

	ovsBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(ctrl)
	ovsBridgeClient.EXPECT().GetOVSVersion().Return(ovsVersion, nil).AnyTimes()

	networkPolicyInfoQuerier := queriertest.NewMockAgentNetworkPolicyInfoQuerier(ctrl)
	networkPolicyInfoQuerier.EXPECT().GetNetworkPolicyNum().Return(10).AnyTimes()
	networkPolicyInfoQuerier.EXPECT().GetAppliedToGroupNum().Return(20).AnyTimes()
	networkPolicyInfoQuerier.EXPECT().GetAddressGroupNum().Return(30).AnyTimes()
	networkPolicyInfoQuerier.EXPECT().GetControllerConnectionStatus().Return(true).AnyTimes()

	querier := querier.NewAgentQuerier(nodeConfig, nil, interfaceStore, client, ofClient, ovsBridgeClient, nil, networkPolicyInfoQuerier, 10349, "", nil, nil, nil)

	return NewAgentMonitor(crdClient, querier, fakeCertData)
}

type testSecondaryNetworkProvider struct {
	report *v1beta1.SecondaryNetworkStatus
	uid    types.UID
}

func (p *testSecondaryNetworkProvider) GetSecondaryNetworkStatus() *agenttypes.SecondaryNetworkStatus {
	if p.report == nil {
		return nil
	}
	uid := p.uid
	if uid == "" {
		uid = "current-uid"
	}
	return &agenttypes.SecondaryNetworkStatus{SecondaryNetworkStatus: p.report, ConfigUID: uid}
}
func (p *testSecondaryNetworkProvider) SecondaryNetworkStatusUpdates() <-chan struct{} { return nil }

type testSecondaryNetworkQuerier struct {
	querier.AgentQuerier
	nodeLister corelisters.NodeLister
}

func (q *testSecondaryNetworkQuerier) GetNodeLister() corelisters.NodeLister { return q.nodeLister }

func TestSyncAgentSecondaryNetworkStatusSchema(t *testing.T) {
	data, err := os.ReadFile("../../build/charts/antrea/crds/antreaagentinfo.yaml")
	require.NoError(t, err)
	var crd apiextensionsv1.CustomResourceDefinition
	require.NoError(t, yaml.Unmarshal(data, &crd))
	var openAPISchema apiextensions.JSONSchemaProps
	require.NoError(t, apiextensionsv1.Convert_v1_JSONSchemaProps_To_apiextensions_JSONSchemaProps(
		crd.Spec.Versions[0].Schema.OpenAPIV3Schema, &openAPISchema, nil))
	_, exists := openAPISchema.Properties["secondaryNetwork"]
	require.True(t, exists)
	_, exists = openAPISchema.Properties["nodeConfigStatus"]
	require.False(t, exists)
	validator, _, err := validation.NewSchemaValidator(&openAPISchema)
	require.NoError(t, err)

	for _, tt := range []struct {
		name        string
		enabled     bool
		nilProvider bool
		windows     bool
		report      *v1beta1.SecondaryNetworkStatus
	}{
		{name: "feature disabled"},
		{name: "disabled ignores provider", report: readySecondaryNetworkReport()},
		{name: "enabled nil provider", enabled: true, nilProvider: true},
		{name: "enabled nil report", enabled: true},
		{name: "missing feature", enabled: true, report: &v1beta1.SecondaryNetworkStatus{ConfigSource: v1beta1.SecondaryNetworkConfigSourceAntreaNodeConfig}},
		{name: "nil conditions", enabled: true, report: &v1beta1.SecondaryNetworkStatus{}},
		{name: "empty conditions", enabled: true, report: &v1beta1.SecondaryNetworkStatus{Conditions: []metav1.Condition{}}},
		{name: "other condition without Ready", enabled: true, report: &v1beta1.SecondaryNetworkStatus{
			ConfigSource:  v1beta1.SecondaryNetworkConfigSourceAntreaNodeConfig,
			CurrentBridge: "br-unconfirmed",
			Conditions:    []metav1.Condition{{Type: "Other", Status: metav1.ConditionTrue, ObservedGeneration: 9}},
		}},
		{name: "Windows with disabled features", nilProvider: true, windows: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			previous := readySecondaryNetworkReport()
			old := &v1beta1.AntreaAgentInfo{ObjectMeta: metav1.ObjectMeta{Name: "testAgentCRD"}, SecondaryNetwork: previous}
			client := fakeclientset.NewSimpleClientset(old)
			monitor := newAgentMonitor(client, t)
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: old.Name, UID: "node-uid"}}
			if tt.windows {
				node.Labels = map[string]string{corev1.LabelOSStable: "windows"}
			}
			require.NoError(t, indexer.Add(node))
			monitor.querier = &testSecondaryNetworkQuerier{AgentQuerier: monitor.querier, nodeLister: corelisters.NewNodeLister(indexer)}
			if !tt.nilProvider {
				monitor.secondaryNetworkStatusProvider = &testSecondaryNetworkProvider{report: tt.report}
			}
			if tt.enabled {
				monitor.SetSecondaryNetworkStatusProvider(monitor.secondaryNetworkStatusProvider)
			}
			original := tt.report.DeepCopy()
			monitor.syncAgentCRD(context.Background())
			current, err := client.CrdV1beta1().AntreaAgentInfos().Get(context.Background(), old.Name, metav1.GetOptions{})
			require.NoError(t, err)
			report := current.SecondaryNetwork
			require.NotNil(t, report)
			require.Len(t, report.Conditions, 1)
			ready := report.Conditions[0]
			wantStatus, wantReason := metav1.ConditionUnknown, "ConfigurationUnavailable"
			if tt.windows {
				wantStatus, wantReason = metav1.ConditionFalse, "UnsupportedNode"
			} else if !tt.enabled {
				wantStatus, wantReason = metav1.ConditionFalse, "FeatureDisabled"
			}
			assert.Equal(t, string(v1beta1.SecondaryNetworkConditionReady), ready.Type)
			assert.Equal(t, wantStatus, ready.Status)
			assert.Equal(t, wantReason, ready.Reason)
			if tt.windows {
				assert.Equal(t, "Secondary network configuration is not supported on Windows Nodes", ready.Message)
			}
			assert.Zero(t, ready.ObservedGeneration)
			assert.Empty(t, report.CurrentBridge)
			assert.Empty(t, report.DesiredBridge)
			assert.EqualValues(t, "node-uid", current.NodeRef.UID)
			require.NotEmpty(t, current.AgentConditions)
			assert.False(t, current.AgentConditions[0].LastHeartbeatTime.IsZero())
			assert.False(t, ready.LastTransitionTime.IsZero())
			assert.Equal(t, original, tt.report, "Publication must not mutate the provider report")
			encoded, err := json.Marshal(current)
			require.NoError(t, err)
			var object map[string]interface{}
			require.NoError(t, json.Unmarshal(encoded, &object))
			assert.Empty(t, validation.ValidateCustomResource(field.NewPath(""), object, validator))
			monitor.syncAgentCRD(context.Background())
			current, err = client.CrdV1beta1().AntreaAgentInfos().Get(context.Background(), old.Name, metav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, ready.LastTransitionTime, current.SecondaryNetwork.Conditions[0].LastTransitionTime,
				"Heartbeat publication must preserve the Ready transition time")
		})
	}
}

func readySecondaryNetworkReport() *v1beta1.SecondaryNetworkStatus {
	return &v1beta1.SecondaryNetworkStatus{
		ConfigSource:  v1beta1.SecondaryNetworkConfigSourceAntreaNodeConfig,
		CurrentBridge: "br-current",
		Conditions: []metav1.Condition{{Type: string(v1beta1.SecondaryNetworkConditionReady), Status: metav1.ConditionTrue,
			ObservedGeneration: 2, Reason: "Reconciled", LastTransitionTime: metav1.Now()}},
	}
}

func TestSyncAgentSecondaryNetworkStatusNodeIdentity(t *testing.T) {
	for _, previousUID := range []types.UID{"", "node-uid", "old-node-uid"} {
		t.Run(string(previousUID), func(t *testing.T) {
			previous := readySecondaryNetworkReport()
			old := &v1beta1.AntreaAgentInfo{
				ObjectMeta:       metav1.ObjectMeta{Name: "testAgentCRD"},
				NodeRef:          corev1.ObjectReference{Kind: "Node", Name: "testAgentCRD", UID: previousUID},
				SecondaryNetwork: previous,
			}
			client := fakeclientset.NewSimpleClientset(old)
			monitor := newAgentMonitor(client, t)
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			monitor.querier = &testSecondaryNetworkQuerier{AgentQuerier: monitor.querier, nodeLister: corelisters.NewNodeLister(indexer)}
			monitor.SetSecondaryNetworkStatusProvider(nil)
			monitor.syncAgentCRD(context.Background())
			assert.Nil(t, monitor.agentCRD, "A failed Node lookup must not publish a new report")
			for _, action := range client.Actions() {
				assert.NotEqual(t, "update", action.GetVerb())
			}
			require.NoError(t, indexer.Add(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: old.Name, UID: "node-uid"}}))
			monitor.syncAgentCRD(context.Background())
			current, err := client.CrdV1beta1().AntreaAgentInfos().Get(context.Background(), old.Name, metav1.GetOptions{})
			require.NoError(t, err)
			report := current.SecondaryNetwork
			require.NotNil(t, report)
			assert.EqualValues(t, "node-uid", current.NodeRef.UID)
			assert.Equal(t, metav1.ConditionUnknown, report.Conditions[0].Status)
		})
	}
}

func TestAgentMonitorRetriesFailedPublication(t *testing.T) {
	info := &v1beta1.AntreaAgentInfo{ObjectMeta: metav1.ObjectMeta{Name: "testAgentCRD"}}
	client := fakeclientset.NewSimpleClientset(info)
	var updates atomic.Int32
	client.PrependReactor("update", "antreaagentinfos", func(cgtesting.Action) (bool, runtime.Object, error) {
		if updates.Add(1) == 1 {
			return true, nil, errors.New("temporary API failure")
		}
		return false, nil, nil
	})
	monitor := newAgentMonitor(client, t)
	stop, done := make(chan struct{}), make(chan struct{})
	go func() { defer close(done); monitor.Run(stop) }()
	defer func() { close(stop); <-done }()

	require.Eventually(t, func() bool { return updates.Load() >= 2 }, 3*time.Second, 10*time.Millisecond)
	current, err := client.CrdV1beta1().AntreaAgentInfos().Get(context.Background(), info.Name, metav1.GetOptions{})
	require.NoError(t, err)
	require.NotEmpty(t, current.AgentConditions)
	assert.False(t, current.AgentConditions[0].LastHeartbeatTime.IsZero())
}

func TestPublishCurrentSecondaryNetworkReport(t *testing.T) {
	info := &v1beta1.AntreaAgentInfo{ObjectMeta: metav1.ObjectMeta{Name: "testAgentCRD"}}
	client := fakeclientset.NewSimpleClientset(info)
	monitor := newAgentMonitor(client, t)
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	require.NoError(t, indexer.Add(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: info.Name, UID: "node-uid"}}))
	monitor.querier = &testSecondaryNetworkQuerier{AgentQuerier: monitor.querier, nodeLister: corelisters.NewNodeLister(indexer)}
	desired := readySecondaryNetworkReport()
	desired.Conditions[0].Status = metav1.ConditionFalse
	desired.Conditions[0].Reason = "BridgeInUse"
	original := desired.DeepCopy()
	provider := &testSecondaryNetworkProvider{report: desired}
	monitor.SetSecondaryNetworkStatusProvider(provider)
	monitor.SetAntreaNodeConfigSnapshotProvider(&testANCProvider{snapshot: currentANCSnapshot()})
	monitor.syncAgentCRD(context.Background())
	current, err := client.CrdV1beta1().AntreaAgentInfos().Get(context.Background(), info.Name, metav1.GetOptions{})
	require.NoError(t, err)
	report := current.SecondaryNetwork
	require.NotNil(t, report)
	assert.Equal(t, original, desired, "Publication must not mutate the provider report")
	assert.Equal(t, desired, report)
	assert.EqualValues(t, "node-uid", current.NodeRef.UID)
	require.NotEmpty(t, current.AgentConditions)
	assert.False(t, current.AgentConditions[0].LastHeartbeatTime.IsZero())
	report.Conditions[0].Message = "modified published report"
	assert.Equal(t, original, desired, "Published conditions must not alias the provider")
	for _, unavailable := range []*v1beta1.SecondaryNetworkStatus{
		{},
		nil,
	} {
		provider.report = unavailable
		monitor.syncAgentCRD(context.Background())
		current, err = client.CrdV1beta1().AntreaAgentInfos().Get(context.Background(), info.Name, metav1.GetOptions{})
		require.NoError(t, err)

		assert.Empty(t, current.SecondaryNetwork.CurrentBridge)
		ready := meta.FindStatusCondition(current.SecondaryNetwork.Conditions, string(v1beta1.SecondaryNetworkConditionReady))
		require.NotNil(t, ready)
		assert.Equal(t, metav1.ConditionUnknown, ready.Status)
		assert.Equal(t, "ConfigurationUnavailable", ready.Reason)
		assert.Zero(t, ready.ObservedGeneration)
	}
	static := &v1beta1.SecondaryNetworkStatus{
		ConfigSource:  v1beta1.SecondaryNetworkConfigSourceAgentConfig,
		CurrentBridge: "br-static", DesiredBridge: "br-static",
		Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Reconciled"}},
	}
	provider.report = static
	monitor.syncAgentCRD(context.Background())
	current, err = client.CrdV1beta1().AntreaAgentInfos().Get(context.Background(), info.Name, metav1.GetOptions{})
	require.NoError(t, err)
	require.NotNil(t, current.SecondaryNetwork)
	require.Len(t, current.SecondaryNetwork.Conditions, 1)
	assert.False(t, current.SecondaryNetwork.Conditions[0].LastTransitionTime.IsZero(), "Transition from Unknown to True must stamp LastTransitionTime")
	expectedStatic := static.DeepCopy()
	expectedStatic.Conditions[0].LastTransitionTime = current.SecondaryNetwork.Conditions[0].LastTransitionTime
	assert.Equal(t, expectedStatic, current.SecondaryNetwork, "Static feature status must be published without an ANC identity")

	for _, action := range client.Actions() {
		assert.Equal(t, "antreaagentinfos", action.GetResource().Resource, "Publishing must only access AgentInfo")
	}
}

func TestSecondaryNetworkTransitionTimeMonotonicAndPreservedOnRestart(t *testing.T) {
	ctx := context.Background()
	t0 := metav1.NewTime(time.Now().Add(-5 * time.Minute))
	info := &v1beta1.AntreaAgentInfo{
		ObjectMeta: metav1.ObjectMeta{Name: "testAgentCRD"},
		SecondaryNetwork: &v1beta1.SecondaryNetworkStatus{
			ConfigSource:  v1beta1.SecondaryNetworkConfigSourceAntreaNodeConfig,
			CurrentBridge: "br-current",
			Conditions: []metav1.Condition{{
				Type:               string(v1beta1.SecondaryNetworkConditionReady),
				Status:             metav1.ConditionTrue,
				ObservedGeneration: 1,
				Reason:             "Reconciled",
				LastTransitionTime: t0,
			}},
		},
	}
	client := fakeclientset.NewSimpleClientset(info)
	monitor := newAgentMonitor(client, t)
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	require.NoError(t, indexer.Add(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: info.Name, UID: "node-uid"}}))
	monitor.querier = &testSecondaryNetworkQuerier{AgentQuerier: monitor.querier, nodeLister: corelisters.NewNodeLister(indexer)}

	// Simulate Agent restart: provider starts with a fresh Ready=True timestamp,
	// while the persisted AgentInfo already has Ready=True from t0.
	snap1 := currentANCSnapshot()
	snap1.AntreaNodeConfig.Generation = 1
	target := &testANCProvider{snapshot: snap1}
	report1 := readySecondaryNetworkReport()
	report1.Conditions[0].ObservedGeneration = 1
	report1.Conditions[0].LastTransitionTime = metav1.NewTime(time.Now().Add(-2 * time.Minute))
	feature := &testSecondaryNetworkProvider{report: report1}
	monitor.SetAntreaNodeConfigSnapshotProvider(target)
	monitor.SetSecondaryNetworkStatusProvider(feature)

	monitor.syncAgentCRD(ctx)
	published, err := client.CrdV1beta1().AntreaAgentInfos().Get(ctx, info.Name, metav1.GetOptions{})
	require.NoError(t, err)
	ready := meta.FindStatusCondition(published.SecondaryNetwork.Conditions, string(v1beta1.SecondaryNetworkConditionReady))
	require.NotNil(t, ready)
	assert.Equal(t, metav1.ConditionTrue, ready.Status)
	assert.Equal(t, t0, ready.LastTransitionTime, "Agent restart with unchanged Ready=True must preserve LastTransitionTime")

	// Advance ANC to generation 2 before feature reconciliation finishes -> Unknown at t1.
	snap2 := currentANCSnapshot()
	snap2.AntreaNodeConfig.Generation = 2
	target.snapshot = snap2
	monitor.syncAgentCRD(ctx)
	published, err = client.CrdV1beta1().AntreaAgentInfos().Get(ctx, info.Name, metav1.GetOptions{})
	require.NoError(t, err)
	unknownReady := meta.FindStatusCondition(published.SecondaryNetwork.Conditions, string(v1beta1.SecondaryNetworkConditionReady))
	require.NotNil(t, unknownReady)
	require.Equal(t, metav1.ConditionUnknown, unknownReady.Status)
	require.True(t, unknownReady.LastTransitionTime.After(t0.Time))

	// Feature reconciles generation 2 while keeping its internal cached t0 timestamp
	// (because the controller itself never transitioned through Unknown).
	report2 := readySecondaryNetworkReport()
	report2.Conditions[0].ObservedGeneration = 2
	report2.Conditions[0].LastTransitionTime = t0
	feature.report = report2
	monitor.syncAgentCRD(ctx)
	published, err = client.CrdV1beta1().AntreaAgentInfos().Get(ctx, info.Name, metav1.GetOptions{})
	require.NoError(t, err)
	recoveredReady := meta.FindStatusCondition(published.SecondaryNetwork.Conditions, string(v1beta1.SecondaryNetworkConditionReady))
	require.NotNil(t, recoveredReady)
	assert.Equal(t, metav1.ConditionTrue, recoveredReady.Status)
	assert.Equal(t, int64(2), recoveredReady.ObservedGeneration)
	assert.False(t, recoveredReady.LastTransitionTime.Before(&unknownReady.LastTransitionTime),
		"Unknown -> True transition must not move LastTransitionTime backwards")
}

func TestSecondaryNetworkReportWithoutNodeIdentity(t *testing.T) {
	for _, nodeType := range []config.NodeType{config.K8sNode, config.ExternalNode} {
		t.Run(nodeType.String(), func(t *testing.T) {
			info := &v1beta1.AntreaAgentInfo{ObjectMeta: metav1.ObjectMeta{Name: "testAgentCRD"},
				SecondaryNetwork: &v1beta1.SecondaryNetworkStatus{ConfigSource: v1beta1.SecondaryNetworkConfigSourceAntreaNodeConfig}}
			client := fakeclientset.NewSimpleClientset(info)
			monitor := newAgentMonitor(client, t)
			monitor.querier.GetNodeConfig().Type = nodeType
			monitor.syncAgentCRD(context.Background())
			current, err := client.CrdV1beta1().AntreaAgentInfos().Get(context.Background(), info.Name, metav1.GetOptions{})
			require.NoError(t, err)
			assert.Nil(t, current.SecondaryNetwork)
			desired := &v1beta1.SecondaryNetworkStatus{ConfigSource: v1beta1.SecondaryNetworkConfigSourceAgentConfig}
			monitor.SetSecondaryNetworkStatusProvider(&testSecondaryNetworkProvider{report: desired})
			monitor.syncAgentCRD(context.Background())
			current, err = client.CrdV1beta1().AntreaAgentInfos().Get(context.Background(), info.Name, metav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, desired, current.SecondaryNetwork)
		})
	}
}
