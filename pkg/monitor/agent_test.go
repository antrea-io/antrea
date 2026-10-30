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
	"testing"

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

type testNodeConfigProvider struct {
	report *v1beta1.AntreaNodeConfigAgentStatus
}

func (p *testNodeConfigProvider) GetAntreaNodeConfigStatus() *v1beta1.AntreaNodeConfigAgentStatus {
	return p.report
}
func (p *testNodeConfigProvider) AntreaNodeConfigStatusUpdates() <-chan struct{} { return nil }

type testNodeConfigQuerier struct {
	querier.AgentQuerier
	nodeLister corelisters.NodeLister
}

func (q *testNodeConfigQuerier) GetNodeLister() corelisters.NodeLister { return q.nodeLister }

func TestSyncAgentNodeConfigStatusSchema(t *testing.T) {
	data, err := os.ReadFile("../../build/charts/antrea/crds/antreaagentinfo.yaml")
	require.NoError(t, err)
	var crd apiextensionsv1.CustomResourceDefinition
	require.NoError(t, yaml.Unmarshal(data, &crd))
	var openAPISchema apiextensions.JSONSchemaProps
	require.NoError(t, apiextensionsv1.Convert_v1_JSONSchemaProps_To_apiextensions_JSONSchemaProps(
		crd.Spec.Versions[0].Schema.OpenAPIV3Schema, &openAPISchema, nil))
	validator, _, err := validation.NewSchemaValidator(&openAPISchema)
	require.NoError(t, err)

	for _, tt := range []struct {
		name        string
		enabled     bool
		nilProvider bool
		windows     bool
		report      *v1beta1.AntreaNodeConfigAgentStatus
	}{
		{name: "feature disabled"},
		{name: "disabled ignores provider", report: readyNodeConfigReport()},
		{name: "enabled nil provider", enabled: true, nilProvider: true},
		{name: "enabled nil report", enabled: true},
		{name: "missing feature", enabled: true, report: &v1beta1.AntreaNodeConfigAgentStatus{ConfigUID: "current-config"}},
		{name: "nil conditions", enabled: true, report: &v1beta1.AntreaNodeConfigAgentStatus{SecondaryNetwork: &v1beta1.SecondaryNetworkStatus{}}},
		{name: "empty conditions", enabled: true, report: &v1beta1.AntreaNodeConfigAgentStatus{SecondaryNetwork: &v1beta1.SecondaryNetworkStatus{Conditions: []metav1.Condition{}}}},
		{name: "other condition without Ready", enabled: true, report: &v1beta1.AntreaNodeConfigAgentStatus{
			ConfigUID: "current-config", SecondaryNetwork: &v1beta1.SecondaryNetworkStatus{CurrentBridge: "br-unconfirmed",
				Conditions: []metav1.Condition{{Type: "Other", Status: metav1.ConditionTrue, ObservedGeneration: 9}}}}},
		{name: "Windows without provider", enabled: true, nilProvider: true, windows: true},
		{name: "Windows ignores provider", enabled: true, windows: true, report: readyNodeConfigReport()},
	} {
		t.Run(tt.name, func(t *testing.T) {
			previous := readyNodeConfigReport()
			previous.NodeUID = "old-node-uid"
			old := &v1beta1.AntreaAgentInfo{ObjectMeta: metav1.ObjectMeta{Name: "testAgentCRD"}, NodeConfigStatus: previous}
			client := fakeclientset.NewSimpleClientset(old)
			monitor := newAgentMonitor(client, t)
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: old.Name, UID: "node-uid"}}
			if tt.windows {
				node.Labels = map[string]string{corev1.LabelOSStable: "windows"}
			}
			require.NoError(t, indexer.Add(node))
			monitor.querier = &testNodeConfigQuerier{AgentQuerier: monitor.querier, nodeLister: corelisters.NewNodeLister(indexer)}
			if !tt.nilProvider {
				monitor.nodeConfigStatusProvider = &testNodeConfigProvider{report: tt.report}
			}
			if tt.enabled {
				monitor.SetNodeConfigStatusProvider(monitor.nodeConfigStatusProvider)
			}
			original := tt.report.DeepCopy()
			monitor.syncAgentCRD(context.Background())
			current, err := client.CrdV1beta1().AntreaAgentInfos().Get(context.Background(), old.Name, metav1.GetOptions{})
			require.NoError(t, err)
			report := current.NodeConfigStatus
			require.NotNil(t, report)
			require.NotNil(t, report.SecondaryNetwork)
			require.Len(t, report.SecondaryNetwork.Conditions, 1)
			ready := report.SecondaryNetwork.Conditions[0]
			wantStatus, wantReason := metav1.ConditionUnknown, "ConfigurationUnavailable"
			if !tt.enabled {
				wantStatus, wantReason = metav1.ConditionFalse, "FeatureDisabled"
			} else if tt.windows {
				wantStatus, wantReason = metav1.ConditionFalse, "UnsupportedNode"
			}
			assert.Equal(t, "Ready", ready.Type)
			assert.Equal(t, wantStatus, ready.Status)
			assert.Equal(t, wantReason, ready.Reason)
			assert.Zero(t, ready.ObservedGeneration)
			assert.Empty(t, report.SecondaryNetwork.CurrentBridge)
			assert.Empty(t, report.SecondaryNetwork.DesiredBridge)
			assert.EqualValues(t, "node-uid", report.NodeUID)
			assert.False(t, report.LastHeartbeatTime.IsZero())
			assert.False(t, ready.LastTransitionTime.IsZero())
			if tt.report == nil || !tt.enabled || tt.windows {
				assert.Empty(t, report.ConfigUID, "Fallback must not restore the previous selection")
				assert.Empty(t, report.ConfigName)
			} else {
				assert.Equal(t, tt.report.ConfigUID, report.ConfigUID)
			}
			assert.Equal(t, original, tt.report, "Publication must not mutate the provider report")
			encoded, err := json.Marshal(current)
			require.NoError(t, err)
			var object map[string]interface{}
			require.NoError(t, json.Unmarshal(encoded, &object))
			assert.Empty(t, validation.ValidateCustomResource(field.NewPath(""), object, validator))
			monitor.syncAgentCRD(context.Background())
			current, err = client.CrdV1beta1().AntreaAgentInfos().Get(context.Background(), old.Name, metav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, ready.LastTransitionTime, current.NodeConfigStatus.SecondaryNetwork.Conditions[0].LastTransitionTime,
				"Heartbeat publication must preserve the Ready transition time")
		})
	}
}

func readyNodeConfigReport() *v1beta1.AntreaNodeConfigAgentStatus {
	return &v1beta1.AntreaNodeConfigAgentStatus{
		ConfigName: "current-config", ConfigUID: "current-uid",
		SecondaryNetwork: &v1beta1.SecondaryNetworkStatus{CurrentBridge: "br-current",
			Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue,
				ObservedGeneration: 2, Reason: "Reconciled", LastTransitionTime: metav1.Now()}}},
	}
}

func TestSyncAgentNodeConfigStatusNodeIdentity(t *testing.T) {
	for _, previousUID := range []types.UID{"", "node-uid", "old-node-uid"} {
		t.Run(string(previousUID), func(t *testing.T) {
			previous := readyNodeConfigReport()
			previous.NodeUID = previousUID
			old := &v1beta1.AntreaAgentInfo{ObjectMeta: metav1.ObjectMeta{Name: "testAgentCRD"}, NodeConfigStatus: previous}
			client := fakeclientset.NewSimpleClientset(old)
			monitor := newAgentMonitor(client, t)
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			monitor.querier = &testNodeConfigQuerier{AgentQuerier: monitor.querier, nodeLister: corelisters.NewNodeLister(indexer)}
			monitor.SetNodeConfigStatusProvider(nil)
			monitor.syncAgentCRD(context.Background())
			assert.Nil(t, monitor.agentCRD, "A failed Node lookup must not publish a new report")
			for _, action := range client.Actions() {
				assert.NotEqual(t, "update", action.GetVerb())
			}
			require.NoError(t, indexer.Add(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: old.Name, UID: "node-uid"}}))
			monitor.syncAgentCRD(context.Background())
			current, err := client.CrdV1beta1().AntreaAgentInfos().Get(context.Background(), old.Name, metav1.GetOptions{})
			require.NoError(t, err)
			report := current.NodeConfigStatus
			require.NotNil(t, report)
			assert.EqualValues(t, "node-uid", report.NodeUID)
			assert.Empty(t, report.ConfigUID)
			assert.Equal(t, metav1.ConditionUnknown, report.SecondaryNetwork.Conditions[0].Status)
		})
	}
}

func TestPublishCurrentNodeConfigurationReport(t *testing.T) {
	info := &v1beta1.AntreaAgentInfo{ObjectMeta: metav1.ObjectMeta{Name: "testAgentCRD"}}
	client := fakeclientset.NewSimpleClientset(info)
	monitor := newAgentMonitor(client, t)
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	require.NoError(t, indexer.Add(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: info.Name, UID: "node-uid"}}))
	monitor.querier = &testNodeConfigQuerier{AgentQuerier: monitor.querier, nodeLister: corelisters.NewNodeLister(indexer)}
	desired := readyNodeConfigReport()
	desired.SecondaryNetwork.Conditions[0].Status = metav1.ConditionFalse
	desired.SecondaryNetwork.Conditions[0].Reason = "BridgeInUse"
	original := desired.DeepCopy()
	provider := &testNodeConfigProvider{report: desired}
	monitor.SetNodeConfigStatusProvider(provider)
	monitor.syncAgentCRD(context.Background())
	current, err := client.CrdV1beta1().AntreaAgentInfos().Get(context.Background(), info.Name, metav1.GetOptions{})
	require.NoError(t, err)
	report := current.NodeConfigStatus
	require.NotNil(t, report)
	assert.Equal(t, original, desired, "Publication must not mutate the provider report")
	assert.Equal(t, desired.SecondaryNetwork, report.SecondaryNetwork)
	assert.Equal(t, desired.ConfigUID, report.ConfigUID)
	assert.EqualValues(t, "node-uid", report.NodeUID)
	assert.False(t, report.LastHeartbeatTime.IsZero())
	report.SecondaryNetwork.Conditions[0].Message = "modified published report"
	assert.Equal(t, original, desired, "Published conditions must not alias the provider")
	for _, unavailable := range []*v1beta1.AntreaNodeConfigAgentStatus{
		{ConfigUID: desired.ConfigUID},
		nil,
	} {
		provider.report = unavailable
		monitor.syncAgentCRD(context.Background())
		current, err = client.CrdV1beta1().AntreaAgentInfos().Get(context.Background(), info.Name, metav1.GetOptions{})
		require.NoError(t, err)
		if unavailable == nil {
			assert.Empty(t, current.NodeConfigStatus.ConfigUID)
		} else {
			assert.Equal(t, unavailable.ConfigUID, current.NodeConfigStatus.ConfigUID)
		}
		assert.Empty(t, current.NodeConfigStatus.SecondaryNetwork.CurrentBridge)
		ready := meta.FindStatusCondition(current.NodeConfigStatus.SecondaryNetwork.Conditions, "Ready")
		require.NotNil(t, ready)
		assert.Equal(t, metav1.ConditionUnknown, ready.Status)
		assert.Equal(t, "ConfigurationUnavailable", ready.Reason)
		assert.Zero(t, ready.ObservedGeneration)
	}
	for _, action := range client.Actions() {
		assert.Equal(t, "antreaagentinfos", action.GetResource().Resource, "Publishing must only access AgentInfo")
	}
}

func TestNodeConfigurationReportWithoutNodeIdentity(t *testing.T) {
	for _, nodeType := range []config.NodeType{config.K8sNode, config.ExternalNode} {
		t.Run(nodeType.String(), func(t *testing.T) {
			info := &v1beta1.AntreaAgentInfo{ObjectMeta: metav1.ObjectMeta{Name: "testAgentCRD"},
				NodeConfigStatus: &v1beta1.AntreaNodeConfigAgentStatus{ConfigUID: "previous-uid"}}
			client := fakeclientset.NewSimpleClientset(info)
			monitor := newAgentMonitor(client, t)
			monitor.querier.GetNodeConfig().Type = nodeType
			monitor.syncAgentCRD(context.Background())
			current, err := client.CrdV1beta1().AntreaAgentInfos().Get(context.Background(), info.Name, metav1.GetOptions{})
			require.NoError(t, err)
			assert.Nil(t, current.NodeConfigStatus)
			desired := &v1beta1.AntreaNodeConfigAgentStatus{ConfigUID: "current-uid"}
			monitor.SetNodeConfigStatusProvider(&testNodeConfigProvider{report: desired})
			monitor.syncAgentCRD(context.Background())
			current, err = client.CrdV1beta1().AntreaAgentInfos().Get(context.Background(), info.Name, metav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, desired, current.NodeConfigStatus)
		})
	}
}
