// Copyright 2024 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

// Code generated by MockGen. DO NOT EDIT.
// Source: antrea.io/antrea/pkg/agent/querier (interfaces: AgentQuerier)
//
// Generated by this command:
//
//	mockgen -copyright_file hack/boilerplate/license_header.raw.txt -destination pkg/agent/querier/testing/mock_querier.go -package testing antrea.io/antrea/pkg/agent/querier AgentQuerier
//

// Package testing is a generated GoMock package.
package testing

import (
	reflect "reflect"

	config "antrea.io/antrea/pkg/agent/config"
	interfacestore "antrea.io/antrea/pkg/agent/interfacestore"
	memberlist "antrea.io/antrea/pkg/agent/memberlist"
	openflow "antrea.io/antrea/pkg/agent/openflow"
	proxy "antrea.io/antrea/pkg/agent/proxy"
	v1beta1 "antrea.io/antrea/pkg/apis/crd/v1beta1"
	ovsctl "antrea.io/antrea/pkg/ovs/ovsctl"
	querier "antrea.io/antrea/pkg/querier"
	gomock "go.uber.org/mock/gomock"
	kubernetes "k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/listers/core/v1"
)

// MockAgentQuerier is a mock of AgentQuerier interface.
type MockAgentQuerier struct {
	ctrl     *gomock.Controller
	recorder *MockAgentQuerierMockRecorder
	isgomock struct{}
}

// MockAgentQuerierMockRecorder is the mock recorder for MockAgentQuerier.
type MockAgentQuerierMockRecorder struct {
	mock *MockAgentQuerier
}

// NewMockAgentQuerier creates a new mock instance.
func NewMockAgentQuerier(ctrl *gomock.Controller) *MockAgentQuerier {
	mock := &MockAgentQuerier{ctrl: ctrl}
	mock.recorder = &MockAgentQuerierMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAgentQuerier) EXPECT() *MockAgentQuerierMockRecorder {
	return m.recorder
}

// GetAgentInfo mocks base method.
func (m *MockAgentQuerier) GetAgentInfo(agentInfo *v1beta1.AntreaAgentInfo, partial bool) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "GetAgentInfo", agentInfo, partial)
}

// GetAgentInfo indicates an expected call of GetAgentInfo.
func (mr *MockAgentQuerierMockRecorder) GetAgentInfo(agentInfo, partial any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAgentInfo", reflect.TypeOf((*MockAgentQuerier)(nil).GetAgentInfo), agentInfo, partial)
}

// GetBGPPolicyInfoQuerier mocks base method.
func (m *MockAgentQuerier) GetBGPPolicyInfoQuerier() querier.AgentBGPPolicyInfoQuerier {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetBGPPolicyInfoQuerier")
	ret0, _ := ret[0].(querier.AgentBGPPolicyInfoQuerier)
	return ret0
}

// GetBGPPolicyInfoQuerier indicates an expected call of GetBGPPolicyInfoQuerier.
func (mr *MockAgentQuerierMockRecorder) GetBGPPolicyInfoQuerier() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetBGPPolicyInfoQuerier", reflect.TypeOf((*MockAgentQuerier)(nil).GetBGPPolicyInfoQuerier))
}

// GetInterfaceStore mocks base method.
func (m *MockAgentQuerier) GetInterfaceStore() interfacestore.InterfaceStore {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetInterfaceStore")
	ret0, _ := ret[0].(interfacestore.InterfaceStore)
	return ret0
}

// GetInterfaceStore indicates an expected call of GetInterfaceStore.
func (mr *MockAgentQuerierMockRecorder) GetInterfaceStore() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetInterfaceStore", reflect.TypeOf((*MockAgentQuerier)(nil).GetInterfaceStore))
}

// GetK8sClient mocks base method.
func (m *MockAgentQuerier) GetK8sClient() kubernetes.Interface {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetK8sClient")
	ret0, _ := ret[0].(kubernetes.Interface)
	return ret0
}

// GetK8sClient indicates an expected call of GetK8sClient.
func (mr *MockAgentQuerierMockRecorder) GetK8sClient() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetK8sClient", reflect.TypeOf((*MockAgentQuerier)(nil).GetK8sClient))
}

// GetMemberlistCluster mocks base method.
func (m *MockAgentQuerier) GetMemberlistCluster() memberlist.Interface {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetMemberlistCluster")
	ret0, _ := ret[0].(memberlist.Interface)
	return ret0
}

// GetMemberlistCluster indicates an expected call of GetMemberlistCluster.
func (mr *MockAgentQuerierMockRecorder) GetMemberlistCluster() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetMemberlistCluster", reflect.TypeOf((*MockAgentQuerier)(nil).GetMemberlistCluster))
}

// GetNetworkConfig mocks base method.
func (m *MockAgentQuerier) GetNetworkConfig() *config.NetworkConfig {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetNetworkConfig")
	ret0, _ := ret[0].(*config.NetworkConfig)
	return ret0
}

// GetNetworkConfig indicates an expected call of GetNetworkConfig.
func (mr *MockAgentQuerierMockRecorder) GetNetworkConfig() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetNetworkConfig", reflect.TypeOf((*MockAgentQuerier)(nil).GetNetworkConfig))
}

// GetNetworkPolicyInfoQuerier mocks base method.
func (m *MockAgentQuerier) GetNetworkPolicyInfoQuerier() querier.AgentNetworkPolicyInfoQuerier {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetNetworkPolicyInfoQuerier")
	ret0, _ := ret[0].(querier.AgentNetworkPolicyInfoQuerier)
	return ret0
}

// GetNetworkPolicyInfoQuerier indicates an expected call of GetNetworkPolicyInfoQuerier.
func (mr *MockAgentQuerierMockRecorder) GetNetworkPolicyInfoQuerier() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetNetworkPolicyInfoQuerier", reflect.TypeOf((*MockAgentQuerier)(nil).GetNetworkPolicyInfoQuerier))
}

// GetNodeConfig mocks base method.
func (m *MockAgentQuerier) GetNodeConfig() *config.NodeConfig {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetNodeConfig")
	ret0, _ := ret[0].(*config.NodeConfig)
	return ret0
}

// GetNodeConfig indicates an expected call of GetNodeConfig.
func (mr *MockAgentQuerierMockRecorder) GetNodeConfig() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetNodeConfig", reflect.TypeOf((*MockAgentQuerier)(nil).GetNodeConfig))
}

// GetNodeLister mocks base method.
func (m *MockAgentQuerier) GetNodeLister() v1.NodeLister {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetNodeLister")
	ret0, _ := ret[0].(v1.NodeLister)
	return ret0
}

// GetNodeLister indicates an expected call of GetNodeLister.
func (mr *MockAgentQuerierMockRecorder) GetNodeLister() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetNodeLister", reflect.TypeOf((*MockAgentQuerier)(nil).GetNodeLister))
}

// GetOVSCtlClient mocks base method.
func (m *MockAgentQuerier) GetOVSCtlClient() ovsctl.OVSCtlClient {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetOVSCtlClient")
	ret0, _ := ret[0].(ovsctl.OVSCtlClient)
	return ret0
}

// GetOVSCtlClient indicates an expected call of GetOVSCtlClient.
func (mr *MockAgentQuerierMockRecorder) GetOVSCtlClient() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetOVSCtlClient", reflect.TypeOf((*MockAgentQuerier)(nil).GetOVSCtlClient))
}

// GetOpenflowClient mocks base method.
func (m *MockAgentQuerier) GetOpenflowClient() openflow.Client {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetOpenflowClient")
	ret0, _ := ret[0].(openflow.Client)
	return ret0
}

// GetOpenflowClient indicates an expected call of GetOpenflowClient.
func (mr *MockAgentQuerierMockRecorder) GetOpenflowClient() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetOpenflowClient", reflect.TypeOf((*MockAgentQuerier)(nil).GetOpenflowClient))
}

// GetProxier mocks base method.
func (m *MockAgentQuerier) GetProxier() proxy.Proxier {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetProxier")
	ret0, _ := ret[0].(proxy.Proxier)
	return ret0
}

// GetProxier indicates an expected call of GetProxier.
func (mr *MockAgentQuerierMockRecorder) GetProxier() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetProxier", reflect.TypeOf((*MockAgentQuerier)(nil).GetProxier))
}
