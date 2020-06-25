// Copyright 2020 Antrea Authors
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
// Source: github.com/vmware-tanzu/antrea/pkg/agent/openflow (interfaces: Client,OFEntryOperations)

// Package testing is a generated GoMock package.
package testing

import (
	gomock "github.com/golang/mock/gomock"
	config "github.com/vmware-tanzu/antrea/pkg/agent/config"
	types "github.com/vmware-tanzu/antrea/pkg/agent/types"
	openflow "github.com/vmware-tanzu/antrea/pkg/ovs/openflow"
	proxy "github.com/vmware-tanzu/antrea/third_party/proxy"
	net "net"
	reflect "reflect"
)

// MockClient is a mock of Client interface
type MockClient struct {
	ctrl     *gomock.Controller
	recorder *MockClientMockRecorder
}

// MockClientMockRecorder is the mock recorder for MockClient
type MockClientMockRecorder struct {
	mock *MockClient
}

// NewMockClient creates a new mock instance
func NewMockClient(ctrl *gomock.Controller) *MockClient {
	mock := &MockClient{ctrl: ctrl}
	mock.recorder = &MockClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockClient) EXPECT() *MockClientMockRecorder {
	return m.recorder
}

// AddPolicyRuleAddress mocks base method
func (m *MockClient) AddPolicyRuleAddress(arg0 uint32, arg1 types.AddressType, arg2 []types.Address, arg3 *uint16) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddPolicyRuleAddress", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddPolicyRuleAddress indicates an expected call of AddPolicyRuleAddress
func (mr *MockClientMockRecorder) AddPolicyRuleAddress(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddPolicyRuleAddress", reflect.TypeOf((*MockClient)(nil).AddPolicyRuleAddress), arg0, arg1, arg2, arg3)
}

// DeletePolicyRuleAddress mocks base method
func (m *MockClient) DeletePolicyRuleAddress(arg0 uint32, arg1 types.AddressType, arg2 []types.Address, arg3 *uint16) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeletePolicyRuleAddress", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeletePolicyRuleAddress indicates an expected call of DeletePolicyRuleAddress
func (mr *MockClientMockRecorder) DeletePolicyRuleAddress(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeletePolicyRuleAddress", reflect.TypeOf((*MockClient)(nil).DeletePolicyRuleAddress), arg0, arg1, arg2, arg3)
}

// DeleteStaleFlows mocks base method
func (m *MockClient) DeleteStaleFlows() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteStaleFlows")
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteStaleFlows indicates an expected call of DeleteStaleFlows
func (mr *MockClientMockRecorder) DeleteStaleFlows() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteStaleFlows", reflect.TypeOf((*MockClient)(nil).DeleteStaleFlows))
}

// Disconnect mocks base method
func (m *MockClient) Disconnect() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Disconnect")
	ret0, _ := ret[0].(error)
	return ret0
}

// Disconnect indicates an expected call of Disconnect
func (mr *MockClientMockRecorder) Disconnect() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Disconnect", reflect.TypeOf((*MockClient)(nil).Disconnect))
}

// GetFlowTableStatus mocks base method
func (m *MockClient) GetFlowTableStatus() []openflow.TableStatus {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetFlowTableStatus")
	ret0, _ := ret[0].([]openflow.TableStatus)
	return ret0
}

// GetFlowTableStatus indicates an expected call of GetFlowTableStatus
func (mr *MockClientMockRecorder) GetFlowTableStatus() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetFlowTableStatus", reflect.TypeOf((*MockClient)(nil).GetFlowTableStatus))
}

// GetNetworkPolicyFlowKeys mocks base method
func (m *MockClient) GetNetworkPolicyFlowKeys(arg0, arg1 string) []string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetNetworkPolicyFlowKeys", arg0, arg1)
	ret0, _ := ret[0].([]string)
	return ret0
}

// GetNetworkPolicyFlowKeys indicates an expected call of GetNetworkPolicyFlowKeys
func (mr *MockClientMockRecorder) GetNetworkPolicyFlowKeys(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetNetworkPolicyFlowKeys", reflect.TypeOf((*MockClient)(nil).GetNetworkPolicyFlowKeys), arg0, arg1)
}

// GetPodFlowKeys mocks base method
func (m *MockClient) GetPodFlowKeys(arg0 string) []string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPodFlowKeys", arg0)
	ret0, _ := ret[0].([]string)
	return ret0
}

// GetPodFlowKeys indicates an expected call of GetPodFlowKeys
func (mr *MockClientMockRecorder) GetPodFlowKeys(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPodFlowKeys", reflect.TypeOf((*MockClient)(nil).GetPodFlowKeys), arg0)
}

// GetTunnelVirtualMAC mocks base method
func (m *MockClient) GetTunnelVirtualMAC() net.HardwareAddr {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetTunnelVirtualMAC")
	ret0, _ := ret[0].(net.HardwareAddr)
	return ret0
}

// GetTunnelVirtualMAC indicates an expected call of GetTunnelVirtualMAC
func (mr *MockClientMockRecorder) GetTunnelVirtualMAC() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTunnelVirtualMAC", reflect.TypeOf((*MockClient)(nil).GetTunnelVirtualMAC))
}

// Initialize mocks base method
func (m *MockClient) Initialize(arg0 types.RoundInfo, arg1 *config.NodeConfig, arg2 config.TrafficEncapModeType, arg3 uint32) (<-chan struct{}, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Initialize", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(<-chan struct{})
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Initialize indicates an expected call of Initialize
func (mr *MockClientMockRecorder) Initialize(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Initialize", reflect.TypeOf((*MockClient)(nil).Initialize), arg0, arg1, arg2, arg3)
}

// InstallBridgeUplinkFlows mocks base method
func (m *MockClient) InstallBridgeUplinkFlows(arg0, arg1 uint32) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InstallBridgeUplinkFlows", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// InstallBridgeUplinkFlows indicates an expected call of InstallBridgeUplinkFlows
func (mr *MockClientMockRecorder) InstallBridgeUplinkFlows(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InstallBridgeUplinkFlows", reflect.TypeOf((*MockClient)(nil).InstallBridgeUplinkFlows), arg0, arg1)
}

// InstallClusterServiceCIDRFlows mocks base method
func (m *MockClient) InstallClusterServiceCIDRFlows(arg0 *net.IPNet, arg1 net.HardwareAddr, arg2 uint32) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InstallClusterServiceCIDRFlows", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// InstallClusterServiceCIDRFlows indicates an expected call of InstallClusterServiceCIDRFlows
func (mr *MockClientMockRecorder) InstallClusterServiceCIDRFlows(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InstallClusterServiceCIDRFlows", reflect.TypeOf((*MockClient)(nil).InstallClusterServiceCIDRFlows), arg0, arg1, arg2)
}

// InstallClusterServiceFlows mocks base method
func (m *MockClient) InstallClusterServiceFlows() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InstallClusterServiceFlows")
	ret0, _ := ret[0].(error)
	return ret0
}

// InstallClusterServiceFlows indicates an expected call of InstallClusterServiceFlows
func (mr *MockClientMockRecorder) InstallClusterServiceFlows() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InstallClusterServiceFlows", reflect.TypeOf((*MockClient)(nil).InstallClusterServiceFlows))
}

// InstallDefaultTunnelFlows mocks base method
func (m *MockClient) InstallDefaultTunnelFlows(arg0 uint32) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InstallDefaultTunnelFlows", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// InstallDefaultTunnelFlows indicates an expected call of InstallDefaultTunnelFlows
func (mr *MockClientMockRecorder) InstallDefaultTunnelFlows(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InstallDefaultTunnelFlows", reflect.TypeOf((*MockClient)(nil).InstallDefaultTunnelFlows), arg0)
}

// InstallEndpointFlows mocks base method
func (m *MockClient) InstallEndpointFlows(arg0 openflow.Protocol, arg1 []proxy.Endpoint) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InstallEndpointFlows", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// InstallEndpointFlows indicates an expected call of InstallEndpointFlows
func (mr *MockClientMockRecorder) InstallEndpointFlows(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InstallEndpointFlows", reflect.TypeOf((*MockClient)(nil).InstallEndpointFlows), arg0, arg1)
}

// InstallExternalFlows mocks base method
func (m *MockClient) InstallExternalFlows(arg0 net.IP, arg1 net.IPNet) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InstallExternalFlows", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// InstallExternalFlows indicates an expected call of InstallExternalFlows
func (mr *MockClientMockRecorder) InstallExternalFlows(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InstallExternalFlows", reflect.TypeOf((*MockClient)(nil).InstallExternalFlows), arg0, arg1)
}

// InstallGatewayFlows mocks base method
func (m *MockClient) InstallGatewayFlows(arg0 net.IP, arg1 net.HardwareAddr, arg2 uint32) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InstallGatewayFlows", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// InstallGatewayFlows indicates an expected call of InstallGatewayFlows
func (mr *MockClientMockRecorder) InstallGatewayFlows(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InstallGatewayFlows", reflect.TypeOf((*MockClient)(nil).InstallGatewayFlows), arg0, arg1, arg2)
}

// InstallNodeFlows mocks base method
func (m *MockClient) InstallNodeFlows(arg0 string, arg1 net.HardwareAddr, arg2 net.IPNet, arg3, arg4 net.IP, arg5, arg6 uint32) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InstallNodeFlows", arg0, arg1, arg2, arg3, arg4, arg5, arg6)
	ret0, _ := ret[0].(error)
	return ret0
}

// InstallNodeFlows indicates an expected call of InstallNodeFlows
func (mr *MockClientMockRecorder) InstallNodeFlows(arg0, arg1, arg2, arg3, arg4, arg5, arg6 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InstallNodeFlows", reflect.TypeOf((*MockClient)(nil).InstallNodeFlows), arg0, arg1, arg2, arg3, arg4, arg5, arg6)
}

// InstallPodFlows mocks base method
func (m *MockClient) InstallPodFlows(arg0 string, arg1 net.IP, arg2, arg3 net.HardwareAddr, arg4 uint32) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InstallPodFlows", arg0, arg1, arg2, arg3, arg4)
	ret0, _ := ret[0].(error)
	return ret0
}

// InstallPodFlows indicates an expected call of InstallPodFlows
func (mr *MockClientMockRecorder) InstallPodFlows(arg0, arg1, arg2, arg3, arg4 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InstallPodFlows", reflect.TypeOf((*MockClient)(nil).InstallPodFlows), arg0, arg1, arg2, arg3, arg4)
}

// InstallPolicyRuleFlows mocks base method
func (m *MockClient) InstallPolicyRuleFlows(arg0 uint32, arg1 *types.PolicyRule, arg2, arg3 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InstallPolicyRuleFlows", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(error)
	return ret0
}

// InstallPolicyRuleFlows indicates an expected call of InstallPolicyRuleFlows
func (mr *MockClientMockRecorder) InstallPolicyRuleFlows(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InstallPolicyRuleFlows", reflect.TypeOf((*MockClient)(nil).InstallPolicyRuleFlows), arg0, arg1, arg2, arg3)
}

// InstallServiceFlows mocks base method
func (m *MockClient) InstallServiceFlows(arg0 openflow.GroupIDType, arg1 net.IP, arg2 uint16, arg3 openflow.Protocol, arg4 uint16) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InstallServiceFlows", arg0, arg1, arg2, arg3, arg4)
	ret0, _ := ret[0].(error)
	return ret0
}

// InstallServiceFlows indicates an expected call of InstallServiceFlows
func (mr *MockClientMockRecorder) InstallServiceFlows(arg0, arg1, arg2, arg3, arg4 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InstallServiceFlows", reflect.TypeOf((*MockClient)(nil).InstallServiceFlows), arg0, arg1, arg2, arg3, arg4)
}

// InstallServiceGroup mocks base method
func (m *MockClient) InstallServiceGroup(arg0 openflow.GroupIDType, arg1 bool, arg2 []proxy.Endpoint) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InstallServiceGroup", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// InstallServiceGroup indicates an expected call of InstallServiceGroup
func (mr *MockClientMockRecorder) InstallServiceGroup(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InstallServiceGroup", reflect.TypeOf((*MockClient)(nil).InstallServiceGroup), arg0, arg1, arg2)
}

// IsConnected mocks base method
func (m *MockClient) IsConnected() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsConnected")
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsConnected indicates an expected call of IsConnected
func (mr *MockClientMockRecorder) IsConnected() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsConnected", reflect.TypeOf((*MockClient)(nil).IsConnected))
}

// ReassignFlowPriorities mocks base method
func (m *MockClient) ReassignFlowPriorities(arg0 map[uint16]uint16) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ReassignFlowPriorities", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// ReassignFlowPriorities indicates an expected call of ReassignFlowPriorities
func (mr *MockClientMockRecorder) ReassignFlowPriorities(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReassignFlowPriorities", reflect.TypeOf((*MockClient)(nil).ReassignFlowPriorities), arg0)
}

// ReplayFlows mocks base method
func (m *MockClient) ReplayFlows() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "ReplayFlows")
}

// ReplayFlows indicates an expected call of ReplayFlows
func (mr *MockClientMockRecorder) ReplayFlows() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReplayFlows", reflect.TypeOf((*MockClient)(nil).ReplayFlows))
}

// UninstallEndpointFlows mocks base method
func (m *MockClient) UninstallEndpointFlows(arg0 openflow.Protocol, arg1 proxy.Endpoint) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UninstallEndpointFlows", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// UninstallEndpointFlows indicates an expected call of UninstallEndpointFlows
func (mr *MockClientMockRecorder) UninstallEndpointFlows(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UninstallEndpointFlows", reflect.TypeOf((*MockClient)(nil).UninstallEndpointFlows), arg0, arg1)
}

// UninstallNodeFlows mocks base method
func (m *MockClient) UninstallNodeFlows(arg0 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UninstallNodeFlows", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// UninstallNodeFlows indicates an expected call of UninstallNodeFlows
func (mr *MockClientMockRecorder) UninstallNodeFlows(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UninstallNodeFlows", reflect.TypeOf((*MockClient)(nil).UninstallNodeFlows), arg0)
}

// UninstallPodFlows mocks base method
func (m *MockClient) UninstallPodFlows(arg0 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UninstallPodFlows", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// UninstallPodFlows indicates an expected call of UninstallPodFlows
func (mr *MockClientMockRecorder) UninstallPodFlows(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UninstallPodFlows", reflect.TypeOf((*MockClient)(nil).UninstallPodFlows), arg0)
}

// UninstallPolicyRuleFlows mocks base method
func (m *MockClient) UninstallPolicyRuleFlows(arg0 uint32) (*[]string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UninstallPolicyRuleFlows", arg0)
	ret0, _ := ret[0].(*[]string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UninstallPolicyRuleFlows indicates an expected call of UninstallPolicyRuleFlows
func (mr *MockClientMockRecorder) UninstallPolicyRuleFlows(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UninstallPolicyRuleFlows", reflect.TypeOf((*MockClient)(nil).UninstallPolicyRuleFlows), arg0)
}

// UninstallServiceFlows mocks base method
func (m *MockClient) UninstallServiceFlows(arg0 net.IP, arg1 uint16, arg2 openflow.Protocol) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UninstallServiceFlows", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// UninstallServiceFlows indicates an expected call of UninstallServiceFlows
func (mr *MockClientMockRecorder) UninstallServiceFlows(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UninstallServiceFlows", reflect.TypeOf((*MockClient)(nil).UninstallServiceFlows), arg0, arg1, arg2)
}

// UninstallServiceGroup mocks base method
func (m *MockClient) UninstallServiceGroup(arg0 openflow.GroupIDType) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UninstallServiceGroup", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// UninstallServiceGroup indicates an expected call of UninstallServiceGroup
func (mr *MockClientMockRecorder) UninstallServiceGroup(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UninstallServiceGroup", reflect.TypeOf((*MockClient)(nil).UninstallServiceGroup), arg0)
}

// MockOFEntryOperations is a mock of OFEntryOperations interface
type MockOFEntryOperations struct {
	ctrl     *gomock.Controller
	recorder *MockOFEntryOperationsMockRecorder
}

// MockOFEntryOperationsMockRecorder is the mock recorder for MockOFEntryOperations
type MockOFEntryOperationsMockRecorder struct {
	mock *MockOFEntryOperations
}

// NewMockOFEntryOperations creates a new mock instance
func NewMockOFEntryOperations(ctrl *gomock.Controller) *MockOFEntryOperations {
	mock := &MockOFEntryOperations{ctrl: ctrl}
	mock.recorder = &MockOFEntryOperationsMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockOFEntryOperations) EXPECT() *MockOFEntryOperationsMockRecorder {
	return m.recorder
}

// Add mocks base method
func (m *MockOFEntryOperations) Add(arg0 openflow.Flow) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Add", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// Add indicates an expected call of Add
func (mr *MockOFEntryOperationsMockRecorder) Add(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Add", reflect.TypeOf((*MockOFEntryOperations)(nil).Add), arg0)
}

// AddAll mocks base method
func (m *MockOFEntryOperations) AddAll(arg0 []openflow.Flow) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddAll", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddAll indicates an expected call of AddAll
func (mr *MockOFEntryOperationsMockRecorder) AddAll(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddAll", reflect.TypeOf((*MockOFEntryOperations)(nil).AddAll), arg0)
}

// AddOFEntries mocks base method
func (m *MockOFEntryOperations) AddOFEntries(arg0 []openflow.OFEntry) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddOFEntries", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddOFEntries indicates an expected call of AddOFEntries
func (mr *MockOFEntryOperationsMockRecorder) AddOFEntries(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddOFEntries", reflect.TypeOf((*MockOFEntryOperations)(nil).AddOFEntries), arg0)
}

// Delete mocks base method
func (m *MockOFEntryOperations) Delete(arg0 openflow.Flow) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Delete", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// Delete indicates an expected call of Delete
func (mr *MockOFEntryOperationsMockRecorder) Delete(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Delete", reflect.TypeOf((*MockOFEntryOperations)(nil).Delete), arg0)
}

// DeleteAll mocks base method
func (m *MockOFEntryOperations) DeleteAll(arg0 []openflow.Flow) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteAll", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteAll indicates an expected call of DeleteAll
func (mr *MockOFEntryOperationsMockRecorder) DeleteAll(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteAll", reflect.TypeOf((*MockOFEntryOperations)(nil).DeleteAll), arg0)
}

// DeleteOFEntries mocks base method
func (m *MockOFEntryOperations) DeleteOFEntries(arg0 []openflow.OFEntry) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteOFEntries", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteOFEntries indicates an expected call of DeleteOFEntries
func (mr *MockOFEntryOperationsMockRecorder) DeleteOFEntries(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteOFEntries", reflect.TypeOf((*MockOFEntryOperations)(nil).DeleteOFEntries), arg0)
}

// Modify mocks base method
func (m *MockOFEntryOperations) Modify(arg0 openflow.Flow) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Modify", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// Modify indicates an expected call of Modify
func (mr *MockOFEntryOperationsMockRecorder) Modify(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Modify", reflect.TypeOf((*MockOFEntryOperations)(nil).Modify), arg0)
}
