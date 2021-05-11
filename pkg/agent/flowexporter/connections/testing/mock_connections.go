// Copyright 2021 Antrea Authors
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
// Source: antrea.io/antrea/pkg/agent/flowexporter/connections (interfaces: ConnectionStore,ConnTrackDumper,NetFilterConnTrack)

// Package testing is a generated GoMock package.
package testing

import (
	flowexporter "antrea.io/antrea/pkg/agent/flowexporter"
	gomock "github.com/golang/mock/gomock"
	reflect "reflect"
)

// MockConnectionStore is a mock of ConnectionStore interface
type MockConnectionStore struct {
	ctrl     *gomock.Controller
	recorder *MockConnectionStoreMockRecorder
}

// MockConnectionStoreMockRecorder is the mock recorder for MockConnectionStore
type MockConnectionStoreMockRecorder struct {
	mock *MockConnectionStore
}

// NewMockConnectionStore creates a new mock instance
func NewMockConnectionStore(ctrl *gomock.Controller) *MockConnectionStore {
	mock := &MockConnectionStore{ctrl: ctrl}
	mock.recorder = &MockConnectionStoreMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockConnectionStore) EXPECT() *MockConnectionStoreMockRecorder {
	return m.recorder
}

// ForAllConnectionsDo mocks base method
func (m *MockConnectionStore) ForAllConnectionsDo(arg0 flowexporter.ConnectionMapCallBack) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ForAllConnectionsDo", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// ForAllConnectionsDo indicates an expected call of ForAllConnectionsDo
func (mr *MockConnectionStoreMockRecorder) ForAllConnectionsDo(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ForAllConnectionsDo", reflect.TypeOf((*MockConnectionStore)(nil).ForAllConnectionsDo), arg0)
}

// GetConnByKey mocks base method
func (m *MockConnectionStore) GetConnByKey(arg0 flowexporter.ConnectionKey) (*flowexporter.Connection, bool) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetConnByKey", arg0)
	ret0, _ := ret[0].(*flowexporter.Connection)
	ret1, _ := ret[1].(bool)
	return ret0, ret1
}

// GetConnByKey indicates an expected call of GetConnByKey
func (mr *MockConnectionStoreMockRecorder) GetConnByKey(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetConnByKey", reflect.TypeOf((*MockConnectionStore)(nil).GetConnByKey), arg0)
}

// Run mocks base method
func (m *MockConnectionStore) Run(arg0 <-chan struct{}) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Run", arg0)
}

// Run indicates an expected call of Run
func (mr *MockConnectionStoreMockRecorder) Run(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Run", reflect.TypeOf((*MockConnectionStore)(nil).Run), arg0)
}

// SetExportDone mocks base method
func (m *MockConnectionStore) SetExportDone(arg0 flowexporter.ConnectionKey) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetExportDone", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetExportDone indicates an expected call of SetExportDone
func (mr *MockConnectionStoreMockRecorder) SetExportDone(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetExportDone", reflect.TypeOf((*MockConnectionStore)(nil).SetExportDone), arg0)
}

// MockConnTrackDumper is a mock of ConnTrackDumper interface
type MockConnTrackDumper struct {
	ctrl     *gomock.Controller
	recorder *MockConnTrackDumperMockRecorder
}

// MockConnTrackDumperMockRecorder is the mock recorder for MockConnTrackDumper
type MockConnTrackDumperMockRecorder struct {
	mock *MockConnTrackDumper
}

// NewMockConnTrackDumper creates a new mock instance
func NewMockConnTrackDumper(ctrl *gomock.Controller) *MockConnTrackDumper {
	mock := &MockConnTrackDumper{ctrl: ctrl}
	mock.recorder = &MockConnTrackDumperMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockConnTrackDumper) EXPECT() *MockConnTrackDumperMockRecorder {
	return m.recorder
}

// DumpFlows mocks base method
func (m *MockConnTrackDumper) DumpFlows(arg0 uint16) ([]*flowexporter.Connection, int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DumpFlows", arg0)
	ret0, _ := ret[0].([]*flowexporter.Connection)
	ret1, _ := ret[1].(int)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// DumpFlows indicates an expected call of DumpFlows
func (mr *MockConnTrackDumperMockRecorder) DumpFlows(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DumpFlows", reflect.TypeOf((*MockConnTrackDumper)(nil).DumpFlows), arg0)
}

// GetMaxConnections mocks base method
func (m *MockConnTrackDumper) GetMaxConnections() (int, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetMaxConnections")
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetMaxConnections indicates an expected call of GetMaxConnections
func (mr *MockConnTrackDumperMockRecorder) GetMaxConnections() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetMaxConnections", reflect.TypeOf((*MockConnTrackDumper)(nil).GetMaxConnections))
}

// MockNetFilterConnTrack is a mock of NetFilterConnTrack interface
type MockNetFilterConnTrack struct {
	ctrl     *gomock.Controller
	recorder *MockNetFilterConnTrackMockRecorder
}

// MockNetFilterConnTrackMockRecorder is the mock recorder for MockNetFilterConnTrack
type MockNetFilterConnTrackMockRecorder struct {
	mock *MockNetFilterConnTrack
}

// NewMockNetFilterConnTrack creates a new mock instance
func NewMockNetFilterConnTrack(ctrl *gomock.Controller) *MockNetFilterConnTrack {
	mock := &MockNetFilterConnTrack{ctrl: ctrl}
	mock.recorder = &MockNetFilterConnTrackMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockNetFilterConnTrack) EXPECT() *MockNetFilterConnTrackMockRecorder {
	return m.recorder
}

// Dial mocks base method
func (m *MockNetFilterConnTrack) Dial() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Dial")
	ret0, _ := ret[0].(error)
	return ret0
}

// Dial indicates an expected call of Dial
func (mr *MockNetFilterConnTrackMockRecorder) Dial() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Dial", reflect.TypeOf((*MockNetFilterConnTrack)(nil).Dial))
}

// DumpFlowsInCtZone mocks base method
func (m *MockNetFilterConnTrack) DumpFlowsInCtZone(arg0 uint16) ([]*flowexporter.Connection, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DumpFlowsInCtZone", arg0)
	ret0, _ := ret[0].([]*flowexporter.Connection)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DumpFlowsInCtZone indicates an expected call of DumpFlowsInCtZone
func (mr *MockNetFilterConnTrackMockRecorder) DumpFlowsInCtZone(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DumpFlowsInCtZone", reflect.TypeOf((*MockNetFilterConnTrack)(nil).DumpFlowsInCtZone), arg0)
}
