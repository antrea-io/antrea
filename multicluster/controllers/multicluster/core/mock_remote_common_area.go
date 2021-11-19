// Copyright 2021 Antrea Authors.
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
//

// Code generated by MockGen. DO NOT EDIT.
// Source: controllers/multicluster/core/remote_common_area.go

// Package core is a generated GoMock package.
package core

import (
	context "context"
	reflect "reflect"

	common "antrea.io/antrea/multicluster/controllers/multicluster/common"
	gomock "github.com/golang/mock/gomock"
	meta "k8s.io/apimachinery/pkg/api/meta"
	runtime "k8s.io/apimachinery/pkg/runtime"
	client "sigs.k8s.io/controller-runtime/pkg/client"
)

// MockRemoteCommonArea is a mock of RemoteCommonArea interface.
type MockRemoteCommonArea struct {
	ctrl     *gomock.Controller
	recorder *MockRemoteCommonAreaMockRecorder
}

// MockRemoteCommonAreaMockRecorder is the mock recorder for MockRemoteCommonArea.
type MockRemoteCommonAreaMockRecorder struct {
	mock *MockRemoteCommonArea
}

// NewMockRemoteCommonArea creates a new mock instance.
func NewMockRemoteCommonArea(ctrl *gomock.Controller) *MockRemoteCommonArea {
	mock := &MockRemoteCommonArea{ctrl: ctrl}
	mock.recorder = &MockRemoteCommonAreaMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRemoteCommonArea) EXPECT() *MockRemoteCommonAreaMockRecorder {
	return m.recorder
}

// Create mocks base method.
func (m *MockRemoteCommonArea) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, obj}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Create", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// Create indicates an expected call of Create.
func (mr *MockRemoteCommonAreaMockRecorder) Create(ctx, obj interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, obj}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockRemoteCommonArea)(nil).Create), varargs...)
}

// Delete mocks base method.
func (m *MockRemoteCommonArea) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, obj}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Delete", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// Delete indicates an expected call of Delete.
func (mr *MockRemoteCommonAreaMockRecorder) Delete(ctx, obj interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, obj}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Delete", reflect.TypeOf((*MockRemoteCommonArea)(nil).Delete), varargs...)
}

// DeleteAllOf mocks base method.
func (m *MockRemoteCommonArea) DeleteAllOf(ctx context.Context, obj client.Object, opts ...client.DeleteAllOfOption) error {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, obj}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "DeleteAllOf", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteAllOf indicates an expected call of DeleteAllOf.
func (mr *MockRemoteCommonAreaMockRecorder) DeleteAllOf(ctx, obj interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, obj}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteAllOf", reflect.TypeOf((*MockRemoteCommonArea)(nil).DeleteAllOf), varargs...)
}

// Get mocks base method.
func (m *MockRemoteCommonArea) Get(ctx context.Context, key client.ObjectKey, obj client.Object) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", ctx, key, obj)
	ret0, _ := ret[0].(error)
	return ret0
}

// Get indicates an expected call of Get.
func (mr *MockRemoteCommonAreaMockRecorder) Get(ctx, key, obj interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockRemoteCommonArea)(nil).Get), ctx, key, obj)
}

// GetClusterID mocks base method.
func (m *MockRemoteCommonArea) GetClusterID() common.ClusterID {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetClusterID")
	ret0, _ := ret[0].(common.ClusterID)
	return ret0
}

// GetClusterID indicates an expected call of GetClusterID.
func (mr *MockRemoteCommonAreaMockRecorder) GetClusterID() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetClusterID", reflect.TypeOf((*MockRemoteCommonArea)(nil).GetClusterID))
}

// GetNamespace mocks base method.
func (m *MockRemoteCommonArea) GetNamespace() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetNamespace")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetNamespace indicates an expected call of GetNamespace.
func (mr *MockRemoteCommonAreaMockRecorder) GetNamespace() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetNamespace", reflect.TypeOf((*MockRemoteCommonArea)(nil).GetNamespace))
}

// IsConnected mocks base method.
func (m *MockRemoteCommonArea) IsConnected() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsConnected")
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsConnected indicates an expected call of IsConnected.
func (mr *MockRemoteCommonAreaMockRecorder) IsConnected() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsConnected", reflect.TypeOf((*MockRemoteCommonArea)(nil).IsConnected))
}

// List mocks base method.
func (m *MockRemoteCommonArea) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, list}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "List", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// List indicates an expected call of List.
func (mr *MockRemoteCommonAreaMockRecorder) List(ctx, list interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, list}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "List", reflect.TypeOf((*MockRemoteCommonArea)(nil).List), varargs...)
}

// Patch mocks base method.
func (m *MockRemoteCommonArea) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, obj, patch}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Patch", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// Patch indicates an expected call of Patch.
func (mr *MockRemoteCommonAreaMockRecorder) Patch(ctx, obj, patch interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, obj, patch}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Patch", reflect.TypeOf((*MockRemoteCommonArea)(nil).Patch), varargs...)
}

// RESTMapper mocks base method.
func (m *MockRemoteCommonArea) RESTMapper() meta.RESTMapper {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RESTMapper")
	ret0, _ := ret[0].(meta.RESTMapper)
	return ret0
}

// RESTMapper indicates an expected call of RESTMapper.
func (mr *MockRemoteCommonAreaMockRecorder) RESTMapper() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RESTMapper", reflect.TypeOf((*MockRemoteCommonArea)(nil).RESTMapper))
}

// Scheme mocks base method.
func (m *MockRemoteCommonArea) Scheme() *runtime.Scheme {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Scheme")
	ret0, _ := ret[0].(*runtime.Scheme)
	return ret0
}

// Scheme indicates an expected call of Scheme.
func (mr *MockRemoteCommonAreaMockRecorder) Scheme() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Scheme", reflect.TypeOf((*MockRemoteCommonArea)(nil).Scheme))
}

// Start mocks base method.
func (m *MockRemoteCommonArea) Start() (context.CancelFunc, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Start")
	ret0, _ := ret[0].(context.CancelFunc)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Start indicates an expected call of Start.
func (mr *MockRemoteCommonAreaMockRecorder) Start() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Start", reflect.TypeOf((*MockRemoteCommonArea)(nil).Start))
}

// StartWatching mocks base method.
func (m *MockRemoteCommonArea) StartWatching() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StartWatching")
	ret0, _ := ret[0].(error)
	return ret0
}

// StartWatching indicates an expected call of StartWatching.
func (mr *MockRemoteCommonAreaMockRecorder) StartWatching() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StartWatching", reflect.TypeOf((*MockRemoteCommonArea)(nil).StartWatching))
}

// Status mocks base method.
func (m *MockRemoteCommonArea) Status() client.StatusWriter {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Status")
	ret0, _ := ret[0].(client.StatusWriter)
	return ret0
}

// Status indicates an expected call of Status.
func (mr *MockRemoteCommonAreaMockRecorder) Status() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Status", reflect.TypeOf((*MockRemoteCommonArea)(nil).Status))
}

// Stop mocks base method.
func (m *MockRemoteCommonArea) Stop() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Stop")
	ret0, _ := ret[0].(error)
	return ret0
}

// Stop indicates an expected call of Stop.
func (mr *MockRemoteCommonAreaMockRecorder) Stop() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Stop", reflect.TypeOf((*MockRemoteCommonArea)(nil).Stop))
}

// StopWatching mocks base method.
func (m *MockRemoteCommonArea) StopWatching() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "StopWatching")
}

// StopWatching indicates an expected call of StopWatching.
func (mr *MockRemoteCommonAreaMockRecorder) StopWatching() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StopWatching", reflect.TypeOf((*MockRemoteCommonArea)(nil).StopWatching))
}

// Update mocks base method.
func (m *MockRemoteCommonArea) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, obj}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Update", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// Update indicates an expected call of Update.
func (mr *MockRemoteCommonAreaMockRecorder) Update(ctx, obj interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, obj}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Update", reflect.TypeOf((*MockRemoteCommonArea)(nil).Update), varargs...)
}
