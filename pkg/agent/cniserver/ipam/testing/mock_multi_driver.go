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

package testing

import (
	argtypes "antrea.io/antrea/pkg/agent/cniserver/types"

	invoke "github.com/containernetworking/cni/pkg/invoke"
	current "github.com/containernetworking/cni/pkg/types/current"
	gomock "github.com/golang/mock/gomock"

	reflect "reflect"
)

// MockIPAMMultiDriver is a mock of IPAMDriver interface
type MockIPAMMultiDriver struct {
	ctrl     *gomock.Controller
	recorder *MockIPAMMultiDriverMockRecorder
	ownsFunc func(*argtypes.K8sArgs) bool
}

// MockIPAMMultiDriverMockRecorder is the mock recorder for MockIPAMMultiDriver
type MockIPAMMultiDriverMockRecorder struct {
	mock *MockIPAMMultiDriver
}

// NewMockIPAMMultiDriver creates a new mock instance
func NewMockIPAMMultiDriver(ctrl *gomock.Controller, ownsFunc func(*argtypes.K8sArgs) bool) *MockIPAMMultiDriver {
	mock := &MockIPAMMultiDriver{ctrl: ctrl}
	mock.recorder = &MockIPAMMultiDriverMockRecorder{mock}
	mock.ownsFunc = ownsFunc
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockIPAMMultiDriver) EXPECT() *MockIPAMMultiDriverMockRecorder {
	return m.recorder
}

// Add mocks base method
func (m *MockIPAMMultiDriver) Add(arg0 *invoke.Args, arg1 []byte, arg2 interface{}) (*current.Result, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Add", arg0, arg1, arg2)
	ret0, _ := ret[0].(*current.Result)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Add indicates an expected call of Add
func (mr *MockIPAMMultiDriverMockRecorder) Add(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Add", reflect.TypeOf((*MockIPAMMultiDriver)(nil).Add), arg0, arg1, arg2)
}

// Check mocks base method
func (m *MockIPAMMultiDriver) Check(arg0 *invoke.Args, arg1 []byte, arg2 interface{}) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Check", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// Check indicates an expected call of Check
func (mr *MockIPAMMultiDriverMockRecorder) Check(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Check", reflect.TypeOf((*MockIPAMMultiDriver)(nil).Check), arg0, arg1, arg2)
}

// Del mocks base method
func (m *MockIPAMMultiDriver) Del(arg0 *invoke.Args, arg1 []byte, arg2 interface{}) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Del", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// Del indicates an expected call of Del
func (mr *MockIPAMMultiDriverMockRecorder) Del(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Del", reflect.TypeOf((*MockIPAMMultiDriver)(nil).Del), arg0, arg1, arg2)
}

// We don't record a call to Owns, since its a helper method, and rely on functional calls
// such as Add, Del in testing
func (m *MockIPAMMultiDriver) Owns(arg0 *invoke.Args, k8sArgs *argtypes.K8sArgs, arg2 []byte) (bool, interface{}, error) {
	if m.ownsFunc == nil {
		return true, nil, nil
	}

	return m.ownsFunc(k8sArgs), nil, nil
}
