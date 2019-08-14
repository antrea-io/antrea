package mocks

import (
	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/golang/mock/gomock"
	"reflect"
)

// MockIPAMDriver is a mock of IPAMDriver interface
type MockIPAMDriver struct {
	ctrl     *gomock.Controller
	recorder *MockIPAMDriverMockRecorder
}

// MockIPAMDriverMockRecorder is the mock recorder for MockIPAMDriver
type MockIPAMDriverMockRecorder struct {
	mock *MockIPAMDriver
}

// NewMockIPAMDriver creates a new mock instance
func NewMockIPAMDriver(ctrl *gomock.Controller) *MockIPAMDriver {
	mock := &MockIPAMDriver{ctrl: ctrl}
	mock.recorder = &MockIPAMDriverMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockIPAMDriver) EXPECT() *MockIPAMDriverMockRecorder {
	return m.recorder
}

// Checkmocks base method
func (m *MockIPAMDriver) Check(arg0 *invoke.Args, arg1 []byte) error {
	ret := m.ctrl.Call(m, "Check", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// Check indicates an expected call of Check
func (mr *MockIPAMDriverMockRecorder) Check(arg0, arg1 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Check", reflect.TypeOf((*MockIPAMDriver)(nil).Check), arg0, arg1)
}

// Del mocks base method
func (m *MockIPAMDriver) Del(arg0 *invoke.Args, arg1 []byte) error {
	ret := m.ctrl.Call(m, "Del", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// ReleaseNetConf indicates an expected call of Del
func (mr *MockIPAMDriverMockRecorder) Del(arg0, arg1 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Del", reflect.TypeOf((*MockIPAMDriver)(nil).Del), arg0, arg1)
}

// Add mocks base method
func (m *MockIPAMDriver) Add(arg0 *invoke.Args, arg1 []byte) (*current.Result, error) {
	ret := m.ctrl.Call(m, "Add", arg0, arg1)
	ret0, _ := ret[0].(*current.Result)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Add indicates an expected call of Add
func (mr *MockIPAMDriverMockRecorder) Add(arg0, arg1 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Add", reflect.TypeOf((*MockIPAMDriver)(nil).Add), arg0, arg1)
}
