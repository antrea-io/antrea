package mocks

import (
	"fmt"
	"github.com/golang/mock/gomock"
	"okn/pkg/ovs/ovsconfig"
	"reflect"
)

// MockOVSdbClient is a mock of OVSBridgeClient interface
type MockOVSdbClient struct {
	ctrl     *gomock.Controller
	recorder *MockOVSdbClientMockRecorder
}

// MockOVSdbClientMockRecorder is the mock recorder for MockOVSdbClient
type MockOVSdbClientMockRecorder struct {
	mock *MockOVSdbClient
}

// NewMockOVSdbClient creates a new mock instance
func NewMockOVSdbClient(ctrl *gomock.Controller) *MockOVSdbClient {
	mock := &MockOVSdbClient{ctrl: ctrl}
	mock.recorder = &MockOVSdbClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockOVSdbClient) EXPECT() *MockOVSdbClientMockRecorder {
	return m.recorder
}

// CreateGenevePort mocks base method
func (m *MockOVSdbClient) CreateGenevePort(arg0 string, arg1 int32, arg2 string) (string, ovsconfig.Error) {
	ret := m.ctrl.Call(m, "CreateGenevePort", arg0, arg1, arg2)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(ovsconfig.Error)
	return ret0, ret1
}

// CreateGenevePort indicates an expected call of CreateGenevePort
func (mr *MockOVSdbClientMockRecorder) CreateGenevePort(arg0, arg1, arg2 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateGenevePort", reflect.TypeOf((*MockOVSdbClient)(nil).CreateGenevePort), arg0, arg1, arg2)
}

// CreateInternalPort mocks base method
func (m *MockOVSdbClient) CreateInternalPort(arg0 string, arg1 int32, arg2 map[string]interface{}) (string, ovsconfig.Error) {
	ret := m.ctrl.Call(m, "CreateInternalPort", arg0, arg1, arg2)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(ovsconfig.Error)
	return ret0, ret1
}

// CreateInternalPort indicates an expected call of CreateInternalPort
func (mr *MockOVSdbClientMockRecorder) CreateInternalPort(arg0, arg1, arg2 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateInternalPort", reflect.TypeOf((*MockOVSdbClient)(nil).CreateInternalPort), arg0, arg1, arg2)
}

// CreatePort mocks base method
func (m *MockOVSdbClient) CreatePort(arg0, arg1 string, arg2 map[string]interface{}) (string, ovsconfig.Error) {
	ret := m.ctrl.Call(m, "CreatePort", arg0, arg1, arg2)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(ovsconfig.Error)
	return ret0, ret1
}

// CreatePort indicates an expected call of CreatePort
func (mr *MockOVSdbClientMockRecorder) CreatePort(arg0, arg1, arg2 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreatePort", reflect.TypeOf((*MockOVSdbClient)(nil).CreatePort), arg0, arg1, arg2)
}

// CreateVXLANPort mocks base method
func (m *MockOVSdbClient) CreateVXLANPort(arg0 string, arg1 int32, arg2 string) (string, ovsconfig.Error) {
	ret := m.ctrl.Call(m, "CreateVXLANPort", arg0, arg1, arg2)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(ovsconfig.Error)
	return ret0, ret1
}

// CreateVXLANPort indicates an expected call of CreateVXLANPort
func (mr *MockOVSdbClientMockRecorder) CreateVXLANPort(arg0, arg1, arg2 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateVXLANPort", reflect.TypeOf((*MockOVSdbClient)(nil).CreateVXLANPort), arg0, arg1, arg2)
}

// Delete mocks base method
func (m *MockOVSdbClient) Delete() ovsconfig.Error {
	ret := m.ctrl.Call(m, "Delete")
	ret0, _ := ret[0].(ovsconfig.Error)
	return ret0
}

// Delete indicates an expected call of Delete
func (mr *MockOVSdbClientMockRecorder) Delete() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Delete", reflect.TypeOf((*MockOVSdbClient)(nil).Delete))
}

// DeletePort mocks base method
func (m *MockOVSdbClient) DeletePort(arg0 string) ovsconfig.Error {
	ret := m.ctrl.Call(m, "DeletePort", arg0)
	ret0, _ := ret[0].(ovsconfig.Error)
	return ret0
}

// DeletePort indicates an expected call of DeletePort
func (mr *MockOVSdbClientMockRecorder) DeletePort(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeletePort", reflect.TypeOf((*MockOVSdbClient)(nil).DeletePort), arg0)
}

// DeletePorts mocks base method
func (m *MockOVSdbClient) DeletePorts(arg0 []string) ovsconfig.Error {
	ret := m.ctrl.Call(m, "DeletePorts", arg0)
	ret0, _ := ret[0].(ovsconfig.Error)
	return ret0
}

// DeletePorts indicates an expected call of DeletePorts
func (mr *MockOVSdbClientMockRecorder) DeletePorts(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeletePorts", reflect.TypeOf((*MockOVSdbClient)(nil).DeletePorts), arg0)
}

// GetOFPort mocks base method
func (m *MockOVSdbClient) GetOFPort(arg0 string) (int32, ovsconfig.Error) {
	ret := m.ctrl.Call(m, "GetOFPort", arg0)
	ret0, _ := ret[0].(int32)
	ret1, _ := ret[1].(ovsconfig.Error)
	return ret0, ret1
}

// GetOFPort indicates an expected call of GetOFPort
func (mr *MockOVSdbClientMockRecorder) GetOFPort(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetOFPort", reflect.TypeOf((*MockOVSdbClient)(nil).GetOFPort), arg0)
}

// GetPortData mocks base method
func (m *MockOVSdbClient) GetPortData(arg0, arg1 string) (*ovsconfig.OVSPortData, ovsconfig.Error) {
	ret := m.ctrl.Call(m, "GetPortData", arg0, arg1)
	ret0, _ := ret[0].(*ovsconfig.OVSPortData)
	ret1, _ := ret[1].(ovsconfig.Error)
	return ret0, ret1
}

// GetPortData indicates an expected call of GetPortData
func (mr *MockOVSdbClientMockRecorder) GetPortData(arg0, arg1 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPortData", reflect.TypeOf((*MockOVSdbClient)(nil).GetPortData), arg0, arg1)
}

// GetPortList mocks base method
func (m *MockOVSdbClient) GetPortList() ([]ovsconfig.OVSPortData, ovsconfig.Error) {
	ret := m.ctrl.Call(m, "GetPortList")
	ret0, _ := ret[0].([]ovsconfig.OVSPortData)
	ret1, _ := ret[1].(ovsconfig.Error)
	return ret0, ret1
}

// GetPortList indicates an expected call of GetPortList
func (mr *MockOVSdbClientMockRecorder) GetPortList() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPortList", reflect.TypeOf((*MockOVSdbClient)(nil).GetPortList))
}

type MockOVSConfigError struct {
	error
	timeout   bool
	temporary bool
}

func (e *MockOVSConfigError) Timeout() bool {
	return e.timeout
}

func (e *MockOVSConfigError) Temporary() bool {
	return e.temporary
}

func NewMockOVSConfigError(errMsg string, temporary bool, timeout bool) *MockOVSConfigError {
	return &MockOVSConfigError{error: fmt.Errorf(errMsg), timeout: timeout, temporary: temporary}
}
