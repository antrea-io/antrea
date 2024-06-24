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
// Source: antrea.io/antrea/multicluster/controllers/multicluster/leader (interfaces: MemberClusterStatusManager)
//
// Generated by this command:
//
//	mockgen -copyright_file hack/boilerplate/license_header.raw.txt -destination multicluster/controllers/multicluster/leader/mock_membercluster_status_manager.go -package leader antrea.io/antrea/multicluster/controllers/multicluster/leader MemberClusterStatusManager
//
// Package leader is a generated GoMock package.
package leader

import (
	reflect "reflect"

	v1alpha2 "antrea.io/antrea/multicluster/apis/multicluster/v1alpha2"
	gomock "go.uber.org/mock/gomock"
)

// MockMemberClusterStatusManager is a mock of MemberClusterStatusManager interface.
type MockMemberClusterStatusManager struct {
	ctrl     *gomock.Controller
	recorder *MockMemberClusterStatusManagerMockRecorder
}

// MockMemberClusterStatusManagerMockRecorder is the mock recorder for MockMemberClusterStatusManager.
type MockMemberClusterStatusManagerMockRecorder struct {
	mock *MockMemberClusterStatusManager
}

// NewMockMemberClusterStatusManager creates a new mock instance.
func NewMockMemberClusterStatusManager(ctrl *gomock.Controller) *MockMemberClusterStatusManager {
	mock := &MockMemberClusterStatusManager{ctrl: ctrl}
	mock.recorder = &MockMemberClusterStatusManagerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockMemberClusterStatusManager) EXPECT() *MockMemberClusterStatusManagerMockRecorder {
	return m.recorder
}

// GetMemberClusterStatuses mocks base method.
func (m *MockMemberClusterStatusManager) GetMemberClusterStatuses() []v1alpha2.ClusterStatus {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetMemberClusterStatuses")
	ret0, _ := ret[0].([]v1alpha2.ClusterStatus)
	return ret0
}

// GetMemberClusterStatuses indicates an expected call of GetMemberClusterStatuses.
func (mr *MockMemberClusterStatusManagerMockRecorder) GetMemberClusterStatuses() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetMemberClusterStatuses", reflect.TypeOf((*MockMemberClusterStatusManager)(nil).GetMemberClusterStatuses))
}
