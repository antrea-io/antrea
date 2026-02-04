// Copyright 2026 Antrea Authors
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

package util

import (
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	mock "go.uber.org/mock/gomock"

	"antrea.io/antrea/pkg/ovs/ovsconfig"
	ovsconfigtest "antrea.io/antrea/pkg/ovs/ovsconfig/testing"
)

const (
	nonExistingInterface = "non-existing"
	firstUplinkOFPort    = 32768
)

func TestConnectPhyInterfacesToOVSBridge(t *testing.T) {
	tests := []struct {
		name               string
		physicalInterfaces []string
		expectedErr        string
		expectedCalls      func(m *ovsconfigtest.MockOVSBridgeClient)
	}{
		{
			name:               "one interface",
			physicalInterfaces: []string{"eth0~"},
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().GetOFPort("eth0~", false).Return(int32(firstUplinkOFPort), ovsconfig.InvalidArgumentsError("port not found"))
				m.EXPECT().CreateUplinkPort("eth0~", int32(firstUplinkOFPort), map[string]interface{}{"antrea-type": "uplink"}).Return("", nil)
			},
		},
		{
			name:               "two interfaces",
			physicalInterfaces: []string{"eth1", "eth2"},
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().GetOFPort("eth1", false).Return(int32(firstUplinkOFPort), ovsconfig.InvalidArgumentsError("port not found"))
				m.EXPECT().CreateUplinkPort("eth1", int32(firstUplinkOFPort), map[string]interface{}{"antrea-type": "uplink"}).Return("", nil)
				m.EXPECT().GetOFPort("eth2", false).Return(int32(firstUplinkOFPort+1), ovsconfig.InvalidArgumentsError("port not found"))
				m.EXPECT().CreateUplinkPort("eth2", int32(firstUplinkOFPort+1), map[string]interface{}{"antrea-type": "uplink"}).Return("", nil)
			},
		},
		{
			name:               "interface already attached",
			physicalInterfaces: []string{"eth1"},
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().GetOFPort("eth1", false).Return(int32(firstUplinkOFPort), nil)
			},
		},
		{
			name:               "non-existing interface",
			physicalInterfaces: []string{nonExistingInterface, "eth2"},
			expectedErr:        "failed to get interface",
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().GetOFPort("eth2", false).Return(int32(firstUplinkOFPort+1), ovsconfig.InvalidArgumentsError("port not found"))
				m.EXPECT().CreateUplinkPort("eth2", int32(firstUplinkOFPort+1), map[string]interface{}{"antrea-type": "uplink"}).Return("", nil)
			},
		},
		{
			name:               "create port error",
			physicalInterfaces: []string{"eth1"},
			expectedErr:        "create error",
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().GetOFPort("eth1", false).Return(int32(firstUplinkOFPort), ovsconfig.InvalidArgumentsError("port not found"))
				m.EXPECT().CreateUplinkPort("eth1", int32(firstUplinkOFPort), map[string]interface{}{"antrea-type": "uplink"}).Return("", ovsconfig.InvalidArgumentsError("create error"))
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			controller := mock.NewController(t)
			mockOVSBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(controller)

			mockInterfaceByName(t)
			if tc.expectedCalls != nil {
				tc.expectedCalls(mockOVSBridgeClient)
			}

			err := ConnectPhyInterfacesToOVSBridge(mockOVSBridgeClient, tc.physicalInterfaces)
			if tc.expectedErr != "" {
				assert.ErrorContains(t, err, tc.expectedErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func mockInterfaceByName(t *testing.T) {
	prevFunc := interfaceByNameFn
	interfaceByNameFn = func(name string) (*net.Interface, error) {
		if name == nonExistingInterface {
			return nil, errors.New("interface not found")
		}
		return nil, nil
	}
	t.Cleanup(func() { interfaceByNameFn = prevFunc })
}
