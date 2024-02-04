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

package secondarynetwork

import (
	"errors"
	"net"
	"testing"

	"github.com/TomCodeLV/OVSDB-golang-lib/pkg/ovsdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	mock "go.uber.org/mock/gomock"

	agentconfig "antrea.io/antrea/pkg/config/agent"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	ovsconfigtest "antrea.io/antrea/pkg/ovs/ovsconfig/testing"
)

const nonExistingInterface = "non-existing"

func TestCreateOVSBridge(t *testing.T) {
	tests := []struct {
		name               string
		ovsBridges         []string
		physicalInterfaces []string
		expectedErr        string
		expectedCalls      func(m *ovsconfigtest.MockOVSBridgeClient)
	}{
		{
			name: "no bridge",
		},
		{
			name:       "no interface",
			ovsBridges: []string{"br1"},
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().Create().Return(nil)
			},
		},
		{
			name:       "two bridges",
			ovsBridges: []string{"br1", "br2"},
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().Create().Return(nil)
			},
		},
		{
			name:        "create br error",
			ovsBridges:  []string{"br1", "br2"},
			expectedErr: "create error",
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().Create().Return(ovsconfig.InvalidArgumentsError("create error"))
			},
		},
		{
			name:               "one interface",
			ovsBridges:         []string{"br1"},
			physicalInterfaces: []string{"eth1"},
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().Create().Return(nil)
				m.EXPECT().GetOFPort("eth1", false).Return(int32(0), ovsconfig.InvalidArgumentsError("port not found"))
				m.EXPECT().CreateUplinkPort("eth1", int32(0), map[string]interface{}{"antrea-type": "uplink"}).Return("", nil)
			},
		},
		{
			name:               "two interfaces",
			ovsBridges:         []string{"br1", "br2"},
			physicalInterfaces: []string{"eth1", "eth2"},
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().Create().Return(nil)
				m.EXPECT().GetOFPort("eth1", false).Return(int32(0), ovsconfig.InvalidArgumentsError("port not found"))
				m.EXPECT().CreateUplinkPort("eth1", int32(0), map[string]interface{}{"antrea-type": "uplink"}).Return("", nil)
				m.EXPECT().GetOFPort("eth2", false).Return(int32(1), ovsconfig.InvalidArgumentsError("port not found"))
				m.EXPECT().CreateUplinkPort("eth2", int32(1), map[string]interface{}{"antrea-type": "uplink"}).Return("", nil)
			},
		},
		{
			name:               "interface already attached",
			ovsBridges:         []string{"br1"},
			physicalInterfaces: []string{"eth1"},
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().Create().Return(nil)
				m.EXPECT().GetOFPort("eth1", false).Return(int32(0), nil)
			},
		},
		{
			name:               "non-existing interface",
			ovsBridges:         []string{"br1"},
			physicalInterfaces: []string{nonExistingInterface, "eth2"},
			expectedErr:        "failed to get interface",
		},
		{
			name:               "create port error",
			ovsBridges:         []string{"br1"},
			physicalInterfaces: []string{"eth1"},
			expectedErr:        "create error",
			expectedCalls: func(m *ovsconfigtest.MockOVSBridgeClient) {
				m.EXPECT().Create().Return(nil)
				m.EXPECT().GetOFPort("eth1", false).Return(int32(0), ovsconfig.InvalidArgumentsError("port not found"))
				m.EXPECT().CreateUplinkPort("eth1", int32(0), map[string]interface{}{"antrea-type": "uplink"}).Return("", ovsconfig.InvalidArgumentsError("create error"))
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var bridges []agentconfig.OVSBridgeConfig
			for _, brName := range tc.ovsBridges {
				br := agentconfig.OVSBridgeConfig{BridgeName: brName}
				br.PhysicalInterfaces = tc.physicalInterfaces
				bridges = append(bridges, br)
			}

			controller := mock.NewController(t)
			mockOVSBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(controller)

			mockNewOVSBridge(t, mockOVSBridgeClient)
			mockInterfaceByName(t)
			if tc.expectedCalls != nil {
				tc.expectedCalls(mockOVSBridgeClient)
			}

			brClient, err := createOVSBridge(bridges, nil)
			if tc.expectedErr != "" {
				assert.ErrorContains(t, err, tc.expectedErr)
				assert.Nil(t, brClient)
			} else {
				require.NoError(t, err)
				if tc.expectedCalls != nil {
					assert.NotNil(t, brClient)
				}
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

func mockNewOVSBridge(t *testing.T, brClient ovsconfig.OVSBridgeClient) {
	prevFunc := newOVSBridgeFn
	newOVSBridgeFn = func(bridgeName string, ovsDatapathType ovsconfig.OVSDatapathType, ovsdb *ovsdb.OVSDB) ovsconfig.OVSBridgeClient {
		return brClient
	}
	t.Cleanup(func() { newOVSBridgeFn = prevFunc })
}
