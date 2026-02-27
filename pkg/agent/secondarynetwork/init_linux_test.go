//go:build linux
// +build linux

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
	"testing"

	"github.com/TomCodeLV/OVSDB-golang-lib/pkg/ovsdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	mock "go.uber.org/mock/gomock"

	agentconfig "antrea.io/antrea/pkg/config/agent"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	ovsconfigtest "antrea.io/antrea/pkg/ovs/ovsconfig/testing"
)

func TestCreateOVSBridge(t *testing.T) {
	tests := []struct {
		name          string
		ovsBridges    []string
		expectedErr   string
		expectedCalls func(m *ovsconfigtest.MockOVSBridgeClient)
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
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var bridges []agentconfig.OVSBridgeConfig
			for _, brName := range tc.ovsBridges {
				br := agentconfig.OVSBridgeConfig{BridgeName: brName}
				bridges = append(bridges, br)
			}

			controller := mock.NewController(t)
			mockOVSBridgeClient := ovsconfigtest.NewMockOVSBridgeClient(controller)

			mockNewOVSBridge(t, mockOVSBridgeClient)
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

func mockNewOVSBridge(t *testing.T, brClient ovsconfig.OVSBridgeClient) {
	prevFunc := newOVSBridgeFn
	newOVSBridgeFn = func(bridgeName string, ovsDatapathType ovsconfig.OVSDatapathType, ovsdb *ovsdb.OVSDB, options ...ovsconfig.OVSBridgeOption) ovsconfig.OVSBridgeClient {
		return brClient
	}
	t.Cleanup(func() { newOVSBridgeFn = prevFunc })
}
