//go:build linux
// +build linux

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

package secondarynetwork

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"antrea.io/antrea/v2/pkg/agent/interfacestore"
	"antrea.io/antrea/v2/pkg/ovs/ovsconfig"
)

func TestSelectStartupSecondaryBridge(t *testing.T) {
	managedBridge := func(name string) ovsconfig.OVSBridgeData {
		return ovsconfig.OVSBridgeData{
			Name: name,
			ExternalIDs: map[string]string{
				interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaSecondaryBridge,
			},
		}
	}
	tests := []struct {
		name               string
		bridges            []ovsconfig.OVSBridgeData
		desiredBridgeName  string
		expectedBridgeName string
		expectedIsLegacy   bool
	}{
		{
			name:              "no startup bridge",
			desiredBridgeName: brNew,
		},
		{
			name: "legacy desired bridge",
			bridges: []ovsconfig.OVSBridgeData{
				{Name: "unrelated"},
				{Name: brNew},
			},
			desiredBridgeName:  brNew,
			expectedBridgeName: brNew,
			expectedIsLegacy:   true,
		},
		{
			name: "managed bridge takes precedence over legacy desired bridge",
			bridges: []ovsconfig.OVSBridgeData{
				{Name: brNew},
				managedBridge(brOld),
			},
			desiredBridgeName:  brNew,
			expectedBridgeName: brOld,
		},
		{
			name: "multiple managed bridges with none matching desired name",
			bridges: []ovsconfig.OVSBridgeData{
				managedBridge(brOld),
				managedBridge(brNew),
			},
			// Neither matches "" → no bridge adopted.
		},
		{
			name: "multiple managed bridges with desired matching one of them",
			bridges: []ovsconfig.OVSBridgeData{
				managedBridge(brOld),
				managedBridge(brNew),
			},
			desiredBridgeName:  brOld,
			expectedBridgeName: brOld,
		},
		{
			name: "multiple managed bridges, desired matches a non-managed bridge",
			bridges: []ovsconfig.OVSBridgeData{
				managedBridge(brOld),
				managedBridge(brNew),
				{Name: "br-other"},
			},
			desiredBridgeName:  "br-other",
			expectedBridgeName: "br-other",
			expectedIsLegacy:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bridgeName, isLegacyBridge, _ := selectStartupSecondaryBridge(tt.bridges, tt.desiredBridgeName)
			assert.Equal(t, tt.expectedBridgeName, bridgeName)
			assert.Equal(t, tt.expectedIsLegacy, isLegacyBridge)
		})
	}
}
